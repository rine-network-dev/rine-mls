# rine patch to mls-rs 0.55.2

This directory is `mls-rs` 0.55.2 as published on crates.io (upstream commit
`42131c9959efb1d3928428259bc89853027f730d`, see `.cargo_vcs_info.json`), under its original
Apache-2.0 / MIT licences (`LICENSE-apache`, `LICENSE-mit`, fetched from that commit because the
crates.io package omits them). The workspace builds it through `[patch.crates-io]` in
`rine-mls/Cargo.toml`; the version stays 0.55.2, so the exact `=0.55.2` pin still binds. The
directory is excluded from the cargo workspace (`exclude = ["vendor"]`), so its own tests and lints
are not part of rine's gates.

Pristine crate SHA-256 (crates.io `mls-rs-0.55.2.crate`, 275,928 bytes): `94cfaf16b4887985489acc3847fd94c2bb5025d87d5d0a4928105fe16c7f1b3a`
(`scripts/check-vendor-patch.sh` hashes the cached crate against this pin and compares its unpacked tree with the
pristine commit.)

The pristine tree is the commit `build(rine-mls): vendor pristine mls-rs 0.55.2`; the patch is the
diff on top of it (`git diff <that commit> -- rine-mls/vendor/mls-rs-0.55.2`). Nothing outside the
files below changed.

## Why

rine's org can read the closed groups its agents sit in, one epoch at a time, from a per-epoch
escrow that holds the two secrets that decrypt a PrivateMessage and the public data needed to check
its signature. Upstream mls-rs offers none of this: the secret tree consumes its root on the first
leaf derivation, so the secrets cannot be read after a message was processed; the ciphertext
processor is crate-private; and it checks the AEAD only.

## What changed

1. `src/group/epoch_read.rs` (new). `EpochReadSecrets`: the epoch's `GroupContext`, leaf count,
   `sender_data_secret`, the secret-tree root (`encryption_secret`), the `epoch_authenticator` and
   the signature public key of every non-empty leaf. Secrets are `Zeroizing`; `Debug` prints the
   epoch only. It holds none of `epoch_secret`, `init_secret`, `exporter_secret`,
   `membership_key`, `confirmation_key`, `resumption_secret` or any private key, so it can open
   messages and cannot advance the group or sign. `EpochReadExports` is the crate-private list of
   untaken exports.

2. Capture at epoch **installation**, not at key derivation. `from_epoch_secret` also runs for
   epochs that are never installed (a received commit refused with `InvalidConfirmationTag`, an own
   commit built and then cleared, a Welcome that fails its checks), so the export is pushed only
   where a group takes an epoch. The four sites in `src/group/mod.rs`, by function:
   - `Group::new`, group creation;
   - `join_with`, reached by a Welcome and by the external joiner's placeholder. The placeholder's
     secret tree is empty (`SecretTree::is_placeholder`) and is skipped; the joiner's real epoch is
     installed when its own commit applies;
   - `apply_detached_commit` (behind `apply_pending_commit`), which covers own commits, external
     commits and resyncs;
   - `update_key_schedule`, the received-commit path, after the confirmation tag checks.
   The root is read through `SecretTree::unconsumed_root` before any `consume_node`. If the root of
   a real tree was already consumed the install fails with the new
   `MlsError::EpochReadSecretsConsumed` instead of skipping. At the two sites that archive the
   outgoing epoch (`apply_detached_commit`, `update_key_schedule`) the export is captured first, then
   `insert_past_epoch` runs, then the export is pushed, so a failure in between leaves the list
   untouched.

3. `Group::take_epoch_read_exports()` returns the exports installed since the last call, oldest
   first, and empties the list. It returns `(exports, dropped)`: the list is capped at
   `MAX_QUEUED_EPOCH_READ_EXPORTS` (32, the Welcomes one commit may carry), so a caller that cannot
   seal (no verified escrow key) does not pile epoch secrets into the snapshot without bound. A push
   past the cap discards the OLDEST export and records only its epoch in `dropped` (8 bytes, not a
   secret), which the same take returns and empties. `Group::epoch_read_backlog()` reports
   `(queued, dropped)` counts without taking. `dropped` is a second trailing vector in the same
   snapshot section, itself capped at `MAX_DROPPED_EPOCH_READ_EPOCHS` (1024, the newest kept) so a
   deferral that never ends cannot grow the snapshot without bound; a section written before it
   existed decodes with none. The list is a trailing section of the group `Snapshot`
   (`src/group/snapshot.rs`), so a snapshot written between install and take holds the exports and
   a crash loses nothing. A snapshot written by an unpatched mls-rs has no such section and decodes
   as an empty list (`EpochReadExports::mls_decode` accepts an exhausted reader). The `Snapshot`
   `version` stays 1. The `Group` field and the snapshot wiring are not feature-gated; `snapshot.rs`
   also gives the test-only `Default` for `Snapshot` an empty list.

   Rolling back to pristine mls-rs: upstream `Snapshot::mls_decode` ignores trailing bytes, so a
   state file written by the patched crate loads, and the exports not yet taken are silently
   dropped. Call `take_epoch_read_exports` and persist its result before swapping the crate out.

4. `src/group/epoch_reader.rs` (new). `EpochReader<P>` rebuilds a `PriorEpoch` from the escrowed
   secrets, with `self_index` `u32::MAX`, and runs the crate's own `CiphertextProcessor` and
   `verify_auth_content_signature` on it. `open` returns the application data, sender leaf and
   generation, and `EpochReadError::Rejected` for a message whose AEAD opens but whose framing
   signature does not verify under the key recorded for the leaf its sender data names. No decrypt
   or signature logic is reimplemented.
   - `self_index = u32::MAX`: `CiphertextProcessor::open` refuses a sender equal to the provider's
     own index, and every real leaf index is smaller, so a message from leaf 0 opens.
   - Forward step: a fresh reader starts every leaf ratchet at generation 0, and mls-rs refuses a
     generation more than `MAX_RATCHET_BACK_HISTORY` (1024) ahead. `SecretTree::skip_forward`
     (`src/group/secret_tree.rs`) steps the sender's ratchet with the crate's own
     `next_message_key` until the target is within 1024, without adding the stepped keys to the
     out-of-order history. Generations within 1024 are handled by the normal path, so messages of
     one sender may be opened out of order inside that window.
   - Reach: a generation more than `MAX_READER_SKIP` (65,536, re-exported from `src/group/mod.rs`)
     steps beyond that window is refused with `EpochReadError::GenerationTooFar`, before any
     ratchet step, so a member cannot make a reader spin by naming a huge generation.
   - Only application content is opened: any other content type is refused before the ratchet
     moves.
   - `OpenedMessage` carries `signer_public_key`, the leaf key the framing signature verified
     under, so a caller can compare it with the key chain-verified for the agent the envelope names.

5. `src/group/secret_tree.rs`: `TreeSecretsVec::node`, `SecretTree::{is_placeholder, leaf_count,
   unconsumed_root, skip_forward}`, `SecretRatchets::skip_forward`,
   `SecretKeyRatchet::skip_forward`.

6. `src/client.rs`: `MlsError::EpochReadSecretsConsumed`.

7. `src/group/mod.rs`: modules `epoch_read` and `epoch_reader`, the re-exports `EpochReadSecrets`,
   `EpochReader`, `EpochReadError` and `OpenedMessage`, and the `epoch_read_exports` field.
   `EpochReader` needs the `prior_epoch` and `private_message` features, which rine's
   `rfc_compliant` set includes.

8. `src/group/mod.rs`: `Group::signer_public_key()` derives the public half of the key the member's
   next frame is signed with. The upstream group exposes the signing identity on its leaf but not
   the key it actually signs with, and the two differ after `set_new_signing_identity` is applied
   by a handle that was installed from an older KeyPackage. rine reads it to refuse an update
   whose framing signature no receiver could verify.

9. `src/group/util.rs`, `src/group/mod.rs`: `validate_sender_signature_key_from_prior_epoch` is
   successor-aware. Upstream refuses a prior-epoch private message whenever the sender's leaf key
   in the current tree differs from the key it held in that epoch, which also refuses the sender's
   own messages after a self-update, because the rotation replaced the key. `PriorEpoch` stores no
   credentials, so the check cannot name who held the epoch's key. The patch uses the current
   leaf's credential as the hypothesis: the message opens when the current leaf carries the same
   key, or when the identity provider's `valid_successor` accepts the current leaf as a successor
   of that credential holding the epoch's key. rine's allowed-set provider decides it, and it
   accepts only a strictly newer chain-verified generation of the same agent. A blank leaf (a
   removed sender) and a leaf another agent now holds still return `MemberNotFound`, so nothing is
   attributed to whoever reuses the index. The framing signature is still verified against the
   epoch's key before this check runs. Both call sites (`prior_epoch_membership_key` and the
   private-message path) pass `&self.config.identity_provider()` and
   `&self.state.context.extensions`. The patch is safe only under a key-aware `valid_successor`: a
   credential-only provider (stock `BasicIdentityProvider`) accepts a leaf reused by another
   identity. The pin is `RineMlsConfig` (`rine-mls-core/src/client/mod.rs`), which names
   `AllowedSetIdentityProvider` concretely, so every rine client is built with it and a second
   provider cannot be wired without changing that type.

## Known limit

The cap is `MAX_READER_SKIP` ratchet steps per `open`, a fixed number rather than a parameter. A
reader that wants a tighter bound than 65,536 + 1024 generations must check the generation itself
before calling `open`.

## Upgrading mls-rs

Re-vendor the new release, re-apply this patch, update this file, and re-run the per-site mutation
proof: removing the export at any one of the four install sites must turn the test in the right
column red (all in `rine-mls-core/tests/escrow_exports.rs`).

| Site | Test that must go red |
|---|---|
| `Group::new` | `test_install_site_create_when_a_group_is_founded_exports_epoch_zero` |
| `join_with` | `test_install_site_welcome_when_a_member_joins_exports_only_the_joined_epoch` |
| `apply_detached_commit` | `test_install_site_own_commit_when_a_member_is_added_exports_the_new_epoch` |
| `update_key_schedule` | `test_install_site_received_commit_when_a_member_applies_it_exports_the_new_epoch` |

Item 9 is proven the same way, in `rine-mls-core/tests/prior_epoch_messages.rs`: deleting the
`valid_successor` branch must turn `test_decrypt_when_sender_self_updated_after_sending_then_opens`
red, and deleting the call in `src/group/mod.rs` must turn the removed-sender and reused-leaf
tests red. The equal-or-older generation, newer-claim and other-agent refusals are pinned by the
`test_decrypt_when_epoch_key_*` tests in the same file (accepting any `Ok(_)` from `valid_successor`
turns the equal and newer-generation ones red).

Upstream's `test_messages_from_prior_epoch_aliased_key_not_processed` cannot run offline (its
dev-dependency crypto provider is not in the cargo registry), and ported onto the cached rustcrypto
provider with the stock `BasicIdentityProvider` it does NOT pass under this patch: the stock
`valid_successor` compares credential identities only, the check builds the predecessor from the
current leaf's credential, so a leaf reused by another agent is accepted and both the prior-epoch
decrypt and `validate_custom_proposal` open (the unpatched crate refuses both with `MemberNotFound`).
The patch is therefore only safe under an identity provider whose `valid_successor` also decides on
the keys, as rine's allowed-set provider does; rine's reused-leaf test covers the same shape under
that provider. Treat the upstream test as unverified and known to differ under a credential-only
provider.

`EpochReadSecrets` is serialised twice: by the MLS codec in the snapshot (`epoch_read.rs`) and by the
hand-written escrow plaintext v1 codec in `rine-mls-core/src/group/escrow/plaintext.rs`, which reads
the accessors one by one. A field added to `EpochReadSecrets` is dropped from the escrow silently
unless the plaintext codec, its version tag and the KAT generator
(`scripts/vectors/sections/escrow.mjs`) change with it; `test_install_site_layout_when_decoded_by_hand_matches_the_epoch`
fails on a reordered or resized field. Upstreaming is tracked separately.
