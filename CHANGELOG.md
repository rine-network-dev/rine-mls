# Changelog

All notable changes to `rine-mls` (npm `@rine-network/mls`, PyPI `rine-mls`) are
documented here.

This project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.2.0] - 2026-10-29

The first release built for rine's org-root key model. A group member's leaf key now
comes from a seed the caller supplies, the library can hand a client the per-epoch
read escrow an organisation needs to read its own groups, and the classical
ciphersuite is gone. Several calls changed shape, so this is a minor release: read
"Changed" and "Removed" before upgrading, and upgrade the npm and PyPI halves together.

### Added

- **Per-epoch read escrow.** Every epoch a group installs (creation, a Welcome, your
  own commit, a received commit) leaves one escrow export behind: the epoch, a
  16-byte fork fingerprint and the sealed-ready secrets that epoch's messages can be
  opened with. `take_escrow_exports()` (`takeEscrowExports()` on npm) returns them
  oldest first, and the stored state keeps them until the next `save()`, so a crash
  between taking and saving yields them again. An epoch that cannot be escrowed
  comes back as a typed gap with its reason (context too large, too many leaves,
  malformed, or discarded because the queue overflowed) instead of failing the
  take for the others. `escrow_backlog()` reports what is waiting without taking it.
  The queue keeps at most 32 exports and remembers at most 1024 discarded epochs.
- **`epoch_fingerprint()` on a group** (`epochFingerprint()` on npm). The fork
  fingerprint of the group's current epoch, the value an export of that epoch
  carries, read without taking anything. Two members on different forks of one
  epoch read different values, so a client can tell whose escrow record speaks for
  the group it is sending to. It is a hash of the epoch authenticator and reveals
  none of it.
- **Opening escrowed messages.** `EpochReader` opens an application message
  of one past epoch from its escrowed secrets, as a party that was never a member.
- **Resyncing from a group-info.** A client that fell behind can rejoin from a
  group-info and keep its credential and leaf key.
- **Seeded keys.** `AllowedIdentities`, a shared set of the (agent id, leaf signature
  key) pairs a client accepts as members, and a client that takes its leaf seed from
  the caller. `ml_kem768_key_pair_from_seed` and `ml_dsa65_public_key_from_seed`
  derive the post-quantum keys the org-root tree needs, deterministically, from a
  seed.
- **Tree enumeration and member errors.** `member_identities()` lists the occupied
  leaves with the agent id each carries. New typed errors name what went wrong: a
  rejected member (`MemberRejectedError`), an ambiguous or missing seat to replace
  (`AmbiguousSeatError`, `NoSeatToReplaceError`), a group-info without its tree
  (`GroupInfoWithoutTreeError`), a message generation too far ahead
  (`GenerationTooFarError`), an invalid escrow (`InvalidEscrowError`), an empty agent id
  (`EmptyAgentIdError`), a credential that cannot be read
  (`UnreadableCredentialError`) and an ML-DSA failure (`MlDsaError`).
- **Escrow limits.** Escrow covers a group of up to 1000 leaves with a 1024-byte group
  context, twice the largest group the server seats, because stale leaves outlive seats.
- **Member and client accessors.** `agent_id()` on a client (`agentId()` on npm) returns
  the agent id it was opened with, and `current_member_index()`
  (`currentMemberIndex()`) on a group returns the leaf the group holds for this member,
  which is the `stale_leaf` a resync by external commit (`resync_by_external_commit()`,
  `resyncByExternalCommit()`) takes.
- **Naming the peer a call refused.** A call that validates leaves (applying a commit,
  joining, resyncing, building a commit) now fails with `RINE_MLS_PEER_NOT_ADMITTED`
  (Python `PeerNotAdmittedError`) when the allowed set refuses a leaf. `refused_peer()`
  (`refusedPeer()` on npm), on a client and on a group, returns the agent id of the leaf
  the last call on that handle refused, and `None` / `null` after any other outcome. The
  handle that raised it is unchanged, so a caller can verify that agent, add it to the
  allowed set and retry the same input on the same handle. This holds for an encrypted
  (PrivateMessage) commit too. The error message shows the agent id only when it is a
  canonical agent UUID and otherwise just its length, because a peer chooses its own id.
- **Which fork a gap belongs to.** An escrow gap carries `fp`, the fork fingerprint of its
  epoch, whenever the epoch's secrets reached the take. It is absent for an export
  discarded because the queue overflowed. `queued_escrow_fingerprints()`
  (`queuedEscrowFingerprints()` on npm) returns the `(epoch, fp)` of every export a take
  would return now, oldest first, without taking anything, so a client that sets a
  snapshot aside can later file what it gives up under the right fork.
- **Giving back a dropped Welcome's KeyPackage.** `discard_welcome_key_package()`
  (`discardWelcomeKeyPackage()` on npm) deletes the KeyPackage private half a Welcome was
  sealed to, for a Welcome that left the caller's spool without being opened, so the
  local count falls and the ordinary top-up republishes. It returns `True` when exactly
  one half held here was deleted and `False` when none or several matched, and it is
  idempotent. A stored half that has become unreadable still counts as held and is
  deleted, so one damaged file cannot stop a Welcome from being released.
- **Retention constants.** `EPOCH_RETENTION_DEFAULT` is the number of prior epochs a group
  keeps secrets for when no limit is set, and `MESSAGE_RETENTION_DAYS` is the number of
  days the server can still hold a message for its reader.
- **A member can move its own leaf to a new key.** `commit_update(new_leaf_seed)`
  (`commitUpdate` on npm) builds the update commit that replaces the leaf with one
  signed by the key the seed derives. The commit is held **pending**: the handle keeps
  its epoch, leaf and signer until `apply_pending_commit()` (`applyPendingCommit`)
  applies it, and `clear_pending_commit()` (`clearPendingCommit`) drops it and restores
  the earlier state. `add_member`, `remove_member` and a second `commit_update` refuse
  with `RINE_MLS_COMMIT_PENDING` while one is held. The pending commit is saved with the
  group, so it survives `save()` and a reload; `pending_commit_epoch()`
  (`pendingCommitEpoch`) names the epoch it would move to, or `None`. The bundle's
  `group_info` is the GroupInfo of the epoch the commit creates, not of the epoch it
  left. A seed that derives the key the leaf already carries is refused with
  `RINE_MLS_LEAF_ALREADY_CURRENT`, and a handle that signs with a different key than its
  leaf carries with `RINE_MLS_SIGNER_LEAF_MISMATCH`. Applying it captures the new
  epoch's escrow export like any other commit.
- **`own_leaf_signature_key()`, `key_package_signature_key()` and
  `MemberIdentity.signature_key`.** The key on this member's own leaf, the key a
  KeyPackage carries (a free function; the KeyPackage's own signature is checked when an
  Add is built, not by the read), and the key on each leaf `member_identities()` lists.
  A caller compares these with the keys it chain-verified for the agents involved.

### Changed

- **`AllowedIdentities.insert()` takes the key's generation.** The third argument is the
  generation the agent's certificate chain signs for that leaf key, and the set stores
  it per pair. A leaf may now replace another leaf of the same agent only when its
  generation is strictly greater; a missing generation on either side is refused as
  `RINE_MLS_PEER_NOT_ADMITTED`. Inserting a pair again at the same generation does
  nothing, and at a different one raises `RINE_MLS_ALLOWED_GENERATION_CONFLICT` and keeps
  the first. A caller that passed two arguments must now pass the third.
- **An external commit may not change the key it replaces.** A resync by external commit
  that removes a leaf now keeps the joiner's own signing key, and one that would
  replace it with a different key is refused with `RINE_MLS_RESYNC_CHANGES_KEY`, on the
  sending side before it is built and on every receiving side. `ResyncChangesKeyError`
  subclasses `MlsProtocolError`. Moving to a new key is `commit_update`.
- **A leaf refused by the allowed set is no longer `RINE_MLS_PROTOCOL`.** It is
  `RINE_MLS_PEER_NOT_ADMITTED`. `PeerNotAdmittedError` subclasses `MlsProtocolError`, so
  an existing `except MlsProtocolError` still catches it. A JavaScript caller that
  compared the code to `RINE_MLS_PROTOCOL` must also accept the new one. An unsupported
  credential type and a successor leaf that does not match stay `RINE_MLS_PROTOCOL`.
- **A client is opened with a leaf seed and an allowed-identity set.** The leaf key is
  derived from the seed you pass, and the identity check admits only pairs you
  registered. A client opened the 0.1.1 way no longer constructs.
- **`public_key()` is now `leaf_public_key()`** (`publicKey()` is now `leafPublicKey()`
  on npm). It returns the raw leaf signature key, the half of the pair that
  `AllowedIdentities.insert()` takes.
- **Group state gains a trailing section for pending escrow exports.** State written
  by 0.1.1 opens as before and reads as having none waiting. A 0.1.1 reader opens a
  0.2.0 state without error, skips the section and writes the state back without it, so
  every export still waiting is discarded with no gap recorded. That is why both halves
  must be upgraded together, as the note below says.
- **Both published packages point at this file.** Neither distribution said where its
  notes were. This file is git-tracked and mirrored, so it was always public, but a
  reader arriving from npm or PyPI had no route to it: npm renders only the README,
  PyPI publishes wheels alone (an sdist would turn "no wheel for your platform" into a
  doomed Rust compile), and neither carried a link. Both crate READMEs now open on a
  Changelog section, and the PyPI metadata carries a `Changelog` URL that renders in
  the sidebar.
- **The release gate that holds every rine package's version against its changelog now
  covers both crates.** It resolves this file for each and reads the workspace version
  out of `Cargo.toml`, so a bump that lands with no entry is refused the same way it is
  everywhere else. It used to skip both crates as "not checked", which read as a
  decision and was a blind spot.

### Fixed

- **A message sent before its sender rotated their key still opens.** A member who
  commits a self-update replaces the key their leaf signs with, and the vendored
  mls-rs then refused every earlier-epoch message they had sent, because the leaf no
  longer carried the key of that epoch. The check now accepts the message when the
  current leaf is a valid successor, under the identity provider, of a leaf that held
  the epoch's key under the same credential. A member who was removed, and a leaf
  another agent now holds, are still refused, so nothing is attributed to whoever
  reuses the index. A reader that has not admitted the sender's earlier generation
  into its allowed set still refuses the message.

### Removed

- **The classical ciphersuite.** Only X-Wing (id `0xF057`, post-quantum) is accepted:
  `CIPHER_SUITE_CLASSICAL` is gone, any other id is refused when a client opens, and a
  group created under the classical suite is refused. The default suite is X-Wing.

### Note — upgrade the npm and PyPI halves together

The two packages are two bindings of one Rust workspace at one version, and every
rine surface on a machine shares one MLS state directory per agent. Run 0.2.0 of
both halves on a machine that runs both.

### Added (since the release candidate)

- **Opening escrowed messages (npm).** `EpochReader` is now in `@rine-network/mls` as
  well as `rine-mls`: `EpochReader.fromEscrow(groupId, epoch, plaintext)` and
  `reader.open(message)` behave as the Python class does and raise the same
  `RINE_MLS_*` codes. The Python-only restriction existed because only the fleet
  read escrow; the organisation reader in `rine-core` now does too. The cost is one more
  class in every runtime that loads the addon. It holds only the secrets of one epoch's
  messages and cannot advance a group or sign. The npm epoch argument is a signed
  64-bit integer, and a negative one is refused as `RINE_MLS_INVALID_ESCROW`.

### Fixed (since the release candidate)

- **A read escrow that declares an absurd tree size is refused by name.** An escrow
  whose leaf count is zero, not a power of two or above 2048 now fails to load with
  an invalid-escrow error instead of sizing a secret tree from the declared count.
  The leaf signature seed a `LeafIdentity` is built from is also wiped from the
  stack once the key is derived.
- **A member re-admitted over the group state it kept, or one resyncing from a newer
  GroupInfo, keeps working.** Its next commit no longer fails with an invalid-epoch error,
  and the epochs it kept from before stay readable. Kept epochs are set aside only when the
  new state is first saved, so a Welcome or GroupInfo that is refused, fails verification or
  is never saved leaves the store exactly as it was. A GroupInfo older than the state the
  member already holds is refused.

## [0.1.1] - 2026-07-25

Two fixes to how local MLS state reaches disk. Existing state is read exactly as
before — nothing has to be migrated, recreated or rejoined.

### Fixed

- **Concurrent saves could leave a spliced group state.** The temp file a save
  wrote through was named after its destination, so two processes saving the
  same group opened the *same* path, truncated it under each other and both
  renamed it into place. The result was a mix of two states, which no reader can
  recover from. Each write now uses a temp name unique to its writer.
- **A save that never finished left its temp file behind.** A process killed
  between opening a temp file and renaming it into place left a full copy of the
  group's state — retired epoch secrets included — in the group directory, where
  nothing removed it and no listing showed it. Each save now reclaims the
  abandoned temps of the file it writes. A temp a live writer still holds is left
  alone. The reclaim covers the temps this release writes. One left behind by
  0.1.0 carries a different name — that release replaced the destination's
  extension, so `epochs/1.bin` was written through `epochs/1.tmp` — and stays
  where it is. Under `<config>/keys/<agent>/mls2/`, a `.tmp` whose name does not
  also carry `.bin` is such a leftover and can be deleted while no rine process
  is running.

### Added

- **A format tag on the files holding `mls-rs`'s serialization** — `state.bin`,
  `epochs/<n>.bin` and `key_packages/<hex>.bin`. Those bytes are only
  interpretable by the `mls-rs` version that wrote them, and nothing on disk said
  which one that was; a future `mls-rs` bump would have reinterpreted them
  silently. State that carries no tag is read as version 1, so files written by
  0.1.0 open normally. State written by a *newer* rine-mls is refused by name and
  reported as its own error, not as corruption.

### Note — upgrade the npm and PyPI halves together

The tag reads in both directions but is only written in one. 0.1.0 knows nothing
about it, so state that 0.1.1 has written is unreadable to a 0.1.0 client, which
reports it as a protocol error.

This matters because an agent has one MLS state directory
(`<config>/keys/<agent>/mls2/`) and every rine surface on the machine shares it:
the Python SDK reads and writes the same files as the CLI, the MCP server and
the TypeScript SDK. Upgrading PyPI `rine-mls` while the npm `@rine-network/mls`
stack stays on 0.1.0 leaves the older half unable to open groups the newer half
has saved, until it is upgraded too. Upgrade both — through the packages that
depend on them, `rine` and `@rine-network/core` — and no group is interrupted.

## [0.1.0] - 2026-07-23

First release of rine's MLS core in Rust — one RFC 9420 implementation, wrapping
[mls-rs](https://github.com/awslabs/mls-rs), shared byte-for-byte by every rine
surface (CLI, MCP, TypeScript SDK, Python SDK, and the integration packages). It
replaces the previous per-language `ts-mls` engine.

### Added

- **Native MLS group crypto** via `crates/rine-mls-core`: create, Welcome join,
  external-commit self-join, Add/Remove, application messages, epoch ordering,
  and local file-backed group state.
- **Two ciphersuites.** `0xF057` — X-Wing (X25519 + ML-KEM-768) · ChaCha20-Poly1305
  · SHA-256 · Ed25519 — is rine's post-quantum suite and the default for new
  groups, at a private-use code point. `0x0001` (RFC 9420's mandatory classical
  suite) remains as the non-PQ fallback. The X-Wing KEM follows
  `draft-connolly-cfrg-xwing-kem-06` over `libcrux-ml-kem` and `x25519-dalek`,
  pinned against the draft's own KAT vectors and cross-checked against the
  RustCrypto `x-wing` crate.
- **ML-KEM-768 primitives** exported for the 1:1 DM path (`ml_kem768_*`), so the
  SDKs' `hpke-hybrid-v1` post-quantum DM envelope shares this one implementation.
- **Two bindings, one surface.** `crates/rine-mls-node` (napi-rs → npm
  `@rine-network/mls`) and `crates/rine-mls-py` (PyO3/maturin → PyPI `rine-mls`)
  expose the same methods, adding only: typed catchable errors spelling the same
  `RINE_MLS_*` code on both sides; a panic firewall that retires a panicked
  handle rather than letting a Rust unwind reach V8 or CPython; and explicit byte
  ownership (arguments copied in, results moved out).
- **Prebuilt wheels / prebuilt binaries** for linux x64/arm64 (glibc + musl) and
  macOS arm64/x64. Windows is not published yet.

### Note — this is a hard cutover for existing MLS groups

The new core does not interoperate with the previous `ts-mls` stack: the old
published KeyPackages are unreadable, and existing MLS group state is not
migrated. See the consuming packages' changelogs (`@rine-network/core`, the CLI,
the SDKs) for the drain-and-republish and group-recreation steps.
