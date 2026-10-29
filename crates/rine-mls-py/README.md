# rine-mls

rine's MLS group core (RFC 9420) for Python, with the X-Wing post-quantum
ciphersuite. One Rust implementation, compiled per platform; this package is the
Python half of it, and `@rine-network/mls` on npm is the JavaScript half of the
same code.

```bash
pip install rine-mls
```

One abi3 wheel per platform covers every CPython from 3.9 up, so no compiler is
needed at install time. Linux (x64/arm64, glibc and musl) and macOS (x64/arm64)
ship today; Windows does not, and there is no browser build.

## Using it

```python
from rine_mls import AllowedIdentities, MlsClient, CIPHER_SUITE_DEFAULT

# The (agent id, leaf key) pairs you have chain-verified; nothing else is seated.
allowed = AllowedIdentities()
allowed.insert(alice_id, alice_leaf_public_key, 0)
allowed.insert(bob_id, bob_leaf_public_key, 0)

alice = MlsClient(
    "/path/to/keys/alice/mls2", alice_id, alice_leaf_seed, allowed, CIPHER_SUITE_DEFAULT
)
group = alice.create_group_with_members(group_id, [bob_key_package])

init = group.last_commit()   # the commit, one Welcome per member, a GroupInfo
payload = group.encrypt_application_message(envelope)
```

`CIPHER_SUITE_DEFAULT` is the post-quantum suite, and the only one: any other id
is refused at construction with `UnsupportedCipherSuiteError`. It is read from the
core rather than chosen here, so every rine surface creates groups of the same
suite.

This package speaks **bytes**. Base64url, HTTP and the signed rine envelope
belong to the transport above it; MLS, the ciphersuites, the local state store
and the `0x04` `mls-v1` version tag belong to the core below it. The wheel ships
type stubs and a `py.typed` marker, so the full API is visible to mypy.

## Identity: the agent id, the leaf key and the allowed set

A client is constructed with the agent's id (the bytes its MLS credential carries
and `member_index` looks members up by; never empty), its 32-byte leaf signature
seed, and an `AllowedIdentities` set. The seed is the key derived for MLS,
separate from the agent's message-signing key; `leaf_public_key()` returns its
public half.

The set holds the `(agent id, leaf public key)` pairs the caller has verified
against the org-signed agent certificates. A KeyPackage, a Welcome that carries a
leaf, or an external commit is accepted only for a pair in the set, so a leaf the
caller has not verified cannot be seated. Keep every verified generation of an
agent in the set, because MLS validates every leaf already in a tree it joins. One
`AllowedIdentities` object can be passed to several clients, and an `insert` is
seen by the clients already open. A client's own pair belongs in its set.
The third `insert` argument is the generation the agent's certificate chain signs for that
key. A leaf may replace another leaf of the same agent only at a strictly newer
generation, and inserting a pair again at a different generation fails
`RINE_MLS_ALLOWED_GENERATION_CONFLICT`.

## Resync

`resync_from_group_info(group_info)` rejoins a group the agent already holds a
seat in, for an agent whose local state is gone. It finds the one leaf carrying
the agent's id in the GroupInfo's ratchet tree and replaces it with a fresh leaf
under the same credential and the same leaf key, in one external commit. No stale
handle is needed, which is what separates it from `resync_by_external_commit`.

A tree with no leaf for the agent raises `NoSeatToReplaceError`, one with several
`AmbiguousSeatError`, and a GroupInfo without the ratchet tree
`GroupInfoWithoutTreeError`. A resync keeps the key it replaces and raises
`ResyncChangesKeyError` otherwise; an agent whose leaf key has rotated moves its
seat with `group.commit_update(new_leaf_seed)`.

## Epoch escrow and the reader

Every time a group installs an epoch (created, joined, committed locally or
applied from a peer) it records that epoch's read secrets. `take_escrow_exports()`
returns an `EscrowTake`: its `exports` are `EscrowExport` objects with `epoch`, `fp`
and `plaintext`, oldest first, the epoch number, a 16-byte fingerprint that differs
between members on different forks of an epoch, and the plaintext (a `bytearray`
to zero after sealing) to seal for whoever reads the group. Seal and store each
export first, then `save()`. The stored state keeps the exports until the next
`save()`, so a crash in between hands them out again on the next load.

An epoch that cannot be escrowed never fails the take for the others. It comes back
in `gaps` as an `EscrowGap` (`group_id`, `epoch`, `reason`, `fp`), with an
`EscrowGapReason`: a tree or group context over the escrow limits, or an export
discarded because more than 32 were waiting (a group keeps at most 32 untaken
exports). A gap's `fp` is the fork fingerprint of its epoch, or `None` for an
export discarded past the cap. Record each gap before `save()`, like an export.
`escrow_backlog()` says how many exports wait and how many epochs were already
discarded, without taking. `queued_escrow_fingerprints()` lists the `(epoch, fp)` of
every export a take would return now, without taking anything.

## Peers the allowed set has not admitted

A call that validates leaves (`apply_commit`, a join, a resync, a commit build)
raises `PeerNotAdmittedError` when the allowed set refuses a leaf. Straight after
the failing call, `refused_peer()` on the same handle returns that leaf's agent id
(`None` after any other outcome). Verify that agent, add it to the allowed set and
retry the same input on the same handle: a refused call leaves the handle as it
was. `discard_welcome_key_package(welcome)` gives back the KeyPackage private half a
Welcome was sealed to when that Welcome leaves the caller's spool unopened: it
returns `True` when exactly one half held here was deleted, and `False` otherwise.

`EpochReader.from_escrow(group_id, epoch, plaintext)` is the other end. Built from
one epoch's plaintext, it opens that epoch's application messages as a party that
was never a member: `reader.open(payload[1:])` takes the `mls-v1` payload without
its leading `0x04` byte and returns an `OpenedMessage` with the signed rine
envelope, the sender's leaf, that leaf's signature key (`signer_public_key`, the
one to compare with the agent's chain-verified `mls` key) and the ratchet
generation. The MLS framing signature is checked against the leaf key the escrow
records, and a message that fails it raises `MemberRejectedError`. Messages within
1024 generations behind a sender's ratchet open in any order; after a longer
jump, open that sender's messages in ascending generation. A generation more than
65,536 steps beyond that window raises `GenerationTooFarError`. The npm package carries the same class
(`EpochReader`) with the same behaviour.

## Seeded keys

`ml_kem768_key_pair_from_seed(seed)` (a 64-byte seed `d||z`, returning
`(public_key, private_key)`) and `ml_dsa65_public_key_from_seed(seed)` (a 32-byte
seed, returning the 1952-byte public key) derive the same FIPS 203 and FIPS 204
keys as `@noble/post-quantum` does from the same seed.

## Errors

Every failure raises its own class under `RineMlsError`, and every class carries
the same `code` string the JavaScript binding puts on `Error.code`:

| exception | `code` | means |
|---|---|---|
| `MlsProtocolError` | `RINE_MLS_PROTOCOL` | RFC 9420 processing failed |
| `PeerNotAdmittedError` (a `MlsProtocolError`) | `RINE_MLS_PEER_NOT_ADMITTED` | the allowed set refused a leaf in the input; `refused_peer()` names the agent |
| `MlsStoreError` | `RINE_MLS_STORE` | the local state store could not be read or written |
| `EpochConflictError` | `RINE_MLS_EPOCH_CONFLICT` | a commit that was not this group's `current + 1` |
| `UnreadableKeyPackageError` | `RINE_MLS_UNREADABLE_KEY_PACKAGE` | a KeyPackage this core cannot read — that agent must republish its pool |
| `CipherSuiteMismatchError` | `RINE_MLS_CIPHER_SUITE_MISMATCH` | a blob minted for another ciphersuite |
| `GroupInactiveError` | `RINE_MLS_GROUP_INACTIVE` | this member was removed from the group |
| `SelfMessageNotCachedError` | `RINE_MLS_SELF_MESSAGE_NOT_CACHED` | a message this member sent, aged out of the self-read cache |
| `KeyPackageBatchTooLargeError` | `RINE_MLS_KEY_PACKAGE_BATCH_TOO_LARGE` | more KeyPackages than one publish may carry |
| `EmptyAgentIdError` | `RINE_MLS_EMPTY_AGENT_ID` | a client constructed with an empty agent id |
| `UnsupportedCipherSuiteError` | `RINE_MLS_UNSUPPORTED_CIPHER_SUITE` | a ciphersuite id other than the post-quantum one |
| `NoSeatToReplaceError` / `AmbiguousSeatError` / `GroupInfoWithoutTreeError` | `RINE_MLS_NO_SEAT_TO_REPLACE` / `RINE_MLS_AMBIGUOUS_SEAT` / `RINE_MLS_GROUP_INFO_WITHOUT_TREE` | a resync from a GroupInfo that cannot name exactly one seat |
| `InvalidEscrowError` / `MemberRejectedError` | `RINE_MLS_INVALID_ESCROW` / `RINE_MLS_MEMBER_REJECTED` | an escrow that cannot be read, or a message whose framing signature does not verify |
| `GenerationTooFarError` | `RINE_MLS_GENERATION_TOO_FAR` | a message naming a generation beyond the reader's reach |
| `MlsPanicError` / `MlsPoisonedError` | `RINE_MLS_PANIC` / `RINE_MLS_POISONED` | an internal panic was caught; the handle is retired |

`except RineMlsError` catches all of them, and the instance always has `.code`.
The stubs list the rest.

## Two things to get right

**One client per store root.** A store root is one agent's MLS state, and group
state is a ratchet. Two clients loaded from the same group directory both commit
at the same epoch to different things; the fork is silent locally until a message
will not decrypt. Give each thread or process its own agent, or serialize on one
client. Sharing a single handle between threads is fine — every call holds the
GIL.

**Nothing persists until `save()`.** Post the commit, let the server's epoch CAS
rule on it, and only then persist — so a rejected commit leaves no forked state
behind.

## Key packages, and the one-way door

A key package minted by rine's previous MLS engine is unreadable here, and so is
one minted here to anything older: the two do not interoperate, and a group whose
members straddle them does not work at all. `UnreadableKeyPackageError` names that
condition. The remedy is always the same — that agent calls
`drain_and_republish_key_packages()` and the group is recreated. Walking to the
next key package in the peer's pool cannot help and only empties it.

## Epoch retention

Past epoch secrets are kept for `EPOCH_RETENTION_DEFAULT` epochs, which is the
rine server's 90-day message retention converted into epochs at the churn rate
of the largest group rine serves. A member returning inside that window still
decrypts the backlog queued for it. Epochs advance on membership changes, not on
messages, so ordinary traffic never moves this.

```python
MlsClient(root, agent_id, leaf_seed, allowed, suite, epoch_retention_limit=8)
```

That keeps the eight most recent epochs and deletes the rest, narrowing the
window in which old secrets exist on disk. Anything still undelivered from a
dropped epoch becomes permanently unreadable to that member — there is no
recovery, because the epoch secret is the only copy.

## Changelog

[`CHANGELOG.md`](https://codeberg.org/rine/rine-mls/src/branch/main/CHANGELOG.md)
— one file for both bindings, because there is one release: this package and npm
`@rine-network/mls` are built from the same Rust workspace at the same version,
and an entry that applies to one applies to the other. Read it before upgrading
either half on a machine that runs both; 0.1.1 has a note about exactly that.

## Building from source

From a checkout of [`codeberg.org/rine/rine-src`](https://codeberg.org/rine/rine-src), at its
root:

```bash
bash rine-mls/crates/rine-mls-py/tests/run.sh   # builds both wheels, runs the suite, then uses the shipped wheel
```

The version is owned by the Rust workspace at `rine-mls/Cargo.toml`; maturin
reads it from there.
