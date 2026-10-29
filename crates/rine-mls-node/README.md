# @rine-network/mls

rine's MLS group core (RFC 9420) for Node, with the X-Wing post-quantum
ciphersuite. One Rust implementation, compiled per platform; this package is the
JavaScript half of it, and `rine-mls` on PyPI is the Python half of the same
code.

```bash
npm install @rine-network/mls
```

The prebuilt addon for the running platform arrives as an optional dependency —
`@rine-network/mls-linux-x64-gnu` and its five siblings. No compiler is needed at
install time. Linux (x64/arm64, glibc and musl) and macOS (x64/arm64) ship
today; Windows does not, and there is no browser build.

Of those six, the four Linux artifacts are executed against the bindings' own
suites — x64 natively, arm64 under emulation. The two macOS artifacts are
cross-built, stamped and string-checked, and executed by nothing.

## Using it

```js
const {
  AllowedIdentities,
  MlsClient,
  CIPHER_SUITE_DEFAULT,
} = require('@rine-network/mls')

// The (agent id, leaf key) pairs you have chain-verified; nothing else is seated.
const allowed = new AllowedIdentities()
allowed.insert(aliceId, aliceLeafPublicKey, 0)
allowed.insert(bobId, bobLeafPublicKey, 0)

const alice = MlsClient.open(
  '/path/to/keys/alice/mls2', aliceId, aliceLeafSeed, allowed, CIPHER_SUITE_DEFAULT)
const group = alice.createGroupWithMembers(groupId, [bobKeyPackage])

const init = group.lastCommit()   // the commit, one Welcome per member, a GroupInfo
const payload = group.encryptApplicationMessage(envelope)
```

`CIPHER_SUITE_DEFAULT` is the post-quantum suite, and the only one: any other id
is refused at `open` with `RINE_MLS_UNSUPPORTED_CIPHER_SUITE`. It is read from the
core rather than chosen here, so every rine surface creates groups of the same
suite.

This package speaks **bytes**. Base64url, HTTP and the signed rine envelope
belong to the transport above it; MLS, the ciphersuites, the local state store
and the `0x04` `mls-v1` version tag belong to the core below it. `index.d.ts`
carries the full API with its documentation.

## Identity: the agent id, the leaf key and the allowed set

A client is opened with the agent's id (the bytes its MLS credential carries and
`memberIndex` looks members up by; never empty), its 32-byte leaf signature seed,
and an `AllowedIdentities` set. The seed is the key derived for MLS, separate from
the agent's message-signing key; `leafPublicKey()` returns its public half.

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

`resyncFromGroupInfo(groupInfo)` rejoins a group the agent already holds a seat
in, for an agent whose local state is gone. It finds the one leaf carrying the
agent's id in the GroupInfo's ratchet tree and replaces it with a fresh leaf under
the same credential and the same leaf key, in one external commit. No stale handle
is needed, which is what separates it from `resyncByExternalCommit`.

A tree with no leaf for the agent fails `RINE_MLS_NO_SEAT_TO_REPLACE`, one with
several `RINE_MLS_AMBIGUOUS_SEAT`, and a GroupInfo without the ratchet tree
`RINE_MLS_GROUP_INFO_WITHOUT_TREE`. A resync keeps the key it replaces and fails
`RINE_MLS_RESYNC_CHANGES_KEY` otherwise; an agent whose leaf key has rotated
moves its seat with `group.commitUpdate(newLeafSeed)`.

## Epoch escrow

Every time a group installs an epoch (created, joined, committed locally or
applied from a peer) it records that epoch's read secrets. `takeEscrowExports()`
returns `{ exports, gaps }`. Each export is `{ epoch, fp, plaintext }`, oldest first:
the epoch number, a 16-byte fingerprint that differs between members on different
forks of an epoch, and the plaintext to seal for whoever reads the group. Seal and
store each export first, then `save()`. The stored state keeps the exports until the
next `save()`, so a crash in between hands them out again on the next load.

Each `plaintext` is one `Uint8Array` that the addon hands over, and the only copy it
leaves in JavaScript: overwrite it with `fill(0)` once it is sealed, on the error path
too, because nothing frees it earlier than the garbage collector.

An epoch that cannot be escrowed never fails the take for the others. It comes back
in `gaps` as `{ groupId, epoch, reason, fp? }`, with an `EscrowGapReason`: a tree or group
context over the escrow limits, or an export discarded because more than 32 were
waiting (a group keeps at most 32 untaken exports). Record each gap before `save()`,
like an export. A gap's `fp` is the fork fingerprint of its epoch, absent for an
export discarded past the cap. `escrowBacklog()` says how many exports wait and how
many epochs were already discarded, without taking. `queuedEscrowFingerprints()`
lists the `{ epoch, fp }` of every export a take would return now, without taking
anything. The record of discarded epochs keeps the
newest 1024; an older epoch is simply missing its escrow.

## Opening escrowed messages

`EpochReader.fromEscrow(groupId, epoch, plaintext)` builds a reader from the
plaintext of one `(group, epoch)` escrow, and `reader.open(message)` opens an
application message of that epoch as a party that was never a member. Pass the
`mls-v1` payload without its leading `0x04` byte. It returns
`{ envelope, senderIndex, signerPublicKey, generation }`: the signed rine envelope,
the sender's leaf, that leaf's signature key (compare it with the agent's
chain-verified `mls` key) and the ratchet generation. The framing signature is
checked against the leaf key the escrow records, and a message that fails it throws
`RINE_MLS_MEMBER_REJECTED`. A generation too far beyond the sender's ratchet throws
`RINE_MLS_GENERATION_TOO_FAR`, and an escrow that cannot be read, or a negative
epoch, throws `RINE_MLS_INVALID_ESCROW`.

The reader holds only the secrets of that epoch's messages. It cannot advance a
group or sign. It is here because the organisation reader in `rine-core` opens
escrowed messages with it, and `rine-mls` on PyPI carries the same class for the
Python reader. The escrow plaintext stays yours: overwrite it with `fill(0)` once
you are done reading. Not every platform executes it in the release smoke: it is
present on all six artifacts and executed on the four Linux ones.

## Peers the allowed set has not admitted

A call that validates leaves (`applyCommit`, a join, a resync, a commit build)
fails with `RINE_MLS_PEER_NOT_ADMITTED` when the allowed set refuses a leaf.
Straight after the failing call, `refusedPeer()` on the same handle returns that
leaf's agent id (`null` after any other outcome). Verify that agent, add it to the
allowed set and retry the same input on the same handle: a refused call leaves the
handle as it was. `discardWelcomeKeyPackage(welcome)` gives back the KeyPackage
private half a Welcome was sealed to when that Welcome leaves the caller's spool
unopened: it returns `true` when exactly one half held here was deleted, and
`false` otherwise.

## Seeded keys

`mlKem768KeyPairFromSeed(seed)` (a 64-byte seed `d||z`, returning
`{ publicKey, privateKey }`) and `mlDsa65PublicKeyFromSeed(seed)` (a 32-byte seed,
returning the 1952-byte public key) derive the same FIPS 203 and FIPS 204 keys
as `@noble/post-quantum` does from the same seed.

## Errors

Every failure is a real `Error` whose `code` is a stable string — `branch on
err.code`, never on the message:

| code | means |
|---|---|
| `RINE_MLS_PROTOCOL` | RFC 9420 processing failed |
| `RINE_MLS_PEER_NOT_ADMITTED` | the allowed set refused a leaf in the input; `refusedPeer()` names the agent |
| `RINE_MLS_STORE` | the local state store could not be read or written |
| `RINE_MLS_EPOCH_CONFLICT` | a commit that was not this group's `current + 1` |
| `RINE_MLS_UNREADABLE_KEY_PACKAGE` | a KeyPackage this core cannot read — that agent must republish its pool |
| `RINE_MLS_CIPHER_SUITE_MISMATCH` | a blob minted for another ciphersuite |
| `RINE_MLS_GROUP_INACTIVE` | this member was removed from the group |
| `RINE_MLS_SELF_MESSAGE_NOT_CACHED` | a message this member sent, aged out of the self-read cache |
| `RINE_MLS_KEY_PACKAGE_BATCH_TOO_LARGE` | more KeyPackages than one publish may carry |
| `RINE_MLS_EMPTY_AGENT_ID` | a client opened with an empty agent id |
| `RINE_MLS_UNSUPPORTED_CIPHER_SUITE` | a ciphersuite id other than the post-quantum one |
| `RINE_MLS_NO_SEAT_TO_REPLACE` / `RINE_MLS_AMBIGUOUS_SEAT` / `RINE_MLS_GROUP_INFO_WITHOUT_TREE` | a resync from a GroupInfo that cannot name exactly one seat |
| `RINE_MLS_INVALID_ESCROW` | an epoch escrow that cannot be encoded or read back |
| `RINE_MLS_PANIC` / `RINE_MLS_POISONED` | an internal panic was caught; the handle is retired |

The full list is in `index.d.ts`'s companion documentation and in the Python
package's exception classes, which carry the same codes.

## Two things to get right

**One client per store root.** A store root is one agent's MLS state, and group
state is a ratchet. Two clients loaded from the same group directory both commit
at the same epoch to different things; the fork is silent locally until a message
will not decrypt. Give each thread or process its own agent, or serialize on one
client. A handle also cannot be shared across worker threads — sending one
through `postMessage` yields an inert copy with no state.

**Nothing persists until `save()`.** Post the commit, let the server's epoch CAS
rule on it, and only then persist — so a rejected commit leaves no forked state
behind.

## Key packages, and the one-way door

A key package minted by rine's previous MLS engine is unreadable here, and so is
one minted here to anything older: the two do not interoperate, and a group whose
members straddle them does not work at all. `RINE_MLS_UNREADABLE_KEY_PACKAGE`
names that condition. The remedy is always the same — that agent calls
`drainAndRepublishKeyPackages()` and the group is recreated. Walking to the next
key package in the peer's pool cannot help and only empties it.

## Epoch retention

Past epoch secrets are kept for `EPOCH_RETENTION_DEFAULT` epochs, which is the
rine server's 90-day message retention converted into epochs at the churn rate
of the largest group rine serves. A member returning inside that window still
decrypts the backlog queued for it. Epochs advance on membership changes, not on
messages, so ordinary traffic never moves this.

```js
MlsClient.open(root, agentId, leafSeed, allowed, suite, { epochRetentionLimit: 8 })
```

That keeps the eight most recent epochs and deletes the rest, narrowing the
window in which old secrets exist on disk. Anything still undelivered from a
dropped epoch becomes permanently unreadable to that member — there is no
recovery, because the epoch secret is the only copy.

## Changelog

[`CHANGELOG.md`](https://codeberg.org/rine/rine-mls/src/branch/main/CHANGELOG.md)
— one file for both bindings, because there is one release: this package and
PyPI `rine-mls` are built from the same Rust workspace at the same version, and
an entry that applies to one applies to the other. Read it before upgrading
either half on a machine that runs both; 0.1.1 has a note about exactly that.

## Building from source

```bash
npm install
npm run build          # release addon for this platform, plus index.js/index.d.ts
npm test               # the full suite, the panic firewall, and the packed package
```

Two more scripts exist for the release path: `npm run create-npm-dirs`
regenerates the six `npm/<platform>/package.json` manifests after a change to
`napi.targets`, and `npm run artifacts` moves cross-built addons collected in
`artifacts/` into those directories ready to publish.

The version is owned by the Rust workspace (`rine-mls/Cargo.toml`) and must be
kept in step with `package.json` and the six `npm/<platform>/package.json` files;
`napi version` syncs the platform packages from `package.json`.
