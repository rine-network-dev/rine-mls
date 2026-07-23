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

Of those six, Linux x64 (glibc) is the target the test suite runs on. The other
five are cross-built and not executed.

## Using it

```js
const {
  MlsClient,
  CIPHER_SUITE_DEFAULT,
} = require('@rine-network/mls')

const alice = MlsClient.open('/path/to/keys/alice/mls2', signingSeed, CIPHER_SUITE_DEFAULT)
const group = alice.createGroupWithMembers(groupId, [bobKeyPackage])

const init = group.lastCommit()   // the commit, one Welcome per member, a GroupInfo
const payload = group.encryptApplicationMessage(envelope)
```

`CIPHER_SUITE_DEFAULT` is the post-quantum suite. It is read from the core rather
than chosen here, so every rine surface creates groups of the same suite.

This package speaks **bytes**. Base64url, HTTP and the signed rine envelope
belong to the transport above it; MLS, the ciphersuites, the local state store
and the `0x04` `mls-v1` version tag belong to the core below it. `index.d.ts`
carries the full API with its documentation.

## Errors

Every failure is a real `Error` whose `code` is a stable string — `branch on
err.code`, never on the message:

| code | means |
|---|---|
| `RINE_MLS_PROTOCOL` | RFC 9420 processing failed |
| `RINE_MLS_STORE` | the local state store could not be read or written |
| `RINE_MLS_EPOCH_CONFLICT` | a commit that was not this group's `current + 1` |
| `RINE_MLS_UNREADABLE_KEY_PACKAGE` | a KeyPackage this core cannot read — that agent must republish its pool |
| `RINE_MLS_CIPHER_SUITE_MISMATCH` | a blob minted for another ciphersuite |
| `RINE_MLS_GROUP_INACTIVE` | this member was removed from the group |
| `RINE_MLS_SELF_MESSAGE_NOT_CACHED` | a message this member sent, aged out of the self-read cache |
| `RINE_MLS_KEY_PACKAGE_BATCH_TOO_LARGE` | more KeyPackages than one publish may carry |
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

By default every past epoch secret is kept, so a member returning after any
number of commits still decrypts the backlog queued for it. Epochs advance on
membership changes, not on messages, so this stays small.

```js
MlsClient.open(root, seed, suite, { epochRetentionLimit: 8 })
```

That keeps the eight most recent epochs and deletes the rest, narrowing the
window in which old secrets exist on disk. Anything still undelivered from a
dropped epoch becomes permanently unreadable to that member.

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
