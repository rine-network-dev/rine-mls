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
from rine_mls import MlsClient, CIPHER_SUITE_DEFAULT

alice = MlsClient("/path/to/keys/alice/mls2", signing_seed, CIPHER_SUITE_DEFAULT)
group = alice.create_group_with_members(group_id, [bob_key_package])

init = group.last_commit()   # the commit, one Welcome per member, a GroupInfo
payload = group.encrypt_application_message(envelope)
```

`CIPHER_SUITE_DEFAULT` is the post-quantum suite. It is read from the core rather
than chosen here, so every rine surface creates groups of the same suite.

This package speaks **bytes**. Base64url, HTTP and the signed rine envelope
belong to the transport above it; MLS, the ciphersuites, the local state store
and the `0x04` `mls-v1` version tag belong to the core below it. The wheel ships
type stubs and a `py.typed` marker, so the full API is visible to mypy.

## Errors

Every failure raises its own class under `RineMlsError`, and every class carries
the same `code` string the JavaScript binding puts on `Error.code`:

| exception | `code` | means |
|---|---|---|
| `MlsProtocolError` | `RINE_MLS_PROTOCOL` | RFC 9420 processing failed |
| `MlsStoreError` | `RINE_MLS_STORE` | the local state store could not be read or written |
| `EpochConflictError` | `RINE_MLS_EPOCH_CONFLICT` | a commit that was not this group's `current + 1` |
| `UnreadableKeyPackageError` | `RINE_MLS_UNREADABLE_KEY_PACKAGE` | a KeyPackage this core cannot read — that agent must republish its pool |
| `CipherSuiteMismatchError` | `RINE_MLS_CIPHER_SUITE_MISMATCH` | a blob minted for another ciphersuite |
| `GroupInactiveError` | `RINE_MLS_GROUP_INACTIVE` | this member was removed from the group |
| `SelfMessageNotCachedError` | `RINE_MLS_SELF_MESSAGE_NOT_CACHED` | a message this member sent, aged out of the self-read cache |
| `KeyPackageBatchTooLargeError` | `RINE_MLS_KEY_PACKAGE_BATCH_TOO_LARGE` | more KeyPackages than one publish may carry |
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
MlsClient(root, seed, suite, epoch_retention_limit=8)
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
