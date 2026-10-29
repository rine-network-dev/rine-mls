# rine-mls

rine's MLS core in Rust. One implementation of RFC 9420 group crypto for every
rine surface, wrapping [mls-rs](https://github.com/awslabs/mls-rs).

| Crate | Purpose |
|---|---|
| `crates/rine-mls-core` | rine's MLS contract: create, Welcome join, external-commit self-join, Add/Remove, application messages, epoch ordering, local file-backed state, on the post-quantum X-Wing suite |
| `crates/rine-mls-node` | napi-rs binding → npm `@rine-network/mls` |
| `crates/rine-mls-py` | PyO3/maturin binding → PyPI `rine-mls` |

The two bindings share the group surface: create, join, Add/Remove,
application messages, key packages, escrow and the epoch reader
(`EpochReader`). They differ on purpose in a few
places. The Python binding also carries the full ML-KEM-768 surface (key generation, encapsulation, decapsulation),
because the Python SDK has no other post-quantum implementation to use. The
Node binding carries, beside the group surface and the epoch reader, only the two seeded
derivations the TypeScript stack needs (`ml_kem768_key_pair_from_seed`,
`ml_dsa65_public_key_from_seed`); the Python binding has both of those as well.
Over the core, both add three things: typed, catchable errors (a
JavaScript `Error.code`, a Python exception class, both spelling the same
`RINE_MLS_*` code); a panic firewall, so no Rust unwind reaches V8 or CPython
and a handle that panicked is retired rather than reused; and explicit byte
ownership, arguments copied in and results moved out.

## Ciphersuites

| Id | Suite | Notes |
|---|---|---|
| `0xF057` | X-Wing (X25519 + ML-KEM-768) · ChaCha20-Poly1305 · SHA-256 · Ed25519 | rine's post-quantum suite, at a private-use code point |

rine-mls is post-quantum only. RFC 9420's classical suite `0x0001` is not
offered and is refused wherever a suite id is parsed. In the one suite, only the
KEM is rine's own: the AEAD, KDF, hash and signature scheme come unmodified
from the providers mls-rs ships. The X-Wing KEM follows
`draft-connolly-cfrg-xwing-kem-06` over `libcrux-ml-kem` and `x25519-dalek`.

Correctness is held down by three independent things, all run by `cargo test`:

- `tests/kat/xwing-draft06.txt` — the draft's own vectors, so key generation,
  encapsulation and decapsulation are pinned byte for byte.
- `tests/xwing_cross.rs` — the same operations crossed against the RustCrypto
  `x-wing` crate, a development dependency that never ships. Each side
  decapsulates what the other encapsulated. If they disagree, ours is wrong.
- `tests/kat/rine-suite-f057.txt` — the suite's primitives and HPKE key
  derivation, computed outside this crate.

Every group-flow test runs on the X-Wing suite.

## Build and test

```bash
cargo test                                        # unit + integration
cargo clippy --all-targets -- -D warnings
cargo check --target wasm32-unknown-unknown -p rine-mls-core   # browser forward-compat guard

cargo build --release -p rine-mls-node -p rine-mls-py          # both bindings
maturin build --release                                        # in crates/rine-mls-py
```

The cross-language proof — a Node process and a Python process joining one
group through a real rine server and exchanging application messages — is `spike/roundtrip/run.sh`. It boots its own throwaway postgres
and uvicorn on free ports.

```bash
bash spike/roundtrip/run.sh
```

rine's production server never compiles Rust: the binaries are cross-built here
and shipped as artifacts.

The dependency graph has its own gate, separate from the three above:

```bash
cargo deny check      # advisories, licences, duplicate crypto crates, sources
```

rine's continuous-integration run carries it as its own stage, and it reports
SKIPPED rather than passing on a machine where `cargo-deny` is not installed.
The policy is `deny.toml`.

## Shipped artifacts: six declared, four executed

The crate ships as compiled binaries — six napi addons and six abi3 wheels, cross
built off-box in the pinned Docker image under `spike/crossbuild/`.

```bash
# Run from the rine monorepo root, where these live:
scripts/build-mls-artifacts.sh      # cross-build and stage all twelve
scripts/verify-mls-artifacts.sh     # stamp + declared API + provenance, a check on BYTES
scripts/smoke-mls-platforms.sh      # LOAD each one and drive a group through it
scripts/attest-mls-artifacts.sh     # regenerate BUILD_ATTESTATION.md, then commit it
```

The verify step greps method names out of each binary; it proves a symbol is present
and cannot see a wrong signature, a panicking body or a broken ABI. The smoke step is
the one that executes: it runs the bindings' own suites against the shipped addon and
wheel inside a container of the matching architecture and libc, and it reaches **four
of the six platforms** — `linux-x64-gnu` and `linux-x64-musl` natively, the two arm64
targets under qemu emulation. It needs `docker run --privileged --rm tonistiigi/binfmt
--install arm64` once, so it is advisory and not part of `ci.sh`.

**`darwin-x64` and `darwin-arm64` are executed by nothing.** No container on a Linux
host runs Darwin, so those two are cross-compiled, stamped, string-checked and shipped
without ever having been loaded. The API is declared on six platforms and executed on
four.

The artifacts are gitignored, so `BUILD_ATTESTATION.md` is what the repository keeps
about them: a SHA-256 per artifact, the `Cargo.lock` hash and the builder image's
identity. It records one machine's build and is not a reproducibility claim.

It is also enforced, not just kept. Everything else above reads a *property* of an
artifact — architecture, build stamp, exported names — and a property is exactly what a
different build of the same source also has, so a host-toolchain addon dropped into
`npm/<platform>/` passes every one of them. The digests are the only check that tells
the pinned builder's bytes from a workstation's, so the publish path runs them twice:
once before the test gates and once after, because those gates compile for the host and
this host's triple is also one of the six cross targets. A mismatch means a rebuild
(`build-mls-artifacts.sh`), never a re-stage — `--stage` copies out of `target/`, which
is the tree a bad build wrote to in the first place.

## Scale measurements

Ten tests are `#[ignore]`d because they found real groups of up to a thousand
members. They are where every cost number rine states about groups comes from,
so they are not optional — they are expensive.

```bash
cargo test --release --workspace -- --ignored --nocapture --test-threads=1
```

Always `--release`: each of these documents itself with it, and unoptimised
ML-KEM and ratchet-tree work measures a different quantity, not a slower one.
`cargo` locks `target/`, so nothing else may run against this crate at the same
time — not another measurement, not `ci.sh`.

**Last measured.**

| | |
|---|---|
| Commit | `d8a40ea0`, plus this crate's subsequent changes |
| Date | 2026-08-02 |
| Host | AMD Ryzen 9 7900X, 12c/24t, 62 GiB |
| Toolchain | `rustc 1.95.0`, `cargo 1.95.0`, `--release` |
| Result | 10 passed, 0 failed |

Two of the ten answer questions nothing else in the tree does, and are the ones
to re-run first after a change to a batch size, a ciphersuite or the ratchet
tree: `scale_founding`'s `A3` walks the live founding schedule at the group-size
ceiling against real bytes, and `epoch_window` prices the client's epoch-retention
window.

## Ground rules

- Crypto and MLS dependencies are exact-pinned in the workspace manifest. A
  minor bump on the E2EE path is a wire-compatibility event, not a refresh.
- No native-only dependency outside the crypto provider seam, so the crate keeps
  building for `wasm32` and every platform in the release matrix.
- MLS state is local and private: it is written to disk 0600 and is never sent
  to the rine server, which only relays opaque wire artifacts.
- This core does not interoperate with the ts-mls engine it replaces. Key
  packages published by either are unreadable to the other, so the switch is a
  cutover: pools are drained and republished, and groups are recreated.
- Past epoch secrets are retained for a fixed window, derived once in
  `policy/retention.rs` from a 90-day client-side reach, so a returning member
  reads a backlog up to ninety days old. The number is the client's own budget
  and does not depend on how long the server keeps messages.
  `RineMlsOptions::epoch_retention` trades that reach for a narrower window in
  which old secrets exist on disk.
