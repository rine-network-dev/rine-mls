# rine-mls

rine's MLS core in Rust. One implementation of RFC 9420 group crypto for every
rine surface, wrapping [mls-rs](https://github.com/awslabs/mls-rs).

| Crate | Purpose |
|---|---|
| `crates/rine-mls-core` | rine's MLS contract: create, Welcome join, external-commit self-join, Add/Remove, application messages, epoch ordering, local file-backed state, and both ciphersuites |
| `crates/rine-mls-node` | napi-rs binding → npm `@rine-network/mls` |
| `crates/rine-mls-py` | PyO3/maturin binding → PyPI `rine-mls` |

The two bindings expose the same surface, method for method. They add exactly
three things over the core and nothing else: typed, catchable errors (a
JavaScript `Error.code`, a Python exception class, both spelling the same
`RINE_MLS_*` code); a panic firewall, so no Rust unwind reaches V8 or CPython
and a handle that panicked is retired rather than reused; and explicit byte
ownership, arguments copied in and results moved out.

## Ciphersuites

| Id | Suite | Notes |
|---|---|---|
| `0x0001` | X25519 · AES-128-GCM · SHA-256 · Ed25519 | RFC 9420's mandatory classical suite; rine's non-PQ fallback |
| `0xF057` | X-Wing (X25519 + ML-KEM-768) · ChaCha20-Poly1305 · SHA-256 · Ed25519 | rine's post-quantum suite, at a private-use code point |

The two suites differ only in the KEM: the AEAD, KDF, hash and signature scheme
come unmodified from the providers mls-rs ships. The X-Wing KEM follows
`draft-connolly-cfrg-xwing-kem-06` over `libcrux-ml-kem` and `x25519-dalek`.

Correctness is held down by three independent things, all run by `cargo test`:

- `tests/kat/xwing-draft06.txt` — the draft's own vectors, so key generation,
  encapsulation and decapsulation are pinned byte for byte.
- `tests/xwing_cross.rs` — the same operations crossed against the RustCrypto
  `x-wing` crate, a development dependency that never ships. Each side
  decapsulates what the other encapsulated. If they disagree, ours is wrong.
- `tests/kat/rine-suite-f057.txt` — the suite's primitives and HPKE key
  derivation, computed outside this crate.

Every group-flow test runs on both suites.

## Build and test

```bash
cargo test                                        # unit + integration
cargo clippy --all-targets -- -D warnings
cargo check --target wasm32-unknown-unknown -p rine-mls-core   # browser forward-compat guard

cargo build --release -p rine-mls-node -p rine-mls-py          # both bindings
maturin build --release                                        # in crates/rine-mls-py
```

The cross-language proof — a Node process and a Python process joining one
group through a real rine server and exchanging application messages on both
ciphersuites — is `spike/roundtrip/run.sh`. It boots its own throwaway postgres
and uvicorn on free ports.

```bash
bash rine-mls/spike/roundtrip/run.sh     # from the repo root
```

Never build this on the production box — Rust compilation there is out of
bounds (see `CLAUDE.md`, ship-broker precedent).

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
- Every past epoch secret is retained by default, so a returning member reads its
  backlog. `RineMlsOptions::epoch_retention` trades that reach for a narrower
  window in which old secrets exist on disk.
