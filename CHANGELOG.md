# Changelog

All notable changes to `rine-mls` (npm `@rine-network/mls`, PyPI `rine-mls`) are
documented here.

This project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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
