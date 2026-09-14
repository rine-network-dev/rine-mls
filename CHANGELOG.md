# Changelog

All notable changes to `rine-mls` (npm `@rine-network/mls`, PyPI `rine-mls`) are
documented here.

This project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Changed — both published packages now point at this file

Neither distribution said where its notes were. This file is git-tracked and
mirrored, so it was always public, but a reader arriving from npm or PyPI had no
route to it: npm renders only the README, PyPI publishes wheels alone (an sdist
would turn "no wheel for your platform" into a doomed Rust compile), and neither
carried a link. Both crate READMEs now open on a Changelog section, and the PyPI
metadata carries a `Changelog` URL that renders in the sidebar. Nothing about
the library changed.

The release gate that holds every rine package's version against its own
changelog now resolves this file for both crates and reads the workspace version
out of `Cargo.toml`, so a bump that lands with no entry is refused the same way
it is everywhere else. It used to skip both crates as "not checked", which read
as a decision and was a blind spot.

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
