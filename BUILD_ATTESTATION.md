# rine-mls 0.2.0 — build attestation

**This is a record of one machine's build, not a reproducibility claim.** Every digest
below was read off the artifacts on the workstation that produced them. Nothing here has
been independently rebuilt, and until somebody else builds from the same inputs and gets
the same digests, the only thing it proves is which bytes were verified and published
from here. Regenerate it with `./scripts/attest-mls-artifacts.sh`; do not hand-edit it.

The artifacts themselves are gitignored — they are compiled binaries, and the registries
receive them directly. This manifest is the part of them that lives in the repository.

Generated: 2026-10-25T14:36:06Z

## Source

| | |
|---|---|
| Commit | `01e9e50015f18ea81105c74b7b0e8e857a8fd9aa` |
| Working tree (`rine-mls/`) | clean |
| `rine-mls/Cargo.lock` SHA-256 | `d38e4b0fb81e7e868b26d1fcf3a048f45367c941643204639e4440f13ca9d57f` |

Every build site passes `--locked`, so the dependency graph is the committed
`Cargo.lock` and a resolver that wanted to move a dependency would have failed the build
(`build-mls-artifacts.sh`).

## Builder

The production box never compiles Rust; all twelve artifacts are cross-built off-box in
one pinned Docker image (`rine-mls/spike/crossbuild/Dockerfile`).

| | |
|---|---|
| Image | `rine-mls-crossbuild:pinned` |
| Image ID | `sha256:b2d3bf282501595122042e6da2f0311ed5c5b601f167c484e18725fd67e0b1dd` |
| Image created | 2026-07-22T13:56:17.64868582Z |
| Dockerfile SHA-256 | `6ade2e316b49521070e5e1ea7f650a73e501606af6e6482e8b340083968c62f1` |
| Base image | `rust:1.88-bookworm` (`sha256:af306cfa71d987911a781c37b59d7d67d934f49684058f96cf72079c3626bfe0`) |
| Base identity | CONFIRMED — every layer of `rust:1.88-bookworm` is a leading layer of the builder |

Toolchain, read out of that image:

```
rustc 1.88.0 (6b00bc388 2025-06-23)
cargo 1.88.0 (873a06493 2025-05-10)
zig 0.13.0
cargo-zigbuild 0.19.8
maturin 1.9.4
ldd (Debian GLIBC 2.36-9+deb12u10) 2.36
```

## Artifacts

SHA-256 over the exact files `./scripts/verify-mls-artifacts.sh` checks and
`./scripts/publish-package.sh --native rine-mls` uploads.

### napi addons — `crates/rine-mls-node/npm/<platform>/`

| File | Bytes | SHA-256 |
|---|---:|---|
| `npm/linux-x64-gnu/rine-mls.linux-x64-gnu.node` | 3318192 | b61b5d349dfef581869f3fdf6e2c0099c847ce9eff805e702b70f65e5a70ef08 |
| `npm/linux-arm64-gnu/rine-mls.linux-arm64-gnu.node` | 2493896 | 9685aabb943d9983bd676c53eb5409a7c3a723d314d9e88c66998e20c3ba4119 |
| `npm/linux-x64-musl/rine-mls.linux-x64-musl.node` | 3314960 | c54e7c2de5ff7d54d84f5dcd5cf0194903736e67ef65b72acac690f726edfe0a |
| `npm/linux-arm64-musl/rine-mls.linux-arm64-musl.node` | 2489720 | d7f2ad77b3e164a40becc65de75ec962e60e1e46b53f71fa61094f701836c97e |
| `npm/darwin-x64/rine-mls.darwin-x64.node` | 6515608 | 1599c7c05ad6cd820da380ca5417cf1491ce5003463c46eb4a768d488df11c09 |
| `npm/darwin-arm64/rine-mls.darwin-arm64.node` | 5939728 | 0b20c389a5c69a6a5cc50573d34b4747959789ac9694470229ede5fba3ea9386 |

### abi3 wheels — `dist-wheels/`

| File | Bytes | SHA-256 |
|---|---:|---|
| `rine_mls-0.2.0-cp39-abi3-macosx_10_12_x86_64.whl` | 2399334 | 1eb084ecc9a4c10b4760f8414fbf51f82c20613bccb312001e82dfce5764a123 |
| `rine_mls-0.2.0-cp39-abi3-macosx_11_0_arm64.whl` | 2274751 | 2ba23f1c5a7c2976d47fc8808f55e76f2e8a5d624528d37a698fc367eb42da43 |
| `rine_mls-0.2.0-cp39-abi3-manylinux_2_17_aarch64.manylinux2014_aarch64.whl` | 1174445 | 73bafccf0a5b1079ba529fedb1e2b574a3b3e8c32d51e8feca7d71f8941e268b |
| `rine_mls-0.2.0-cp39-abi3-manylinux_2_17_x86_64.manylinux2014_x86_64.whl` | 1322754 | 7e82a361d5a828107514dde8a571c7cffd7e8c6d791962ebb2c977df0cabed13 |
| `rine_mls-0.2.0-cp39-abi3-musllinux_1_2_aarch64.whl` | 1171447 | 9a5ea2b56ce8c4277ea97a1c7984f1a690ca4b493ab1d70136d1bb931561298f |
| `rine_mls-0.2.0-cp39-abi3-musllinux_1_2_x86_64.whl` | 1322257 | 965ad3e67f07fe64b0607ec24e5b820a7d9212c0d4babd3cc3bdc2b50d9039b8 |

## What has been checked against these bytes, and what has not

- `./scripts/verify-mls-artifacts.sh` — build stamp, declared API surface, `file`
  fingerprint, no panic-probe, on all twelve. It is a **string-presence** check: it
  cannot see a wrong signature, a panicking body or a broken ABI.
- `./scripts/smoke-mls-platforms.sh` — **executes** the addon and the wheel, running the
  bindings' own suites (a real create → add → send → decrypt round trip on the one
  ciphersuite) inside a container of the matching architecture and libc. It reaches
  four of the six platforms: `linux-x64-gnu` and `linux-x64-musl` natively,
  `linux-arm64-gnu` and `linux-arm64-musl` under qemu emulation.
- **`darwin-x64` and `darwin-arm64` are executed by nothing.** No container on a Linux
  host runs Darwin. Those two artifacts are cross-compiled, stamped and string-checked,
  and have never been loaded. "Proven on six platforms" is not a sentence this project
  may write.
