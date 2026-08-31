# rine-mls 0.1.1 — build attestation

**This is a record of one machine's build, not a reproducibility claim.** Every digest
below was read off the artifacts on the workstation that produced them. Nothing here has
been independently rebuilt, and until somebody else builds from the same inputs and gets
the same digests, the only thing it proves is which bytes were verified and published
from here. Regenerate it with `./scripts/attest-mls-artifacts.sh`; do not hand-edit it.

The artifacts themselves are gitignored — they are compiled binaries, and the registries
receive them directly. This manifest is the part of them that lives in the repository.

Generated: 2026-08-27T16:13:45Z

## Source

| | |
|---|---|
| Commit | `9d6565d1273aaa9a613195ecd7bdcc1ec3039aac` |
| Working tree (`rine-mls/`) | clean |
| `rine-mls/Cargo.lock` SHA-256 | `9fbce6eb3ffdc950f0a313b435cafdaca312bb0a0937615d0c3bd7194d86974c` |

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
| `npm/linux-x64-gnu/rine-mls.linux-x64-gnu.node` | 2703936 | a826123f488fed69f0938fa154093370b09a6c94f3bb726323bc3d6f703f3a29 |
| `npm/linux-arm64-gnu/rine-mls.linux-arm64-gnu.node` | 2128504 | 3a2b2cfbe4b4bf204fb7ed902784b8431addde0e9649a324a31f80e0e99fda8c |
| `npm/linux-x64-musl/rine-mls.linux-x64-musl.node` | 2700400 | 7f841fe4c24c81be702471b03697120727b38efce3a101b211592b1fffec1c02 |
| `npm/linux-arm64-musl/rine-mls.linux-arm64-musl.node` | 2123016 | be19b0c599a27769ed5cf6cf3607771e5b9e5cdb934f9a31e2d1b49ae4e2c728 |
| `npm/darwin-x64/rine-mls.darwin-x64.node` | 5374312 | c56a36aa03be4509b993a2489f13c111d3842df571be7596a931b65b01cccfc8 |
| `npm/darwin-arm64/rine-mls.darwin-arm64.node` | 4976304 | 86b22d9629901cb16cfec54eb5fbe53ac712e98a71381f04d43561439cda6272 |

### abi3 wheels — `dist-wheels/`

| File | Bytes | SHA-256 |
|---|---:|---|
| `rine_mls-0.1.1-cp39-abi3-macosx_10_12_x86_64.whl` | 2012280 | b3dadb4305a0b98b521a87489c76e411616f5d73f21b08afa5967ce17b11a85e |
| `rine_mls-0.1.1-cp39-abi3-macosx_11_0_arm64.whl` | 1885412 | b226e591ad66adc82f48e55b2917d1eb4ca31d3cb5f5917a4c867ba86b5dc812 |
| `rine_mls-0.1.1-cp39-abi3-manylinux_2_17_aarch64.manylinux2014_aarch64.whl` | 988690 | 71f28761bf8f9dcd67b13fe588141b8e37137293ebcd71a8c1e6778b97e721a4 |
| `rine_mls-0.1.1-cp39-abi3-manylinux_2_17_x86_64.manylinux2014_x86_64.whl` | 1097365 | 5561fc9176746a349018624a01948bbac4cd8181716ae29b4f9d2260285e7266 |
| `rine_mls-0.1.1-cp39-abi3-musllinux_1_2_aarch64.whl` | 985527 | e93be50e70d011dab6c7913c957c33363d93d4c8456d5a80b2eb685ca42b398b |
| `rine_mls-0.1.1-cp39-abi3-musllinux_1_2_x86_64.whl` | 1096168 | 9fad289b71f30d870724bf6df82eeabe69afb4b54bf49164f3a7c819c76a23e3 |

## What has been checked against these bytes, and what has not

- `./scripts/verify-mls-artifacts.sh` — build stamp, declared API surface, `file`
  fingerprint, no panic-probe, on all twelve. It is a **string-presence** check: it
  cannot see a wrong signature, a panicking body or a broken ABI.
- `./scripts/smoke-mls-platforms.sh` — **executes** the addon and the wheel, running the
  bindings' own suites (a real create → add → send → decrypt round trip on both
  ciphersuites) inside a container of the matching architecture and libc. It reaches
  four of the six platforms: `linux-x64-gnu` and `linux-x64-musl` natively,
  `linux-arm64-gnu` and `linux-arm64-musl` under qemu emulation.
- **`darwin-x64` and `darwin-arm64` are executed by nothing.** No container on a Linux
  host runs Darwin. Those two artifacts are cross-compiled, stamped and string-checked,
  and have never been loaded. "Proven on six platforms" is not a sentence this project
  may write.
