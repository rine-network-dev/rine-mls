#!/usr/bin/env bash
# W2.4 proof: cross-compile rine-mls-core + the napi/PyO3 bindings for every
# DEC-4 day-one platform, off-box, via a pinned Docker builder + zig — and
# smoke-build rine-mls-core for wasm32 (browser forward-compat door, no
# binding). NEVER compiled on the production CX22 (ship-broker.sh precedent).
#
# DEC-4 targets: linux x64/arm64 (glibc + musl) + macOS x64/arm64. Windows is
# explicitly DEFERRED — not attempted here.
#
#   bash rine-mls/spike/crossbuild/run.sh
#
# Outputs land in rine-mls/dist-wheels/ (Python wheels) and are printed from
# the container for the node/core artifacts (this script itself just proves
# the build matrix; artifact extraction is left to the caller / CI).
set -euo pipefail

cd "$(dirname "$0")/../.."  # rine-mls/
IMAGE_TAG="rine-mls-crossbuild:pinned"

export DOCKER_CONFIG="${DOCKER_CONFIG:-/tmp/rine_docker_cfg}"
export DOCKER_BUILDKIT="${DOCKER_BUILDKIT:-0}"
mkdir -p "$DOCKER_CONFIG"

echo "[crossbuild] building pinned toolchain image..."
docker build -t "$IMAGE_TAG" spike/crossbuild

TARGETS=(
  x86_64-unknown-linux-gnu
  aarch64-unknown-linux-gnu
  x86_64-unknown-linux-musl
  aarch64-unknown-linux-musl
  x86_64-apple-darwin
  aarch64-apple-darwin
)

echo "[crossbuild] rine-mls-core + rine-mls-node across the DEC-4 matrix..."
docker run --rm -v "$(pwd)":/work -w /work "$IMAGE_TAG" bash -euo pipefail -c '
  targets=('"${TARGETS[*]}"')
  for t in ${targets[@]}; do
    echo "=== rine-mls-core :: $t ==="
    cargo zigbuild --release --target "$t" -p rine-mls-core
    echo "=== rine-mls-node (napi cdylib) :: $t ==="
    case "$t" in
      *musl*) RUSTFLAGS="-C target-feature=-crt-static" cargo zigbuild --release --target "$t" -p rine-mls-node ;;
      *)      cargo zigbuild --release --target "$t" -p rine-mls-node ;;
    esac
  done
'

echo "[crossbuild] rine-mls-py wheels (maturin --zig) across the DEC-4 matrix..."
docker run --rm -v "$(pwd)":/work -w /work/crates/rine-mls-py "$IMAGE_TAG" bash -euo pipefail -c '
  targets=('"${TARGETS[*]}"')
  for t in ${targets[@]}; do
    echo "=== rine-mls-py (maturin wheel) :: $t ==="
    case "$t" in
      *musl*) export RUSTFLAGS="-C target-feature=-crt-static" ;;
      *)      unset RUSTFLAGS ;;
    esac
    maturin build --release --target "$t" --zig -o /work/dist-wheels
  done
'

echo "[crossbuild] rine-mls-core wasm32-unknown-unknown smoke build (no binding)..."
docker run --rm -v "$(pwd)":/work -w /work "$IMAGE_TAG" \
  cargo build --release --target wasm32-unknown-unknown -p rine-mls-core

echo "[crossbuild] done. Python wheels in rine-mls/dist-wheels/."
