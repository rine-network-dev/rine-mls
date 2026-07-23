#!/usr/bin/env bash
#
# The whole Python-binding gate, in the order that makes each half meaningful.
#
#   1. build the abi3 wheel WITH `panic-probe`, install it into a clean venv and
#      run the suite — the panic tests need a real panic to catch;
#   2. build the wheel WITHOUT it, install it into a *second* clean venv with no
#      pytest and no source tree, and use it as a consumer would — which also
#      asserts the probe is gone from what ships.
#
# Running only step 1 would prove the firewall on a wheel nobody installs;
# running only step 2 would prove the wheel while leaving the firewall untested.
#
# Both venvs install the built wheel, never the source tree: `rine_mls` is a
# compiled extension, so an importable source directory would be a different
# thing from the artifact under test.

set -euo pipefail

crate_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

# Pinned to the version the cross-compile builder image uses, so a wheel built
# here and a wheel built there come off the same tool.
MATURIN=maturin==1.9.4
PYTEST=pytest==8.3.4

build_wheel() {  # build_wheel <out-dir> [extra maturin args...]
    local out="$1"; shift
    uv run --quiet --no-project --with "$MATURIN" -- \
        maturin build --release --quiet --manifest-path "$crate_dir/Cargo.toml" \
        --out "$out" "$@" >/dev/null
    ls "$out"/*.whl
}

echo "== wheel with panic-probe, in a clean venv =="
probe_wheel="$(build_wheel "$work/probe" --features pyo3/extension-module,panic-probe)"
uv venv --quiet "$work/venv-probe"
VIRTUAL_ENV="$work/venv-probe" uv pip install --quiet "$probe_wheel" "$PYTEST"
RINE_MLS_EXPECT_PROBE=1 "$work/venv-probe/bin/python" -m pytest "$crate_dir/tests" -p no:cacheprovider

echo
echo "== wheel as a user installs it =="
shipped_wheel="$(build_wheel "$work/shipped")"
uv venv --quiet "$work/venv-shipped"
VIRTUAL_ENV="$work/venv-shipped" uv pip install --quiet "$shipped_wheel"
"$work/venv-shipped/bin/python" "$crate_dir/tests/package_consumer.py"

echo "OK: rine-mls builds, installs and works from the wheel ($(basename "$shipped_wheel"))"
