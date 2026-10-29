#!/usr/bin/env bash
#
# Prove the npm package, not the build directory.
#
# Everything else in test/ loads `../index.js`, which happily falls back to the
# `.node` file sitting next to it — so it would keep passing even if the package
# shipped nothing. This script packs `@rine-network/mls` and its platform
# package exactly as `npm publish` would, installs both into a clean directory
# with no toolchain and no source tree, and drives real MLS through them.
#
# It also asserts the shipped addon carries no `panicProbe`: that method exists
# only to prove the panic firewall, and must never reach a user.
#
# 🔴 It proves the packaging with a HOST build, and must leave no trace of it. The
# release artifacts staged in npm/<platform>/ come off the pinned Docker builder and are
# what `--native` uploads; this script used to `cp` its host build straight into
# npm/linux-x64-gnu/, so running the test gate silently changed what would ship. Both the
# build tree (CARGO_TARGET_DIR below) and the pack tree ($work/platform) are therefore
# private to this run — nothing here writes inside the crate's npm/ directories, and the
# crate-root addon the build overwrites is restored on exit (keep-addon.sh).

set -euo pipefail

crate_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
work="$(mktemp -d)"

cd "$crate_dir"

# The release build below writes its addon into the crate root; put back whatever was there.
# shellcheck source=keep-addon.sh
. "$crate_dir/test/keep-addon.sh"
keep_addon
trap 'rm -rf "$work"; restore_addon' EXIT

# Same reason as test/run.sh: the host triple collides with a cross-build target, and
# target/gate is inside the one path rine-mls/.gitignore covers.
export CARGO_TARGET_DIR="$(cd "$crate_dir/../.." && pwd)/target/gate"

echo "[1/4] release build (no panic-probe) + private pack tree"
npm run --silent build
node_file="$(ls ./*.node)"
platform_dir="npm/$(basename "$node_file" .node | sed 's/^rine-mls\.//')"
test -d "$platform_dir" || { echo "no npm dir for $node_file"; exit 1; }
# Pack the platform package from a copy: same package.json and README that ship, this
# run's addon, and the staged release artifact left exactly as the builder wrote it.
pack_dir="$work/platform"
mkdir -p "$pack_dir"
cp "$platform_dir/package.json" "$platform_dir/README.md" "$node_file" "$pack_dir/"

echo "[2/4] npm pack both packages"
main_tgz="$work/$(npm pack --silent --pack-destination "$work")"
platform_tgz="$work/$(cd "$pack_dir" && npm pack --silent --pack-destination "$work")"

echo "[3/4] install into a clean project"
mkdir -p "$work/consumer"
cd "$work/consumer"
npm init -y >/dev/null
npm install --silent --no-audit --no-fund --omit=optional "$main_tgz" "$platform_tgz"

echo "[4/4] use it as a consumer would"
cp "$crate_dir/test/package-consumer.mjs" ./consumer.mjs
node ./consumer.mjs

echo "OK: @rine-network/mls installs and works from the packed tarballs"
