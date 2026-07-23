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

set -euo pipefail

crate_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

cd "$crate_dir"

echo "[1/4] release build (no panic-probe) + staged artifact"
npm run --silent build
node_file="$(ls ./*.node)"
platform_dir="npm/$(basename "$node_file" .node | sed 's/^rine-mls\.//')"
test -d "$platform_dir" || { echo "no npm dir for $node_file"; exit 1; }
cp "$node_file" "$platform_dir/"

echo "[2/4] npm pack both packages"
main_tgz="$work/$(npm pack --silent --pack-destination "$work")"
platform_tgz="$work/$(cd "$platform_dir" && npm pack --silent --pack-destination "$work")"

echo "[3/4] install into a clean project"
mkdir -p "$work/consumer"
cd "$work/consumer"
npm init -y >/dev/null
npm install --silent --no-audit --no-fund --omit=optional "$main_tgz" "$platform_tgz"

echo "[4/4] use it as a consumer would"
cp "$crate_dir/test/package-consumer.mjs" ./consumer.mjs
node ./consumer.mjs

echo "OK: @rine-network/mls installs and works from the packed tarballs"
