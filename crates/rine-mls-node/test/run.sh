#!/usr/bin/env bash
#
# The whole Node-binding gate, in the order that makes each half meaningful.
#
#   1. build WITH `panic-probe` and run the suite — the panic tests need a real
#      panic to catch, and they assert the probe is present;
#   2. build WITHOUT it, pack, install into a clean project and use the package
#      — which also asserts the probe is gone from what ships.
#
# Running only step 1 would prove the firewall on a build nobody installs;
# running only step 2 would prove the package while leaving the firewall
# untested. Both, in this order, is the point.

set -euo pipefail

crate_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$crate_dir"

echo "== build with panic-probe =="
npm run --silent build:probe

echo "== suite (RINE_MLS_EXPECT_PROBE=1) =="
RINE_MLS_EXPECT_PROBE=1 node --test "test/*.test.mjs"

echo
echo "== packaged, as a user installs it =="
bash test/package.sh
