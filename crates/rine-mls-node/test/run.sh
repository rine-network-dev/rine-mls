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

# This gate builds for the HOST, and this host's triple (x86_64-unknown-linux-gnu) is
# ALSO one of the six cross-build targets. With a shared target/ the gate's cdylib lands
# on top of the pinned builder's at target/x86_64-unknown-linux-gnu/release/, and the
# re-stage step then copies a workstation build into npm/linux-x64-gnu/ — five published
# addons off the pinned builder plus one off whatever machine ran the tests. Every other
# gate passes it: same architecture, same stamp, same exported names.
# So gate builds get their own tree. It lives inside target/ because rine-mls/.gitignore
# ignores `/target` and nothing else — a sibling target-gate/ would be untracked, and
# sync-codeberg.sh `git add -A`s untracked files that main's .gitignore does not cover.
export CARGO_TARGET_DIR="$(cd "$crate_dir/../.." && pwd)/target/gate"

echo "== build with panic-probe =="
npm run --silent build:probe

echo "== suite (RINE_MLS_EXPECT_PROBE=1) =="
RINE_MLS_EXPECT_PROBE=1 node --test "test/*.test.mjs"

echo
echo "== packaged, as a user installs it =="
bash test/package.sh
