# Sourced by run.sh and package.sh: leaves the crate-root addon exactly as the gate found it.
#
# `napi build` writes its host build to ./rine-mls.<triple>.node, and index.js loads that file,
# so the gate cannot build anywhere else. The file is not the gate's to keep: the Claude Code rig
# byte-compares it with the pinned builder's addon staged in npm/<platform>/, so a host build
# left behind turns every later rig run red (and, worse, would make the two agree only by
# accident). Save before the first build, restore on every exit path.
#
# The caller sets $crate_dir, calls keep_addon before its first build and calls restore_addon from
# its EXIT trap.

keep_addon() {
    addon_keep_dir="$(mktemp -d)"
    find "$crate_dir" -maxdepth 1 -name '*.node' -exec cp -p {} "$addon_keep_dir"/ \;
}

restore_addon() {
    [ -n "${addon_keep_dir:-}" ] || return 0
    find "$crate_dir" -maxdepth 1 -name '*.node' -delete
    find "$addon_keep_dir" -maxdepth 1 -name '*.node' -exec cp -p {} "$crate_dir"/ \;
    rm -rf "$addon_keep_dir"
}
