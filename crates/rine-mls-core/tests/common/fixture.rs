//! Locating the committed golden files that live outside the crate.
//!
//! A public mirror of `rine-mls` has no `rine-core/` or `scripts/` beside it, so
//! a file under a top-level directory that is absent is skipped, with a note. A
//! file missing from a directory that is present is a failure: a moved or
//! deleted vector must turn the suite red, never silently green.

use std::path::Path;

use serde_json::Value;

/// The JSON file at `relative` (from the repo root), or `None` when its
/// top-level directory is not present at all.
pub fn load_json(relative: &str) -> Option<Value> {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .ancestors()
        .nth(3)
        .expect("the repo root is three levels above the crate");
    let top = relative.split('/').next().expect("a relative path");

    if !root.join(top).exists() {
        eprintln!("skipped: {top}/ is not present, so {relative} cannot be read");
        return None;
    }

    let path = root.join(relative);
    let text = std::fs::read_to_string(&path).unwrap_or_else(|error| {
        panic!(
            "{} is missing from a present {top}/: {error}",
            path.display()
        )
    });

    Some(
        serde_json::from_str(&text)
            .unwrap_or_else(|error| panic!("{relative} is not JSON: {error}")),
    )
}
