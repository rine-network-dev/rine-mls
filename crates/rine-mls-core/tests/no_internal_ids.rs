//! No internal SPEC/gate identifier may reach a shipped or public-mirror surface.
//!
//! rine's release gate scrubs internal decision IDs (`SPEC DEC` decision tags)
//! and gate finding IDs (single-letter finding tags) from anything a user or the
//! Codeberg mirror receives: they point into `phases/`, which the mirror
//! excludes, so on a
//! public surface they are dangling references to nothing. The npm package ships
//! `index.d.ts` as its `types` and the maturin sdist ships `pyproject.toml`; the
//! whole `rine-mls/` source tree mirrors publicly. This walks every text source
//! in the workspace and refuses any `<PREFIX>-<digit>` internal-ID token.

use std::fs;
use std::path::{Path, PathBuf};

/// Root of the `rine-mls/` workspace: this crate is `rine-mls/crates/rine-mls-core`.
fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .ancestors()
        .nth(2)
        .expect("crate lives two levels under the rine-mls root")
        .to_path_buf()
}

/// Internal-ID prefixes assembled at runtime, so this test's own source never
/// contains a literal `<PREFIX>-<digit>` token that would flag itself.
fn id_prefixes() -> Vec<String> {
    ["DEC", "REQ", "G", "X", "F", "W"]
        .iter()
        .map(|p| format!("{p}-"))
        .collect()
}

fn is_text_source(path: &Path) -> bool {
    matches!(
        path.extension().and_then(|e| e.to_str()),
        Some("rs" | "ts" | "toml" | "py" | "md")
    )
}

/// An internal-ID hit is a prefix immediately followed by an ASCII digit, with a
/// non-alphanumeric char before the prefix (word boundary) so `AVG-3` / hex like
/// `0xF-` / `X-Wing` never match.
fn find_internal_id(text: &str, prefixes: &[String]) -> Option<String> {
    let bytes = text.as_bytes();
    for prefix in prefixes {
        let mut from = 0;
        while let Some(rel) = text[from..].find(prefix.as_str()) {
            let start = from + rel;
            let after = start + prefix.len();
            let boundary_ok = start == 0 || !bytes[start - 1].is_ascii_alphanumeric();
            let digit_after = bytes.get(after).is_some_and(u8::is_ascii_digit);
            if boundary_ok && digit_after {
                let end = (after + 1).min(text.len());
                return Some(text[start..end].to_string());
            }
            from = after;
        }
    }
    None
}

fn walk(dir: &Path, prefixes: &[String], hits: &mut Vec<String>) {
    let Ok(entries) = fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        let name = entry.file_name();
        if path.is_dir() {
            // Build artifacts (`target/`) and VCS metadata carry regenerated or
            // irrelevant text; they are not a shipped or mirrored surface.
            if name == "target" || name == ".git" {
                continue;
            }
            walk(&path, prefixes, hits);
        } else if is_text_source(&path) {
            let text = String::from_utf8_lossy(&fs::read(&path).unwrap_or_default()).into_owned();
            if let Some(token) = find_internal_id(&text, prefixes) {
                hits.push(format!("{}: {token}", path.display()));
            }
        }
    }
}

#[test]
fn no_internal_ids_on_shipped_or_mirrored_sources() {
    let prefixes = id_prefixes();
    let mut hits = Vec::new();
    walk(&workspace_root(), &prefixes, &mut hits);
    assert!(
        hits.is_empty(),
        "internal SPEC/gate identifiers leaked onto a shipped or public-mirror surface \
         (strip the ID, keep the prose):\n  {}",
        hits.join("\n  ")
    );
}

#[test]
fn detector_flags_a_planted_internal_id() {
    // Guards the guard: the detector must actually catch a leak, so a green
    // suite means the tree is clean, not that the scan is inert.
    let prefixes = id_prefixes();
    let planted = format!("keeps the full backlog ({}DEC{}8).", "SPEC ", "-");
    assert!(find_internal_id(&planted, &prefixes).is_some());
    // ...and must not flag ordinary prose or the X-Wing suite name.
    assert!(find_internal_id("the X-Wing ciphersuite at 0xF057", &prefixes).is_none());
    assert!(find_internal_id("a December refresh of AVG-latency", &prefixes).is_none());
}
