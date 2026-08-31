//! The frame around every file whose payload is `mls-rs`'s own serialization.
//!
//! `state.bin`, `epochs/<n>.bin` and `key_packages/<hex>.bin` hold bytes that
//! only a pinned `mls-rs` can interpret, and nothing on disk used to say which
//! one wrote them. A future `mls-rs` bump that changes an encoding would then
//! reinterpret an existing file rather than refuse it, and a misparsed group
//! state surfaces as damage somewhere far from the file that caused it. The
//! tag turns "written by a format this build does not know" into its own
//! failure, named at the file it came from.
//!
//! `self_read.bin` is deliberately not framed here: it is this crate's own
//! serialization and carries its own version byte (`self_read/codec.rs`).

use std::path::Path;

use super::{Result, StoreError};

/// Leading bytes of a framed file. Detection is "starts with these eight
/// bytes", never a heuristic. A collision with an untagged 0.1.0 file is not a
/// real risk: what follows the tag is an `mls-rs` `MlsEncode` payload, which
/// opens with an MLS varint length prefix, so a legacy file could only be
/// mistaken for a framed one by having that prefix and the six bytes after it
/// spell this exact word.
const MAGIC: &[u8; 8] = b"RINEMLS\0";

/// The frame this build writes and the only one it reads.
const VERSION: u8 = 1;

pub(super) fn frame(payload: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(MAGIC.len() + 1 + payload.len());
    out.extend_from_slice(MAGIC);
    out.push(VERSION);
    out.extend_from_slice(payload);
    out
}

/// Strip the frame, if there is one.
///
/// Untagged bytes are 0.1.0's output and are version 1 by definition — the tag
/// was added after those files were written, so refusing them would orphan
/// every group an installed client already holds, which is the exact failure
/// this tag exists to prevent.
pub(super) fn unframe(path: &Path, mut bytes: Vec<u8>) -> Result<Vec<u8>> {
    if !bytes.starts_with(MAGIC) {
        return Ok(bytes);
    }

    match bytes.get(MAGIC.len()) {
        Some(&VERSION) => {
            bytes.drain(..MAGIC.len() + 1);
            Ok(bytes)
        }
        // A newer rine-mls wrote this directory. Handing its payload to this
        // build's `mls-rs` is the one outcome the tag is here to rule out.
        Some(&version) => Err(StoreError::UnknownFormatVersion {
            path: path.to_path_buf(),
            version,
        }),
        None => Err(StoreError::Corrupt {
            path: path.to_path_buf(),
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn path() -> &'static Path {
        Path::new("state.bin")
    }

    #[test]
    fn test_frame_when_round_tripped_returns_the_payload() {
        let payload = b"mls-rs serialized group state".to_vec();

        assert_eq!(unframe(path(), frame(&payload)).expect("unframe"), payload);
    }

    #[test]
    fn test_unframe_when_the_bytes_carry_no_tag_returns_them_verbatim() {
        let legacy = b"written by 0.1.0, no tag".to_vec();

        assert_eq!(unframe(path(), legacy.clone()).expect("unframe"), legacy);
    }

    #[test]
    fn test_unframe_when_the_version_is_from_the_future_names_the_version() {
        let mut bytes = frame(b"payload of a layout this build cannot know");
        bytes[MAGIC.len()] = VERSION + 1;

        let err = unframe(path(), bytes).unwrap_err();

        assert!(
            matches!(err, StoreError::UnknownFormatVersion { version, .. } if version == VERSION + 1),
            "expected an unknown-version error, got {err}",
        );
    }

    #[test]
    fn test_unframe_when_the_tag_has_no_version_byte_reports_corruption() {
        let err = unframe(path(), MAGIC.to_vec()).unwrap_err();

        assert!(matches!(err, StoreError::Corrupt { .. }), "got {err}");
    }
}
