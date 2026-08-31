//! Reading and writing one file of local MLS state: owner-only, crash-safe,
//! and — for the `mls-rs` payloads — format-tagged.

use std::fs;
use std::io;
use std::path::Path;

use super::temps::{sweep_stale_temps, temp_path};
use super::{format, Result, StoreError};

pub(super) fn create_private_dir(path: &Path) -> Result<()> {
    let mut builder = fs::DirBuilder::new();
    builder.recursive(true);

    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        builder.mode(0o700);
    }

    builder.create(path).map_err(|e| StoreError::io(path, e))
}

/// Write `bytes` to `path` via a temp file + rename so a crash mid-write cannot
/// leave a half-written group state behind. The file is 0600 from creation, not
/// chmod'd afterwards, so secrets are never briefly world-readable.
pub(super) fn write_private(path: &Path, bytes: &[u8]) -> Result<()> {
    let dir = path.parent().unwrap_or(Path::new("."));
    create_private_dir(dir)?;

    let tmp = temp_path(path);
    let mut options = fs::OpenOptions::new();
    options.write(true).create(true).truncate(true);

    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }

    {
        use std::io::Write;
        let mut file = options.open(&tmp).map_err(|e| StoreError::io(&tmp, e))?;
        file.write_all(bytes).map_err(|e| StoreError::io(&tmp, e))?;
        file.sync_all().map_err(|e| StoreError::io(&tmp, e))?;
    }

    fs::rename(&tmp, path).map_err(|e| StoreError::io(path, e))?;

    // After the rename, not before: the state is durable and this writer's own
    // temp no longer exists, so the sweep cannot be looking at it.
    sweep_stale_temps(path);

    Ok(())
}

pub(super) fn read_optional(path: &Path) -> Result<Option<Vec<u8>>> {
    match fs::read(path) {
        Ok(bytes) => Ok(Some(bytes)),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(StoreError::io(path, e)),
    }
}

/// [`write_private`] for a payload only `mls-rs` can interpret. Every such
/// writer goes through here so the format tag cannot be present on one path and
/// missing on another — see [`mod@format`].
pub(super) fn write_framed(path: &Path, payload: &[u8]) -> Result<()> {
    write_private(path, &format::frame(payload))
}

/// [`read_optional`] for a framed file, returning the `mls-rs` payload.
pub(super) fn read_optional_framed(path: &Path) -> Result<Option<Vec<u8>>> {
    read_optional(path)?
        .map(|bytes| format::unframe(path, bytes))
        .transpose()
}

pub(super) fn remove_if_present(path: &Path) -> Result<()> {
    match fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(StoreError::io(path, e)),
    }
}
