//! File-backed MLS state, entirely local.
//!
//! MLS client state is implementation-private: it is never sent to the rine
//! server, which only relays opaque wire artifacts. Layout under the per-agent
//! root (`<config>/keys/<agent>/mls2/` on the rine surfaces):
//!
//! ```text
//! groups/<hex group id>/state.bin        current group state
//! groups/<hex group id>/epochs/<n>.bin   retained prior epochs
//! groups/<hex group id>/self_read.bin    plaintext of this member's own sends
//! key_packages/<hex ref>.bin             private half of published KeyPackages
//! ```
//!
//! Directories are 0700 and files 0600 — they hold group secrets, plaintext and
//! the private halves of published KeyPackages.
//!
//! The directory is new (`mls2/`) and its serialization is this crate's own.
//! The ts-mls-era `mls/` directory is never read and never written: MLS client
//! state is implementation-private and never leaves the machine, so there is no
//! interop reason to migrate it, and rine's MLS cutover recreates groups rather
//! than carrying state across cores. The two directories cannot
//! collide because they do not share a name.

mod group_state;
mod key_package;
mod self_read;

use std::fs;
use std::io;
use std::path::{Path, PathBuf};

use mls_rs_core::error::IntoAnyError;

pub use group_state::FileGroupStateStorage;
pub use key_package::FileKeyPackageStorage;
pub use self_read::{SelfReadCache, SELF_READ_MAX_BYTES, SELF_READ_MAX_ENTRIES};

#[derive(Debug, thiserror::Error)]
pub enum StoreError {
    #[error("MLS state store I/O error at {path}: {source}")]
    Io {
        path: PathBuf,
        #[source]
        source: io::Error,
    },

    #[error("corrupt MLS state store entry at {path}")]
    Corrupt { path: PathBuf },
}

impl StoreError {
    fn io(path: impl Into<PathBuf>, source: io::Error) -> Self {
        Self::Io {
            path: path.into(),
            source,
        }
    }
}

impl IntoAnyError for StoreError {
    fn into_dyn_error(
        self,
    ) -> core::result::Result<Box<dyn std::error::Error + Send + Sync>, Self> {
        Ok(self.into())
    }
}

type Result<T> = core::result::Result<T, StoreError>;

/// Root of one agent's local MLS state.
#[derive(Debug, Clone)]
pub struct MlsStoreRoot {
    root: PathBuf,
}

impl MlsStoreRoot {
    pub fn new(root: impl Into<PathBuf>) -> Self {
        Self { root: root.into() }
    }

    pub(crate) fn group_dir(&self, group_id: &[u8]) -> PathBuf {
        self.root.join("groups").join(hex::encode(group_id))
    }

    pub(crate) fn key_packages_dir(&self) -> PathBuf {
        self.root.join("key_packages")
    }

    /// Delete one group's local state directory — current state, retained
    /// epoch secrets and the self-read cache's plaintext go together, because
    /// the last thing left on disk after a group is retired must not be the
    /// only unencrypted copy of its messages. Only ever called explicitly: see
    /// [`crate::RineMlsClient::delete_group_state`].
    pub(crate) fn remove_group(&self, group_id: &[u8]) -> Result<()> {
        let dir = self.group_dir(group_id);

        match fs::remove_dir_all(&dir) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(StoreError::io(&dir, e)),
        }
    }
}

fn create_private_dir(path: &Path) -> Result<()> {
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
fn write_private(path: &Path, bytes: &[u8]) -> Result<()> {
    let dir = path.parent().unwrap_or(Path::new("."));
    create_private_dir(dir)?;

    let tmp = path.with_extension("tmp");
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

    fs::rename(&tmp, path).map_err(|e| StoreError::io(path, e))
}

fn read_optional(path: &Path) -> Result<Option<Vec<u8>>> {
    match fs::read(path) {
        Ok(bytes) => Ok(Some(bytes)),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(StoreError::io(path, e)),
    }
}

fn remove_if_present(path: &Path) -> Result<()> {
    match fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(StoreError::io(path, e)),
    }
}
