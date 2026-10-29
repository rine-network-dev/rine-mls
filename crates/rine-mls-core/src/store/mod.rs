//! File-backed MLS state, entirely local.
//!
//! MLS client state is implementation-private: it is never sent to the rine
//! server, which only relays opaque wire artifacts. Layout under the per-agent
//! root (`<config>/keys/<agent>/mls2/` on the rine surfaces):
//!
//! ```text
//! groups/<hex group id>/state.bin        current group state
//! groups/<hex group id>/epochs/<n>.bin   retained prior epochs
//! groups/<hex group id>/floor            epoch the current state began at
//! groups/<hex group id>/self_read.bin    plaintext of this member's own sends
//! key_packages/<hex ref>.bin             private half of published KeyPackages
//! ```
//!
//! Directories are 0700 and files 0600 — they hold group secrets, plaintext and
//! the private halves of published KeyPackages.
//!
//! Every file above whose payload is `mls-rs`'s serialization carries a format
//! tag ([`mod@format`]); `self_read.bin` carries its own version byte instead.
//!
//! The directory is new (`mls2/`) and its serialization is this crate's own.
//! The ts-mls-era `mls/` directory is never read and never written: MLS client
//! state is implementation-private and never leaves the machine, so there is no
//! interop reason to migrate it, and rine's MLS cutover recreates groups rather
//! than carrying state across cores. The two directories cannot
//! collide because they do not share a name.

mod files;
mod floor;
mod format;
mod group_state;
mod key_package;
mod self_read;
mod temps;

use std::fs;
use std::io;
use std::path::PathBuf;

use mls_rs_core::error::IntoAnyError;

use files::{
    create_private_dir, read_optional, read_optional_framed, remove_if_present, write_framed,
    write_private,
};

pub(crate) use floor::Incarnation;
pub use group_state::FileGroupStateStorage;
pub use key_package::FileKeyPackageStorage;
pub use self_read::{SelfReadCache, SELF_READ_MAX_BYTES, SELF_READ_MAX_ENTRIES};

/// Marked non-exhaustive because a new way for the store to fail is a patch
/// release here, not a breaking change for whoever matches on it.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum StoreError {
    #[error("MLS state store I/O error at {path}: {source}")]
    Io {
        path: PathBuf,
        #[source]
        source: io::Error,
    },

    #[error("corrupt MLS state store entry at {path}")]
    Corrupt { path: PathBuf },

    /// Distinct from [`Self::Corrupt`] on purpose: the file is intact and was
    /// written by a *newer* rine-mls over the same directory. The remedy is to
    /// upgrade this client, not to discard state.
    #[error(
        "MLS state store entry at {path} is format version {version}, which this \
         build of rine-mls does not know how to read"
    )]
    UnknownFormatVersion { path: PathBuf, version: u8 },
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
