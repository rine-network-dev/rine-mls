use std::fs;
use std::path::PathBuf;

use mls_rs_core::group::{EpochRecord, GroupState, GroupStateStorage};
use zeroize::Zeroizing;

use crate::policy::EpochRetention;

use super::floor::StagedGroups;
use super::{
    create_private_dir, read_optional_framed, remove_if_present, write_framed, MlsStoreRoot,
    Result, StoreError,
};

/// [`GroupStateStorage`] backed by one directory per group.
///
/// How far back epoch secrets are kept is [`EpochRetention`]'s decision, taken
/// once in `policy.rs`: this type only applies it. mls-rs never deletes an
/// epoch from storage itself and its own repository defers to storage for
/// anything not in the pending commit, so the retention set here is the whole
/// of the policy — nothing upstream trims underneath it.
///
/// Each group directory may also hold an incarnation floor, and a new state of
/// a group is staged until its first save; both live in `store/floor.rs`.
#[derive(Debug, Clone)]
pub struct FileGroupStateStorage {
    pub(super) root: MlsStoreRoot,
    retention: EpochRetention,
    pub(super) staged: StagedGroups,
}

impl FileGroupStateStorage {
    /// Storage under rine's shipped retention policy.
    pub fn new(root: MlsStoreRoot) -> Self {
        Self::with_retention(root, EpochRetention::DEFAULT)
    }

    pub fn with_retention(root: MlsStoreRoot, retention: EpochRetention) -> Self {
        Self {
            root,
            retention,
            staged: StagedGroups::default(),
        }
    }

    fn state_path(&self, group_id: &[u8]) -> PathBuf {
        self.root.group_dir(group_id).join("state.bin")
    }

    fn epochs_dir(&self, group_id: &[u8]) -> PathBuf {
        self.root.group_dir(group_id).join("epochs")
    }

    pub(super) fn epoch_path(&self, group_id: &[u8], epoch_id: u64) -> PathBuf {
        self.epochs_dir(group_id).join(format!("{epoch_id}.bin"))
    }

    /// Epoch ids currently on disk, oldest first.
    pub(super) fn stored_epochs(&self, group_id: &[u8]) -> Result<Vec<u64>> {
        let dir = self.epochs_dir(group_id);

        let entries = match fs::read_dir(&dir) {
            Ok(entries) => entries,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
            Err(e) => return Err(StoreError::io(&dir, e)),
        };

        let mut ids = Vec::new();

        for entry in entries {
            let path = entry.map_err(|e| StoreError::io(&dir, e))?.path();

            // A `.tmp` left behind by a crash mid-write is not an epoch; it is
            // the write that never landed. Counting it would report an epoch
            // that has no readable state.
            if path.extension().and_then(|e| e.to_str()) != Some("bin") {
                continue;
            }

            let id = path
                .file_stem()
                .and_then(|s| s.to_str())
                .and_then(|s| s.parse::<u64>().ok())
                .ok_or_else(|| StoreError::Corrupt { path: path.clone() })?;

            ids.push(id);
        }

        ids.sort_unstable();
        Ok(ids)
    }

    /// Delete the epochs the retention policy no longer covers.
    ///
    /// The window is a deletion rather than a filter: a secret past it is gone
    /// from disk, not merely ignored on read. There is no policy under which
    /// this is a no-op — [`EpochRetention`] is always a finite count — which is
    /// what stops a group's epoch directory growing for the life of the group.
    fn trim_epochs(&self, group_id: &[u8]) -> Result<()> {
        let keep = self.retention.limit();
        let ids = self.stored_epochs(group_id)?;

        for id in ids.iter().rev().skip(keep) {
            remove_if_present(&self.epoch_path(group_id, *id))?;
        }

        Ok(())
    }
}

impl GroupStateStorage for FileGroupStateStorage {
    type Error = StoreError;

    fn state(&self, group_id: &[u8]) -> Result<Option<Zeroizing<Vec<u8>>>> {
        Ok(read_optional_framed(&self.state_path(group_id))?.map(Zeroizing::new))
    }

    fn epoch(&self, group_id: &[u8], epoch_id: u64) -> Result<Option<Zeroizing<Vec<u8>>>> {
        Ok(read_optional_framed(&self.epoch_path(group_id, epoch_id))?.map(Zeroizing::new))
    }

    fn write(
        &mut self,
        state: GroupState,
        epoch_inserts: Vec<EpochRecord>,
        epoch_updates: Vec<EpochRecord>,
    ) -> Result<()> {
        create_private_dir(&self.epochs_dir(&state.id))?;

        // Only an insert can widen the retained set, and trimming costs a
        // listing of the whole window — MEASURED at +1.4 ms per persist once it
        // is full, against a 5.0 ms persist (`tests/epoch_window.rs`).
        // Persisting a message inserts no epoch, and messages are the write
        // path that runs hundreds of times a day against a handful of commits,
        // so paying it there would be a directory scan bought for nothing. The
        // one consequence: a client reopened under a *tighter* limit keeps the
        // excess until its next commit — one membership change of lag, not an
        // unbounded one.
        let widened = !epoch_inserts.is_empty();

        for epoch in epoch_inserts.into_iter().chain(epoch_updates) {
            write_framed(&self.epoch_path(&state.id, epoch.id), &epoch.data)?;
        }

        write_framed(&self.state_path(&state.id), &state.data)?;

        if widened {
            self.trim_epochs(&state.id)?;
        }

        Ok(())
    }

    fn max_epoch_id(&self, group_id: &[u8]) -> Result<Option<u64>> {
        self.visible_max_epoch_id(group_id)
    }
}
