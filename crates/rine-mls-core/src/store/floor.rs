//! The incarnation floor of a group directory, and the staging that keeps a new
//! group state off the disk until its first save.
//!
//! The floor (`floor` in the group directory) is the epoch at which the group's
//! current state began. mls-rs only accepts a new prior epoch at the stored
//! maximum plus one, so epochs retained from an earlier state of the same group
//! (a member re-added after a removal, or one that resynced) would stop the new
//! state from advancing. Ids below the floor stay readable through
//! [`GroupStateStorage::epoch`](mls_rs_core::group::GroupStateStorage::epoch)
//! but are invisible to the contiguity check.
//!
//! A new state, from a Welcome or an external commit, is staged from the moment
//! it is built until its first save. While it is staged, the contiguity check
//! sees no stored epochs for the group, so the new state advances in memory and
//! nothing on disk changes: a Welcome or GroupInfo that is refused, fails
//! verification or is never saved leaves the directory exactly as it was. The
//! first save adopts the floor, and only then are the dead fork's epochs
//! deleted. The staging set is shared by every clone of one storage, which is
//! how the client's own handle reaches the clone each group writes through.
//!
//! The floor is written before the deletions and before the new state. A crash
//! after the floor is written and before the new state is saved leaves the old
//! state live: it still loads, its retained epochs still read, and its ids below
//! the floor stop counting towards the contiguity check until the next adoption.
//! The epochs a dead fork left at or above the floor may be deleted or not,
//! depending on where the crash fell. Nothing becomes readable that was not
//! readable before.

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};

use super::group_state::FileGroupStateStorage;
use super::{
    read_optional, read_optional_framed, remove_if_present, write_framed, Result, StoreError,
};

/// Group ids with a staged new state, each with the number of unsaved handles
/// that hold it. One set per storage, shared by every clone.
pub(super) type StagedGroups = Arc<Mutex<HashMap<Vec<u8>, usize>>>;

impl FileGroupStateStorage {
    fn floor_path(&self, group_id: &[u8]) -> PathBuf {
        self.root.group_dir(group_id).join("floor")
    }

    /// The incarnation floor, or 0 for a group that has never adopted one.
    fn floor(&self, group_id: &[u8]) -> Result<u64> {
        let path = self.floor_path(group_id);

        match read_optional_framed(&path)? {
            None => Ok(0),
            Some(bytes) => <[u8; 8]>::try_from(bytes.as_slice())
                .map(u64::from_le_bytes)
                .map_err(|_| StoreError::Corrupt { path }),
        }
    }

    /// Start the group's current state at epoch `floor`.
    ///
    /// Stored ids at or above the floor belong to a fork that no longer exists
    /// and are deleted; ids below it stay readable. A group directory with
    /// nothing to hide gets no floor, so a first join leaves none behind. The old
    /// floor is never read, so a corrupt one is replaced rather than refused.
    pub(crate) fn adopt_floor(&self, group_id: &[u8], floor: u64) -> Result<()> {
        let stored = self.stored_epochs(group_id)?;

        if stored.is_empty() && read_optional(&self.floor_path(group_id))?.is_none() {
            return Ok(());
        }

        write_framed(&self.floor_path(group_id), &floor.to_le_bytes())?;

        for id in stored.into_iter().filter(|id| *id >= floor) {
            remove_if_present(&self.epoch_path(group_id, id))?;
        }

        Ok(())
    }

    /// Stage a new state of the group until the returned guard drops.
    pub(crate) fn stage(&self, group_id: &[u8]) -> StagedIncarnation {
        *self.staged_groups().entry(group_id.to_vec()).or_insert(0) += 1;

        StagedIncarnation {
            storage: self.clone(),
            group_id: group_id.to_vec(),
        }
    }

    /// The highest stored epoch id the contiguity check may see: none while a
    /// new state of the group is staged, and none below the floor.
    pub(super) fn visible_max_epoch_id(&self, group_id: &[u8]) -> Result<Option<u64>> {
        if self.staged_groups().contains_key(group_id) {
            return Ok(None);
        }

        let floor = self.floor(group_id)?;

        Ok(self
            .stored_epochs(group_id)?
            .last()
            .copied()
            .filter(|id| *id >= floor))
    }

    /// Every update to the map completes under the lock, so a poisoned lock
    /// still guards a consistent map.
    fn staged_groups(&self) -> MutexGuard<'_, HashMap<Vec<u8>, usize>> {
        self.staged.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

/// Keeps one group staged on a storage until it drops.
pub(crate) struct StagedIncarnation {
    storage: FileGroupStateStorage,
    group_id: Vec<u8>,
}

impl Drop for StagedIncarnation {
    fn drop(&mut self) {
        let mut staged = self.storage.staged_groups();

        if let Some(count) = staged.get_mut(&self.group_id) {
            *count -= 1;
            if *count == 0 {
                staged.remove(&self.group_id);
            }
        }
    }
}

/// A new state of one group, staged until its first save adopts `floor`.
pub(crate) struct Incarnation {
    pub(crate) stage: StagedIncarnation,
    pub(crate) floor: u64,
}

impl Incarnation {
    /// Idempotent, so a save that fails after it can simply be retried.
    pub(crate) fn adopt(&self) -> Result<()> {
        self.stage
            .storage
            .adopt_floor(&self.stage.group_id, self.floor)
    }
}

#[cfg(test)]
mod tests {
    use crate::{
        AllowedIdentities, FileGroupStateStorage, LeafIdentity, MlsStoreRoot, RineCipherSuite,
        RineMlsClient,
    };

    fn client(dir: &std::path::Path, seed: u8, allowed: &AllowedIdentities) -> RineMlsClient {
        let leaf = LeafIdentity::new(&[seed; 8], &[seed; 32]).expect("seed");
        allowed
            .insert(&[seed; 8], &leaf.leaf_public_key(), 0)
            .expect("record the pair");
        let root = MlsStoreRoot::new(dir.join(seed.to_string()));
        RineMlsClient::open(root, &leaf, allowed.clone(), RineCipherSuite::DEFAULT)
    }

    #[test]
    fn a_crash_between_floor_and_state_leaves_the_old_state_loadable() {
        let dir = tempfile::tempdir().expect("temp dir");
        let allowed = AllowedIdentities::new();
        let alice = client(dir.path(), 1, &allowed);
        let bob = client(dir.path(), 2, &allowed);
        let carol = client(dir.path(), 3, &allowed);
        let id = [7u8; 16];

        let (mut alice_group, founding) = alice
            .create_group_with_members(&id, &[bob.generate_key_package().expect("kp")])
            .expect("found with bob");
        let mut bob_group = bob
            .join_from_welcome(&founding.welcomes[0])
            .expect("bob joins");
        bob_group.save().expect("save");
        let unread = alice_group
            .encrypt_application_message(b"sent at epoch 1")
            .expect("encrypt");
        let add = alice_group
            .add_member(&carol.generate_key_package().expect("kp"))
            .expect("add carol");
        bob_group.apply_commit(&add.commit).expect("bob applies");
        bob_group.save().expect("save");
        drop(bob_group);

        // The adoption a new state of the group would run, with the crash
        // falling before that state is written.
        FileGroupStateStorage::new(MlsStoreRoot::new(dir.path().join("2")))
            .adopt_floor(&id, 2)
            .expect("adopt");

        let mut reopened = bob.load_group(&id).expect("the old state still loads");
        assert_eq!(reopened.epoch(), 2);
        let opened = reopened
            .decrypt_application_message(&unread)
            .expect("its retained epoch still reads");
        assert_eq!(opened.envelope, b"sent at epoch 1");
    }
}
