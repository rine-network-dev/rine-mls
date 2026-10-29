//! Moving a member's own leaf to a new key, and the pending commit that holds
//! the move, in their own `impl` block so `group.rs` stays about the group.

use napi::bindgen_prelude::Uint8Array;
use napi_derive::napi;
use rine_mls_core::wire_epoch;

use crate::error::{guard, MlsError};
use crate::group::MlsGroup;
use crate::types::CommitBundle;

#[napi]
impl MlsGroup {
    /// Commit a move of this member's own leaf to the signing key derived from
    /// `newLeafSeed` (the agent's current `mls.key`). The leaf is signed by the
    /// new key and the commit's framing by the key the member holds now.
    ///
    /// The commit is left **pending**: this handle keeps its epoch, leaf and
    /// signer until `applyPendingCommit()`, and until then `addMember`,
    /// `removeMember` and a second `commitUpdate` fail `RINE_MLS_COMMIT_PENDING`.
    /// `groupInfo` in the bundle is the GroupInfo of the epoch the commit
    /// creates. A seed that derives the key the leaf already carries fails
    /// `RINE_MLS_LEAF_ALREADY_CURRENT`; a handle that signs with a different key
    /// than its leaf carries fails `RINE_MLS_SIGNER_LEAF_MISMATCH`.
    #[napi]
    pub fn commit_update(&mut self, new_leaf_seed: Uint8Array) -> Result<CommitBundle, MlsError> {
        self.commit(|inner| inner.commit_update(&new_leaf_seed))
    }

    /// The signature key on this member's own leaf.
    #[napi]
    pub fn own_leaf_signature_key(&mut self) -> Result<Uint8Array, MlsError> {
        let inner = &self.inner;
        guard(&mut self.poison, || inner.own_leaf_signature_key()).map(Uint8Array::new)
    }

    /// The epoch the pending commit would move this handle to, or `null` when
    /// nothing is pending. A pending commit is saved with the group, so it is
    /// still pending after `save()` and a reload.
    #[napi]
    pub fn pending_commit_epoch(&mut self) -> Result<Option<i64>, MlsError> {
        let inner = &self.inner;
        guard(&mut self.poison, || {
            inner.pending_commit_epoch().map(wire_epoch).transpose()
        })
    }

    /// Apply the pending commit and return the epoch the handle is now at. Its
    /// escrow export is captured here, so take it after this call. Fails
    /// `RINE_MLS_NO_PENDING_COMMIT` when nothing is pending.
    #[napi]
    pub fn apply_pending_commit(&mut self) -> Result<i64, MlsError> {
        let inner = &mut self.inner;
        guard(&mut self.poison, || {
            wire_epoch(inner.apply_pending_commit()?)
        })
    }

    /// Drop the pending commit. The handle keeps its epoch, leaf and signer, so
    /// this restores the state before `commitUpdate`. Does nothing when no
    /// commit is pending.
    #[napi]
    pub fn clear_pending_commit(&mut self) -> Result<(), MlsError> {
        let inner = &mut self.inner;
        guard(&mut self.poison, || {
            inner.clear_pending_commit();
            Ok(())
        })
    }
}
