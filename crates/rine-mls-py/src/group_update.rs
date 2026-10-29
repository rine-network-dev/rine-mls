//! Moving a member's own leaf to a new key, and the pending commit that holds
//! the move, in their own `pymethods` block so `group.rs` stays about the group.

use pyo3::prelude::*;
use pyo3::types::PyBytes;
use rine_mls_core::wire_epoch;

use crate::error::guard;
use crate::group::MlsGroup;
use crate::types::CommitBundle;

#[pymethods]
impl MlsGroup {
    /// Commit a move of this member's own leaf to the signing key derived from
    /// ``new_leaf_seed`` (the agent's current ``mls.key``). The leaf is signed by
    /// the new key and the commit's framing by the key the member holds now.
    ///
    /// The commit is left **pending**: this handle keeps its epoch, leaf and
    /// signer until ``apply_pending_commit()``, and until then ``add_member``,
    /// ``remove_member`` and a second ``commit_update`` raise
    /// ``CommitPendingError``. ``group_info`` in the bundle is the GroupInfo of
    /// the epoch the commit creates. A seed that derives the key the leaf
    /// already carries raises ``LeafAlreadyCurrentError``; a handle that signs
    /// with a different key than its leaf carries raises
    /// ``SignerLeafMismatchError``.
    fn commit_update(&mut self, new_leaf_seed: &[u8]) -> PyResult<CommitBundle> {
        self.commit(|inner| inner.commit_update(new_leaf_seed))
    }

    /// The signature key on this member's own leaf.
    fn own_leaf_signature_key<'py>(&mut self, py: Python<'py>) -> PyResult<Bound<'py, PyBytes>> {
        let inner = &self.inner;
        let key = guard(&mut self.poison, || inner.own_leaf_signature_key())?;

        Ok(PyBytes::new(py, &key))
    }

    /// The epoch the pending commit would move this handle to, or ``None`` when
    /// nothing is pending. A pending commit is saved with the group, so it is
    /// still pending after ``save()`` and a reload.
    fn pending_commit_epoch(&mut self) -> PyResult<Option<i64>> {
        let inner = &self.inner;
        guard(&mut self.poison, || {
            inner.pending_commit_epoch().map(wire_epoch).transpose()
        })
    }

    /// Apply the pending commit and return the epoch the handle is now at. Its
    /// escrow export is captured here, so take it after this call. Raises
    /// ``NoPendingCommitError`` when nothing is pending.
    fn apply_pending_commit(&mut self) -> PyResult<i64> {
        let inner = &mut self.inner;
        guard(&mut self.poison, || {
            wire_epoch(inner.apply_pending_commit()?)
        })
    }

    /// Drop the pending commit. The handle keeps its epoch, leaf and signer, so
    /// this restores the state before ``commit_update``. Does nothing when no
    /// commit is pending.
    fn clear_pending_commit(&mut self) -> PyResult<()> {
        let inner = &mut self.inner;
        guard(&mut self.poison, || {
            inner.clear_pending_commit();
            Ok(())
        })
    }
}
