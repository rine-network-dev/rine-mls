//! Moving this member's own leaf to a new key, and holding the commit that does
//! it until the caller decides to apply or drop it.

use crate::error::{LeafUpdateFault, Result, RineMlsError};
use crate::identity::LeafIdentity;

use super::commit::next_group_info;
use super::{CommitBundle, RineMlsGroup};

impl RineMlsGroup {
    /// Build an UpdatePath commit that moves this member's own leaf to the
    /// signing key derived from `leaf_seed` (the agent's current `mls.key`).
    /// The leaf node is signed by the new key, the commit's framing by the key
    /// the member held before it.
    ///
    /// The commit is left pending: the handle keeps its epoch, leaf and signer
    /// until [`Self::apply_pending_commit`], and until then every other commit
    /// builder refuses with `RINE_MLS_COMMIT_PENDING`. The bundle's GroupInfo is
    /// the one for the epoch the commit creates, so an external joiner can
    /// target it once the commit is applied.
    pub fn commit_update(&mut self, leaf_seed: &[u8]) -> Result<CommitBundle> {
        self.active()?;

        let current = self.inner.current_member_signing_identity()?.clone();
        let agent_id = current
            .credential
            .as_basic()
            .ok_or(RineMlsError::UnreadableCredential {
                index: self.inner.current_member_index(),
            })?
            .identifier
            .clone();
        let next = LeafIdentity::new(&agent_id, leaf_seed)?;

        if next.leaf_public_key().as_slice() == &*current.signature_key {
            return Err(LeafUpdateFault::LeafAlreadyCurrent.into());
        }
        // A handle installed from an older KeyPackage while its client holds a
        // newer seed signs with a key its leaf does not carry: every receiver
        // would refuse the commit's framing signature.
        if self.inner.signer_public_key()? != current.signature_key {
            return Err(LeafUpdateFault::SignerLeafMismatch.into());
        }

        let output = self
            .inner
            .commit_builder()
            .set_new_signing_identity(next.signer(), next.signing_identity())
            .build()?;

        Ok(CommitBundle {
            commit: output.commit_message.to_bytes()?,
            welcomes: Vec::new(),
            group_info: next_group_info(&output)?,
            epoch: self.next_epoch()?,
        })
    }

    /// The signature key on this member's own leaf.
    pub fn own_leaf_signature_key(&self) -> Result<Vec<u8>> {
        self.active()?;

        Ok(self
            .inner
            .current_member_signing_identity()?
            .signature_key
            .to_vec())
    }

    /// The epoch the pending commit would move this handle to, or `None` when
    /// nothing is pending. A pending commit is part of the saved group state,
    /// so it survives [`Self::save`] and a reload.
    pub fn pending_commit_epoch(&self) -> Option<u64> {
        self.inner
            .has_pending_commit()
            .then(|| self.next_epoch().ok())
            .flatten()
    }

    /// Apply the pending commit, which also captures its epoch's escrow export,
    /// and return the epoch the handle is now at.
    pub fn apply_pending_commit(&mut self) -> Result<u64> {
        self.active()?;

        if !self.inner.has_pending_commit() {
            return Err(LeafUpdateFault::NoPendingCommit.into());
        }
        self.inner.apply_pending_commit()?;

        Ok(self.epoch())
    }

    /// Drop the pending commit. The handle keeps its epoch, leaf, signer and
    /// secrets, so this is the restore of the state before the commit was
    /// built. A no-op when nothing is pending.
    pub fn clear_pending_commit(&mut self) {
        self.inner.clear_pending_commit();
    }

    fn next_epoch(&self) -> Result<u64> {
        self.epoch()
            .checked_add(1)
            .ok_or(RineMlsError::EpochOverflow {
                current: self.epoch(),
            })
    }
}
