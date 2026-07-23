//! The group lifecycle a rine client drives: founding, both join paths,
//! reloading from disk, and retiring local state.

use mls_rs::ExtensionList;

use crate::error::{MlsBlobKind, Result};
use crate::group::{CommitBundle, RineMlsGroup};
use crate::wire;

use super::RineMlsClient;

impl RineMlsClient {
    /// Create a group whose only member is its creator, and mint the one commit
    /// rine's group-init POST carries.
    ///
    /// `group_id` is the rine group UUID's raw bytes: keying MLS state by the
    /// rine group id (never by the server's opaque `mls_group_id` latch) is
    /// what lets [`RineMlsClient::load_group`] find state again.
    pub fn create_group(&self, group_id: &[u8]) -> Result<(RineMlsGroup, CommitBundle)> {
        self.create_group_with_members(group_id, &[])
    }

    /// Create a group and admit its founding members in the same commit.
    ///
    /// This is rine's group-init path. The bundle it returns is the whole init
    /// POST: one commit, one Welcome per member in the order their KeyPackages
    /// were passed, and the GroupInfo for the epoch that commit lands on. The
    /// group is left at epoch 1 whatever its size — every commit a founder
    /// mints here is a commit the server is actually given, so no epoch is
    /// spent on a message no peer ever sees.
    ///
    /// `key_packages` are claimed from `GET /agents/{id}/mls/key-packages`, and
    /// they must have been published by this MLS core. A pool published by a
    /// pre-cutover client is unreadable in its entirety, so a
    /// member whose KeyPackage fails here fails for every KeyPackage it has:
    /// the answer is for that agent to drain and republish its pool, never for
    /// the adder to try the next entry.
    pub fn create_group_with_members(
        &self,
        group_id: &[u8],
        key_packages: &[Vec<u8>],
    ) -> Result<(RineMlsGroup, CommitBundle)> {
        let inner = self.inner.create_group_with_id(
            group_id.to_vec(),
            ExtensionList::new(),
            ExtensionList::new(),
            None,
        )?;

        let mut group = self.group(inner);
        let bundle = group.add_members(key_packages)?;

        Ok((group, bundle))
    }

    /// Join from a Welcome fetched by the one-shot `GET /agents/{id}/mls/welcomes`.
    /// The ratchet tree rides in the Welcome's group info extension, so no
    /// out-of-band tree is needed.
    ///
    /// A Welcome for a group running a different ciphersuite than this client
    /// was opened with is refused by name, rather than as a missing-key-package
    /// failure several steps later.
    pub fn join_from_welcome(&self, welcome: &[u8]) -> Result<RineMlsGroup> {
        let message = wire::decode(welcome, MlsBlobKind::Welcome, self.suite)?;
        let (inner, _) = self.inner.join_group(None, &message, None)?;

        Ok(self.group(inner))
    }

    /// Self-join by RFC 9420 external commit, from a GroupInfo carrying
    /// `external_pub` + `ratchet_tree` (`GET /groups/{id}/mls/group-info`).
    /// No Welcome, no admin action: the joiner mints its own commit, which
    /// existing members apply to advance the epoch.
    ///
    /// The joiner enters as a new leaf and removes nothing — RFC 9420's resync
    /// form of an external commit, which replaces an existing leaf, is not a
    /// path rine offers.
    pub fn join_by_external_commit(
        &self,
        group_info: &[u8],
    ) -> Result<(RineMlsGroup, CommitBundle)> {
        let message = wire::decode(group_info, MlsBlobKind::GroupInfo, self.suite)?;
        let (inner, commit) = self.inner.external_commit_builder()?.build(message)?;

        let group = self.group(inner);
        let bundle = group.external_join_bundle(commit)?;

        Ok((group, bundle))
    }

    /// Reload a group from local state — the proof that state survives the
    /// process, and that it lives only on this machine.
    pub fn load_group(&self, group_id: &[u8]) -> Result<RineMlsGroup> {
        let inner = self.inner.load_group(group_id)?;

        Ok(self.group(inner))
    }

    /// Delete one group's local MLS state: its current state, every retained
    /// epoch secret, and the plaintext its self-read cache held.
    ///
    /// Explicit on purpose, and the core never does it on its own. Two callers
    /// need it. A member evicted by a Remove commit keeps a readable handle so
    /// it can still decrypt the backlog it already had secrets for; when the
    /// caller is done with that backlog, retiring the state is its call, not
    /// this crate's. And rine's MLS cutover recreates existing groups,
    /// which means clearing the state a group of the same id left
    /// behind — otherwise the new group's create collides with the old one's
    /// stored state.
    ///
    /// Deleting the state of a group still in use is not recoverable: the epoch
    /// secrets are the only copy, and no peer can re-send them. Rejoin is the
    /// only way back in.
    pub fn delete_group_state(&self, group_id: &[u8]) -> Result<()> {
        Ok(self.root.remove_group(group_id)?)
    }
}
