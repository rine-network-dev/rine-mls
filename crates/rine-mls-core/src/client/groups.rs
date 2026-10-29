//! The group lifecycle a rine client drives: founding, both join paths,
//! reloading from disk, and retiring local state.

use mls_rs::error::MlsError;
use mls_rs::{ExtensionList, MlsMessage};

use crate::error::{MlsBlobKind, Result, RineMlsError};
use crate::group::{CommitBundle, RineMlsGroup};
use crate::store::Incarnation;
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

        let mut group = self.group(inner, None);
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

        // The join verified the epoch it lands on, which is where the new state
        // begins; nothing on disk changes until the handle's first save.
        let stage = self.group_state.stage(inner.group_id());
        let floor = inner.current_epoch();

        Ok(self.group(inner, Some(Incarnation { stage, floor })))
    }

    /// Self-join by RFC 9420 external commit, from a GroupInfo carrying
    /// `external_pub` + `ratchet_tree` (`GET /groups/{id}/mls/group-info`).
    /// No Welcome, no admin action: the joiner mints its own commit, which
    /// existing members apply to advance the epoch.
    ///
    /// The joiner enters as a new leaf and removes nothing. An agent that is
    /// **already** a member cannot use this path — MLS refuses a second leaf
    /// carrying an identity the tree already holds — so a member recovering
    /// from unusable local state wants
    /// [`RineMlsClient::resync_by_external_commit`] instead.
    pub fn join_by_external_commit(
        &self,
        group_info: &[u8],
    ) -> Result<(RineMlsGroup, CommitBundle)> {
        self.external_commit(group_info, None)
    }

    /// Rejoin a group this agent is already a member of, replacing its own
    /// leaf: RFC 9420's resync form of an external commit.
    ///
    /// This is the path out of unusable local state — a config dir restored
    /// from a backup, or one whose epoch secrets no longer match the group.
    /// `stale_leaf` is the leaf this agent currently occupies, read from the
    /// old handle with [`RineMlsGroup::current_member_index`].
    ///
    /// The removal rides in the **same** commit as the join, which is what
    /// makes this the resync form rather than a join followed by a cleanup:
    /// the group is never in a state where one agent holds two leaves, so
    /// there is no window in which a stale leaf can be orphaned, and the
    /// recovery costs one O(N) commit rather than two.
    ///
    /// Naming a leaf that is not this agent's own is refused by MLS, not by
    /// rine: an external commit may carry exactly one Remove, and RFC 9420
    /// requires it to target the committer's own prior identity.
    pub fn resync_by_external_commit(
        &self,
        group_info: &[u8],
        stale_leaf: u32,
    ) -> Result<(RineMlsGroup, CommitBundle)> {
        self.external_commit(group_info, Some(stale_leaf))
    }

    fn external_commit(
        &self,
        group_info: &[u8],
        replacing: Option<u32>,
    ) -> Result<(RineMlsGroup, CommitBundle)> {
        let message = wire::decode(group_info, MlsBlobKind::GroupInfo, self.suite)?;

        self.external_commit_message(message, replacing)
    }

    pub(super) fn external_commit_message(
        &self,
        message: MlsMessage,
        replacing: Option<u32>,
    ) -> Result<(RineMlsGroup, CommitBundle)> {
        let (group_id, epoch) = message.group_id().zip(message.epoch()).ok_or(
            RineMlsError::UnexpectedMessageContent {
                expected: MlsBlobKind::GroupInfo,
            },
        )?;
        self.refuse_older_than_held(group_id, epoch)?;

        // The build applies its own commit, which inserts the GroupInfo's epoch
        // as a prior epoch of the new state; staged, that insert does not have to
        // follow epochs kept from an earlier state of this group.
        let stage = self.group_state.stage(group_id);

        let mut builder = self.inner.external_commit_builder()?;
        if let Some(stale_leaf) = replacing {
            builder = builder.with_removal(stale_leaf);
        }

        let (inner, commit) = builder.build(message)?;

        // The verified GroupInfo epoch: the build applied exactly one commit.
        let floor = inner.current_epoch() - 1;
        let group = self.group(inner, Some(Incarnation { stage, floor }));
        let bundle = group.external_join_bundle(commit)?;

        Ok((group, bundle))
    }

    /// Refuse a GroupInfo older than the state this client holds for the group,
    /// which would fork this member back to an epoch it has left. The header
    /// epoch is unverified, but it only ever refuses: accepting still rests on
    /// the build verifying the GroupInfo. State that does not load is not
    /// compared, as every caller already treats it as absent.
    fn refuse_older_than_held(&self, group_id: &[u8], epoch: u64) -> Result<()> {
        match self.inner.load_group(group_id) {
            Ok(held) if epoch < held.current_epoch() => {
                Err(RineMlsError::Mls(MlsError::InvalidEpoch))
            }
            _ => Ok(()),
        }
    }

    /// Reload a group from local state — the proof that state survives the
    /// process, and that it lives only on this machine.
    pub fn load_group(&self, group_id: &[u8]) -> Result<RineMlsGroup> {
        let inner = self.inner.load_group(group_id)?;

        Ok(self.group(inner, None))
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
