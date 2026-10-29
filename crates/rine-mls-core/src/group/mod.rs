//! One MLS group as seen by one agent: its state and the commits it receives.
//! Building commits is [`mod@commit`]; application messages are [`mod@data`].

mod apply;
mod commit;
mod data;
mod escrow;
mod update;

pub use commit::CommitBundle;
pub use data::AppMessage;
pub use escrow::{
    fingerprint, EpochFingerprint, EpochReader, EscrowBacklog, EscrowExport, EscrowGap,
    EscrowGapReason, EscrowTake, OpenedMessage, FINGERPRINT_LEN, MAX_CONTEXT_LEN,
    MAX_DROPPED_EPOCH_READ_EPOCHS, MAX_LEAVES, MAX_QUEUED_EPOCH_READ_EXPORTS,
};

use mls_rs::Group;

use crate::client::RineMlsConfig;
use crate::error::{Result, RineMlsError};
use crate::store::{Incarnation, SelfReadCache};
use crate::suite::RineCipherSuite;

/// One occupied leaf of the ratchet tree.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MemberLeaf {
    /// The true leaf index, in the space [`RineMlsGroup::remove_member`] takes.
    pub index: u32,
    /// The member's agent id: its basic-credential identity.
    pub identity: Vec<u8>,
    /// The leaf's Ed25519 signature public key, the `mls` field of the agent
    /// certificate generation the leaf was built from.
    pub signature_key: Vec<u8>,
}

/// One MLS group as seen by one agent.
///
/// State changes stay in memory until [`RineMlsGroup::save`] is called. That is
/// deliberate: rine posts a commit to the server first and only persists once
/// the server's epoch CAS accepts it, so a rejected commit leaves no forked
/// state behind.
pub struct RineMlsGroup {
    inner: Group<RineMlsConfig>,
    /// Set by the Remove commit that evicted this member, to the epoch that
    /// commit created. RFC 9420 forward secrecy means the eviction is the last
    /// thing this handle ever learns about the group.
    removed_at: Option<u64>,
    /// Plaintext of this member's own sends, which MLS will not decrypt back.
    self_read: SelfReadCache,
    /// Set on a state begun by a Welcome or an external commit until its first
    /// save adopts the incarnation floor.
    incarnation: Option<Incarnation>,
}

impl RineMlsGroup {
    pub(crate) fn new(
        inner: Group<RineMlsConfig>,
        self_read: SelfReadCache,
        incarnation: Option<Incarnation>,
    ) -> Self {
        Self {
            inner,
            removed_at: None,
            self_read,
            incarnation,
        }
    }

    /// The rine group UUID's raw bytes. MLS state is keyed by it, never by the
    /// server's opaque `mls_group_id` latch.
    pub fn group_id(&self) -> Vec<u8> {
        self.inner.group_id().to_vec()
    }

    pub fn epoch(&self) -> u64 {
        self.inner.current_epoch()
    }

    /// The group's own ciphersuite, read from its group context rather than
    /// from whatever suite the client that opened it mints with. A Welcome
    /// joiner learns the suite this way and records it as `mls_cipher_suite`.
    pub fn cipher_suite(&self) -> Result<RineCipherSuite> {
        let id = self.inner.cipher_suite().raw_value();

        RineCipherSuite::try_from(id).map_err(|id| RineMlsError::UnsupportedCipherSuite { id })
    }

    /// False once a Remove commit evicted this member. Every operation that
    /// would change or use the group refuses from then on; the handle survives
    /// only so the caller can see what happened and retire its local state.
    ///
    /// A sync loop must check this after [`Self::apply_commit`]: eviction is not
    /// an error there, it is the correct outcome of a valid commit.
    pub fn is_active(&self) -> bool {
        self.removed_at.is_none()
    }

    /// Leaf index of the member whose basic-credential identity (its agent id)
    /// is `identity` — the input to
    /// [`RineMlsGroup::remove_member`].
    pub fn member_index(&self, identity: &[u8]) -> Result<u32> {
        Ok(self.inner.member_with_identity(identity)?.index)
    }

    /// Every occupied leaf in the ratchet tree, as a [`MemberLeaf`]: its leaf
    /// index, basic-credential identity and signature key — the inverse of
    /// [`RineMlsGroup::member_index`], and the only way to learn that a leaf
    /// exists without already knowing whose it is.
    ///
    /// That is what an *orphan* leaf needs: one whose agent the server reports
    /// in neither the member roster nor the live-invitation list, so no caller
    /// can produce its identity to ask about it. Reclaiming those leaves is the
    /// difference between expiry freeing a seat and expiry bounding the tree —
    /// a blanked leaf is genuinely re-occupied by the next joiner, so a
    /// reclaimed leaf stops taxing every later Welcome and commit.
    ///
    /// The indices are true leaf indices, in the same space
    /// [`RineMlsGroup::remove_member`] takes. mls-rs documents its *iterator
    /// position* as uncorrelated with `ReceivedMessage` sender indices, which
    /// is a different quantity; the round trip against `member_index` is
    /// asserted per leaf on every suite by `tests/leaf_enumeration.rs`, because
    /// this feeds a verb that removes members.
    ///
    /// Order follows the tree, so it is stable for a given tree but carries no
    /// meaning — never index into the result to identify a member.
    pub fn member_identities(&self) -> Result<Vec<MemberLeaf>> {
        self.inner
            .roster()
            .members_iter()
            .map(|member| {
                let identity = member
                    .signing_identity
                    .credential
                    .as_basic()
                    .ok_or(RineMlsError::UnreadableCredential {
                        index: member.index,
                    })?
                    .identifier
                    .clone();

                Ok(MemberLeaf {
                    index: member.index,
                    identity,
                    signature_key: member.signing_identity.signature_key.to_vec(),
                })
            })
            .collect()
    }

    /// This handle's own leaf index.
    ///
    /// The `stale_leaf` argument to
    /// [`RineMlsClient::resync_by_external_commit`](crate::RineMlsClient::resync_by_external_commit),
    /// and the only place it may come from: a resync names the leaf this agent
    /// already occupies, and this handle is the only party that knows which one
    /// that is — the server does not know MLS leaf indices, and an identity
    /// never occupies two leaves for MLS to be asked about.
    ///
    /// A leaf index survives staleness, which is the property the whole resync
    /// path rests on: `tests/leaf_enumeration.rs` measures a handle stranded at
    /// epoch 2 while its group ran to epoch 13 — through five joins and three
    /// departures — reload from disk and still report leaf 1.
    pub fn current_member_index(&self) -> Result<u32> {
        self.active()?;

        Ok(self.inner.current_member_index())
    }

    /// A fresh GroupInfo for the current epoch, carrying `external_pub` and the
    /// ratchet tree. Single-use per epoch (RFC 9420 §12.4.3.2), so every commit
    /// republishes one or the next external joiner targets a stale epoch.
    pub fn group_info(&self) -> Result<Vec<u8>> {
        self.active()?;

        Ok(self
            .inner
            .group_info_message_allowing_ext_commit(true)?
            .to_bytes()?)
    }

    /// Persist to the local file store. Never sent to the server.
    ///
    /// The first save of a state begun by a Welcome or an external commit
    /// adopts its incarnation floor first; until then nothing on disk changed.
    pub fn save(&mut self) -> Result<()> {
        if let Some(incarnation) = &self.incarnation {
            incarnation.adopt()?;
        }
        self.inner.write_to_storage()?;
        self.incarnation = None;

        Ok(())
    }

    fn active(&self) -> Result<()> {
        match self.removed_at {
            None => Ok(()),
            Some(epoch) => Err(RineMlsError::GroupInactive { epoch }),
        }
    }
}
