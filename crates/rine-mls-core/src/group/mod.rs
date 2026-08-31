//! One MLS group as seen by one agent: its state and the commits it receives.
//! Building commits is [`mod@commit`]; application messages are [`mod@data`].

mod commit;
mod data;

pub use commit::CommitBundle;
pub use data::AppMessage;

use mls_rs::group::{CommitEffect, ReceivedMessage};
use mls_rs::Group;

use crate::client::RineMlsConfig;
use crate::epoch::epoch_after_commit;
use crate::error::{MlsBlobKind, Result, RineMlsError};
use crate::store::SelfReadCache;
use crate::suite::RineCipherSuite;
use crate::wire;

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
}

impl RineMlsGroup {
    pub(crate) fn new(inner: Group<RineMlsConfig>, self_read: SelfReadCache) -> Self {
        Self {
            inner,
            removed_at: None,
            self_read,
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

    /// Leaf index of the member whose basic-credential identity (its raw
    /// Ed25519 public key) is `identity` — the input to
    /// [`RineMlsGroup::remove_member`].
    pub fn member_index(&self, identity: &[u8]) -> Result<u32> {
        Ok(self.inner.member_with_identity(identity)?.index)
    }

    /// Every occupied leaf in the ratchet tree, as `(leaf index,
    /// basic-credential identity)` — the inverse of
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
    /// asserted per leaf on both suites by `tests/leaf_enumeration.rs`, because
    /// this feeds a verb that removes members.
    ///
    /// Order follows the tree, so it is stable for a given tree but carries no
    /// meaning — never index into the result to identify a member.
    pub fn member_identities(&self) -> Result<Vec<(u32, Vec<u8>)>> {
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

                Ok((member.index, identity))
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

    /// Apply a commit received from the server's handshake feed.
    ///
    /// The epoch is checked before the commit is handed to MLS: the group must
    /// be exactly at the epoch the commit was built at, which is the same
    /// `current + 1` CAS the server enforces. A stale or skipped commit is
    /// refused rather than forking local state.
    ///
    /// A commit that removes *this* member returns the epoch the group is left
    /// at — RFC 9420 gives an evicted member no key schedule for the new epoch,
    /// so there is no new epoch to report — and retires the handle
    /// ([`Self::is_active`]).
    pub fn apply_commit(&mut self, commit: &[u8]) -> Result<u64> {
        self.active()?;

        let message = wire::decode(commit, MlsBlobKind::Commit, self.cipher_suite()?)?;
        let commit_epoch = message
            .epoch()
            .ok_or(RineMlsError::UnexpectedMessageContent {
                expected: MlsBlobKind::Commit,
            })?;

        let expected = epoch_after_commit(self.epoch(), commit_epoch)?;

        match self.inner.process_incoming_message(message)? {
            ReceivedMessage::Commit(description) => {
                if matches!(description.effect, CommitEffect::Removed { .. }) {
                    self.removed_at = Some(expected);
                } else {
                    debug_assert_eq!(self.epoch(), expected);
                }
            }
            _ => {
                return Err(RineMlsError::UnexpectedMessageContent {
                    expected: MlsBlobKind::Commit,
                })
            }
        }

        Ok(self.epoch())
    }

    /// Persist to the local file store. Never sent to the server.
    pub fn save(&mut self) -> Result<()> {
        Ok(self.inner.write_to_storage()?)
    }

    fn active(&self) -> Result<()> {
        match self.removed_at {
            None => Ok(()),
            Some(epoch) => Err(RineMlsError::GroupInactive { epoch }),
        }
    }
}
