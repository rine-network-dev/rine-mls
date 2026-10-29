//! Applying a commit received from the server's handshake feed.

use mls_rs::group::{CommitEffect, ReceivedMessage};
use mls_rs::WireFormat;

use crate::epoch::epoch_after_commit;
use crate::error::{MlsBlobKind, Result, RineMlsError};
use crate::wire;

use super::RineMlsGroup;

impl RineMlsGroup {
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

        match self.process(message)? {
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

    /// Hand one message to MLS. When the allowed set refuses a leaf in it, the
    /// handle is left exactly as it was, so the caller can verify the agent and
    /// retry the same bytes.
    ///
    /// mls-rs authenticates the message and runs every identity check before it
    /// changes any state, so a PublicMessage commit leaves the handle untouched
    /// already. Opening a PrivateMessage consumes the sender's handshake
    /// ratchet key first, so that shape alone is processed on a copy of the
    /// group that is restored on a refusal; the ordinary path clones nothing.
    fn process(&mut self, message: mls_rs::MlsMessage) -> Result<ReceivedMessage> {
        let restore =
            (message.wire_format() == WireFormat::PrivateMessage).then(|| self.inner.clone());

        match self.inner.process_incoming_message(message) {
            Ok(received) => Ok(received),
            Err(error) => {
                let error = RineMlsError::from(error);
                if let (RineMlsError::PeerNotAdmitted { .. }, Some(restore)) = (&error, restore) {
                    self.inner = restore;
                }
                Err(error)
            }
        }
    }
}
