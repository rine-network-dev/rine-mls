//! The group's data plane: `mls-v1` application messages in and out, including
//! the one message MLS itself refuses to decrypt — the sender's own.

use mls_rs::error::MlsError;
use mls_rs::group::ReceivedMessage;

use crate::error::{MlsBlobKind, Result, RineMlsError};
use crate::{frame, wire};

use super::RineMlsGroup;

/// A decrypted MLS application message. The payload is the signed rine
/// envelope: MLS wraps it, but the inner Ed25519 signature is what actually
/// authenticates the sender, because the MLS credential layer is accept-all.
#[derive(Debug, Clone)]
pub struct AppMessage {
    pub envelope: Vec<u8>,
    pub sender_index: u32,
}

impl RineMlsGroup {
    /// Encrypt a rine envelope into an `mls-v1` payload: the MLS PrivateMessage
    /// behind its `0x04` version tag. The transport base64url-encodes the
    /// result and sends it as `encrypted_payload`.
    ///
    /// Forward secrecy consumes the sender's ratchet step here, so MLS will
    /// never decrypt this message for this member again. The plaintext is
    /// therefore written to the local self-read cache before the payload is
    /// returned, which is what makes [`Self::decrypt_application_message`] able
    /// to answer for a message this member sent.
    ///
    /// A cache write that fails fails the send. It is the same directory the
    /// group state is about to be written to, so a disk that cannot hold the
    /// one cannot hold the other — and a send that quietly returns a payload
    /// its own sender will never be able to read back is exactly the silent
    /// failure this crate is built not to have.
    pub fn encrypt_application_message(&mut self, envelope: &[u8]) -> Result<Vec<u8>> {
        self.active()?;

        let message = self
            .inner
            .encrypt_application_message(envelope, Vec::new())?;

        let payload = frame::tag(&message.to_bytes()?);
        self.self_read
            .record(self.inner.group_id(), &payload, envelope)?;

        Ok(payload)
    }

    /// Decrypt an `mls-v1` payload — the base64url-decoded `encrypted_payload`,
    /// version tag included.
    ///
    /// Still allowed after an eviction, for the messages the member already
    /// held epoch secrets for: being removed ends participation, it does not
    /// retroactively unread an inbox.
    pub fn decrypt_application_message(&mut self, payload: &[u8]) -> Result<AppMessage> {
        let suite = self.cipher_suite()?;
        let message = wire::decode(
            frame::untag(payload)?,
            MlsBlobKind::ApplicationMessage,
            suite,
        )?;

        match self.inner.process_incoming_message(message) {
            Ok(ReceivedMessage::ApplicationMessage(app)) => Ok(AppMessage {
                envelope: app.data().to_vec(),
                sender_index: app.sender_index,
            }),
            Ok(_) => Err(RineMlsError::UnexpectedMessageContent {
                expected: MlsBlobKind::ApplicationMessage,
            }),
            // MLS names this case exactly, and names it before touching any
            // ratchet state, so the self-read fallback can be reached for the
            // one failure it answers and no other.
            Err(MlsError::CantProcessMessageFromSelf) => self.own_message(payload),
            Err(e) => Err(e.into()),
        }
    }

    /// A message this member sent. The plaintext comes from the self-read cache
    /// the encrypt call wrote; when the cache has aged it out, that is said in
    /// as many words rather than returned as a decryption failure the caller
    /// would go looking for a key problem behind.
    fn own_message(&self, payload: &[u8]) -> Result<AppMessage> {
        match self.self_read.lookup(self.inner.group_id(), payload)? {
            Some(envelope) => Ok(AppMessage {
                envelope,
                sender_index: self.inner.current_member_index(),
            }),
            None => Err(RineMlsError::SelfMessageNotCached),
        }
    }
}
