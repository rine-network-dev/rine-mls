//! The org reader's side of the escrow: opens the PrivateMessages of one epoch
//! from its `EpochReadSecrets` v1 plaintext, as a party that was never a member.

use mls_rs::group::{EpochReadError, EpochReader as MlsEpochReader};

use crate::crypto::RineCipherSuiteProvider;
use crate::error::{EscrowFault, MlsBlobKind, Result, RineMlsError};
use crate::suite::RineCipherSuite;
use crate::wire;

use super::plaintext;

/// An application message opened by an [`EpochReader`], its MLS framing
/// signature verified against the leaf key the escrow records.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OpenedMessage {
    /// The signed rine envelope.
    pub envelope: Vec<u8>,
    pub sender_index: u32,
    /// The leaf signature key the escrow records for `sender_index`, which the
    /// framing signature verified under. The caller binds the sender to an agent
    /// by comparing it with the `mls` key chain-verified for that agent.
    pub signer_public_key: Vec<u8>,
    /// The sender's ratchet generation: with `sender_index` it identifies the
    /// message within its epoch, for duplicate detection.
    pub generation: u32,
}

/// Opens the application messages of one `(group, epoch)`.
///
/// It runs the member decrypt path (`CiphertextProcessor::open` and the same
/// framing-signature verification) over the escrowed secrets, with a leaf index
/// no real leaf has, so a message from any sender, leaf 0 included, opens. It
/// holds the sender-data secret and the secret-tree root and nothing that can
/// advance the group or sign.
///
/// Within the 1024 generations behind a sender's ratchet, messages open in any
/// order. A jump further ahead drops the keys it steps over, so open each
/// sender's messages in ascending generation; a message the reader has passed
/// needs a reader rebuilt from the escrow. A jump of more than
/// [`mls_rs::group::MAX_READER_SKIP`] past that window is refused with
/// [`RineMlsError::GenerationTooFar`].
pub struct EpochReader {
    inner: MlsEpochReader<RineCipherSuiteProvider>,
    suite: RineCipherSuite,
}

impl EpochReader {
    /// Build a reader from the plaintext of the escrow for `(group_id, epoch)`.
    ///
    /// The plaintext's own group context must name that group and epoch: an
    /// escrow sealed for one slot but carrying another epoch's secrets is
    /// refused here rather than failing every message later.
    pub fn from_escrow(group_id: &[u8], epoch: u64, plaintext: &[u8]) -> Result<Self> {
        let suite = RineCipherSuite::DEFAULT;
        let parsed = plaintext::parse(suite, plaintext)?;

        if parsed.group_context.group_id != group_id || parsed.group_context.epoch != epoch {
            return Err(EscrowFault::SlotMismatch.into());
        }

        let provider = RineCipherSuiteProvider::for_suite(suite)?;
        let inner = MlsEpochReader::new(
            provider,
            parsed.group_context,
            parsed.leaf_count,
            &parsed.sender_data_secret,
            &parsed.encryption_secret,
            parsed.leaf_signature_keys,
        );

        Ok(Self { inner, suite })
    }

    /// Open one application message: the PrivateMessage bytes, with the `mls-v1`
    /// version tag already stripped.
    pub fn open(&mut self, message: &[u8]) -> Result<OpenedMessage> {
        let message = wire::decode(message, MlsBlobKind::ApplicationMessage, self.suite)?;

        match self.inner.open(&message) {
            Ok(opened) => Ok(OpenedMessage {
                envelope: opened.application_data,
                sender_index: opened.sender,
                signer_public_key: opened.signer_public_key,
                generation: opened.generation,
            }),
            Err(EpochReadError::Rejected { sender, generation }) => {
                Err(RineMlsError::MemberRejected { sender, generation })
            }
            Err(EpochReadError::GenerationTooFar { generation }) => {
                Err(RineMlsError::GenerationTooFar { generation })
            }
            Err(EpochReadError::Mls(error)) => Err(error.into()),
        }
    }
}
