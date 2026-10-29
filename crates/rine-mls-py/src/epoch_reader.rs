use pyo3::prelude::*;
use rine_mls_core::{EpochReader as CoreEpochReader, PanicGuard};

use crate::error::guard;
use crate::types::OpenedMessage;

/// Opens the application messages of one ``(group, epoch)`` from the
/// ``MlsEscrow`` plaintext, as a party that was never a member.
///
/// The MLS framing signature is verified against the leaf key the escrow
/// records, so a message from a leaf the escrow does not know is refused. The
/// reader holds the sender-data secret and the secret-tree root and nothing that
/// can advance the group or sign.
///
/// The Node binding carries the same class: the organisation reader in
/// `rine-core` opens escrowed messages through it. It holds only per-epoch read
/// secrets, so it adds no way to advance a group or sign.
#[pyclass(module = "rine_mls")]
pub struct EpochReader {
    inner: CoreEpochReader,
    poison: PanicGuard,
}

#[pymethods]
impl EpochReader {
    /// Build a reader from the plaintext of the escrow for ``(group_id,
    /// epoch)``. The plaintext's own group context must name that group and
    /// epoch, or the call raises ``InvalidEscrowError``.
    #[staticmethod]
    fn from_escrow(group_id: &[u8], epoch: u64, plaintext: &[u8]) -> PyResult<Self> {
        let mut poison = PanicGuard::default();
        let inner = guard(&mut poison, || {
            CoreEpochReader::from_escrow(group_id, epoch, plaintext)
        })?;

        Ok(Self { inner, poison })
    }

    /// Open one application message: the PrivateMessage bytes with the leading
    /// ``0x04`` ``mls-v1`` tag already stripped.
    ///
    /// Messages within 1024 generations behind a sender's ratchet open in any
    /// order; after a longer jump, open that sender's messages in ascending
    /// generation, because a message the reader has passed needs a reader
    /// rebuilt from the escrow. A message whose framing signature does not
    /// verify raises ``MemberRejectedError``; one naming a generation too far
    /// ahead of its sender's ratchet raises ``GenerationTooFarError``.
    ///
    /// ``signer_public_key`` is the leaf key the signature verified under: compare
    /// it with the ``mls`` key chain-verified for the agent the envelope names.
    fn open(&mut self, message: &[u8]) -> PyResult<OpenedMessage> {
        let inner = &mut self.inner;
        let opened = guard(&mut self.poison, || inner.open(message))?;

        Ok(OpenedMessage {
            envelope: opened.envelope,
            sender_index: opened.sender_index,
            signer_public_key: opened.signer_public_key,
            generation: opened.generation,
        })
    }
}
