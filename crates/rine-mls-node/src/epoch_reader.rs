//! The org reader's side of the escrow: opens the application messages of one
//! `(group, epoch)` from its `EpochReadSecrets` plaintext.

use napi::bindgen_prelude::Uint8Array;
use napi_derive::napi;
use rine_mls_core::{EpochReader as CoreEpochReader, EscrowFault, PanicGuard};

use crate::error::{guard, MlsError};

/// An application message opened by an [`EpochReader`], its MLS framing
/// signature verified against the leaf key the escrow records.
/// `signerPublicKey` is the key the signature verified under: compare it with
/// the `mls` key chain-verified for the agent the envelope names.
#[napi(object)]
pub struct OpenedMessage {
    pub envelope: Uint8Array,
    pub sender_index: u32,
    pub signer_public_key: Uint8Array,
    pub generation: u32,
}

/// Opens the application messages of one `(group, epoch)` from the `MlsEscrow`
/// plaintext, as a party that was never a member.
///
/// The MLS framing signature is verified against the leaf key the escrow
/// records, so a message from a leaf the escrow does not know is refused. The
/// reader holds the sender-data secret and the secret-tree root and nothing that
/// can advance the group or sign.
///
/// Like every handle here it belongs to the thread that created it, and a panic
/// retires it (`RINE_MLS_POISONED`).
#[napi]
pub struct EpochReader {
    inner: CoreEpochReader,
    poison: PanicGuard,
}

/// A JS number is an epoch only when it is a non-negative safe integer, so napi's
/// silent truncation (1.9 to 1) and saturation never pick a different epoch.
fn exact_epoch(value: f64) -> Option<u64> {
    const MAX_SAFE: f64 = 9_007_199_254_740_991.0;
    (value.fract() == 0.0 && (0.0..=MAX_SAFE).contains(&value)).then_some(value as u64)
}

#[napi]
impl EpochReader {
    /// Build a reader from the plaintext of the escrow for `(groupId, epoch)`.
    /// The plaintext's own group context must name that group and epoch, or the
    /// call throws `RINE_MLS_INVALID_ESCROW`; so does an `epoch` that is negative,
    /// fractional or beyond the safe-integer range.
    #[napi(factory)]
    pub fn from_escrow(
        group_id: Uint8Array,
        epoch: f64,
        plaintext: Uint8Array,
    ) -> Result<Self, MlsError> {
        let mut poison = PanicGuard::default();
        let inner = guard(&mut poison, || {
            let epoch = exact_epoch(epoch).ok_or(EscrowFault::SlotMismatch)?;
            CoreEpochReader::from_escrow(&group_id, epoch, &plaintext)
        })?;

        Ok(Self { inner, poison })
    }

    /// Open one application message: the PrivateMessage bytes with the leading
    /// `0x04` `mls-v1` tag already stripped.
    ///
    /// Messages within 1024 generations behind a sender's ratchet open in any
    /// order; after a longer jump, open that sender's messages in ascending
    /// generation, because a message the reader has passed needs a reader
    /// rebuilt from the escrow. A message whose framing signature does not
    /// verify throws `RINE_MLS_MEMBER_REJECTED`; one naming a generation too far
    /// ahead of its sender's ratchet throws `RINE_MLS_GENERATION_TOO_FAR`.
    #[napi]
    pub fn open(&mut self, message: Uint8Array) -> Result<OpenedMessage, MlsError> {
        let inner = &mut self.inner;
        let opened = guard(&mut self.poison, || inner.open(&message))?;

        Ok(OpenedMessage {
            envelope: Uint8Array::new(opened.envelope),
            sender_index: opened.sender_index,
            signer_public_key: Uint8Array::new(opened.signer_public_key),
            generation: opened.generation,
        })
    }
}
