//! Per-epoch read escrow: what a group exports each time it enters an epoch so
//! the org can later read that epoch's messages, and the reader that
//! does the reading.
//!
//! The exports are captured by the vendored mls-rs when an epoch is
//! *installed* (create, join, applied own commit, received commit), never when
//! its secrets are merely derived, so a refused commit or a cleared pending
//! commit exports nothing.

mod gap;
mod plaintext;
mod reader;

pub use gap::{EscrowBacklog, EscrowGap, EscrowGapReason, EscrowTake};
pub use mls_rs::group::{MAX_DROPPED_EPOCH_READ_EPOCHS, MAX_QUEUED_EPOCH_READ_EXPORTS};
pub use plaintext::{MAX_CONTEXT_LEN, MAX_LEAVES};
pub use reader::{EpochReader, OpenedMessage};

use mls_rs::error::MlsError;
use mls_rs_core::crypto::CipherSuiteProvider;
use mls_rs_core::error::IntoAnyError;
use zeroize::Zeroizing;

use crate::crypto::RineCipherSuiteProvider;
use crate::error::Result;
use crate::suite::RineCipherSuite;

use super::RineMlsGroup;

/// Bytes of the fork fingerprint, the first half of a SHA-256.
pub const FINGERPRINT_LEN: usize = 16;

const FINGERPRINT_DOMAIN: &[u8] = b"rine.v1.mls-escrow-fp\0";

/// An epoch and its fork fingerprint.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EpochFingerprint {
    pub epoch: u64,
    pub fp: [u8; FINGERPRINT_LEN],
}

/// One epoch's escrow, ready to seal. `plaintext` is the `EpochReadSecrets` v1
/// layout and is zeroized when dropped.
pub struct EscrowExport {
    pub epoch: u64,
    /// `SHA-256("rine.v1.mls-escrow-fp" || 0x00 || epoch_authenticator)[0..16]`:
    /// two members on different forks of an epoch produce different values.
    pub fp: [u8; FINGERPRINT_LEN],
    pub plaintext: Zeroizing<Vec<u8>>,
}

impl RineMlsGroup {
    /// Every epoch this group installed since the last take, oldest first.
    ///
    /// Taking empties the in-memory list, but the stored snapshot keeps the
    /// exports until the next [`Self::save`], so a crash between this call and
    /// that save yields them again on the next load. Call this, seal and
    /// persist the results, and only then save.
    ///
    /// One epoch that cannot be escrowed never fails the take for the others:
    /// an export that cannot be encoded or fingerprinted (a group context or
    /// tree over the escrow limits), and an export discarded past
    /// [`MAX_QUEUED_EPOCH_READ_EXPORTS`], come back as an [`EscrowGap`] instead.
    /// Record the gaps beside the sealed files before saving, exactly like the
    /// exports: once saved, nothing else remembers them.
    pub fn take_escrow_exports(&mut self) -> Result<EscrowTake> {
        let suite = self.cipher_suite()?;
        let group_id = self.group_id();
        let (secrets, dropped) = self.inner.take_epoch_read_exports();

        let mut gaps: Vec<EscrowGap> = dropped
            .into_iter()
            .map(|epoch| EscrowGap {
                group_id: group_id.clone(),
                epoch,
                reason: EscrowGapReason::QueueOverflow,
                fp: None,
            })
            .collect();
        let mut exports = Vec::with_capacity(secrets.len());

        for secrets in &secrets {
            let epoch = secrets.group_context().epoch;

            let fp = fingerprint(secrets.epoch_authenticator()).ok();
            let export = match (fp, plaintext::encode(suite, secrets)) {
                (Some(fp), Ok(plaintext)) => Ok(EscrowExport {
                    epoch,
                    fp,
                    plaintext,
                }),
                (_, Err(fault)) => Err(EscrowGapReason::from(fault)),
                (None, Ok(_)) => Err(EscrowGapReason::Malformed),
            };

            match export {
                Ok(export) => exports.push(export),
                Err(reason) => gaps.push(EscrowGap {
                    group_id: group_id.clone(),
                    epoch,
                    reason,
                    fp,
                }),
            }
        }

        Ok(EscrowTake { exports, gaps })
    }

    /// The fork fingerprint of the group's CURRENT epoch: the value an export of
    /// this epoch carries as its `fp`, read without taking anything.
    ///
    /// Two members on different forks of the same epoch read different values,
    /// so a client can tell which fork's escrow marker speaks for this group.
    /// The fingerprint is a hash of the epoch authenticator and reveals none of
    /// it.
    pub fn epoch_fingerprint(&self) -> Result<[u8; FINGERPRINT_LEN]> {
        let authenticator = self.inner.epoch_authenticator()?;

        fingerprint(&authenticator)
    }

    /// The `(epoch, fork fingerprint)` of every export a take would return now,
    /// oldest first, without taking anything.
    ///
    /// The exports are taken from a copy of the group, which is dropped (and
    /// its secrets zeroized) before this returns, so the backlog is unchanged
    /// and no secret leaves the core. A client parks a snapshot it may later
    /// fail to read; recording these first lets it file the epochs it gives up
    /// under their own fork.
    pub fn queued_escrow_fingerprints(&self) -> Result<Vec<EpochFingerprint>> {
        let (secrets, _) = self.inner.clone().take_epoch_read_exports();

        secrets
            .iter()
            .map(|secrets| {
                Ok(EpochFingerprint {
                    epoch: secrets.group_context().epoch,
                    fp: fingerprint(secrets.epoch_authenticator())?,
                })
            })
            .collect()
    }

    /// What the next [`Self::take_escrow_exports`] will return, without taking it.
    pub fn escrow_backlog(&self) -> EscrowBacklog {
        let (queued, dropped) = self.inner.epoch_read_backlog();

        EscrowBacklog { queued, dropped }
    }
}

/// The fork fingerprint of an epoch, from its `epoch_authenticator`.
pub fn fingerprint(epoch_authenticator: &[u8]) -> Result<[u8; FINGERPRINT_LEN]> {
    let provider = RineCipherSuiteProvider::for_suite(RineCipherSuite::DEFAULT)?;
    let input = Zeroizing::new([FINGERPRINT_DOMAIN, epoch_authenticator].concat());
    let digest = provider
        .hash(&input)
        .map_err(|error| MlsError::CryptoProviderError(error.into_any_error()))?;

    Ok(digest[..FINGERPRINT_LEN]
        .try_into()
        .expect("SHA-256 is longer than the fingerprint"))
}
