// rine patch, described in PATCH.md: not part of upstream mls-rs 0.55.2.

use alloc::vec::Vec;
use core::fmt::{self, Debug};

use mls_rs_codec::{MlsDecode, MlsEncode, MlsSize};
use zeroize::Zeroizing;

use super::{epoch::EpochSecrets, key_schedule::KeySchedule, GroupContext};
use crate::{client::MlsError, tree_kem::TreeKemPublic};

/// The signature public key of one occupied leaf.
#[derive(Clone, Debug, PartialEq, MlsSize, MlsEncode, MlsDecode)]
struct LeafSignatureKey {
    leaf_index: u32,
    #[mls_codec(with = "mls_rs_codec::byte_vec")]
    key: Vec<u8>,
}

/// What a reader that is not a member needs to open every PrivateMessage of one
/// epoch and to check the framing signatures: the two secrets that decrypt, the
/// epoch's public context and leaf signature keys, and the epoch authenticator
/// (public to members) that tells two forks of an epoch apart.
///
/// Captured when an epoch is installed, before any message is processed, because
/// the secret tree consumes its root on the first leaf derivation. Holds neither
/// `epoch_secret`, `init_secret`, `exporter_secret`, `membership_key`,
/// `confirmation_key`, `resumption_secret` nor any private key, so it cannot
/// advance the group or sign anything.
#[derive(Clone, PartialEq, MlsSize, MlsEncode, MlsDecode)]
pub struct EpochReadSecrets {
    group_context: GroupContext,
    leaf_count: u32,
    #[mls_codec(with = "mls_rs_codec::byte_vec")]
    sender_data_secret: Zeroizing<Vec<u8>>,
    #[mls_codec(with = "mls_rs_codec::byte_vec")]
    encryption_secret: Zeroizing<Vec<u8>>,
    #[mls_codec(with = "mls_rs_codec::byte_vec")]
    epoch_authenticator: Zeroizing<Vec<u8>>,
    leaf_signature_keys: Vec<LeafSignatureKey>,
}

impl Debug for EpochReadSecrets {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("EpochReadSecrets")
            .field("epoch", &self.group_context.epoch)
            .finish()
    }
}

impl EpochReadSecrets {
    /// Called at every place a group assigns `epoch_secrets`, with the state of the epoch being
    /// installed and before the install changes anything.
    ///
    /// `Ok(None)` for the placeholder epoch of an external committer, whose
    /// secret tree is empty; its real epoch is exported when its commit applies.
    /// An error if the root of a real tree was already consumed.
    pub(crate) fn capture(
        key_schedule: &KeySchedule,
        secrets: &EpochSecrets,
        context: &GroupContext,
        tree: &TreeKemPublic,
    ) -> Result<Option<Self>, MlsError> {
        if secrets.secret_tree.is_placeholder() {
            return Ok(None);
        }

        let root = secrets
            .secret_tree
            .unconsumed_root()
            .ok_or(MlsError::EpochReadSecretsConsumed)?;

        Ok(Some(Self {
            group_context: context.clone(),
            leaf_count: *secrets.secret_tree.leaf_count(),
            sender_data_secret: Zeroizing::new(secrets.sender_data_secret.to_vec()),
            encryption_secret: Zeroizing::new(root.to_vec()),
            epoch_authenticator: key_schedule.authentication_secret.clone(),
            leaf_signature_keys: tree
                .non_empty_leaves()
                .map(|(index, leaf)| LeafSignatureKey {
                    leaf_index: *index,
                    key: leaf.signing_identity.signature_key.to_vec(),
                })
                .collect(),
        }))
    }

    pub fn group_context(&self) -> &GroupContext {
        &self.group_context
    }

    /// Leaves in the ratchet tree at this epoch, empty ones included.
    pub fn leaf_count(&self) -> u32 {
        self.leaf_count
    }

    pub fn sender_data_secret(&self) -> &[u8] {
        &self.sender_data_secret
    }

    /// The secret-tree root.
    pub fn encryption_secret(&self) -> &[u8] {
        &self.encryption_secret
    }

    pub fn epoch_authenticator(&self) -> &[u8] {
        &self.epoch_authenticator
    }

    /// `(leaf index, signature public key)` of every non-empty leaf.
    pub fn leaf_signature_keys(&self) -> impl Iterator<Item = (u32, &[u8])> {
        self.leaf_signature_keys
            .iter()
            .map(|leaf| (leaf.leaf_index, leaf.key.as_slice()))
    }
}

/// The most untaken exports a group keeps. Each holds an epoch's unconsumed
/// `encryption_secret`, so the cap bounds how many epochs sit readable in the
/// stored snapshot while the caller cannot seal them. 32 is the number of
/// Welcomes one commit may carry, far above the one export per installed epoch
/// a drain normally leaves.
pub const MAX_QUEUED_EPOCH_READ_EXPORTS: usize = 32;

/// The most discarded epochs a group remembers. Past it the oldest record is
/// forgotten, so a deferral that never ends cannot grow the snapshot without
/// bound; the epoch still has no escrow, which every reader reports as missing.
pub const MAX_DROPPED_EPOCH_READ_EPOCHS: usize = 1024;

/// Exports captured since the last [`Group::take_epoch_read_exports`], persisted
/// in their own section of the group snapshot so a crash between install and
/// take loses nothing. A snapshot written before this section existed decodes as
/// empty.
///
/// At most [`MAX_QUEUED_EPOCH_READ_EXPORTS`] are kept: the oldest is discarded
/// when a new one arrives past the cap, and only its epoch is remembered
/// (`dropped`, itself capped at [`MAX_DROPPED_EPOCH_READ_EPOCHS`]), so the caller
/// can still record that the epoch was lost. A snapshot written before `dropped`
/// existed decodes with none.
///
/// [`Group::take_epoch_read_exports`]: super::Group::take_epoch_read_exports
#[derive(Clone, Debug, Default, PartialEq, MlsSize, MlsEncode)]
pub(crate) struct EpochReadExports {
    queued: Vec<EpochReadSecrets>,
    dropped: Vec<u64>,
}

impl MlsDecode for EpochReadExports {
    fn mls_decode(reader: &mut &[u8]) -> Result<Self, mls_rs_codec::Error> {
        if reader.is_empty() {
            return Ok(Self::default());
        }

        let queued = Vec::mls_decode(reader)?;
        let dropped = if reader.is_empty() {
            Vec::new()
        } else {
            Vec::mls_decode(reader)?
        };

        Ok(Self { queued, dropped })
    }
}

impl EpochReadExports {
    /// Queues the export captured for an epoch. Call it only once the epoch is installed:
    /// [`EpochReadSecrets::capture`] first, then every fallible step of the install, then
    /// this, so a failed install leaves nothing queued.
    pub(crate) fn push(&mut self, export: Option<EpochReadSecrets>) {
        let Some(export) = export else { return };

        if self.queued.len() >= MAX_QUEUED_EPOCH_READ_EXPORTS {
            let oldest = self.queued.remove(0);

            if self.dropped.len() >= MAX_DROPPED_EPOCH_READ_EPOCHS {
                self.dropped.remove(0);
            }

            self.dropped.push(oldest.group_context().epoch);
        }

        self.queued.push(export);
    }

    pub(crate) fn take(&mut self) -> (Vec<EpochReadSecrets>, Vec<u64>) {
        (
            core::mem::take(&mut self.queued),
            core::mem::take(&mut self.dropped),
        )
    }

    /// `(queued, dropped)` counts, without taking.
    pub(crate) fn backlog(&self) -> (usize, usize) {
        (self.queued.len(), self.dropped.len())
    }
}
