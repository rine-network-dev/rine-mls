//! The epochs a group could not hand over as an escrow, and why.

use crate::error::EscrowFault;

/// Why an installed epoch has no escrow export.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EscrowGapReason {
    /// The epoch's group context encodes to more than `MAX_CONTEXT_LEN` bytes.
    ContextTooLarge,
    /// The epoch's tree holds more occupied leaves than `MAX_LEAVES`.
    TooManyLeaves,
    /// The epoch's secrets or leaf keys have a length the plaintext cannot carry.
    Malformed,
    /// More than `MAX_QUEUED_EPOCH_READ_EXPORTS` exports were waiting, so this
    /// epoch's was discarded unread.
    QueueOverflow,
}

impl From<EscrowFault> for EscrowGapReason {
    fn from(fault: EscrowFault) -> Self {
        match fault {
            EscrowFault::ContextTooLarge { .. } => Self::ContextTooLarge,
            EscrowFault::TooManyLeaves { .. } => Self::TooManyLeaves,
            _ => Self::Malformed,
        }
    }
}

/// An installed epoch that has no escrow: the group, the epoch, and the reason.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EscrowGap {
    pub group_id: Vec<u8>,
    pub epoch: u64,
    pub reason: EscrowGapReason,
    /// The fork fingerprint of the epoch that has no escrow, when the epoch's
    /// secrets reached the take. `None` for a discarded export, which keeps only
    /// its epoch number, and for an epoch whose fingerprint could not be
    /// computed.
    pub fp: Option<[u8; super::FINGERPRINT_LEN]>,
}

/// What a take yields: an export per epoch that could be encoded, a gap per
/// epoch that could not, in no particular order between the two lists.
pub struct EscrowTake {
    pub exports: Vec<super::EscrowExport>,
    pub gaps: Vec<EscrowGap>,
}

/// What a group is holding for the next take.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EscrowBacklog {
    /// Exports waiting to be taken.
    pub queued: usize,
    /// Epochs already discarded past the cap.
    pub dropped: usize,
}
