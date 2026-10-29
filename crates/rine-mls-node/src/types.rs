//! The value objects a group operation hands back.
//!
//! Both are plain JS objects owning buffers moved out of Rust, so nothing a
//! caller holds points into MLS state.

use napi::bindgen_prelude::Uint8Array;
use napi_derive::napi;
use rine_mls_core::{wire_epoch, MemberLeaf, RineMlsError};

/// Everything one commit produces. `welcomes` is one entry per member added by
/// this commit, in add order, which is what `POST /groups/{id}/mls/commit`
/// wants as `welcomes: [{agent_id, welcome}]`.
#[napi(object)]
pub struct CommitBundle {
    pub commit: Uint8Array,
    pub welcomes: Vec<Uint8Array>,
    pub group_info: Uint8Array,
    pub epoch: i64,
}

/// A decrypted `mls-v1` message: the signed rine envelope MLS was carrying, and
/// the leaf that sent it.
#[napi(object)]
pub struct AppMessage {
    pub envelope: Uint8Array,
    pub sender_index: u32,
}

/// One occupied leaf of the ratchet tree: where it sits, whose it is, and the
/// key it signs with. `identity` is the member's agent id bytes — the
/// basic-credential identity, the value `MlsClient.agentId()` returns and
/// `MlsGroup.memberIndex` takes. `signatureKey` is the raw 32-byte leaf
/// signature key, the `mls` field of the agent's certificate.
#[napi(object)]
pub struct MemberIdentity {
    pub index: u32,
    pub identity: Uint8Array,
    pub signature_key: Uint8Array,
}

/// One epoch's escrow, ready to seal: the epoch it belongs to, the fork
/// fingerprint, and the `EpochReadSecrets` v1 plaintext.
#[napi(object)]
pub struct EscrowExport {
    pub epoch: i64,
    /// `SHA-256("rine.v1.mls-escrow-fp" || 0x00 || epoch_authenticator)[0..16]`:
    /// two members on different forks of an epoch produce different values.
    pub fp: Uint8Array,
    pub plaintext: Uint8Array,
}

/// Why an installed epoch has no escrow export. The values are the snake_case
/// names the client files its gap markers under.
#[napi(string_enum = "snake_case")]
pub enum EscrowGapReason {
    /// The epoch's group context is over the escrow size limit.
    ContextTooLarge,
    /// The epoch's tree holds more occupied leaves than an escrow can carry.
    TooManyLeaves,
    /// The epoch's secrets or leaf keys have a length the plaintext cannot carry.
    Malformed,
    /// More exports were waiting than the group keeps, so this epoch's was
    /// discarded unread.
    QueueOverflow,
}

/// An installed epoch that has no escrow: nothing can be sealed for it.
#[napi(object)]
pub struct EscrowGap {
    pub group_id: Uint8Array,
    pub epoch: i64,
    pub reason: EscrowGapReason,
    /// The fork fingerprint of the epoch, when its secrets reached the take.
    /// Absent for an export discarded past the cap and for an epoch whose
    /// fingerprint could not be computed.
    pub fp: Option<Uint8Array>,
}

/// An epoch and its fork fingerprint.
#[napi(object)]
pub struct EpochFingerprint {
    pub epoch: i64,
    pub fp: Uint8Array,
}

/// What one take yields: an export for every epoch that could be encoded and a
/// gap for every one that could not.
#[napi(object)]
pub struct EscrowTake {
    pub exports: Vec<EscrowExport>,
    pub gaps: Vec<EscrowGap>,
}

/// What a group holds for the next take: exports waiting, and epochs already
/// discarded past the group's cap.
#[napi(object)]
pub struct EscrowBacklog {
    pub queued: u32,
    pub dropped: u32,
}

/// Move the core's leaves out to JS.
pub(crate) fn into_members(members: Vec<MemberLeaf>) -> Vec<MemberIdentity> {
    members
        .into_iter()
        .map(|leaf| MemberIdentity {
            index: leaf.index,
            identity: Uint8Array::new(leaf.identity),
            signature_key: Uint8Array::new(leaf.signature_key),
        })
        .collect()
}

/// Copy JS-owned buffers into Rust for the duration of a call.
pub(crate) fn to_vecs(arrays: &[Uint8Array]) -> Vec<Vec<u8>> {
    arrays.iter().map(|a| a.to_vec()).collect()
}

/// Move Rust-owned buffers out to JS.
pub(crate) fn into_arrays(blobs: Vec<Vec<u8>>) -> Vec<Uint8Array> {
    blobs.into_iter().map(Uint8Array::new).collect()
}

pub(crate) fn convert_bundle(
    bundle: rine_mls_core::CommitBundle,
) -> Result<CommitBundle, RineMlsError> {
    Ok(CommitBundle {
        commit: Uint8Array::new(bundle.commit),
        welcomes: bundle.welcomes.into_iter().map(Uint8Array::new).collect(),
        group_info: Uint8Array::new(bundle.group_info),
        epoch: wire_epoch(bundle.epoch)?,
    })
}

pub(crate) fn convert_export(
    export: rine_mls_core::EscrowExport,
) -> Result<EscrowExport, RineMlsError> {
    Ok(EscrowExport {
        epoch: wire_epoch(export.epoch)?,
        fp: Uint8Array::new(export.fp.to_vec()),
        plaintext: Uint8Array::new(export.plaintext.to_vec()),
    })
}

fn convert_reason(reason: rine_mls_core::EscrowGapReason) -> EscrowGapReason {
    use rine_mls_core::EscrowGapReason as Core;

    match reason {
        Core::ContextTooLarge => EscrowGapReason::ContextTooLarge,
        Core::TooManyLeaves => EscrowGapReason::TooManyLeaves,
        Core::Malformed => EscrowGapReason::Malformed,
        Core::QueueOverflow => EscrowGapReason::QueueOverflow,
    }
}

pub(crate) fn convert_take(take: rine_mls_core::EscrowTake) -> Result<EscrowTake, RineMlsError> {
    Ok(EscrowTake {
        exports: take
            .exports
            .into_iter()
            .map(convert_export)
            .collect::<Result<_, _>>()?,
        gaps: take
            .gaps
            .into_iter()
            .map(|gap| {
                Ok(EscrowGap {
                    group_id: Uint8Array::new(gap.group_id),
                    epoch: wire_epoch(gap.epoch)?,
                    reason: convert_reason(gap.reason),
                    fp: gap.fp.map(|fp| Uint8Array::new(fp.to_vec())),
                })
            })
            .collect::<Result<_, RineMlsError>>()?,
    })
}

pub(crate) fn convert_backlog(backlog: rine_mls_core::EscrowBacklog) -> EscrowBacklog {
    EscrowBacklog {
        queued: u32::try_from(backlog.queued).unwrap_or(u32::MAX),
        dropped: u32::try_from(backlog.dropped).unwrap_or(u32::MAX),
    }
}

pub(crate) fn convert_fingerprints(
    queued: Vec<rine_mls_core::EpochFingerprint>,
) -> Result<Vec<EpochFingerprint>, RineMlsError> {
    queued
        .into_iter()
        .map(|queued| {
            Ok(EpochFingerprint {
                epoch: wire_epoch(queued.epoch)?,
                fp: Uint8Array::new(queued.fp.to_vec()),
            })
        })
        .collect()
}
