//! The value objects a group operation hands back.
//!
//! Both are plain JS objects owning buffers moved out of Rust, so nothing a
//! caller holds points into MLS state.

use napi::bindgen_prelude::Uint8Array;
use napi_derive::napi;
use rine_mls_core::{wire_epoch, RineMlsError};

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
