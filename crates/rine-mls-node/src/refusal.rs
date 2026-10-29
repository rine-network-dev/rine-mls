//! Which agent the last failed call on a handle was refused for.
//!
//! A call that fails because the allowed set refused a leaf raises
//! `RINE_MLS_PEER_NOT_ADMITTED`; this getter names the agent. It reads state the
//! guard recorded and runs nothing, so it is deliberately not behind `guard`
//! (which would clear what it is asked to read). Each handle has its own
//! `impl` block here so `client.rs` and `group.rs` do not grow.

use napi::bindgen_prelude::Uint8Array;
use napi_derive::napi;

use crate::client::MlsClient;
use crate::group::MlsGroup;

#[napi]
impl MlsClient {
    /// The agent id bytes of the leaf the allowed set refused in the last call
    /// on this handle, or `null` after any other outcome. Read it straight
    /// after the failing call.
    #[napi]
    pub fn refused_peer(&self) -> Option<Uint8Array> {
        self.poison
            .refused_peer()
            .map(|id| Uint8Array::new(id.to_vec()))
    }
}

#[napi]
impl MlsGroup {
    /// As [`MlsClient::refused_peer`], for the last call on this group handle.
    #[napi]
    pub fn refused_peer(&self) -> Option<Uint8Array> {
        self.poison
            .refused_peer()
            .map(|id| Uint8Array::new(id.to_vec()))
    }
}
