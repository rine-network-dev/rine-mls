//! Giving back the KeyPackage a dropped Welcome was sealed to, in its own
//! `impl` block so `client.rs` does not grow.

use napi::bindgen_prelude::Uint8Array;
use napi_derive::napi;

use crate::client::MlsClient;
use crate::error::{guard, MlsError};

#[napi]
impl MlsClient {
    /// For a Welcome that left the caller's spool without being opened: delete
    /// the KeyPackage private half it was sealed to, so the local count falls
    /// and the ordinary top-up republishes. `true` when exactly one of the
    /// Welcome's references named a half held here (now deleted); `false`,
    /// deleting nothing, when none or several did. Idempotent. A blob that is
    /// not a Welcome raises `RINE_MLS_UNEXPECTED_BLOB`. Never call it for a
    /// Welcome that was installed.
    #[napi]
    pub fn discard_welcome_key_package(&mut self, welcome: Uint8Array) -> Result<bool, MlsError> {
        let inner = &self.inner;
        guard(&mut self.poison, || {
            inner.discard_welcome_key_package(&welcome)
        })
    }
}
