//! Giving back the KeyPackage a dropped Welcome was sealed to, in its own
//! `pymethods` block so `client.rs` does not grow.

use pyo3::prelude::*;

use crate::client::MlsClient;
use crate::error::guard;

#[pymethods]
impl MlsClient {
    /// For a Welcome that left the caller's spool without being opened: delete
    /// the KeyPackage private half it was sealed to, so the local count falls
    /// and the ordinary top-up republishes. ``True`` when exactly one of the
    /// Welcome's references named a half held here (now deleted); ``False``,
    /// deleting nothing, when none or several did. Idempotent. A blob that is
    /// not a Welcome raises ``UnexpectedBlobError``. Never call it for a
    /// Welcome that was installed.
    fn discard_welcome_key_package(&mut self, welcome: &[u8]) -> PyResult<bool> {
        let inner = &self.inner;
        guard(&mut self.poison, || {
            inner.discard_welcome_key_package(welcome)
        })
    }
}
