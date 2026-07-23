//! The deployment knobs a client is opened with, and the copy-out helper the
//! calls that return several blobs share.
//!
//! The napi binding's `MlsClientOptions` is an options object because that is
//! the JavaScript idiom; here the same knob is a keyword argument, because that
//! is the Python one. The knob itself, its name and its meaning are the same.

use pyo3::prelude::*;
use pyo3::types::PyBytes;
use rine_mls_core::{EpochRetention, Result as CoreResult, RineMlsOptions};

/// Build the core's options from the keyword form Python passes.
///
/// `epoch_retention_limit` is how many prior epochs a group keeps secrets for.
/// `None` keeps the full backlog, so anything the server's undelivered queue can
/// still be holding stays decryptable; a number trades that reach for a narrower
/// forward-secrecy window. `0` is refused — it would not tighten anything, it
/// would break the group.
pub(crate) fn client_options(epoch_retention_limit: Option<usize>) -> CoreResult<RineMlsOptions> {
    Ok(RineMlsOptions {
        epoch_retention: EpochRetention::from_limit(epoch_retention_limit)?,
    })
}

/// Copy Rust-owned blobs out as a list of `bytes`.
pub(crate) fn to_bytes(py: Python<'_>, blobs: Vec<Vec<u8>>) -> Vec<Bound<'_, PyBytes>> {
    blobs.iter().map(|b| PyBytes::new(py, b)).collect()
}
