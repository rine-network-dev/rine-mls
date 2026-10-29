//! Reading the leaf key off a KeyPackage, for the claim check.

use napi::bindgen_prelude::Uint8Array;
use napi_derive::napi;

use crate::error::{from_core, MlsError};

/// The leaf signature key a KeyPackage carries, as the raw 32 bytes. The caller
/// compares it with the key it chain-verified for the agent that published the
/// KeyPackage. The KeyPackage's own signature is checked when an Add is built,
/// not here.
#[napi]
pub fn key_package_signature_key(key_package: Uint8Array) -> Result<Uint8Array, MlsError> {
    rine_mls_core::key_package_signature_key(&key_package)
        .map(Uint8Array::new)
        .map_err(from_core)
}
