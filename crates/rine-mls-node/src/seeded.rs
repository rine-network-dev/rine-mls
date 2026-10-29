//! Seeded post-quantum key derivation, for the org-root tree.
//!
//! The derivations and their rationale live in [`rine_mls_core::mlkem`] and
//! [`rine_mls_core::mldsa`]; this file is only the Node boundary.

use napi::bindgen_prelude::Uint8Array;
use napi_derive::napi;
use rine_mls_core::{mldsa, mlkem};

use crate::error::{from_core, MlsError};

/// An ML-KEM-768 key pair, both halves as raw FIPS 203 encodings.
#[napi(object)]
pub struct MlKemKeyPair {
    /// The 1184-byte encapsulation key, the half that is published.
    pub public_key: Uint8Array,
    /// The 2400-byte expanded decapsulation key, the half that stays local.
    pub private_key: Uint8Array,
}

/// The ML-KEM-768 key pair the 64-byte `d‖z` seed generates, `d` first (the
/// ACVP layout). The same seed always yields the same pair; the private key is
/// the 2400-byte expanded form the rest of the ML-KEM surface takes.
#[napi]
pub fn ml_kem768_key_pair_from_seed(seed: Uint8Array) -> Result<MlKemKeyPair, MlsError> {
    let (private, public) = mlkem::key_pair_from_seed(&seed).map_err(|e| from_core(e.into()))?;

    Ok(MlKemKeyPair {
        public_key: Uint8Array::new(public.to_vec()),
        private_key: Uint8Array::new(private.to_vec()),
    })
}

/// The 1952-byte ML-DSA-65 public key the 32-byte seed `xi` generates.
#[napi]
pub fn ml_dsa65_public_key_from_seed(seed: Uint8Array) -> Result<Uint8Array, MlsError> {
    let public = mldsa::public_key_from_seed(&seed).map_err(|e| from_core(e.into()))?;

    Ok(Uint8Array::new(public.to_vec()))
}
