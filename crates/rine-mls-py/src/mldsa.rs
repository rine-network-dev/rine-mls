//! ML-DSA-65 public keys from a seed, for the Python SDK's org-root tree.
//!
//! The derivation and its rationale live in [`rine_mls_core::mldsa`]; this file
//! is only the Python boundary.
//!
//! Bytes in, `bytes` out, copied at the boundary like the rest of this binding.

use pyo3::prelude::*;
use pyo3::types::PyBytes;
use rine_mls_core::mldsa;

use crate::error::from_core;

/// The 1952-byte ML-DSA-65 public key the 32-byte seed ``xi`` generates. The
/// same seed always yields the same key, and the encoding is FIPS 204's, so it
/// matches what every other rine stack derives from that seed.
#[pyfunction]
fn ml_dsa65_public_key_from_seed<'py>(
    py: Python<'py>,
    seed: &[u8],
) -> PyResult<Bound<'py, PyBytes>> {
    let public_key = mldsa::public_key_from_seed(seed).map_err(|e| from_core(e.into()))?;

    Ok(PyBytes::new(py, &public_key))
}

pub fn register(m: &Bound<'_, PyModule>) -> PyResult<()> {
    // Sizes are read off the core, like every other constant this binding
    // exports, so the SDK's length checks cannot drift from the implementation.
    m.add("ML_DSA65_SEED_SIZE", mldsa::SEED_SIZE)?;
    m.add("ML_DSA65_PUBLIC_KEY_SIZE", mldsa::PUBLIC_KEY_SIZE)?;
    m.add_function(wrap_pyfunction!(ml_dsa65_public_key_from_seed, m)?)
}
