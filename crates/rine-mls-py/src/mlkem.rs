//! Raw ML-KEM-768 for the Python SDK's `hpke-hybrid-v1` DM envelope.
//!
//! The only part of this wheel that is not MLS. It is here so the Python SDK
//! has the same post-quantum implementation the group path runs on rather than
//! a second one of its own — `cryptography` ships no ML-KEM at all, so without
//! it a Python agent could not read a post-quantum DM from any other rine
//! stack.
//!
//! Everything is bytes in, `bytes` out, copied at the boundary like the rest of
//! this binding. The wire format the four functions feed — the envelope layout,
//! the HKDF combiner, the AAD — belongs to the SDK, not here.

use pyo3::prelude::*;
use pyo3::types::PyBytes;
use rine_mls_core::mlkem;

use crate::error::from_core;

/// Mint a key pair, returned as `(public_key, private_key)` — publication order,
/// which is the order the SDK stores them in.
#[pyfunction]
fn ml_kem768_generate_key_pair(py: Python<'_>) -> PyResult<(Py<PyBytes>, Py<PyBytes>)> {
    let (private_key, public_key) = mlkem::generate_key_pair().map_err(|e| from_core(e.into()))?;

    Ok((
        PyBytes::new(py, &public_key).unbind(),
        PyBytes::new(py, private_key.as_slice()).unbind(),
    ))
}

#[pyfunction]
fn ml_kem768_public_key<'py>(py: Python<'py>, private_key: &[u8]) -> PyResult<Bound<'py, PyBytes>> {
    let public_key = mlkem::public_key(private_key).map_err(|e| from_core(e.into()))?;

    Ok(PyBytes::new(py, &public_key))
}

#[pyfunction]
fn ml_kem768_encapsulate(
    py: Python<'_>,
    public_key: &[u8],
) -> PyResult<(Py<PyBytes>, Py<PyBytes>)> {
    let (ciphertext, shared_secret) =
        mlkem::encapsulate(public_key).map_err(|e| from_core(e.into()))?;

    Ok((
        PyBytes::new(py, &ciphertext).unbind(),
        PyBytes::new(py, shared_secret.as_slice()).unbind(),
    ))
}

#[pyfunction]
fn ml_kem768_decapsulate<'py>(
    py: Python<'py>,
    ciphertext: &[u8],
    private_key: &[u8],
) -> PyResult<Bound<'py, PyBytes>> {
    let shared_secret =
        mlkem::decapsulate(ciphertext, private_key).map_err(|e| from_core(e.into()))?;

    Ok(PyBytes::new(py, shared_secret.as_slice()))
}

pub fn register(m: &Bound<'_, PyModule>) -> PyResult<()> {
    // Sizes are read off the core, like every other constant this module
    // exports, so the SDK's length checks cannot drift from the implementation.
    m.add("ML_KEM768_PUBLIC_KEY_SIZE", mlkem::PUBLIC_KEY_SIZE)?;
    m.add("ML_KEM768_PRIVATE_KEY_SIZE", mlkem::PRIVATE_KEY_SIZE)?;
    m.add("ML_KEM768_CIPHERTEXT_SIZE", mlkem::CIPHERTEXT_SIZE)?;
    m.add("ML_KEM768_SHARED_SECRET_SIZE", mlkem::SHARED_SECRET_SIZE)?;
    m.add_function(wrap_pyfunction!(ml_kem768_generate_key_pair, m)?)?;
    m.add_function(wrap_pyfunction!(ml_kem768_public_key, m)?)?;
    m.add_function(wrap_pyfunction!(ml_kem768_encapsulate, m)?)?;
    m.add_function(wrap_pyfunction!(ml_kem768_decapsulate, m)?)
}
