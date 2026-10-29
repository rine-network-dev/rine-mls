//! Reading the leaf key off a KeyPackage, for the claim check.

use pyo3::prelude::*;
use pyo3::types::PyBytes;

use crate::error::from_core;

/// The leaf signature key a KeyPackage carries, as the raw 32 bytes. The caller
/// compares it with the key it chain-verified for the agent that published the
/// KeyPackage. The KeyPackage's own signature is checked when an Add is built,
/// not here.
#[pyfunction]
fn key_package_signature_key<'py>(
    py: Python<'py>,
    key_package: &[u8],
) -> PyResult<Bound<'py, PyBytes>> {
    let key = rine_mls_core::key_package_signature_key(key_package).map_err(from_core)?;

    Ok(PyBytes::new(py, &key))
}

pub fn register(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(key_package_signature_key, m)?)
}
