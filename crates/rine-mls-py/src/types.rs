//! The value objects a group operation hands back.
//!
//! Both are frozen and copy-out: they own plain Rust buffers and expose them as
//! `bytes`, so nothing a caller holds points into MLS state.

use pyo3::prelude::*;
use pyo3::types::PyBytes;
use rine_mls_core::{wire_epoch, RineMlsError as CoreError};

/// Everything one commit produces. `welcomes` is one entry per member added by
/// this commit, in add order, which is what `POST /groups/{id}/mls/commit`
/// wants as `welcomes: [{agent_id, welcome}]`.
#[pyclass(frozen, module = "rine_mls")]
pub struct CommitBundle {
    pub(crate) commit: Vec<u8>,
    pub(crate) welcomes: Vec<Vec<u8>>,
    pub(crate) group_info: Vec<u8>,
    pub(crate) epoch: i64,
}

#[pymethods]
impl CommitBundle {
    #[getter]
    fn commit<'py>(&self, py: Python<'py>) -> Bound<'py, PyBytes> {
        PyBytes::new(py, &self.commit)
    }

    #[getter]
    fn welcomes<'py>(&self, py: Python<'py>) -> Vec<Bound<'py, PyBytes>> {
        self.welcomes.iter().map(|w| PyBytes::new(py, w)).collect()
    }

    #[getter]
    fn group_info<'py>(&self, py: Python<'py>) -> Bound<'py, PyBytes> {
        PyBytes::new(py, &self.group_info)
    }

    #[getter]
    fn epoch(&self) -> i64 {
        self.epoch
    }
}

/// A decrypted `mls-v1` message: the signed rine envelope MLS was carrying, and
/// the leaf that sent it.
#[pyclass(frozen, module = "rine_mls")]
pub struct AppMessage {
    pub(crate) envelope: Vec<u8>,
    pub(crate) sender_index: u32,
}

#[pymethods]
impl AppMessage {
    #[getter]
    fn envelope<'py>(&self, py: Python<'py>) -> Bound<'py, PyBytes> {
        PyBytes::new(py, &self.envelope)
    }

    #[getter]
    fn sender_index(&self) -> u32 {
        self.sender_index
    }
}

pub(crate) fn convert_bundle(
    bundle: rine_mls_core::CommitBundle,
) -> Result<CommitBundle, CoreError> {
    Ok(CommitBundle {
        commit: bundle.commit,
        welcomes: bundle.welcomes,
        group_info: bundle.group_info,
        epoch: wire_epoch(bundle.epoch)?,
    })
}
