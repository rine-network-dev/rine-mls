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

/// One occupied leaf of the ratchet tree: where it sits, and whose it is.
/// ``identity`` is the member's raw Ed25519 public key, the same value
/// ``MlsClient.public_key()`` returns and ``MlsGroup.member_index`` takes.
#[pyclass(frozen, module = "rine_mls")]
pub struct MemberIdentity {
    pub(crate) index: u32,
    pub(crate) identity: Vec<u8>,
}

#[pymethods]
impl MemberIdentity {
    #[getter]
    fn index(&self) -> u32 {
        self.index
    }

    #[getter]
    fn identity<'py>(&self, py: Python<'py>) -> Bound<'py, PyBytes> {
        PyBytes::new(py, &self.identity)
    }
}

/// Copy the core's `(index, identity)` pairs out to Python.
pub(crate) fn convert_members(members: Vec<(u32, Vec<u8>)>) -> Vec<MemberIdentity> {
    members
        .into_iter()
        .map(|(index, identity)| MemberIdentity { index, identity })
        .collect()
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
