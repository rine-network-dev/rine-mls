//! The value objects a group operation hands back.
//!
//! All are frozen and copy-out: they own plain Rust buffers and expose them as
//! `bytes`, so nothing a caller holds points into MLS state.

use pyo3::prelude::*;
use pyo3::types::PyBytes;
use rine_mls_core::{wire_epoch, MemberLeaf, RineMlsError as CoreError};

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

/// One occupied leaf of the ratchet tree: where it sits, whose it is, and the
/// key it signs with. ``identity`` is the member's agent id bytes — its MLS
/// basic-credential identity, the same value ``MlsClient.agent_id()`` returns
/// and ``MlsGroup.member_index`` takes. ``signature_key`` is the raw 32-byte
/// leaf signature key, the ``mls`` field of the agent's certificate.
#[pyclass(frozen, module = "rine_mls")]
pub struct MemberIdentity {
    pub(crate) index: u32,
    pub(crate) identity: Vec<u8>,
    pub(crate) signature_key: Vec<u8>,
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

    #[getter]
    fn signature_key<'py>(&self, py: Python<'py>) -> Bound<'py, PyBytes> {
        PyBytes::new(py, &self.signature_key)
    }
}

/// An application message opened by an ``EpochReader``: the signed rine
/// envelope, the leaf that sent it, the signature key it verified under, and the
/// sender's ratchet generation.
#[pyclass(frozen, module = "rine_mls")]
pub struct OpenedMessage {
    pub(crate) envelope: Vec<u8>,
    pub(crate) sender_index: u32,
    pub(crate) signer_public_key: Vec<u8>,
    pub(crate) generation: u32,
}

#[pymethods]
impl OpenedMessage {
    #[getter]
    fn envelope<'py>(&self, py: Python<'py>) -> Bound<'py, PyBytes> {
        PyBytes::new(py, &self.envelope)
    }

    #[getter]
    fn sender_index(&self) -> u32 {
        self.sender_index
    }

    #[getter]
    fn signer_public_key<'py>(&self, py: Python<'py>) -> Bound<'py, PyBytes> {
        PyBytes::new(py, &self.signer_public_key)
    }

    #[getter]
    fn generation(&self) -> u32 {
        self.generation
    }
}

/// Copy the core's leaves out to Python.
pub(crate) fn convert_members(members: Vec<MemberLeaf>) -> Vec<MemberIdentity> {
    members
        .into_iter()
        .map(|leaf| MemberIdentity {
            index: leaf.index,
            identity: leaf.identity,
            signature_key: leaf.signature_key,
        })
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
