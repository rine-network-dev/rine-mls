//! The escrow value objects a group take hands back: the exports to seal, the
//! gaps that have none, and the backlog a deferral leaves behind.
//!
//! Frozen and copy-out like the rest of the binding; the one mutable thing is
//! each export's plaintext ``bytearray``, which the caller zeroes after sealing.

use pyo3::prelude::*;
use pyo3::types::{PyByteArray, PyBytes};
use rine_mls_core::wire_epoch;

use crate::error::from_core;

/// One epoch's escrow, ready to seal: the epoch it belongs to, the fork
/// fingerprint that tells two members' views of that epoch apart, and the
/// ``EpochReadSecrets`` v1 plaintext an ``EpochReader`` opens messages with.
///
/// The plaintext is the epoch's secrets, held in one ``bytearray`` the caller
/// overwrites with zeros once it has sealed it; every read of ``plaintext``
/// returns that same object.
#[pyclass(frozen, module = "rine_mls")]
pub struct EscrowExport {
    pub(crate) epoch: i64,
    pub(crate) fp: Vec<u8>,
    pub(crate) plaintext: Py<PyByteArray>,
}

#[pymethods]
impl EscrowExport {
    #[getter]
    fn epoch(&self) -> i64 {
        self.epoch
    }

    #[getter]
    fn fp<'py>(&self, py: Python<'py>) -> Bound<'py, PyBytes> {
        PyBytes::new(py, &self.fp)
    }

    #[getter]
    fn plaintext<'py>(&self, py: Python<'py>) -> Bound<'py, PyByteArray> {
        self.plaintext.bind(py).clone()
    }
}

/// Why an installed epoch has no escrow export. ``value`` is the snake_case name
/// the client files its gap markers under.
#[pyclass(
    frozen,
    eq,
    eq_int,
    skip_from_py_object,
    module = "rine_mls",
    rename_all = "SCREAMING_SNAKE_CASE"
)]
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum EscrowGapReason {
    /// The epoch's group context is over the escrow size limit.
    ContextTooLarge,
    /// The epoch's tree holds more occupied leaves than an escrow can carry.
    TooManyLeaves,
    /// The epoch's secrets or leaf keys have a length the plaintext cannot carry.
    Malformed,
    /// More exports were waiting than the group keeps, so this epoch's was
    /// discarded unread.
    QueueOverflow,
}

#[pymethods]
impl EscrowGapReason {
    #[getter]
    fn value(&self) -> &'static str {
        match self {
            Self::ContextTooLarge => "context_too_large",
            Self::TooManyLeaves => "too_many_leaves",
            Self::Malformed => "malformed",
            Self::QueueOverflow => "queue_overflow",
        }
    }
}

/// An installed epoch that has no escrow: nothing can be sealed for it.
#[pyclass(frozen, module = "rine_mls")]
pub struct EscrowGap {
    pub(crate) group_id: Vec<u8>,
    pub(crate) epoch: i64,
    pub(crate) reason: EscrowGapReason,
    pub(crate) fp: Option<Vec<u8>>,
}

#[pymethods]
impl EscrowGap {
    #[getter]
    fn group_id<'py>(&self, py: Python<'py>) -> Bound<'py, PyBytes> {
        PyBytes::new(py, &self.group_id)
    }

    #[getter]
    fn epoch(&self) -> i64 {
        self.epoch
    }

    #[getter]
    fn reason(&self) -> EscrowGapReason {
        self.reason
    }

    /// The fork fingerprint of the epoch, when its secrets reached the take.
    /// ``None`` for an export discarded past the cap and for an epoch whose
    /// fingerprint could not be computed.
    #[getter]
    fn fp<'py>(&self, py: Python<'py>) -> Option<Bound<'py, PyBytes>> {
        self.fp.as_deref().map(|fp| PyBytes::new(py, fp))
    }
}

/// What one take yields: an export for every epoch that could be encoded and a
/// gap for every one that could not.
#[pyclass(frozen, module = "rine_mls")]
pub struct EscrowTake {
    pub(crate) exports: Vec<Py<EscrowExport>>,
    pub(crate) gaps: Vec<Py<EscrowGap>>,
}

#[pymethods]
impl EscrowTake {
    #[getter]
    fn exports(&self, py: Python<'_>) -> Vec<Py<EscrowExport>> {
        self.exports.iter().map(|e| e.clone_ref(py)).collect()
    }

    #[getter]
    fn gaps(&self, py: Python<'_>) -> Vec<Py<EscrowGap>> {
        self.gaps.iter().map(|g| g.clone_ref(py)).collect()
    }
}

/// What a group holds for the next take: exports waiting, and epochs already
/// discarded past the group's cap.
#[pyclass(frozen, module = "rine_mls")]
pub struct EscrowBacklog {
    #[pyo3(get)]
    pub(crate) queued: usize,
    #[pyo3(get)]
    pub(crate) dropped: usize,
}

/// Copy one core escrow export out to Python.
fn convert_export(
    py: Python<'_>,
    export: rine_mls_core::EscrowExport,
) -> PyResult<Py<EscrowExport>> {
    let export_py = EscrowExport {
        epoch: wire_epoch(export.epoch).map_err(from_core)?,
        fp: export.fp.to_vec(),
        plaintext: PyByteArray::new(py, &export.plaintext).unbind(),
    };

    Py::new(py, export_py)
}

fn convert_reason(reason: rine_mls_core::EscrowGapReason) -> EscrowGapReason {
    use rine_mls_core::EscrowGapReason as Core;

    match reason {
        Core::ContextTooLarge => EscrowGapReason::ContextTooLarge,
        Core::TooManyLeaves => EscrowGapReason::TooManyLeaves,
        Core::Malformed => EscrowGapReason::Malformed,
        Core::QueueOverflow => EscrowGapReason::QueueOverflow,
    }
}

/// Copy one core take out to Python.
pub(crate) fn convert_take(
    py: Python<'_>,
    take: rine_mls_core::EscrowTake,
) -> PyResult<EscrowTake> {
    let exports = take
        .exports
        .into_iter()
        .map(|export| convert_export(py, export))
        .collect::<PyResult<_>>()?;
    let gaps = take
        .gaps
        .into_iter()
        .map(|gap| {
            Py::new(
                py,
                EscrowGap {
                    group_id: gap.group_id,
                    epoch: wire_epoch(gap.epoch).map_err(from_core)?,
                    reason: convert_reason(gap.reason),
                    fp: gap.fp.map(|fp| fp.to_vec()),
                },
            )
        })
        .collect::<PyResult<_>>()?;

    Ok(EscrowTake { exports, gaps })
}

pub(crate) fn convert_backlog(backlog: rine_mls_core::EscrowBacklog) -> EscrowBacklog {
    EscrowBacklog {
        queued: backlog.queued,
        dropped: backlog.dropped,
    }
}
