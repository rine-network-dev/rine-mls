//! The per-epoch escrow accessors of a group handle, in their own `pymethods`
//! block so `group.rs` stays about the group itself.

use pyo3::prelude::*;
use pyo3::types::PyBytes;
use rine_mls_core::wire_epoch;

use crate::error::{from_core, guard};
use crate::escrow::{convert_backlog, convert_take, EscrowBacklog, EscrowTake};
use crate::group::MlsGroup;

#[pymethods]
impl MlsGroup {
    /// Every epoch this group installed since the last take, oldest first.
    ///
    /// Seal and persist each result before calling ``save()``. Taking empties the
    /// in-memory list, but the stored snapshot keeps the exports until the next
    /// ``save()``, so a crash in between yields them again on the next load.
    ///
    /// An epoch that cannot be escrowed (a tree or group context over the escrow
    /// limits, or an export discarded because too many were waiting) comes back
    /// in ``gaps`` and never fails the take for the others. Record each gap
    /// beside the sealed files before saving: once saved, nothing else remembers
    /// it. Each export's ``plaintext`` is a ``bytearray``: overwrite it with zeros
    /// once it is sealed.
    fn take_escrow_exports(&mut self, py: Python<'_>) -> PyResult<EscrowTake> {
        let inner = &mut self.inner;
        let take = guard(&mut self.poison, || inner.take_escrow_exports())?;

        convert_take(py, take)
    }

    /// The fork fingerprint of the group's current epoch — the ``fp`` an
    /// ``EscrowExport`` of this epoch carries — without taking anything. Two
    /// members on different forks of one epoch read different values.
    fn epoch_fingerprint<'py>(&mut self, py: Python<'py>) -> PyResult<Bound<'py, PyBytes>> {
        let inner = &self.inner;
        let fp = guard(&mut self.poison, || inner.epoch_fingerprint())?;

        Ok(PyBytes::new(py, &fp))
    }

    /// What the next ``take_escrow_exports()`` will return, without taking it:
    /// how many exports wait, and how many epochs were already discarded past
    /// the group's cap.
    fn escrow_backlog(&self) -> EscrowBacklog {
        convert_backlog(self.inner.escrow_backlog())
    }

    /// The ``(epoch, fp)`` of every export a take would return now, oldest
    /// first, without taking anything. Record them before parking a snapshot
    /// that may later be unreadable, so the epochs given up are filed under
    /// their fork.
    fn queued_escrow_fingerprints<'py>(
        &mut self,
        py: Python<'py>,
    ) -> PyResult<Vec<(i64, Bound<'py, PyBytes>)>> {
        let inner = &self.inner;
        let queued = guard(&mut self.poison, || inner.queued_escrow_fingerprints())?;

        queued
            .into_iter()
            .map(|queued| {
                let epoch = wire_epoch(queued.epoch).map_err(from_core)?;
                Ok((epoch, PyBytes::new(py, &queued.fp)))
            })
            .collect()
    }
}
