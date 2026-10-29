//! Which agent the last failed call on a handle was refused for.
//!
//! A call that fails because the allowed set refused a leaf raises
//! `PeerNotAdmittedError`; this getter names the agent. It reads state the
//! guard recorded and runs nothing, so it is deliberately not behind `guard`
//! (which would clear what it is asked to read).

use pyo3::prelude::*;
use pyo3::types::PyBytes;

use crate::client::MlsClient;
use crate::group::MlsGroup;

#[pymethods]
impl MlsClient {
    /// The agent id bytes of the leaf the allowed set refused in the last call
    /// on this handle, or ``None`` after any other outcome. Read it straight
    /// after the failing call.
    fn refused_peer<'py>(&self, py: Python<'py>) -> Option<Bound<'py, PyBytes>> {
        self.poison.refused_peer().map(|id| PyBytes::new(py, id))
    }
}

#[pymethods]
impl MlsGroup {
    /// As ``MlsClient.refused_peer``, for the last call on this group handle.
    fn refused_peer<'py>(&self, py: Python<'py>) -> Option<Bound<'py, PyBytes>> {
        self.poison.refused_peer().map(|id| PyBytes::new(py, id))
    }
}
