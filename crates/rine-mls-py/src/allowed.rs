use pyo3::prelude::*;

use crate::error::from_core;

/// The set of ``(agent id, leaf signature public key)`` pairs the caller has
/// chain-verified against org-signed agent certificates.
///
/// One object may be passed to several clients: it is a cheap shared handle, and
/// an addition is seen by every client already open on it. The client's own pair
/// must be in it — nothing is implicitly trusted — and it must hold every
/// verified generation of an agent, not only the current one, because MLS
/// validates every leaf already in a tree a client joins.
#[pyclass(module = "rine_mls")]
pub struct AllowedIdentities {
    pub(crate) inner: rine_mls_core::AllowedIdentities,
}

#[pymethods]
impl AllowedIdentities {
    #[new]
    fn new() -> Self {
        Self {
            inner: rine_mls_core::AllowedIdentities::new(),
        }
    }

    /// Admit one ``(agent id, leaf signature public key)`` pair at ``key_gen``,
    /// the generation the agent's certificate chain signs for that key. The leaf
    /// key is the 32-byte ``mls`` field of the certificate.
    ///
    /// A leaf may replace another leaf of the same agent only when its
    /// generation is strictly greater. Inserting a pair again with the same
    /// generation does nothing; with a different generation it raises
    /// ``AllowedGenerationConflictError`` and the set keeps the first.
    fn insert(&self, agent_id: &[u8], leaf_public_key: &[u8], key_gen: u32) -> PyResult<()> {
        self.inner
            .insert(agent_id, leaf_public_key, key_gen)
            .map_err(from_core)
    }

    /// Whether that exact pair is in the set.
    fn contains(&self, agent_id: &[u8], leaf_public_key: &[u8]) -> bool {
        self.inner.contains(agent_id, leaf_public_key)
    }
}
