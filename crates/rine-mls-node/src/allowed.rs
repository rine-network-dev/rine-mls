use napi::bindgen_prelude::Uint8Array;
use napi_derive::napi;

use crate::error::{from_core, MlsError};

/// The `(agent id, leaf signature public key)` pairs a caller has
/// chain-verified against org-signed agent certificates.
///
/// A client accepts a leaf only if its pair is in the set it was opened with,
/// and the client's own pair must be in it too — nothing is implicitly trusted.
/// One object may be passed to several clients, and an addition is seen by
/// clients already open, so a caller can keep verifying and keep adding.
///
/// Keep every verified generation of an agent, not only the current one: MLS
/// validates every leaf already in a tree a client joins, so a pair that has
/// been rotated away is still needed to read the tree it sits in.
#[napi]
pub struct AllowedIdentities {
    pub(crate) inner: rine_mls_core::AllowedIdentities,
}

impl Default for AllowedIdentities {
    fn default() -> Self {
        Self::new()
    }
}

#[napi]
impl AllowedIdentities {
    /// An empty set. Nothing is allowed until it is inserted.
    #[napi(constructor)]
    pub fn new() -> Self {
        Self {
            inner: rine_mls_core::AllowedIdentities::new(),
        }
    }

    /// Allow the pair `(agentId, leafPublicKey)` at `keyGen`, the generation
    /// the agent's certificate chain signs for that key. `leafPublicKey` is the
    /// raw 32-byte Ed25519 leaf signature key, the `mls` field of the
    /// certificate.
    ///
    /// A leaf may replace another leaf of the same agent only when its
    /// generation is strictly greater. Inserting a pair again with the same
    /// generation does nothing; with a different generation it throws
    /// `RINE_MLS_ALLOWED_GENERATION_CONFLICT` and the set keeps the first.
    #[napi]
    pub fn insert(
        &self,
        agent_id: Uint8Array,
        leaf_public_key: Uint8Array,
        key_gen: u32,
    ) -> Result<(), MlsError> {
        self.inner
            .insert(&agent_id, &leaf_public_key, key_gen)
            .map_err(from_core)
    }

    /// Whether the pair `(agentId, leafPublicKey)` is in the set.
    #[napi]
    pub fn contains(&self, agent_id: Uint8Array, leaf_public_key: Uint8Array) -> bool {
        self.inner.contains(&agent_id, &leaf_public_key)
    }
}
