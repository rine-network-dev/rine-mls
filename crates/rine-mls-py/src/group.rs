use pyo3::prelude::*;
use pyo3::types::PyBytes;
use rine_mls_core::{wire_epoch, PanicGuard, RineMlsError as CoreError, RineMlsGroup};

use crate::error::{from_core, guard};
use crate::types::{convert_bundle, convert_members, AppMessage, CommitBundle, MemberIdentity};

/// One MLS group as seen by one agent.
///
/// Ownership: the handle owns its Rust state and the Python garbage collector
/// owns the handle. Every byte string crossing the boundary is copied — a
/// `bytes` argument is read during the call and never retained, and a returned
/// `bytes` is built from a Rust buffer that is then dropped. No pointer into
/// either heap outlives a call, and the GIL is held throughout, so a handle is
/// never mutated by two threads at once.
///
/// Nothing is written to disk until [`MlsGroup::save`], mirroring the core: post
/// the commit, let the server's epoch CAS rule on it, and only then persist, so
/// a rejected commit leaves no forked state behind.
#[pyclass(module = "rine_mls")]
pub struct MlsGroup {
    /// `pub(crate)` for the sibling modules that add methods to this handle.
    pub(crate) inner: RineMlsGroup,
    last_commit: Option<rine_mls_core::CommitBundle>,
    pub(crate) poison: PanicGuard,
}

impl MlsGroup {
    pub(crate) fn new(
        inner: RineMlsGroup,
        last_commit: Option<rine_mls_core::CommitBundle>,
    ) -> Self {
        Self {
            inner,
            last_commit,
            poison: PanicGuard::default(),
        }
    }
}

#[pymethods]
impl MlsGroup {
    /// The rine group UUID's raw bytes — MLS state is keyed by it, never by the
    /// server's opaque ``mls_group_id`` latch.
    fn group_id<'py>(&mut self, py: Python<'py>) -> PyResult<Bound<'py, PyBytes>> {
        let inner = &self.inner;
        let id = guard(&mut self.poison, || Ok(inner.group_id()))?;

        Ok(PyBytes::new(py, &id))
    }

    fn epoch(&mut self) -> PyResult<i64> {
        let inner = &self.inner;
        guard(&mut self.poison, || wire_epoch(inner.epoch()))
    }

    /// The group's own suite, read from its group context — what a Welcome
    /// joiner records as ``mls_cipher_suite``, rather than whatever suite the
    /// client that opened it mints with.
    fn cipher_suite(&mut self) -> PyResult<u16> {
        let inner = &self.inner;
        guard(&mut self.poison, || Ok(inner.cipher_suite()?.id()))
    }

    /// ``False`` once a Remove commit evicted this member. **A sync loop must
    /// check this after ``apply_commit``**: eviction is not an error there, it
    /// is the correct outcome of a valid commit. Every operation that would
    /// change or use the group then raises ``GroupInactiveError``; decryption
    /// stays open for the backlog this member already held secrets for.
    fn is_active(&mut self) -> PyResult<bool> {
        let inner = &self.inner;
        guard(&mut self.poison, || Ok(inner.is_active()))
    }

    /// Leaf index of the member whose basic-credential identity (its agent id
    /// bytes) is ``identity`` — the input to ``remove_member``.
    fn member_index(&mut self, identity: &[u8]) -> PyResult<u32> {
        let inner = &self.inner;
        guard(&mut self.poison, || inner.member_index(identity))
    }

    /// Every occupied leaf in the ratchet tree — the inverse of
    /// ``member_index``, and the only way to learn that a leaf exists without
    /// already knowing whose it is. That is what an *orphan* leaf needs: one
    /// whose agent the server reports in neither ``GET /groups/{id}/members``
    /// nor ``GET /groups/{id}/requests?outstanding=live``, so no caller can
    /// produce its identity to ask about it.
    ///
    /// A leaf carrying a credential this core cannot read raises
    /// ``UnreadableCredentialError`` for the whole call rather than being
    /// skipped. Order follows the tree, so it is stable for a given tree but
    /// carries no meaning — never index into the result to identify a
    /// member.
    fn member_identities(&mut self) -> PyResult<Vec<MemberIdentity>> {
        let inner = &self.inner;
        guard(&mut self.poison, || inner.member_identities()).map(convert_members)
    }

    /// This handle's own leaf index — the ``stale_leaf`` argument to
    /// ``MlsClient.resync_by_external_commit``, and the only place it may come
    /// from. The server does not know MLS leaf indices.
    fn current_member_index(&mut self) -> PyResult<u32> {
        let inner = &self.inner;
        guard(&mut self.poison, || inner.current_member_index())
    }

    /// A fresh GroupInfo for the current epoch, carrying ``external_pub`` and
    /// the ratchet tree. Single-use per epoch, so every commit republishes one.
    fn group_info<'py>(&mut self, py: Python<'py>) -> PyResult<Bound<'py, PyBytes>> {
        let inner = &self.inner;
        let blob = guard(&mut self.poison, || inner.group_info())?;

        Ok(PyBytes::new(py, &blob))
    }

    /// The commit produced by whatever created this handle: the init commit
    /// after ``create_group``/``create_group_with_members``, the external commit
    /// after ``join_by_external_commit``, the last add/remove otherwise.
    /// ``None`` for a Welcome join, which mints no commit.
    fn last_commit(&mut self) -> PyResult<Option<CommitBundle>> {
        let last = &self.last_commit;
        let bundle = guard(&mut self.poison, || Ok(last.clone()))?;

        bundle.map(convert_bundle).transpose().map_err(from_core)
    }

    /// Commit an inline Add — rine's steady-state one-agent-at-a-time add.
    fn add_member(&mut self, key_package: &[u8]) -> PyResult<CommitBundle> {
        self.commit(|inner| inner.add_member(key_package))
    }

    /// Commit inline Adds for every claimed KeyPackage, in one commit.
    /// ``welcomes[i]`` is the Welcome for ``key_packages[i]``.
    fn add_members(&mut self, key_packages: Vec<Vec<u8>>) -> PyResult<CommitBundle> {
        self.commit(move |inner| inner.add_members(&key_packages))
    }

    /// Commit an inline Remove. The evicted member reads no later message.
    fn remove_member(&mut self, leaf_index: u32) -> PyResult<CommitBundle> {
        self.commit(|inner| inner.remove_member(leaf_index))
    }

    /// Apply a commit from ``GET /groups/{id}/mls/handshakes``. Refuses anything
    /// but the group's own ``current + 1``, the same CAS the server enforces.
    fn apply_commit(&mut self, commit: &[u8]) -> PyResult<i64> {
        let inner = &mut self.inner;
        guard(&mut self.poison, || wire_epoch(inner.apply_commit(commit)?))
    }

    /// Encrypt a signed rine envelope into an ``mls-v1`` payload — version tag
    /// included, base64url left to the transport.
    fn encrypt_application_message<'py>(
        &mut self,
        py: Python<'py>,
        envelope: &[u8],
    ) -> PyResult<Bound<'py, PyBytes>> {
        let inner = &mut self.inner;
        let payload = guard(&mut self.poison, || {
            inner.encrypt_application_message(envelope)
        })?;

        Ok(PyBytes::new(py, &payload))
    }

    /// Decrypt a base64url-decoded ``encrypted_payload``. A message this member
    /// sent comes back from the self-read cache, or as
    /// ``SelfMessageNotCachedError`` once it has aged out.
    fn decrypt_application_message(&mut self, payload: &[u8]) -> PyResult<AppMessage> {
        let inner = &mut self.inner;
        let message = guard(&mut self.poison, || {
            inner.decrypt_application_message(payload)
        })?;

        Ok(AppMessage {
            envelope: message.envelope,
            sender_index: message.sender_index,
        })
    }

    /// Persist to the local store. Never sent to the server.
    fn save(&mut self) -> PyResult<()> {
        let inner = &mut self.inner;
        guard(&mut self.poison, || inner.save())
    }

    /// Panic on purpose — see ``MlsClient.panic_probe``. Compiled only under the
    /// ``panic-probe`` feature, which no published wheel is built with.
    #[cfg(feature = "panic-probe")]
    fn panic_probe(&mut self) -> PyResult<()> {
        guard(&mut self.poison, || -> rine_mls_core::Result<()> {
            panic!("panic probe: deliberate unwind inside the MLS core")
        })
    }
}

impl MlsGroup {
    pub(crate) fn commit(
        &mut self,
        build: impl FnOnce(&mut RineMlsGroup) -> Result<rine_mls_core::CommitBundle, CoreError>,
    ) -> PyResult<CommitBundle> {
        let inner = &mut self.inner;
        let bundle = guard(&mut self.poison, || build(inner))?;

        self.last_commit = Some(bundle.clone());
        convert_bundle(bundle).map_err(from_core)
    }
}
