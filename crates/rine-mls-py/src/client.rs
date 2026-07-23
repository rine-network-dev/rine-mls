use pyo3::prelude::*;
use pyo3::types::PyBytes;
use rine_mls_core::{
    AgentSigningKey, MlsStoreRoot, PanicGuard, RineCipherSuite, RineMlsClient,
    RineMlsError as CoreError,
};

use crate::error::guard;
use crate::group::MlsGroup;
use crate::options::{client_options, to_bytes};

/// One rine agent's MLS client, bound to that agent's Ed25519 identity and its
/// own local state directory.
///
/// The identity seed is copied into Rust on construction and the copy is
/// zeroized when the client drops. The caller's ``bytes`` belongs to the Python
/// heap and is immutable, so it cannot be wiped from here.
///
/// **One client per store root at a time.** Group state is a ratchet: two
/// clients loaded from the same group directory both commit, at the same epoch,
/// to different things — a fork whose losing side goes unnoticed locally until a
/// message will not decrypt, with the last ``save()`` winning on disk. The store
/// takes no lock, so nothing here will stop it — a caller that fans work out
/// across threads or processes must give each its own agent, or serialize on one
/// client. (Founding the same group twice is refused, and the KeyPackage store
/// is safe under concurrent minting; group state is what is unprotected.)
#[pyclass(module = "rine_mls")]
pub struct MlsClient {
    inner: RineMlsClient,
    poison: PanicGuard,
}

#[pymethods]
impl MlsClient {
    /// ``store_root`` is this agent's private MLS directory
    /// (``keys/<agent>/mls2``), ``signing_seed`` its 32-byte Ed25519 private key
    /// as rine stores it, and ``cipher_suite`` the wire id the server persists as
    /// ``mls_cipher_suite`` — ``CIPHER_SUITE_DEFAULT`` unless there is a reason
    /// to pin one. ``epoch_retention_limit`` is documented on
    /// [`crate::options::client_options`].
    #[new]
    #[pyo3(signature = (store_root, signing_seed, cipher_suite, *, epoch_retention_limit=None))]
    fn new(
        store_root: &str,
        signing_seed: &[u8],
        cipher_suite: u16,
        epoch_retention_limit: Option<usize>,
    ) -> PyResult<Self> {
        let mut poison = PanicGuard::default();
        let inner = guard(&mut poison, || {
            let suite = RineCipherSuite::try_from(cipher_suite)
                .map_err(|id| CoreError::UnsupportedCipherSuite { id })?;
            let key = AgentSigningKey::from_seed(signing_seed)?;

            Ok(RineMlsClient::open_with(
                MlsStoreRoot::new(store_root),
                &key,
                suite,
                client_options(epoch_retention_limit)?,
            ))
        })?;

        Ok(Self { inner, poison })
    }

    /// The suite this client MINTS with — new key packages and new groups. A
    /// group loaded from local state keeps its own suite whatever this says.
    fn cipher_suite(&self) -> u16 {
        self.inner.cipher_suite().id()
    }

    /// The agent's raw Ed25519 public key, which is also its MLS
    /// basic-credential identity and the input to ``MlsGroup.member_index``.
    fn public_key<'py>(&self, py: Python<'py>) -> Bound<'py, PyBytes> {
        PyBytes::new(py, &self.inner.public_key())
    }

    /// Mint one KeyPackage for ``POST /agents/{id}/mls/key-packages``. Its
    /// private half stays in the local store; only these bytes leave.
    fn generate_key_package<'py>(&mut self, py: Python<'py>) -> PyResult<Bound<'py, PyBytes>> {
        let inner = &self.inner;
        let blob = guard(&mut self.poison, || inner.generate_key_package())?;

        Ok(PyBytes::new(py, &blob))
    }

    /// Mint ``count`` KeyPackages for one publish request. More than
    /// ``KEY_PACKAGE_MAX_BATCH`` is refused outright, never truncated.
    fn generate_key_packages<'py>(
        &mut self,
        py: Python<'py>,
        count: usize,
    ) -> PyResult<Vec<Bound<'py, PyBytes>>> {
        let inner = &self.inner;
        let blobs = guard(&mut self.poison, || inner.generate_key_packages(count))?;

        Ok(to_bytes(py, blobs))
    }

    /// How many published KeyPackages this agent still holds the private half of
    /// — read locally, since claiming from the server consumes what it returns.
    fn key_package_count(&mut self) -> PyResult<usize> {
        let inner = &self.inner;
        guard(&mut self.poison, || inner.key_package_count())
    }

    /// The batch a low-water top-up needs, empty when the inventory is healthy.
    /// Publish whatever comes back.
    fn replenish_key_packages<'py>(
        &mut self,
        py: Python<'py>,
    ) -> PyResult<Vec<Bound<'py, PyBytes>>> {
        let inner = &self.inner;
        let blobs = guard(&mut self.poison, || inner.replenish_key_packages())?;

        Ok(to_bytes(py, blobs))
    }

    /// Discard this agent's whole KeyPackage pool and mint a fresh one — rine's
    /// MLS cutover. Publish what comes back after draining the server's copy.
    fn drain_and_republish_key_packages<'py>(
        &mut self,
        py: Python<'py>,
    ) -> PyResult<Vec<Bound<'py, PyBytes>>> {
        let inner = &self.inner;
        let blobs = guard(&mut self.poison, || {
            inner.drain_and_republish_key_packages()
        })?;

        Ok(to_bytes(py, blobs))
    }

    /// Create a group keyed by the rine group UUID's raw bytes, with no other
    /// member. Its ``last_commit()`` is the init POST.
    fn create_group(&mut self, group_id: &[u8]) -> PyResult<MlsGroup> {
        self.create_group_with_members(group_id, Vec::new())
    }

    /// Create a group and admit its founding members in the same commit, one
    /// Welcome each in the order their KeyPackages are passed.
    fn create_group_with_members(
        &mut self,
        group_id: &[u8],
        key_packages: Vec<Vec<u8>>,
    ) -> PyResult<MlsGroup> {
        let inner = &self.inner;
        let (group, bundle) = guard(&mut self.poison, || {
            inner.create_group_with_members(group_id, &key_packages)
        })?;

        Ok(MlsGroup::new(group, Some(bundle)))
    }

    /// Join from the one-shot ``GET /agents/{id}/mls/welcomes``.
    /// ``last_commit()`` is ``None``: a Welcome joiner mints no commit.
    fn join_from_welcome(&mut self, welcome: &[u8]) -> PyResult<MlsGroup> {
        let inner = &self.inner;
        let group = guard(&mut self.poison, || inner.join_from_welcome(welcome))?;

        Ok(MlsGroup::new(group, None))
    }

    /// Self-join by RFC 9420 external commit from
    /// ``GET /groups/{id}/mls/group-info``. ``last_commit()`` carries the commit
    /// to POST and the GroupInfo to republish.
    fn join_by_external_commit(&mut self, group_info: &[u8]) -> PyResult<MlsGroup> {
        let inner = &self.inner;
        let (group, bundle) = guard(&mut self.poison, || {
            inner.join_by_external_commit(group_info)
        })?;

        Ok(MlsGroup::new(group, Some(bundle)))
    }

    /// Reload a group from local state — what a restarted process does.
    fn load_group(&mut self, group_id: &[u8]) -> PyResult<MlsGroup> {
        let inner = &self.inner;
        let group = guard(&mut self.poison, || inner.load_group(group_id))?;

        Ok(MlsGroup::new(group, None))
    }

    /// Delete one group's local state: current state, retained epoch secrets and
    /// the self-read cache's plaintext. Rejoining is the only way back in;
    /// deleting a group that was never there is not an error.
    fn delete_group_state(&mut self, group_id: &[u8]) -> PyResult<()> {
        let inner = &self.inner;
        guard(&mut self.poison, || inner.delete_group_state(group_id))
    }

    /// Panic on purpose, so the firewall can be proven from Python: a caught
    /// panic must raise ``MlsPanicError`` and retire the handle. Compiled only
    /// under the ``panic-probe`` feature, which no published wheel is built with.
    #[cfg(feature = "panic-probe")]
    fn panic_probe(&mut self) -> PyResult<()> {
        guard(&mut self.poison, || -> rine_mls_core::Result<()> {
            panic!("panic probe: deliberate unwind inside the MLS core")
        })
    }
}
