use pyo3::prelude::*;
use pyo3::types::PyBytes;
use rine_mls_core::{
    LeafIdentity, MlsStoreRoot, PanicGuard, RineCipherSuite, RineMlsClient,
    RineMlsError as CoreError,
};

use crate::allowed::AllowedIdentities;
use crate::error::guard;
use crate::group::MlsGroup;
use crate::options::{client_options, to_bytes};

/// One rine agent's MLS client, bound to that agent's leaf identity and its own
/// local state directory.
///
/// The identity is the agent id — its MLS basic-credential identity — plus the
/// 32-byte leaf signature seed derived for it (``mls.key``). Both are copied
/// into Rust on construction and the copy is zeroized when the client drops. The
/// caller's ``bytes`` belongs to the Python heap and is immutable, so it cannot
/// be wiped from here.
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
    /// `pub(crate)` for the sibling modules that add methods to this handle.
    pub(crate) inner: RineMlsClient,
    pub(crate) poison: PanicGuard,
}

#[pymethods]
impl MlsClient {
    /// ``store_root`` is this agent's private MLS directory
    /// (``keys/<agent>/mls2``), ``agent_id`` its credential identity,
    /// ``leaf_seed`` the 32-byte derived leaf signature seed (``mls.key``), and
    /// ``cipher_suite`` the wire id the server persists as ``mls_cipher_suite``
    /// — ``CIPHER_SUITE_DEFAULT`` unless there is a reason to pin one.
    /// ``allowed`` is the chain-verified set of ``(agent id, leaf key)`` pairs
    /// this client accepts as members, its own pair included.
    /// ``epoch_retention_limit`` is documented on
    /// [`crate::options::client_options`].
    #[new]
    #[pyo3(signature = (store_root, agent_id, leaf_seed, allowed, cipher_suite, *, epoch_retention_limit=None))]
    fn new(
        store_root: &str,
        agent_id: &[u8],
        leaf_seed: &[u8],
        allowed: &AllowedIdentities,
        cipher_suite: u16,
        epoch_retention_limit: Option<usize>,
    ) -> PyResult<Self> {
        let mut poison = PanicGuard::default();
        let inner = guard(&mut poison, || {
            let suite = RineCipherSuite::try_from(cipher_suite)
                .map_err(|id| CoreError::UnsupportedCipherSuite { id })?;
            let identity = LeafIdentity::new(agent_id, leaf_seed)?;

            Ok(RineMlsClient::open_with(
                MlsStoreRoot::new(store_root),
                &identity,
                allowed.inner.clone(),
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

    /// The agent id: its MLS basic-credential identity, and the input to
    /// ``MlsGroup.member_index``.
    fn agent_id<'py>(&self, py: Python<'py>) -> Bound<'py, PyBytes> {
        PyBytes::new(py, self.inner.agent_id())
    }

    /// The raw 32-byte Ed25519 leaf signature public key this client's
    /// KeyPackages and commits are signed under — the ``mls`` field of the
    /// agent's certificate, and the second half of the pair ``allowed`` holds.
    fn leaf_public_key<'py>(&self, py: Python<'py>) -> Bound<'py, PyBytes> {
        PyBytes::new(py, &self.inner.leaf_public_key())
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
    ///
    /// A genuine first join: the joiner enters as a new leaf and removes
    /// nothing. An agent the tree **already** holds is refused by MLS — a
    /// second leaf carrying one identity is not a thing that can exist — so a
    /// member recovering from unusable local state wants
    /// ``resync_by_external_commit`` (with a stale handle) or
    /// ``resync_from_group_info`` (without one) instead.
    fn join_by_external_commit(&mut self, group_info: &[u8]) -> PyResult<MlsGroup> {
        let inner = &self.inner;
        let (group, bundle) = guard(&mut self.poison, || {
            inner.join_by_external_commit(group_info)
        })?;

        Ok(MlsGroup::new(group, Some(bundle)))
    }

    /// Rejoin a group this agent is already a member of, replacing its own
    /// leaf: RFC 9420's resync form of an external commit, and the path out of
    /// unusable local state.
    ///
    /// ``stale_leaf`` is ``MlsGroup.current_member_index()`` on the old handle,
    /// read before this call — never a server-supplied index, and never a
    /// guess. The Remove rides in the same commit as the join, so one O(N)
    /// commit replaces the leaf with no window in between and nothing to
    /// reclaim afterwards; the membership count is unchanged. ``last_commit()``
    /// carries the commit to POST and the GroupInfo to republish, and its
    /// ``welcomes`` is empty because an external commit adds nobody.
    ///
    /// It needs loadable stale state, because that is where the leaf index
    /// comes from. An agent whose group state is gone entirely wants
    /// ``resync_from_group_info`` instead.
    fn resync_by_external_commit(
        &mut self,
        group_info: &[u8],
        stale_leaf: u32,
    ) -> PyResult<MlsGroup> {
        let inner = &self.inner;
        let (group, bundle) = guard(&mut self.poison, || {
            inner.resync_by_external_commit(group_info, stale_leaf)
        })?;

        Ok(MlsGroup::new(group, Some(bundle)))
    }

    /// Rejoin a group this agent already holds a seat in when its local state is
    /// gone: an external commit that finds the seat in the GroupInfo's ratchet
    /// tree, removes that leaf and adds a fresh one under the same credential.
    ///
    /// The new leaf keeps the credential **and** the leaf key; a resync that
    /// changes the key raises ``ResyncChangesKeyError``, and an agent whose leaf
    /// key rotated moves its seat with ``MlsGroup.commit_update`` instead. A
    /// tree with no leaf for
    /// this agent raises ``NoSeatToReplaceError``, one with several raises
    /// ``AmbiguousSeatError``, and a GroupInfo carrying no ratchet tree raises
    /// ``GroupInfoWithoutTreeError``. ``last_commit()`` carries the commit to
    /// POST and the GroupInfo to republish, and the resync epoch is escrowed
    /// like any other.
    fn resync_from_group_info(&mut self, group_info: &[u8]) -> PyResult<MlsGroup> {
        let inner = &self.inner;
        let (group, bundle) = guard(&mut self.poison, || {
            inner.resync_from_group_info(group_info)
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
