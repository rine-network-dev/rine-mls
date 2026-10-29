use napi::bindgen_prelude::Uint8Array;
use napi_derive::napi;
use rine_mls_core::{
    LeafIdentity, MlsStoreRoot, PanicGuard, RineCipherSuite, RineMlsClient, RineMlsError,
};

use crate::allowed::AllowedIdentities;
use crate::error::{guard, MlsError};
use crate::group::MlsGroup;
use crate::options::MlsClientOptions;
use crate::types::{into_arrays, to_vecs};

/// One rine agent's MLS client, bound to that agent's leaf identity and its own
/// local state directory.
///
/// The identity seed is copied into Rust on open and the copy is zeroized when
/// the client drops. The caller's `Uint8Array` belongs to the JS heap and cannot
/// be wiped from here.
///
/// **One client per store root at a time.** Group state is a ratchet: two
/// clients loaded from the same group directory both commit, at the same epoch,
/// to different things — a fork whose losing side goes unnoticed locally until a
/// message will not decrypt, with the last `save()` winning on disk. The store
/// takes no lock, so nothing here will stop it — a caller that fans work out
/// across threads or processes must give each its own agent, or serialize on one
/// client. (Founding the same group twice is refused, and the KeyPackage store
/// is safe under concurrent minting; group state is what is unprotected.)
#[napi]
pub struct MlsClient {
    /// `pub(crate)` for the sibling modules that add methods to this handle.
    pub(crate) inner: RineMlsClient,
    /// `pub(crate)` so a sibling module can trip it deliberately (the
    /// `panic-probe` feature) or read what it recorded.
    pub(crate) poison: PanicGuard,
}

#[napi]
impl MlsClient {
    /// `storeRoot` is this agent's private MLS directory (`keys/<agent>/mls2`),
    /// `agentId` its MLS basic-credential identity, `leafSeed` its 32-byte
    /// derived leaf signature seed (`mls.key`), and `cipherSuite` the wire id
    /// the server persists as `mls_cipher_suite` — `CIPHER_SUITE_DEFAULT`
    /// unless there is a reason to pin one. `allowed` is the chain-verified set
    /// of `(agent id, leaf key)` pairs this client accepts as members; the
    /// client's own pair must be in it.
    #[napi(factory)]
    pub fn open(
        store_root: String,
        agent_id: Uint8Array,
        leaf_seed: Uint8Array,
        allowed: &AllowedIdentities,
        cipher_suite: u16,
        options: Option<MlsClientOptions>,
    ) -> Result<Self, MlsError> {
        let mut poison = PanicGuard::default();
        let inner = guard(&mut poison, || {
            let suite = RineCipherSuite::try_from(cipher_suite)
                .map_err(|id| RineMlsError::UnsupportedCipherSuite { id })?;
            let identity = LeafIdentity::new(&agent_id, &leaf_seed)?;
            let options = options.unwrap_or_default().to_core()?;

            Ok(RineMlsClient::open_with(
                MlsStoreRoot::new(store_root),
                &identity,
                allowed.inner.clone(),
                suite,
                options,
            ))
        })?;

        Ok(Self { inner, poison })
    }

    /// The suite this client MINTS with — new key packages and new groups. A
    /// group loaded from local state keeps its own suite whatever this says.
    #[napi]
    pub fn cipher_suite(&self) -> u16 {
        self.inner.cipher_suite().id()
    }

    /// The agent id: its MLS basic-credential identity, and the value
    /// `MlsGroup.memberIndex` looks members up by.
    #[napi]
    pub fn agent_id(&self) -> Uint8Array {
        Uint8Array::new(self.inner.agent_id().to_vec())
    }

    /// The raw 32-byte Ed25519 leaf signature public key this client's
    /// KeyPackages and commits are signed under — the `mls` field of the
    /// agent's certificate.
    #[napi]
    pub fn leaf_public_key(&self) -> Uint8Array {
        Uint8Array::new(self.inner.leaf_public_key().to_vec())
    }

    /// Mint one KeyPackage for `POST /agents/{id}/mls/key-packages`. Its private
    /// half stays in the local store; only these bytes leave the machine.
    #[napi]
    pub fn generate_key_package(&mut self) -> Result<Uint8Array, MlsError> {
        let inner = &self.inner;
        guard(&mut self.poison, || inner.generate_key_package()).map(Uint8Array::new)
    }

    /// Mint `count` KeyPackages for one publish request. More than
    /// `KEY_PACKAGE_MAX_BATCH` is refused outright, never truncated.
    #[napi]
    pub fn generate_key_packages(&mut self, count: u32) -> Result<Vec<Uint8Array>, MlsError> {
        let inner = &self.inner;
        guard(&mut self.poison, || {
            inner.generate_key_packages(count as usize)
        })
        .map(into_arrays)
    }

    /// How many published KeyPackages this agent still holds the private half
    /// of — read locally, since claiming from the server consumes what it returns.
    #[napi]
    pub fn key_package_count(&mut self) -> Result<u32, MlsError> {
        let inner = &self.inner;
        guard(&mut self.poison, || inner.key_package_count()).map(|n| n as u32)
    }

    /// The batch a low-water top-up needs, empty when the inventory is healthy.
    /// Publish whatever comes back.
    #[napi]
    pub fn replenish_key_packages(&mut self) -> Result<Vec<Uint8Array>, MlsError> {
        let inner = &self.inner;
        guard(&mut self.poison, || inner.replenish_key_packages()).map(into_arrays)
    }

    /// Discard this agent's whole KeyPackage pool and mint a fresh one — rine's
    /// MLS cutover. Publish what comes back after draining the server's copy.
    #[napi]
    pub fn drain_and_republish_key_packages(&mut self) -> Result<Vec<Uint8Array>, MlsError> {
        let inner = &self.inner;
        guard(&mut self.poison, || {
            inner.drain_and_republish_key_packages()
        })
        .map(into_arrays)
    }

    /// Create a group keyed by the rine group UUID's raw bytes, with no other
    /// member. Its `lastCommit()` is the init POST.
    #[napi]
    pub fn create_group(&mut self, group_id: Uint8Array) -> Result<MlsGroup, MlsError> {
        self.create_group_with_members(group_id, Vec::new())
    }

    /// Create a group and admit its founding members in the same commit, one
    /// Welcome each in the order their KeyPackages are passed.
    #[napi]
    pub fn create_group_with_members(
        &mut self,
        group_id: Uint8Array,
        key_packages: Vec<Uint8Array>,
    ) -> Result<MlsGroup, MlsError> {
        let inner = &self.inner;
        let owned = to_vecs(&key_packages);
        let (group, bundle) = guard(&mut self.poison, || {
            inner.create_group_with_members(&group_id, &owned)
        })?;

        Ok(MlsGroup::new(group, Some(bundle)))
    }

    /// Join from the one-shot `GET /agents/{id}/mls/welcomes`. `lastCommit()`
    /// is null: a Welcome joiner mints no commit.
    #[napi]
    pub fn join_from_welcome(&mut self, welcome: Uint8Array) -> Result<MlsGroup, MlsError> {
        let inner = &self.inner;
        let group = guard(&mut self.poison, || inner.join_from_welcome(&welcome))?;

        Ok(MlsGroup::new(group, None))
    }

    /// Self-join by RFC 9420 external commit from
    /// `GET /groups/{id}/mls/group-info`. `lastCommit()` carries the commit to
    /// POST and the GroupInfo to republish.
    ///
    /// A genuine first join: the joiner enters as a new leaf and removes
    /// nothing. An agent the tree **already** holds is refused by MLS — a
    /// second leaf carrying one identity is not a thing that can exist — so a
    /// member recovering from unusable local state wants
    /// `resyncByExternalCommit` (with the stale handle) or
    /// `resyncFromGroupInfo` (without one) instead.
    #[napi]
    pub fn join_by_external_commit(
        &mut self,
        group_info: Uint8Array,
    ) -> Result<MlsGroup, MlsError> {
        let inner = &self.inner;
        let (group, bundle) = guard(&mut self.poison, || {
            inner.join_by_external_commit(&group_info)
        })?;

        Ok(MlsGroup::new(group, Some(bundle)))
    }

    /// Rejoin a group this agent is already a member of, replacing its own
    /// leaf: RFC 9420's resync form of an external commit, and the path out of
    /// unusable local state.
    ///
    /// `staleLeaf` is `MlsGroup.currentMemberIndex()` on the old handle, read
    /// before this call — never a server-supplied index, and never a guess.
    /// The Remove rides in the same commit as the join, so one O(N) commit
    /// replaces the leaf with no window in between and nothing to reclaim
    /// afterwards; the membership count is unchanged. `lastCommit()` carries
    /// the commit to POST and the GroupInfo to republish, and its `welcomes` is
    /// empty because an external commit adds nobody.
    ///
    /// It needs loadable stale state, because that is where the leaf index
    /// comes from. An agent whose group state is gone entirely wants
    /// `resyncFromGroupInfo` instead.
    #[napi]
    pub fn resync_by_external_commit(
        &mut self,
        group_info: Uint8Array,
        stale_leaf: u32,
    ) -> Result<MlsGroup, MlsError> {
        let inner = &self.inner;
        let (group, bundle) = guard(&mut self.poison, || {
            inner.resync_by_external_commit(&group_info, stale_leaf)
        })?;

        Ok(MlsGroup::new(group, Some(bundle)))
    }

    /// Rejoin a group this agent already holds a seat in when its local state is
    /// gone, finding that seat in the GroupInfo's ratchet tree: an external
    /// commit that removes the one leaf whose credential equals this agent's id
    /// and adds a fresh leaf under the same credential and leaf key.
    ///
    /// It differs from `resyncByExternalCommit` only in where the leaf comes
    /// from: that call needs the stale handle's `currentMemberIndex()`, this one
    /// needs nothing but the GroupInfo. A tree with no leaf for this agent is
    /// refused with `RINE_MLS_NO_SEAT_TO_REPLACE`, one with several with
    /// `RINE_MLS_AMBIGUOUS_SEAT`, and a GroupInfo without a ratchet tree with
    /// `RINE_MLS_GROUP_INFO_WITHOUT_TREE`.
    ///
    /// The new leaf must carry the same credential **and** leaf key as the one
    /// it replaces; a resync that changes the key fails
    /// `RINE_MLS_RESYNC_CHANGES_KEY`. An agent whose leaf key rotated moves its
    /// seat with `MlsGroup.commitUpdate` instead. The resync epoch is escrowed
    /// like any other.
    #[napi]
    pub fn resync_from_group_info(&mut self, group_info: Uint8Array) -> Result<MlsGroup, MlsError> {
        let inner = &self.inner;
        let (group, bundle) = guard(&mut self.poison, || {
            inner.resync_from_group_info(&group_info)
        })?;

        Ok(MlsGroup::new(group, Some(bundle)))
    }

    /// Reload a group from local state — what a restarted process does.
    #[napi]
    pub fn load_group(&mut self, group_id: Uint8Array) -> Result<MlsGroup, MlsError> {
        let inner = &self.inner;
        let group = guard(&mut self.poison, || inner.load_group(&group_id))?;

        Ok(MlsGroup::new(group, None))
    }

    /// Delete one group's local state: current state, retained epoch secrets and
    /// the self-read cache's plaintext. Rejoining is the only way back in;
    /// deleting a group that was never there is not an error.
    #[napi]
    pub fn delete_group_state(&mut self, group_id: Uint8Array) -> Result<(), MlsError> {
        let inner = &self.inner;
        guard(&mut self.poison, || inner.delete_group_state(&group_id))
    }
}
