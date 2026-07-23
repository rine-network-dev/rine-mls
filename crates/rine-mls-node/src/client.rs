use napi::bindgen_prelude::Uint8Array;
use napi_derive::napi;
use rine_mls_core::{
    AgentSigningKey, MlsStoreRoot, PanicGuard, RineCipherSuite, RineMlsClient, RineMlsError,
};

use crate::error::{guard, MlsError};
use crate::group::MlsGroup;
use crate::options::MlsClientOptions;
use crate::types::{into_arrays, to_vecs};

/// One rine agent's MLS client, bound to that agent's Ed25519 identity and its
/// own local state directory.
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
    inner: RineMlsClient,
    /// `pub(crate)` only so the `panic-probe` module can trip it deliberately.
    pub(crate) poison: PanicGuard,
}

#[napi]
impl MlsClient {
    /// `storeRoot` is this agent's private MLS directory (`keys/<agent>/mls2`),
    /// `signingSeed` its 32-byte Ed25519 private key as rine stores it, and
    /// `cipherSuite` the wire id the server persists as `mls_cipher_suite` —
    /// `CIPHER_SUITE_DEFAULT` unless there is a reason to pin one.
    #[napi(factory)]
    pub fn open(
        store_root: String,
        signing_seed: Uint8Array,
        cipher_suite: u16,
        options: Option<MlsClientOptions>,
    ) -> Result<Self, MlsError> {
        let mut poison = PanicGuard::default();
        let inner = guard(&mut poison, || {
            let suite = RineCipherSuite::try_from(cipher_suite)
                .map_err(|id| RineMlsError::UnsupportedCipherSuite { id })?;
            let key = AgentSigningKey::from_seed(&signing_seed)?;
            let options = options.unwrap_or_default().to_core()?;

            Ok(RineMlsClient::open_with(
                MlsStoreRoot::new(store_root),
                &key,
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

    /// The agent's raw Ed25519 public key, which is also its MLS basic-credential
    /// identity and the input to `MlsGroup.memberIndex`.
    #[napi]
    pub fn public_key(&self) -> Uint8Array {
        Uint8Array::new(self.inner.public_key().to_vec())
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
