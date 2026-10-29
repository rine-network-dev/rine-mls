//! One rine agent's MLS client: what it is opened with, and what it holds.
//! The group lifecycle is [`mod@groups`]; the KeyPackage pool is
//! [`mod@key_packages`]; resync without a handle is [`mod@resync`].

mod groups;
mod key_packages;
mod resync;
mod rules;

pub use key_packages::key_package_signature_key;
pub(crate) use rules::RineRulesError;

use mls_rs::client_builder::{
    BaseConfig, WithCryptoProvider, WithGroupStateStorage, WithIdentityProvider,
    WithKeyPackageRepo, WithMlsRules,
};
use mls_rs::Client;

use crate::allowed::{AllowedIdentities, AllowedSetIdentityProvider};
use crate::crypto::RineCryptoProvider;
use crate::group::RineMlsGroup;
use crate::identity::LeafIdentity;
use crate::policy::EpochRetention;
use crate::store::{
    FileGroupStateStorage, FileKeyPackageStorage, Incarnation, MlsStoreRoot, SelfReadCache,
};
use crate::suite::RineCipherSuite;

use self::rules::RineMlsRules;

/// The one mls-rs configuration rine uses: rine's crypto provider (pure Rust,
/// portable across the whole platform matrix, post-quantum suite), basic
/// credentials held to a caller-supplied allowed set, rine's commit rules, and
/// file-backed local state.
///
/// The identity provider is named concretely on purpose: the vendored
/// prior-epoch sender check (vendor/mls-rs-0.55.2/PATCH.md item 9) is safe only
/// under a key-aware `valid_successor`. A credential-only provider would accept a
/// leaf another identity reuses, so wiring a different provider means changing
/// this type, and that change must revisit the patch first.
pub type RineMlsConfig = WithMlsRules<
    RineMlsRules,
    WithIdentityProvider<
        AllowedSetIdentityProvider,
        WithCryptoProvider<
            RineCryptoProvider,
            WithGroupStateStorage<
                FileGroupStateStorage,
                WithKeyPackageRepo<FileKeyPackageStorage, BaseConfig>,
            >,
        >,
    >,
>;

/// The deployment-tunable knobs a client is opened with. `Default` is rine's
/// shipped policy, and every value in it is owned by `policy.rs` — a caller
/// that wants the defaults never restates a number.
#[derive(Debug, Clone, Copy, Default)]
pub struct RineMlsOptions {
    /// How far back groups keep epoch secrets. The default reaches
    /// the full undelivered backlog; tightening it trades backlog reach for a
    /// narrower forward-secrecy window.
    pub epoch_retention: EpochRetention,
}

/// One rine agent's MLS client, bound to that agent's leaf identity, the set of
/// identities it accepts as members, and its local state directory.
pub struct RineMlsClient {
    inner: Client<RineMlsConfig>,
    suite: RineCipherSuite,
    identity: LeafIdentity,
    root: MlsStoreRoot,
    /// A clone of the group-state storage the client writes through. It shares
    /// that storage's staging set, which is how a new group state is staged on
    /// the very storage its group will save to.
    group_state: FileGroupStateStorage,
    /// A second handle on the same directory the client writes through, for the
    /// inventory questions `KeyPackageStorage` has no method for.
    key_packages: FileKeyPackageStorage,
    self_read: SelfReadCache,
}

impl RineMlsClient {
    /// Open under rine's shipped policy.
    pub fn open(
        store_root: MlsStoreRoot,
        identity: &LeafIdentity,
        allowed: AllowedIdentities,
        suite: RineCipherSuite,
    ) -> Self {
        Self::open_with(
            store_root,
            identity,
            allowed,
            suite,
            RineMlsOptions::default(),
        )
    }

    pub fn open_with(
        store_root: MlsStoreRoot,
        identity: &LeafIdentity,
        allowed: AllowedIdentities,
        suite: RineCipherSuite,
        options: RineMlsOptions,
    ) -> Self {
        let key_packages = FileKeyPackageStorage::new(store_root.clone());
        let group_state =
            FileGroupStateStorage::with_retention(store_root.clone(), options.epoch_retention);

        let inner = Client::builder()
            .key_package_repo(key_packages.clone())
            .group_state_storage(group_state.clone())
            .identity_provider(AllowedSetIdentityProvider::new(allowed))
            .crypto_provider(RineCryptoProvider)
            .mls_rules(RineMlsRules::new())
            .signing_identity(
                identity.signing_identity(),
                identity.signer(),
                suite.mls_rs(),
            )
            .build();

        Self {
            inner,
            suite,
            identity: identity.clone(),
            self_read: SelfReadCache::new(store_root.clone()),
            root: store_root,
            group_state,
            key_packages,
        }
    }

    pub fn cipher_suite(&self) -> RineCipherSuite {
        self.suite
    }

    /// The agent id: its MLS basic-credential identity, and the value
    /// [`RineMlsGroup::member_index`] looks members up by.
    pub fn agent_id(&self) -> &[u8] {
        self.identity.agent_id()
    }

    /// The raw Ed25519 leaf signature public key this client's KeyPackages and
    /// commits are signed under.
    pub fn leaf_public_key(&self) -> [u8; 32] {
        self.identity.leaf_public_key()
    }

    fn group(
        &self,
        inner: mls_rs::Group<RineMlsConfig>,
        incarnation: Option<Incarnation>,
    ) -> RineMlsGroup {
        RineMlsGroup::new(inner, self.self_read.clone(), incarnation)
    }
}
