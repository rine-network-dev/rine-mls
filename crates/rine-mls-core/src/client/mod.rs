//! One rine agent's MLS client: what it is opened with, and what it holds.
//! The group lifecycle is [`mod@groups`]; the KeyPackage pool is
//! [`mod@key_packages`].

mod groups;
mod key_packages;

use mls_rs::client_builder::{
    BaseConfig, WithCryptoProvider, WithGroupStateStorage, WithIdentityProvider, WithKeyPackageRepo,
};
use mls_rs::identity::basic::BasicIdentityProvider;
use mls_rs::mls_rules::{CommitOptions, DefaultMlsRules};
use mls_rs::Client;

use crate::crypto::RineCryptoProvider;
use crate::group::RineMlsGroup;
use crate::identity::AgentSigningKey;
use crate::policy::EpochRetention;
use crate::store::{FileGroupStateStorage, FileKeyPackageStorage, MlsStoreRoot, SelfReadCache};
use crate::suite::RineCipherSuite;

/// The one mls-rs configuration rine uses: rine's crypto provider (pure Rust,
/// portable across the whole platform matrix, classical and post-quantum
/// suites), accept-all basic credentials, and file-backed local state.
pub type RineMlsConfig = WithIdentityProvider<
    BasicIdentityProvider,
    WithCryptoProvider<
        RineCryptoProvider,
        WithGroupStateStorage<
            FileGroupStateStorage,
            WithKeyPackageRepo<FileKeyPackageStorage, BaseConfig>,
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

/// One rine agent's MLS client, bound to that agent's Ed25519 identity key and
/// its local state directory.
pub struct RineMlsClient {
    inner: Client<RineMlsConfig>,
    suite: RineCipherSuite,
    identity: [u8; 32],
    root: MlsStoreRoot,
    /// A second handle on the same directory the client writes through, for the
    /// inventory questions `KeyPackageStorage` has no method for.
    key_packages: FileKeyPackageStorage,
    self_read: SelfReadCache,
}

impl RineMlsClient {
    /// Open under rine's shipped policy.
    pub fn open(
        store_root: MlsStoreRoot,
        signing_key: &AgentSigningKey,
        suite: RineCipherSuite,
    ) -> Self {
        Self::open_with(store_root, signing_key, suite, RineMlsOptions::default())
    }

    pub fn open_with(
        store_root: MlsStoreRoot,
        signing_key: &AgentSigningKey,
        suite: RineCipherSuite,
        options: RineMlsOptions,
    ) -> Self {
        // Two commit options rine's control plane depends on:
        //
        // - the ratchet tree rides in every commit and GroupInfo, because rine
        //   has no out-of-band tree-sync channel, so a joiner's only source of
        //   the tree is the extension inside what it is handed;
        // - one Welcome per added member, never one shared Welcome, because
        //   rine delivers Welcomes per agent (`welcomes: [{agent_id, welcome}]`)
        //   and a shared one has no single recipient to address it to. MLS
        //   defaults the other way, so this is set rather than assumed.
        let mls_rules = DefaultMlsRules::new().with_commit_options(
            CommitOptions::new()
                .with_ratchet_tree_extension(true)
                .with_single_welcome_message(false),
        );

        let key_packages = FileKeyPackageStorage::new(store_root.clone());

        let inner = Client::builder()
            .key_package_repo(key_packages.clone())
            .group_state_storage(FileGroupStateStorage::with_retention(
                store_root.clone(),
                options.epoch_retention,
            ))
            .identity_provider(BasicIdentityProvider)
            .crypto_provider(RineCryptoProvider)
            .mls_rules(mls_rules)
            .signing_identity(
                signing_key.signing_identity(),
                signing_key.signer(),
                suite.mls_rs(),
            )
            .build();

        Self {
            inner,
            suite,
            identity: signing_key.public_key(),
            self_read: SelfReadCache::new(store_root.clone()),
            root: store_root,
            key_packages,
        }
    }

    pub fn cipher_suite(&self) -> RineCipherSuite {
        self.suite
    }

    /// The agent's raw Ed25519 public key: its MLS basic-credential identity,
    /// and the value [`RineMlsGroup::member_index`] looks members up by.
    pub fn public_key(&self) -> [u8; 32] {
        self.identity
    }

    fn group(&self, inner: mls_rs::Group<RineMlsConfig>) -> RineMlsGroup {
        RineMlsGroup::new(inner, self.self_read.clone())
    }
}
