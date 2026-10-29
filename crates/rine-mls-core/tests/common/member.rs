//! Hand-opened clients for tests that need a per-client allowed set.
//!
//! The shared `TestAgent` trusts every agent it makes, so a test that probes
//! who a group may seat opens its clients here, each with the set it is meant
//! to have.

use ed25519_dalek::SigningKey;
use mls_rs::client_builder::MlsConfig;
use mls_rs::identity::basic::BasicCredential;
use mls_rs::identity::SigningIdentity;
use mls_rs::mls_rules::{CommitOptions, DefaultMlsRules, EncryptionOptions};
use mls_rs::Client;
use mls_rs_core::crypto::{CipherSuite, SignaturePublicKey};
use rine_mls_core::{
    AllowedIdentities, AllowedSetIdentityProvider, LeafIdentity, MlsStoreRoot, RineCipherSuite,
    RineCryptoProvider, RineMlsClient,
};
use tempfile::TempDir;

pub const SUITE: RineCipherSuite = RineCipherSuite::XWing;

/// One agent: its leaf identity and a private state directory.
pub struct Member {
    pub leaf: LeafIdentity,
    pub dir: TempDir,
    seed_byte: u8,
}

impl Member {
    pub fn new(agent: &str, seed_byte: u8) -> Self {
        Self {
            leaf: LeafIdentity::new(agent.as_bytes(), &[seed_byte; 32]).expect("32-byte seed"),
            dir: tempfile::tempdir().expect("temp dir"),
            seed_byte,
        }
    }

    /// The same agent on a device with no state yet.
    pub fn on_a_fresh_device(&self) -> Self {
        Self::new(
            std::str::from_utf8(self.leaf.agent_id()).expect("utf-8 agent id"),
            self.seed_byte,
        )
    }

    pub fn open(&self, allowed: &AllowedIdentities) -> RineMlsClient {
        RineMlsClient::open(
            MlsStoreRoot::new(self.dir.path().join("mls2")),
            &self.leaf,
            allowed.clone(),
            SUITE,
        )
    }

    pub fn allow(&self, allowed: &AllowedIdentities) {
        allowed
            .insert(self.leaf.agent_id(), &self.leaf.leaf_public_key(), 0)
            .expect("record the pair");
    }
}

pub fn allowing(members: &[&Member]) -> AllowedIdentities {
    let allowed = AllowedIdentities::new();
    for member in members {
        member.allow(&allowed);
    }

    allowed
}

pub fn group_id(tag: u8) -> [u8; 16] {
    [tag; 16]
}

/// How a stock client frames what it sends, in the two ways rine's own client
/// never does but any peer is free to.
#[derive(Clone, Copy)]
pub enum StockWire {
    /// Commits travel as PrivateMessages.
    EncryptedCommits,
    /// One Welcome names every member the commit adds.
    SharedWelcome,
}

/// A stock mls-rs client holding `member`'s identity, checking leaves against
/// `allowed`.
pub fn stock_client(
    member: &Member,
    allowed: AllowedIdentities,
    wire: StockWire,
) -> Client<impl MlsConfig> {
    let mut encryption = EncryptionOptions::default();
    encryption.encrypt_control_messages = matches!(wire, StockWire::EncryptedCommits);
    let signer = SigningKey::from_bytes(&[member.seed_byte; 32]).to_keypair_bytes();

    Client::builder()
        .identity_provider(AllowedSetIdentityProvider::new(allowed))
        .crypto_provider(RineCryptoProvider)
        .mls_rules(
            DefaultMlsRules::new()
                .with_commit_options(
                    CommitOptions::new()
                        .with_ratchet_tree_extension(true)
                        .with_single_welcome_message(matches!(wire, StockWire::SharedWelcome))
                        .with_path_required(true),
                )
                .with_encryption_options(encryption),
        )
        .signing_identity(
            SigningIdentity::new(
                BasicCredential::new(member.leaf.agent_id().to_vec()).into_credential(),
                SignaturePublicKey::from(member.leaf.leaf_public_key().to_vec()),
            ),
            signer.to_vec().into(),
            CipherSuite::new(SUITE.id()),
        )
        .build()
}
