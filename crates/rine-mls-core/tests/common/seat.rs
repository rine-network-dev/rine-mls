//! Agents that rotate: one agent id, one private state directory, and a leaf
//! key per generation, each opened against a per-test allowed set.
//!
//! Generation `g` of a seat derives its leaf from the seed byte `base + g`, so
//! two generations of one agent never share a key and two agents (bases at
//! least 16 apart) never share a seed.

use mls_rs::client_builder::MlsConfig;
use mls_rs::Client;
use rine_mls_core::{AllowedIdentities, LeafIdentity, MlsStoreRoot, RineMlsClient, RineMlsGroup};
use tempfile::TempDir;

use super::member::{stock_client, Member, StockWire, SUITE};

pub struct Seat {
    agent: String,
    base: u8,
    dir: TempDir,
}

impl Seat {
    pub fn new(agent: &str, base: u8) -> Self {
        Self {
            agent: agent.to_owned(),
            base,
            dir: tempfile::tempdir().expect("temp dir"),
        }
    }

    pub fn agent_id(&self) -> &[u8] {
        self.agent.as_bytes()
    }

    pub fn leaf(&self, generation: u32) -> LeafIdentity {
        let seed = self.base + u8::try_from(generation).expect("a small generation");

        LeafIdentity::new(self.agent.as_bytes(), &[seed; 32]).expect("32-byte seed")
    }

    /// The seed `commit_update` takes for `generation`.
    pub fn seed(&self, generation: u32) -> [u8; 32] {
        [self.base + u8::try_from(generation).expect("a small generation"); 32]
    }

    pub fn public_key(&self, generation: u32) -> [u8; 32] {
        self.leaf(generation).leaf_public_key()
    }

    /// Record this seat's `generation` leaf in `allowed`.
    pub fn allow(&self, allowed: &AllowedIdentities, generation: u32) {
        allowed
            .insert(self.agent_id(), &self.public_key(generation), generation)
            .expect("one generation per pair");
    }

    /// A client over this seat's state directory that signs with the
    /// `generation` leaf key. Reopening at another generation reuses the same
    /// directory, so KeyPackages minted at one generation are found at another.
    pub fn open(&self, allowed: &AllowedIdentities, generation: u32) -> RineMlsClient {
        RineMlsClient::open(
            MlsStoreRoot::new(self.dir.path().join("mls2")),
            &self.leaf(generation),
            allowed.clone(),
            SUITE,
        )
    }

    /// A bare mls-rs client holding this seat's `generation` identity under
    /// stock rules, which enforce nothing about a resync.
    pub fn stock(&self, allowed: &AllowedIdentities, generation: u32) -> Client<impl MlsConfig> {
        let member = Member::new(
            &self.agent,
            self.base + u8::try_from(generation).expect("a small generation"),
        );

        stock_client(&member, allowed.clone(), StockWire::EncryptedCommits)
    }
}

/// An allowed set holding `(seat, generation)` for each pair given.
pub fn allowing(pairs: &[(&Seat, u32)]) -> AllowedIdentities {
    let allowed = AllowedIdentities::new();
    for (seat, generation) in pairs {
        seat.allow(&allowed, *generation);
    }

    allowed
}

/// Alice founds a group with `bob` in one commit; both hold epoch 1, and each
/// opens at generation 0 against the set it is given.
pub fn found_pair(
    id: &[u8],
    alice: &Seat,
    alice_allowed: &AllowedIdentities,
    bob: &Seat,
    bob_allowed: &AllowedIdentities,
) -> (RineMlsGroup, RineMlsGroup) {
    let (alice_group, bundle) = alice
        .open(alice_allowed, 0)
        .create_group_with_members(
            id,
            &[bob
                .open(bob_allowed, 0)
                .generate_key_package()
                .expect("key package")],
        )
        .expect("create with bob");
    let bob_group = bob
        .open(bob_allowed, 0)
        .join_from_welcome(&bundle.welcomes[0])
        .expect("welcome join");

    (alice_group, bob_group)
}

/// The signature key the tree records for `agent`.
pub fn leaf_key_of(group: &RineMlsGroup, agent: &[u8]) -> Vec<u8> {
    group
        .member_identities()
        .expect("enumerate tree")
        .into_iter()
        .find(|leaf| leaf.identity == agent)
        .expect("the agent is seated")
        .signature_key
}

/// The signature key on this handle's own leaf.
pub fn own_key(group: &RineMlsGroup) -> Vec<u8> {
    group.own_leaf_signature_key().expect("own leaf key")
}

/// A sends `text` at its current epoch and the peer reads it.
pub fn send_and_read(a_group: &mut RineMlsGroup, r_group: &mut RineMlsGroup, text: &[u8]) {
    let payload = a_group.encrypt_application_message(text).expect("send");
    let read = r_group.decrypt_application_message(&payload).expect("read");
    assert_eq!(read.envelope, text);
}
