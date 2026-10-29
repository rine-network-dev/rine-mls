// Each integration test binary compiles this module separately and uses a
// different slice of it, so per-binary dead-code warnings are expected here.
#![allow(dead_code)]

pub mod escrow;
pub mod fixture;
pub mod kept_store;
pub mod member;
pub mod rfc9420;
pub mod rfc9420_seal;
pub mod rotation;
pub mod scale;
pub mod seat;
pub mod trio;
pub mod unit_costs;

use std::fs;
use std::path::{Path, PathBuf};
use std::sync::OnceLock;

use rine_mls_core::{
    AllowedIdentities, LeafIdentity, MlsStoreRoot, RineCipherSuite, RineMlsClient, RineMlsOptions,
};
use tempfile::TempDir;

/// The allowed set every test agent shares: each [`TestAgent`] adds its own
/// pair on creation, standing in for an SDK that has chain-verified every
/// agent the test makes.
fn everyone() -> &'static AllowedIdentities {
    static SET: OnceLock<AllowedIdentities> = OnceLock::new();

    SET.get_or_init(AllowedIdentities::new)
}

/// One rine agent: its agent id and derived leaf key, its own private state
/// directory, and a client over both. Agents never share a directory, exactly
/// as they never share a process in production.
pub struct TestAgent {
    pub client: RineMlsClient,
    pub identity: Vec<u8>,
    leaf: LeafIdentity,
    store: PathBuf,
    suite: RineCipherSuite,
    options: RineMlsOptions,
    _dir: TempDir,
}

impl TestAgent {
    pub fn new(seed_byte: u8, suite: RineCipherSuite) -> Self {
        Self::with_options(seed_byte, suite, RineMlsOptions::default())
    }

    /// An agent whose client is opened under a non-default lifecycle policy —
    /// a deployment that has tuned [`RineMlsOptions`].
    pub fn with_options(seed_byte: u8, suite: RineCipherSuite, options: RineMlsOptions) -> Self {
        Self::seeded([seed_byte; 32], suite, options)
    }

    /// A distinct agent per `index`, for cohorts wider than a seed byte can
    /// address. MLS refuses two leaves carrying the same basic-credential
    /// identity, so a thousand-member group needs a thousand distinct agent
    /// ids — [`TestAgent::new`]'s seed byte wraps at 256 and would build a
    /// tree mls-rs rejects rather than a group of a thousand.
    pub fn indexed(index: u32, suite: RineCipherSuite) -> Self {
        let mut seed = [0xA5; 32];
        seed[..4].copy_from_slice(&index.to_le_bytes());

        Self::seeded(seed, suite, RineMlsOptions::default())
    }

    fn seeded(seed: [u8; 32], suite: RineCipherSuite, options: RineMlsOptions) -> Self {
        let dir = tempfile::tempdir().expect("temp dir");
        let store = dir.path().join("mls2");
        let agent_id = hex::encode(&seed[..8]).into_bytes();
        let leaf = LeafIdentity::new(&agent_id, &seed).expect("32-byte seed");
        everyone()
            .insert(&agent_id, &leaf.leaf_public_key(), 0)
            .expect("record the pair");

        Self {
            client: open(&store, &leaf, suite, options),
            identity: agent_id,
            leaf,
            store,
            suite,
            options,
            _dir: dir,
        }
    }

    /// A second client over the same on-disk state — what a restarted process
    /// sees. Nothing is carried over in memory.
    pub fn reopen(&self) -> RineMlsClient {
        open(&self.store, &self.leaf, self.suite, self.options)
    }

    /// A second agent for the SAME agent id under a different leaf signing
    /// seed: a rotated generation. The new leaf key is registered in the shared
    /// allowed set alongside the old one, so both generations are accepted —
    /// which is what a resync carrying a rotated key needs, and what a Welcome
    /// validating a tree that holds the rotated leaf needs.
    pub fn rotated(&self, new_seed_byte: u8) -> Self {
        let dir = tempfile::tempdir().expect("temp dir");
        let store = dir.path().join("mls2");
        let leaf = LeafIdentity::new(&self.identity, &[new_seed_byte; 32]).expect("32-byte seed");
        everyone()
            .insert(&self.identity, &leaf.leaf_public_key(), 0)
            .expect("record the pair");

        Self {
            client: open(&store, &leaf, self.suite, self.options),
            identity: self.identity.clone(),
            leaf,
            store,
            suite: self.suite,
            options: self.options,
            _dir: dir,
        }
    }

    pub fn store_path(&self) -> &Path {
        &self.store
    }
}

fn open(
    store: &Path,
    leaf: &LeafIdentity,
    suite: RineCipherSuite,
    options: RineMlsOptions,
) -> RineMlsClient {
    RineMlsClient::open_with(
        MlsStoreRoot::new(store),
        leaf,
        everyone().clone(),
        suite,
        options,
    )
}

/// Run a flow test once per ciphersuite rine speaks (see `RineCipherSuite::ALL`). The suite is printed so a
/// failure names which one broke.
pub fn for_each_suite(test: impl Fn(RineCipherSuite)) {
    for suite in RineCipherSuite::ALL {
        eprintln!("--- cipher suite {suite:?} (0x{:04X}) ---", suite.id());
        test(suite);
    }
}

/// The rine group UUID's raw bytes, which is what the MLS group id is set to.
pub fn group_id(tag: u8) -> [u8; 16] {
    [tag; 16]
}

/// Length of a byte string once base64-encoded, which is how every MLS blob
/// travels in a rine request body. Sizes are reported in this unit throughout,
/// because the number that has to fit in a POST is the encoded one.
pub fn base64_len(raw: usize) -> usize {
    4 * raw.div_ceil(3)
}

/// Where one agent keeps a group's local state: `state.bin`, the retained
/// `epochs/`, and `self_read.bin`. The layout is `store/mod.rs`'s, restated
/// here because the store's own path helpers are crate-private and a
/// measurement of what a group costs on disk has to look at real files.
pub fn group_dir(store: &Path, group_id: &[u8]) -> PathBuf {
    store.join("groups").join(hex::encode(group_id))
}

/// Total size of every file under `path`, recursively. Zero for a path that
/// does not exist — a group that has never been saved costs nothing on disk,
/// which is an answer, not an error.
pub fn dir_size(path: &Path) -> u64 {
    let Ok(entries) = fs::read_dir(path) else {
        return 0;
    };

    entries
        .filter_map(|entry| entry.ok())
        .map(|entry| match entry.metadata() {
            Ok(meta) if meta.is_dir() => dir_size(&entry.path()),
            Ok(meta) => meta.len(),
            Err(_) => 0,
        })
        .sum()
}

/// Size of one file, or zero when it is not there.
pub fn file_size(path: &Path) -> u64 {
    fs::metadata(path).map(|meta| meta.len()).unwrap_or(0)
}
