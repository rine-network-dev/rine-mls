// Each integration test binary compiles this module separately and uses a
// different slice of it, so per-binary dead-code warnings are expected here.
#![allow(dead_code)]

use std::path::{Path, PathBuf};

use rine_mls_core::{
    AgentSigningKey, MlsStoreRoot, RineCipherSuite, RineMlsClient, RineMlsOptions,
};
use tempfile::TempDir;

/// One rine agent: its Ed25519 identity, its own private state directory, and a
/// client over both. Agents never share a directory, exactly as they never
/// share a process in production.
pub struct TestAgent {
    pub client: RineMlsClient,
    pub identity: Vec<u8>,
    key: AgentSigningKey,
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
        let dir = tempfile::tempdir().expect("temp dir");
        let store = dir.path().join("mls2");
        let key = AgentSigningKey::from_seed(&[seed_byte; 32]).expect("32-byte seed");

        Self {
            client: open(&store, &key, suite, options),
            identity: key.public_key().to_vec(),
            key,
            store,
            suite,
            options,
            _dir: dir,
        }
    }

    /// A second client over the same on-disk state — what a restarted process
    /// sees. Nothing is carried over in memory.
    pub fn reopen(&self) -> RineMlsClient {
        self.reopen_as(self.suite)
    }

    /// The same agent and the same state directory, but a client built for a
    /// different ciphersuite.
    pub fn reopen_as(&self, suite: RineCipherSuite) -> RineMlsClient {
        open(&self.store, &self.key, suite, self.options)
    }

    pub fn store_path(&self) -> &Path {
        &self.store
    }
}

fn open(
    store: &Path,
    key: &AgentSigningKey,
    suite: RineCipherSuite,
    options: RineMlsOptions,
) -> RineMlsClient {
    RineMlsClient::open_with(MlsStoreRoot::new(store), key, suite, options)
}

/// Run a flow test once per ciphersuite rine speaks. The whole group flow has
/// to hold on the post-quantum suite exactly as it does on the classical one —
/// a suite that only works for key exchange in isolation is not a suite rine
/// can ship. The suite is printed so a failure names which one broke.
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
