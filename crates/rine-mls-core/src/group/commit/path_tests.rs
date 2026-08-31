//! Every commit rine builds carries an UpdatePath.
//!
//! This lives beside the commit builder rather than in `tests/` because the
//! evidence is [`CommitOutput::contains_update_path`], which MLS reports on the
//! commit it just built and which no blob on the wire exposes as a field.

use std::path::Path;

use tempfile::TempDir;

use crate::client::RineMlsClient;
use crate::identity::AgentSigningKey;
use crate::store::MlsStoreRoot;
use crate::suite::RineCipherSuite;

/// An Add-only commit is the case MLS lets skip the path: no member's leaf key
/// has to change for a joiner to be admitted. Skipping it means the new epoch's
/// secrets descend from key material the committer already held, so a committer
/// compromised before the commit stays able to read the epoch after it — the
/// group never heals. rine sets `path_required`, so the path is there whatever
/// the commit contains.
#[test]
fn test_add_only_commit_carries_an_update_path() {
    for suite in RineCipherSuite::ALL {
        let dir = tempfile::tempdir().expect("temp dir");
        let alice = open(&dir, "alice", 1, suite);
        let bob = open(&dir, "bob", 2, suite);

        let (mut group, _) = alice.create_group(&[0xC1; 16]).expect("create group");
        let key_package = bob.generate_key_package().expect("key package");

        let (output, _) = group.build_add_commit(&[key_package]).expect("add commit");

        assert!(
            output.contains_update_path,
            "suite 0x{:04X}: an Add-only commit was built with no UpdatePath, so the epoch \
             it creates inherits any compromise of the committer instead of healing it",
            suite.id(),
        );
    }
}

fn open(dir: &TempDir, name: &str, seed_byte: u8, suite: RineCipherSuite) -> RineMlsClient {
    let store: &Path = &dir.path().join(name);
    let key = AgentSigningKey::from_seed(&[seed_byte; 32]).expect("32-byte seed");

    RineMlsClient::open(MlsStoreRoot::new(store), &key, suite)
}
