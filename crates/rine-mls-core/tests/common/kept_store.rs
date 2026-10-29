//! A member with a kept group directory, which is what a re-entry, an external
//! join or a resync over earlier state starts from, and a byte-level view of
//! that directory to prove a path left it as it was.

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

use rine_mls_core::{RineCipherSuite, RineMlsGroup};

use super::{group_dir, group_id, TestAgent};

pub const SUITE: RineCipherSuite = RineCipherSuite::DEFAULT;

/// Alice founds with Bob and adds Carol and Dave. Bob applies and saves every
/// commit, so he sits at epoch 3 with prior epochs 1 and 2 on disk.
pub struct KeptStore {
    pub id: Vec<u8>,
    pub alice: TestAgent,
    pub alice_group: RineMlsGroup,
    pub bob: TestAgent,
    pub bob_group: RineMlsGroup,
    pub carol: TestAgent,
    group_infos: BTreeMap<u64, Vec<u8>>,
}

impl KeptStore {
    pub fn new(tag: u8) -> Self {
        let id = group_id(tag).to_vec();
        let alice = TestAgent::new(0x11, SUITE);
        let bob = TestAgent::new(0x12, SUITE);
        let carol = TestAgent::new(0x13, SUITE);
        let dave = TestAgent::new(0x14, SUITE);

        let (mut alice_group, founding) = alice
            .client
            .create_group_with_members(&id, &[bob.client.generate_key_package().expect("kp")])
            .expect("found with bob");
        let mut bob_group = bob
            .client
            .join_from_welcome(&founding.welcomes[0])
            .expect("bob joins");
        bob_group.save().expect("save");

        let mut group_infos = BTreeMap::new();
        for joiner in [&carol, &dave] {
            group_infos.insert(alice_group.epoch(), alice_group.group_info().expect("gi"));
            let add = alice_group
                .add_member(&joiner.client.generate_key_package().expect("kp"))
                .expect("add");
            bob_group
                .apply_commit(&add.commit)
                .expect("bob applies the add");
            bob_group.save().expect("save");
        }
        group_infos.insert(alice_group.epoch(), alice_group.group_info().expect("gi"));
        assert_eq!(bob_group.epoch(), 3);

        let kept = Self {
            id,
            alice,
            alice_group,
            bob,
            bob_group,
            carol,
            group_infos,
        };
        assert!(
            !kept.bob_epochs().is_empty(),
            "precondition: bob's store retains prior epochs",
        );
        kept
    }

    /// Alice's GroupInfo as it was at `epoch`, a genuine one Bob passed through.
    pub fn group_info_at(&self, epoch: u64) -> &[u8] {
        &self.group_infos[&epoch]
    }

    pub fn bob_dir(&self) -> PathBuf {
        group_dir(self.bob.store_path(), &self.id)
    }

    /// Alice removes Bob, who applies and saves his removal: the whole group
    /// directory stays on disk.
    pub fn remove_bob(&mut self) {
        let leaf = self
            .alice_group
            .member_index(&self.bob.identity)
            .expect("bob's leaf");
        let removal = self.alice_group.remove_member(leaf).expect("remove bob");
        self.bob_group
            .apply_commit(&removal.commit)
            .expect("bob applies his removal");
        self.bob_group.save().expect("save");
    }

    /// Bob's current state is lost while his retained epochs survive.
    pub fn lose_bob_state(&self) {
        fs::remove_file(self.bob_dir().join("state.bin")).expect("drop the state file");
    }

    /// Bob's retained epoch files, by name, oldest first.
    pub fn bob_epochs(&self) -> Vec<String> {
        let mut names: Vec<String> = fs::read_dir(self.bob_dir().join("epochs"))
            .expect("epochs dir")
            .map(|e| e.expect("entry").file_name().into_string().expect("utf8"))
            .collect();
        names.sort();
        names
    }
}

/// Every file under `dir`, by path relative to it, with its bytes.
pub fn snapshot(dir: &Path) -> BTreeMap<PathBuf, Vec<u8>> {
    let mut files = BTreeMap::new();
    collect(dir, dir, &mut files);
    assert!(!files.is_empty(), "precondition: the directory holds state");
    files
}

/// Rewrites `dir` to hold exactly the files of an earlier `snapshot`.
pub fn restore(dir: &Path, files: &BTreeMap<PathBuf, Vec<u8>>) {
    fs::remove_dir_all(dir).expect("drop the live directory");
    for (relative, bytes) in files {
        let path = dir.join(relative);
        fs::create_dir_all(path.parent().expect("under dir")).expect("create dir");
        fs::write(path, bytes).expect("write file");
    }
}

fn collect(root: &Path, dir: &Path, files: &mut BTreeMap<PathBuf, Vec<u8>>) {
    for entry in fs::read_dir(dir).expect("read dir") {
        let path = entry.expect("dir entry").path();
        if path.is_dir() {
            collect(root, &path, files);
        } else {
            let relative = path.strip_prefix(root).expect("under root").to_path_buf();
            files.insert(relative, fs::read(&path).expect("read file"));
        }
    }
}
