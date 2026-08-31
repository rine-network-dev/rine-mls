//! The on-disk format of local MLS state: what the tag promises about files
//! written by another release, and what two writers at once may not do to each
//! other.
//!
//! The frame is ciphersuite-independent — it wraps whatever `mls-rs` serialized
//! — so these run once on the default suite rather than once per suite.

mod common;

use std::fs;
use std::path::{Path, PathBuf};
use std::thread;

use common::{group_id, TestAgent};
use mls_rs_core::group::{EpochRecord, GroupState, GroupStateStorage};
use rine_mls_core::{FileGroupStateStorage, MlsStoreRoot, RineCipherSuite, StoreError};
use zeroize::Zeroizing;

/// The on-disk frame, spelled out here rather than imported from the crate:
/// these bytes are a compatibility contract with files already written on
/// users' machines, so changing them has to fail a test rather than pass
/// quietly.
const FRAME_MAGIC: &[u8] = b"RINEMLS\0";
const FRAME_VERSION: u8 = 1;

fn group_dir(store: &Path, id: &[u8]) -> PathBuf {
    store.join("groups").join(hex::encode(id))
}

/// Rewrite a file the way 0.1.0 wrote it: the `mls-rs` payload, no tag. Files
/// that already carry no tag are left alone, so the test states the guarantee
/// ("an untagged file opens") rather than the mechanism.
fn untag(path: &Path) {
    let bytes = fs::read(path).unwrap_or_else(|e| panic!("read {}: {e}", path.display()));

    if let Some(tagged) = bytes.strip_prefix(FRAME_MAGIC) {
        fs::write(path, &tagged[1..]).expect("write untagged");
    }

    assert!(
        !fs::read(path).expect("reread").starts_with(FRAME_MAGIC),
        "{} still carries a tag, so this fixture is not a 0.1.0 file",
        path.display(),
    );
}

fn untag_group_state(store: &Path, id: &[u8]) {
    let dir = group_dir(store, id);
    untag(&dir.join("state.bin"));

    for entry in fs::read_dir(dir.join("epochs")).expect("epochs dir") {
        untag(&entry.expect("entry").path());
    }
}

/// The payload a `GroupStateStorage` read handed back, out of its zeroizing
/// wrapper so a test can compare it to the bytes it wrote.
fn stored(read: Result<Option<Zeroizing<Vec<u8>>>, StoreError>) -> Option<Vec<u8>> {
    read.expect("read").map(|bytes| bytes.to_vec())
}

fn storage(store: &Path) -> FileGroupStateStorage {
    FileGroupStateStorage::new(MlsStoreRoot::new(store))
}

fn write_state(store: &Path, id: &[u8], payload: &[u8]) {
    let dir = group_dir(store, id).join("epochs");
    fs::create_dir_all(&dir).expect("group dir");
    fs::write(dir.parent().expect("group dir").join("state.bin"), payload).expect("write state");
}

#[test]
fn test_group_state_when_written_by_the_previous_release_still_opens() {
    let alice = TestAgent::new(1, RineCipherSuite::DEFAULT);
    let bob = TestAgent::new(2, RineCipherSuite::DEFAULT);
    let id = group_id(0xF1);

    let (mut alice_group, _) = alice.client.create_group(&id).expect("create");
    let add = alice_group
        .add_member(&bob.client.generate_key_package().expect("key package"))
        .expect("add commit");

    let mut bob_group = bob
        .client
        .join_from_welcome(&add.welcomes[0])
        .expect("welcome join");
    bob_group.save().expect("persist");
    drop(bob_group);

    // Everything bob has on disk now looks exactly as 0.1.0 left it.
    untag_group_state(bob.store_path(), &id);

    let ciphertext = alice_group
        .encrypt_application_message(b"written before the tag existed")
        .expect("encrypt");
    let mut reloaded = bob
        .reopen()
        .load_group(&id)
        .expect("an untagged group must still open");

    assert_eq!(reloaded.epoch(), 2);
    assert_eq!(
        reloaded
            .decrypt_application_message(&ciphertext)
            .expect("decrypt")
            .envelope,
        b"written before the tag existed",
    );
}

#[test]
fn test_key_package_when_written_by_the_previous_release_still_joins() {
    let alice = TestAgent::new(3, RineCipherSuite::DEFAULT);
    let bob = TestAgent::new(4, RineCipherSuite::DEFAULT);

    let key_package = bob.client.generate_key_package().expect("key package");

    for entry in fs::read_dir(bob.store_path().join("key_packages")).expect("dir") {
        untag(&entry.expect("entry").path());
    }

    let (mut group, _) = alice.client.create_group(&group_id(0xF2)).expect("create");
    let add = group.add_member(&key_package).expect("add commit");

    assert_eq!(
        bob.reopen()
            .join_from_welcome(&add.welcomes[0])
            .expect("an untagged KeyPackage private half must still join")
            .epoch(),
        2,
    );
}

#[test]
fn test_group_state_when_written_carries_the_format_tag() {
    let dir = tempfile::tempdir().expect("temp dir");
    let mut store = storage(dir.path());
    let id = vec![0xF3; 16];
    let payload = b"mls-rs serialized group state".to_vec();

    store
        .write(
            GroupState {
                id: id.clone(),
                data: Zeroizing::new(payload.clone()),
            },
            vec![EpochRecord::new(1, Zeroizing::new(payload.clone()))],
            Vec::new(),
        )
        .expect("write");

    for file in ["state.bin", "epochs/1.bin"] {
        let bytes = fs::read(group_dir(dir.path(), &id).join(file)).expect("read");

        assert_eq!(
            &bytes[..FRAME_MAGIC.len()],
            FRAME_MAGIC,
            "{file} is untagged"
        );
        assert_eq!(bytes[FRAME_MAGIC.len()], FRAME_VERSION, "{file} version");
        assert_eq!(
            &bytes[FRAME_MAGIC.len() + 1..],
            &payload[..],
            "{file} payload"
        );
    }

    assert_eq!(stored(store.state(&id)), Some(payload.clone()));
    assert_eq!(stored(store.epoch(&id, 1)), Some(payload));
}

#[test]
fn test_group_state_when_stored_untagged_reads_back_verbatim() {
    let dir = tempfile::tempdir().expect("temp dir");
    let id = vec![0xF4; 16];
    let payload = b"raw mls-rs bytes, exactly as 0.1.0 wrote them".to_vec();

    write_state(dir.path(), &id, &payload);

    assert_eq!(stored(storage(dir.path()).state(&id)), Some(payload));
}

#[test]
fn test_group_state_when_tagged_with_a_future_version_is_refused_by_name() {
    let dir = tempfile::tempdir().expect("temp dir");
    let id = vec![0xF5; 16];

    let mut tagged = FRAME_MAGIC.to_vec();
    tagged.push(FRAME_VERSION + 1);
    tagged.extend_from_slice(b"a layout this build cannot know");
    write_state(dir.path(), &id, &tagged);

    let err = storage(dir.path()).state(&id).unwrap_err();

    assert!(
        matches!(
            err,
            StoreError::UnknownFormatVersion { version, .. } if version == FRAME_VERSION + 1,
        ),
        "a newer format must be named, not misread as corruption or as state: {err}",
    );
}

#[test]
fn test_load_group_when_the_state_is_from_a_future_format_fails_loudly() {
    let alice = TestAgent::new(5, RineCipherSuite::DEFAULT);
    let id = group_id(0xF6);

    let (mut group, _) = alice.client.create_group(&id).expect("create");
    group.save().expect("persist");

    let state = group_dir(alice.store_path(), &id).join("state.bin");
    let mut bytes = fs::read(&state).expect("read");
    bytes[FRAME_MAGIC.len()] = FRAME_VERSION + 1;
    fs::write(&state, &bytes).expect("write");

    let err = alice
        .reopen()
        .load_group(&id)
        .err()
        .expect("a state this build cannot read must not load")
        .to_string();

    // mls-rs flattens a storage failure into its own opaque error wrapper on
    // the load path, keeping the message and dropping the type — so the text is
    // what tells an operator to upgrade rather than to recreate the group.
    assert!(
        err.contains("format version") && err.contains(&(FRAME_VERSION + 1).to_string()),
        "state written by a newer rine-mls must say so, got: {err}",
    );
}

#[test]
fn test_group_state_when_written_concurrently_is_never_a_splice_of_two_writers() {
    // One writer per byte value, each payload large enough that two of them
    // sharing a temp file would interleave rather than happen to serialize.
    const WRITERS: u8 = 8;
    const PAYLOAD_BYTES: usize = 1 << 20;

    let dir = tempfile::tempdir().expect("temp dir");
    let root = MlsStoreRoot::new(dir.path());
    let id = vec![0xF7; 16];

    thread::scope(|scope| {
        for writer in 1..=WRITERS {
            let mut store = FileGroupStateStorage::new(root.clone());
            let id = id.clone();

            scope.spawn(move || {
                store
                    .write(
                        GroupState {
                            id,
                            data: Zeroizing::new(vec![writer; PAYLOAD_BYTES]),
                        },
                        vec![EpochRecord::new(
                            1,
                            Zeroizing::new(vec![writer; PAYLOAD_BYTES]),
                        )],
                        Vec::new(),
                    )
                    .expect("concurrent write");
            });
        }
    });

    let store = storage(dir.path());

    for (what, bytes) in [
        ("state", store.state(&id).expect("state")),
        ("epoch 1", store.epoch(&id, 1).expect("epoch")),
    ] {
        let bytes = bytes.unwrap_or_else(|| panic!("{what} is missing"));
        let writer = bytes[0];

        assert_eq!(bytes.len(), PAYLOAD_BYTES, "{what} is not one whole write");
        assert!((1..=WRITERS).contains(&writer), "{what} names no writer");
        assert!(
            bytes.iter().all(|byte| *byte == writer),
            "{what} is a splice of two writers, not the work of one",
        );
    }

    assert_eq!(
        store.max_epoch_id(&id).expect("max epoch"),
        Some(1),
        "a temp file must never be counted as an epoch",
    );
}
