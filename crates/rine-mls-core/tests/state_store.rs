//! Local MLS state: file-backed, owner-only, and never leaving the machine.

mod common;

use std::fs;
use std::path::Path;

use common::{for_each_suite, group_id, TestAgent};

#[cfg(unix)]
fn mode(path: &Path) -> u32 {
    use std::os::unix::fs::PermissionsExt;

    fs::metadata(path)
        .unwrap_or_else(|e| panic!("stat {}: {e}", path.display()))
        .permissions()
        .mode()
        & 0o777
}

fn state_path(agent: &TestAgent, id: &[u8]) -> std::path::PathBuf {
    agent
        .store_path()
        .join("groups")
        .join(hex::encode(id))
        .join("state.bin")
}

#[test]
fn test_group_state_when_reloaded_by_a_new_client_continues_the_ratchet() {
    for_each_suite(|suite| {
        let alice = TestAgent::new(1, suite);
        let bob = TestAgent::new(2, suite);
        let id = group_id(0xB1);

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

        let ciphertext = alice_group
            .encrypt_application_message(b"sent while bob was offline")
            .expect("encrypt");

        // A fresh client over the same directory: everything it needs came off disk.
        let reopened = bob.reopen();
        let mut bob_group = reopened.load_group(&id).expect("load from disk");

        assert_eq!(bob_group.epoch(), 2);
        assert_eq!(
            bob_group
                .decrypt_application_message(&ciphertext)
                .expect("decrypt after reload")
                .envelope,
            b"sent while bob was offline",
        );
    });
}

#[test]
fn test_group_state_when_never_saved_is_absent_from_disk() {
    for_each_suite(|suite| {
        let alice = TestAgent::new(1, suite);
        let id = group_id(0xB2);

        let (mut group, _) = alice.client.create_group(&id).expect("create");
        group
            .encrypt_application_message(b"unsaved work")
            .expect("encrypt");

        assert!(
            !state_path(&alice, &id).exists(),
            "state must not be written until save(); a commit the server rejects \
             has to leave no forked state behind",
        );
        assert!(alice.reopen().load_group(&id).is_err());

        group.save().expect("persist");

        assert!(state_path(&alice, &id).exists());
        assert_eq!(alice.reopen().load_group(&id).expect("load").epoch(), 1);
    });
}

#[test]
fn test_group_state_when_many_epochs_pass_stays_loadable() {
    for_each_suite(|suite| {
        let alice = TestAgent::new(1, suite);
        let bob = TestAgent::new(2, suite);
        let id = group_id(0xB3);

        let (mut alice_group, _) = alice.client.create_group(&id).expect("create");
        let add = alice_group
            .add_member(&bob.client.generate_key_package().expect("key package"))
            .expect("add commit");
        let mut bob_group = bob
            .client
            .join_from_welcome(&add.welcomes[0])
            .expect("welcome join");

        // Six more epochs of real churn: three short-lived members join and leave.
        for seed in 3..6u8 {
            let transient = TestAgent::new(seed, suite);

            let joined = alice_group
                .add_member(
                    &transient
                        .client
                        .generate_key_package()
                        .expect("key package"),
                )
                .expect("add commit");
            bob_group.apply_commit(&joined.commit).expect("sync add");
            bob_group.save().expect("persist");

            let left = alice_group
                .remove_member(
                    alice_group
                        .member_index(&transient.identity)
                        .expect("transient leaf"),
                )
                .expect("remove commit");
            bob_group.apply_commit(&left.commit).expect("sync remove");
            bob_group.save().expect("persist");
        }

        assert_eq!(bob_group.epoch(), 8);

        let mut reloaded = bob.reopen().load_group(&id).expect("load from disk");

        assert_eq!(reloaded.epoch(), 8);
        let ciphertext = alice_group
            .encrypt_application_message(b"eight epochs in")
            .expect("encrypt");
        assert_eq!(
            reloaded
                .decrypt_application_message(&ciphertext)
                .expect("decrypt")
                .envelope,
            b"eight epochs in",
        );
    });
}

#[cfg(unix)]
#[test]
fn test_state_files_when_written_are_owner_only() {
    for_each_suite(|suite| {
        let alice = TestAgent::new(1, suite);
        let bob = TestAgent::new(2, suite);
        let id = group_id(0xB4);

        bob.client.generate_key_package().expect("key package");

        let (mut group, _) = alice.client.create_group(&id).expect("create");
        group.save().expect("persist");

        let group_dir = alice.store_path().join("groups").join(hex::encode(id));

        assert_eq!(mode(&group_dir), 0o700);
        assert_eq!(mode(&group_dir.join("state.bin")), 0o600);
        assert_eq!(mode(&group_dir.join("epochs")), 0o700);

        let key_packages = bob.store_path().join("key_packages");
        assert_eq!(mode(&key_packages), 0o700);

        for entry in fs::read_dir(&key_packages).expect("key package dir") {
            assert_eq!(mode(&entry.expect("entry").path()), 0o600);
        }
    });
}

#[test]
fn test_key_package_private_half_when_used_to_join_is_consumed() {
    for_each_suite(|suite| {
        let alice = TestAgent::new(1, suite);
        let bob = TestAgent::new(2, suite);

        let key_package = bob.client.generate_key_package().expect("key package");
        let stored = bob.store_path().join("key_packages");
        assert_eq!(fs::read_dir(&stored).expect("dir").count(), 1);

        let (mut group, _) = alice.client.create_group(&group_id(0xB5)).expect("create");
        let add = group.add_member(&key_package).expect("add commit");
        let mut bob_group = bob
            .client
            .join_from_welcome(&add.welcomes[0])
            .expect("welcome join");

        assert_eq!(
            fs::read_dir(&stored).expect("dir").count(),
            1,
            "persist before consume: a join that is never saved must stay retryable",
        );

        bob_group.save().expect("persist");

        assert_eq!(
            fs::read_dir(&stored).expect("dir").count(),
            0,
            "MLS KeyPackages are single-use; the private half must not survive a saved join",
        );
    });
}
