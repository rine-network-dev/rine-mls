//! What a returning member can still read.
//!
//! rine's undelivered queue never drops an undelivered message, so a member
//! that has been away is handed messages from epochs the group has long since
//! committed past. Whether those messages are readable is decided entirely by
//! how many epoch secrets the member kept — hence the default that reaches the
//! whole backlog, and the knob a deployment sets when it would rather lose
//! backlog than keep old secrets on disk.

mod common;

use std::fs;
use std::num::NonZeroUsize;

use common::{group_id, TestAgent};
use rine_mls_core::{EpochRetention, RineCipherSuite, RineMlsGroup, RineMlsOptions};

const CHURN_COMMITS: u8 = 6;

/// Alice founds a group with Bob, sends one message at the epoch Bob joined at,
/// then churns the group through `CHURN_COMMITS` further epochs which Bob
/// applies and persists. Returns the early ciphertext and the epoch reached.
fn backlog_scenario(bob: &TestAgent, suite: RineCipherSuite) -> (Vec<u8>, u64) {
    let alice = TestAgent::new(1, suite);
    let id = group_id(0xD1);

    let (mut alice_group, _) = alice.client.create_group(&id).expect("create");
    let add = alice_group
        .add_member(&bob.client.generate_key_package().expect("key package"))
        .expect("add commit");

    let mut bob_group = bob
        .client
        .join_from_welcome(&add.welcomes[0])
        .expect("welcome join");
    bob_group.save().expect("persist");

    // Sent while Bob is present but before he goes away: the message the
    // undelivered queue would still be holding when he comes back.
    let early = alice_group
        .encrypt_application_message(b"queued before the churn")
        .expect("encrypt");

    for seed in 0..CHURN_COMMITS / 2 {
        let transient = TestAgent::new(10 + seed, suite);

        let joined = alice_group
            .add_member(
                &transient
                    .client
                    .generate_key_package()
                    .expect("key package"),
            )
            .expect("add commit");
        sync(&mut bob_group, &joined.commit);

        let left = alice_group
            .remove_member(
                alice_group
                    .member_index(&transient.identity)
                    .expect("transient leaf"),
            )
            .expect("remove commit");
        sync(&mut bob_group, &left.commit);
    }

    let epoch = bob_group.epoch();
    drop(bob_group);

    (early, epoch)
}

fn sync(group: &mut RineMlsGroup, commit: &[u8]) {
    group.apply_commit(commit).expect("apply commit");
    group.save().expect("persist");
}

#[test]
fn test_backlog_when_retention_is_default_stays_decryptable_after_many_commits() {
    for suite in RineCipherSuite::ALL {
        let bob = TestAgent::new(2, suite);
        let (early, epoch) = backlog_scenario(&bob, suite);

        assert!(
            epoch > 3,
            "the scenario has to outrun the old fixed retention of 3 to mean anything",
        );

        // A restarted process: everything it has comes off disk.
        let mut reloaded = bob
            .reopen()
            .load_group(&group_id(0xD1))
            .expect("load from disk");

        assert_eq!(
            reloaded
                .decrypt_application_message(&early)
                .expect("a message the undelivered queue still holds must stay readable")
                .envelope,
            b"queued before the churn",
        );
    }
}

#[test]
fn test_backlog_when_retention_is_tightened_is_traded_away_deliberately() {
    for suite in RineCipherSuite::ALL {
        let bob = TestAgent::with_options(
            2,
            suite,
            RineMlsOptions {
                epoch_retention: EpochRetention::Recent(NonZeroUsize::new(2).unwrap()),
            },
        );
        let (early, _) = backlog_scenario(&bob, suite);

        let mut reloaded = bob
            .reopen()
            .load_group(&group_id(0xD1))
            .expect("load from disk");

        assert!(
            reloaded.decrypt_application_message(&early).is_err(),
            "a deployment that tightened retention has given up this message, \
             and that is the trade it asked for",
        );
    }
}

#[test]
fn test_epoch_secrets_when_retention_is_tightened_are_deleted_from_disk() {
    let suite = RineCipherSuite::Classical;
    let keep = 2;
    let bob = TestAgent::with_options(
        2,
        suite,
        RineMlsOptions {
            epoch_retention: EpochRetention::Recent(NonZeroUsize::new(keep).unwrap()),
        },
    );

    let (_, epoch) = backlog_scenario(&bob, suite);

    let epochs = bob
        .store_path()
        .join("groups")
        .join(hex::encode(group_id(0xD1)))
        .join("epochs");
    let kept = fs::read_dir(&epochs).expect("epochs dir").count();

    assert_eq!(
        kept, keep,
        "retention is a deletion, not a filter: at epoch {epoch} only the newest \
         {keep} epoch secrets may remain on disk",
    );
}

#[test]
fn test_epoch_secrets_when_retention_is_default_are_all_kept_on_disk() {
    let suite = RineCipherSuite::Classical;
    let bob = TestAgent::new(2, suite);

    let (_, epoch) = backlog_scenario(&bob, suite);

    let epochs = bob
        .store_path()
        .join("groups")
        .join(hex::encode(group_id(0xD1)))
        .join("epochs");
    let kept = fs::read_dir(&epochs).expect("epochs dir").count();

    assert!(
        kept as u64 >= epoch - 2,
        "the default keeps every prior epoch: {kept} files at epoch {epoch}",
    );
}
