//! Strict current+1 epoch ordering, the client-side mirror of the rine
//! server's epoch CAS: a replayed or skipped commit is refused, not applied.

mod common;

use common::{for_each_suite, group_id, TestAgent};
use rine_mls_core::RineMlsError;

#[test]
fn test_apply_commit_when_replayed_is_refused_by_the_epoch_cas() {
    for_each_suite(|suite| {
        let alice = TestAgent::new(1, suite);
        let bob = TestAgent::new(2, suite);
        let carol = TestAgent::new(3, suite);

        let (mut alice_group, _) = alice.client.create_group(&group_id(0xA7)).expect("create");
        let add = alice_group
            .add_member(&bob.client.generate_key_package().expect("key package"))
            .expect("add commit");
        let mut bob_group = bob
            .client
            .join_from_welcome(&add.welcomes[0])
            .expect("welcome join");

        let (_, carol_commit) = carol
            .client
            .join_by_external_commit(&add.group_info)
            .expect("external join");

        assert_eq!(
            bob_group.apply_commit(&carol_commit.commit).expect("first"),
            3
        );

        let replayed = bob_group.apply_commit(&carol_commit.commit).unwrap_err();

        assert!(
            matches!(
                replayed,
                RineMlsError::EpochConflict {
                    current: 3,
                    commit: 2
                }
            ),
            "expected an epoch conflict, got {replayed}",
        );
        assert_eq!(bob_group.epoch(), 3, "the refused commit changed nothing");
    });
}

#[test]
fn test_apply_commit_when_an_epoch_was_skipped_is_refused_by_the_epoch_cas() {
    for_each_suite(|suite| {
        let alice = TestAgent::new(1, suite);
        let bob = TestAgent::new(2, suite);
        let carol = TestAgent::new(3, suite);

        let (mut alice_group, _) = alice.client.create_group(&group_id(0xA8)).expect("create");
        let add_bob = alice_group
            .add_member(&bob.client.generate_key_package().expect("key package"))
            .expect("add bob");
        let mut bob_group = bob
            .client
            .join_from_welcome(&add_bob.welcomes[0])
            .expect("welcome join");

        let add_carol = alice_group
            .add_member(&carol.client.generate_key_package().expect("key package"))
            .expect("add carol");
        let removal = alice_group
            .remove_member(
                alice_group
                    .member_index(&carol.identity)
                    .expect("carol leaf"),
            )
            .expect("remove carol");

        // Bob is at epoch 2 and is handed the epoch-3 commit first: applying it
        // would leave a hole no later commit can fill.
        let skipped = bob_group.apply_commit(&removal.commit).unwrap_err();

        assert!(
            matches!(
                skipped,
                RineMlsError::EpochConflict {
                    current: 2,
                    commit: 3
                }
            ),
            "expected an epoch conflict, got {skipped}",
        );

        bob_group.apply_commit(&add_carol.commit).expect("in order");
        assert_eq!(
            bob_group.apply_commit(&removal.commit).expect("in order"),
            4
        );
    });
}
