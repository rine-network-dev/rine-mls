//! A new group state over a kept group directory, from a Welcome, an external
//! join or a resync, touches nothing on disk until its first save. A Welcome or
//! GroupInfo that is refused, fails verification or is never saved leaves the
//! store exactly as it was.

mod common;

use std::fs;

use common::kept_store::{snapshot, KeptStore, SUITE};
use common::TestAgent;

/// The GroupInfo with the epoch in its group context rewritten to `epoch`.
/// The signature covers the context, so the result no longer verifies.
fn with_forged_epoch(group_info: &[u8], group_id: &[u8], epoch: u64) -> Vec<u8> {
    let mut prefix = vec![u8::try_from(group_id.len()).expect("short id")];
    prefix.extend_from_slice(group_id);
    let at = group_info
        .windows(prefix.len())
        .position(|window| window == prefix.as_slice())
        .expect("the group id in the group context")
        + prefix.len();

    let mut forged = group_info.to_vec();
    forged[at..at + 8].copy_from_slice(&epoch.to_be_bytes());
    assert_ne!(forged, group_info, "precondition: the epoch changed");
    forged
}

#[test]
fn a_welcome_join_dropped_unsaved_leaves_the_store_byte_identical() {
    let mut scene = KeptStore::new(0xA1);
    scene.remove_bob();
    let before = snapshot(&scene.bob_dir());

    let readd = scene
        .alice_group
        .add_member(&scene.bob.client.generate_key_package().expect("kp"))
        .expect("re-add bob");
    let joined = scene
        .bob
        .client
        .join_from_welcome(&readd.welcomes[0])
        .expect("the Welcome joins");
    drop(joined);

    assert_eq!(snapshot(&scene.bob_dir()), before);
}

#[test]
fn an_external_commit_dropped_unsaved_leaves_the_store_byte_identical() {
    let mut scene = KeptStore::new(0xA2);
    scene.remove_bob();
    let before = snapshot(&scene.bob_dir());

    let (joined, _bundle) = scene
        .bob
        .client
        .join_by_external_commit(&scene.alice_group.group_info().expect("gi"))
        .expect("the external join builds");
    drop(joined);

    assert_eq!(snapshot(&scene.bob_dir()), before);
}

#[test]
fn a_group_info_failing_verification_leaves_the_store_byte_identical() {
    let scene = KeptStore::new(0xA3);
    scene.lose_bob_state();
    let before = snapshot(&scene.bob_dir());
    let forged = with_forged_epoch(scene.group_info_at(3), &scene.id, 0);

    assert!(scene.bob.client.resync_from_group_info(&forged).is_err());

    assert_eq!(snapshot(&scene.bob_dir()), before);
}

#[test]
fn with_no_local_state_leftover_epochs_at_or_above_the_floor_are_deleted_on_save() {
    let scene = KeptStore::new(0xA4);
    scene.lose_bob_state();
    assert_eq!(scene.bob_epochs(), ["1.bin", "2.bin"]);

    let (mut resynced, _bundle) = scene
        .bob
        .client
        .resync_from_group_info(scene.group_info_at(1))
        .expect("with no state to compare against, the resync builds");
    assert_eq!(
        scene.bob_epochs(),
        ["1.bin", "2.bin"],
        "nothing is deleted before the save",
    );

    resynced.save().expect("save");

    assert_eq!(
        scene.bob_epochs(),
        ["1.bin"],
        "the dead fork's epoch 2 is gone"
    );
    let reloaded = scene.bob.reopen().load_group(&scene.id).expect("reload");
    assert_eq!(reloaded.epoch(), 2);
}

/// Bob's directory holds a dead fork that ran to epoch 3 under the same group
/// id. A new group of that id re-founded with Bob joins him at epoch 1, and his
/// new handle applies two commits before it is ever saved.
#[test]
fn a_new_handle_processes_commits_before_its_first_save() {
    let scene = KeptStore::new(0xA5);
    let founder = TestAgent::new(0x21, SUITE);
    let dave = TestAgent::new(0x22, SUITE);
    let (mut founder_group, founding) = founder
        .client
        .create_group_with_members(
            &scene.id,
            &[scene.bob.client.generate_key_package().expect("kp")],
        )
        .expect("re-found with bob");
    let mut joined = scene
        .bob
        .client
        .join_from_welcome(&founding.welcomes[0])
        .expect("bob joins the new group");
    assert_eq!(joined.epoch(), 1);

    for joiner in [&scene.carol, &dave] {
        let add = founder_group
            .add_member(&joiner.client.generate_key_package().expect("kp"))
            .expect("add");
        joined
            .apply_commit(&add.commit)
            .expect("the unsaved handle applies the commit");
    }
    joined.save().expect("the first save succeeds");

    let reloaded = scene.bob.reopen().load_group(&scene.id).expect("reload");
    assert_eq!(reloaded.epoch(), founder_group.epoch());
}

#[test]
fn a_save_after_a_failed_adoption_repeats_it_and_succeeds() {
    let mut scene = KeptStore::new(0xA6);
    scene.remove_bob();
    let readd = scene
        .alice_group
        .add_member(&scene.bob.client.generate_key_package().expect("kp"))
        .expect("re-add bob");
    let mut joined = scene
        .bob
        .client
        .join_from_welcome(&readd.welcomes[0])
        .expect("the Welcome joins");

    let blocker = scene.bob_dir().join("floor");
    fs::create_dir(&blocker).expect("a directory where the floor file goes");
    assert!(
        joined.save().is_err(),
        "the adoption cannot write its floor"
    );
    fs::remove_dir(&blocker).expect("unblock");

    joined.save().expect("the retried save adopts and saves");
    let carol_leaf = scene
        .alice_group
        .member_index(&scene.carol.identity)
        .expect("carol's leaf");
    let next = scene
        .alice_group
        .remove_member(carol_leaf)
        .expect("next commit");
    assert_eq!(
        joined
            .apply_commit(&next.commit)
            .expect("the adopted state advances over the kept epochs"),
        scene.alice_group.epoch(),
    );
}
