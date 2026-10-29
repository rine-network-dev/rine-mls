//! A member that holds group state refuses a GroupInfo older than that state,
//! and still resyncs from one at the same epoch or ahead of it.

mod common;

use common::kept_store::{snapshot, KeptStore};
use mls_rs::error::MlsError;
use rine_mls_core::RineMlsError;

#[test]
fn an_older_group_info_is_refused_while_local_state_is_newer() {
    let scene = KeptStore::new(0xB1);
    let before = snapshot(&scene.bob_dir());

    let refused = scene
        .bob
        .client
        .resync_from_group_info(scene.group_info_at(2))
        .err()
        .expect("a GroupInfo at epoch 2 is refused while bob holds epoch 3");

    assert_eq!(refused.code().as_str(), "RINE_MLS_PROTOCOL");
    assert!(matches!(refused, RineMlsError::Mls(MlsError::InvalidEpoch)));
    assert_eq!(snapshot(&scene.bob_dir()), before);
}

/// Bob's own commit was never accepted and another member advanced the group.
#[test]
fn a_group_info_one_epoch_ahead_resyncs_and_saves() {
    let mut scene = KeptStore::new(0xB2);
    let carol_leaf = scene
        .alice_group
        .member_index(&scene.carol.identity)
        .expect("carol's leaf");
    scene
        .alice_group
        .remove_member(carol_leaf)
        .expect("alice advances to epoch 4");

    let (mut resynced, bundle) = scene
        .bob
        .client
        .resync_from_group_info(&scene.alice_group.group_info().expect("gi"))
        .expect("the resync builds");
    resynced.save().expect("save");
    scene
        .alice_group
        .apply_commit(&bundle.commit)
        .expect("alice applies the resync");

    let reloaded = scene.bob.reopen().load_group(&scene.id).expect("reload");
    assert_eq!(reloaded.epoch(), scene.alice_group.epoch());
}

#[test]
fn an_equal_epoch_group_info_resyncs() {
    let mut scene = KeptStore::new(0xB3);

    let (mut resynced, bundle) = scene
        .bob
        .client
        .resync_from_group_info(scene.group_info_at(3))
        .expect("the resync builds");
    resynced.save().expect("save");
    scene
        .alice_group
        .apply_commit(&bundle.commit)
        .expect("alice applies the resync");

    assert_eq!(resynced.epoch(), scene.alice_group.epoch());
}
