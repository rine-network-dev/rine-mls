//! The self-update commit is held pending on the committer: nothing moves until
//! it is applied, and dropping it restores the handle.

mod common;

use common::escrow;
use common::group_id;
use common::rotation::{pair, pair_with};
use common::seat::{leaf_key_of, own_key, send_and_read};

#[test]
fn self_update_pending_leaves_state_untouched() {
    let id = group_id(0xD1);
    let (a, _r, mut a_group, mut r_group, _) = pair(&id);

    let bundle = a_group.commit_update(&a.seed(1)).expect("commit update");

    assert_eq!(a_group.epoch(), 1, "the founding epoch is untouched");
    assert_eq!(own_key(&a_group), a.public_key(0).to_vec());
    assert_eq!(a_group.pending_commit_epoch(), Some(2));
    assert_eq!(bundle.epoch, 2);

    send_and_read(&mut a_group, &mut r_group, b"still at epoch one");
    assert_eq!(
        leaf_key_of(&r_group, a.agent_id()),
        a.public_key(0).to_vec()
    );
}

#[test]
fn self_update_pending_apply_moves_leaf() {
    let id = group_id(0xD2);
    let (a, _r, mut a_group, mut r_group, _) = pair(&id);

    let bundle = a_group.commit_update(&a.seed(1)).expect("commit update");
    assert_eq!(a_group.apply_pending_commit().expect("apply"), 2);
    assert_eq!(own_key(&a_group), a.public_key(1).to_vec());
    assert_eq!(a_group.pending_commit_epoch(), None);

    r_group
        .apply_commit(&bundle.commit)
        .expect("the peer applies");
    send_and_read(&mut a_group, &mut r_group, b"rotated");
    assert_eq!(
        leaf_key_of(&r_group, a.agent_id()),
        a.public_key(1).to_vec()
    );
}

#[test]
fn self_update_pending_clear_restores() {
    let id = group_id(0xD3);
    let (a, _r, mut a_group, mut r_group, _) = pair(&id);

    a_group.commit_update(&a.seed(1)).expect("commit update");
    a_group.clear_pending_commit();

    assert_eq!(a_group.pending_commit_epoch(), None);
    assert_eq!(a_group.epoch(), 1);
    assert_eq!(own_key(&a_group), a.public_key(0).to_vec());
    send_and_read(&mut a_group, &mut r_group, b"dropped");

    let second = a_group.commit_update(&a.seed(1)).expect("retry");
    r_group
        .apply_commit(&second.commit)
        .expect("the peer applies the retry");
    assert_eq!(
        leaf_key_of(&r_group, a.agent_id()),
        a.public_key(1).to_vec()
    );
}

#[test]
fn self_update_pending_survives_reload() {
    let id = group_id(0xD4);
    let (a, r, mut a_group, mut r_group, set) = pair(&id);

    // Drain the founding exports so only the update's epoch is new.
    let _ = escrow::take(&mut a_group);
    let bundle = a_group.commit_update(&a.seed(1)).expect("commit update");
    a_group.save().expect("save the pending commit");

    let mut reloaded = a.open(&set, 0).load_group(&id).expect("reload");
    assert_eq!(reloaded.pending_commit_epoch(), Some(2));
    assert_eq!(reloaded.apply_pending_commit().expect("apply"), 2);
    assert_eq!(own_key(&reloaded), a.public_key(1).to_vec());
    assert!(escrow::take(&mut reloaded).iter().any(|e| e.epoch == 2));
    r_group
        .apply_commit(&bundle.commit)
        .expect("the peer applies");

    // A dropped pending commit must not come back after a reload.
    let id2 = group_id(0xD5);
    let (mut a_group, _, set) = pair_with(&id2, &a, &r, &[]);
    a_group.commit_update(&a.seed(1)).expect("commit update");
    a_group.save().expect("save the pending commit");
    let mut reloaded = a.open(&set, 0).load_group(&id2).expect("reload");
    reloaded.clear_pending_commit();
    reloaded.save().expect("save the cleared handle");
    let reloaded = a.open(&set, 0).load_group(&id2).expect("reload again");
    assert_eq!(reloaded.pending_commit_epoch(), None);
}
