//! A pending self-update against other commits: a rival commit drops it, it
//! blocks the committer's own, and its GroupInfo admits an external join.

mod common;

use common::group_id;
use common::rotation::{pair, pair_with};
use common::seat::{own_key, Seat};
use rine_mls_core::RineMlsErrorCode;

#[test]
fn self_update_pending_dropped_by_competing_commit() {
    let id = group_id(0xD6);
    let a = Seat::new("agent-a", 16);
    let r = Seat::new("agent-r", 48);
    let s = Seat::new("agent-s", 80);
    let (mut a_group, mut r_group, set) = pair_with(&id, &a, &r, &[&s]);

    a_group.commit_update(&a.seed(1)).expect("commit update");
    let kp = s.open(&set, 0).generate_key_package().expect("key package");
    let r_commit = r_group.add_member(&kp).expect("the peer adds a member");

    assert_eq!(a_group.apply_commit(&r_commit.commit).expect("apply"), 2);
    assert_eq!(own_key(&a_group), a.public_key(0).to_vec());
    assert_eq!(a_group.pending_commit_epoch(), None);

    let bundle = a_group.commit_update(&a.seed(1)).expect("a fresh update");
    assert_eq!(bundle.epoch, 3);
}

#[test]
fn self_update_pending_blocks_other_commits() {
    let id = group_id(0xD7);
    let a = Seat::new("agent-a", 16);
    let r = Seat::new("agent-r", 48);
    let s = Seat::new("agent-s", 80);
    let (mut a_group, r_group, set) = pair_with(&id, &a, &r, &[&s]);

    a_group.commit_update(&a.seed(1)).expect("commit update");
    let kp = s.open(&set, 0).generate_key_package().expect("key package");
    let r_index = r_group.current_member_index().expect("the peer's leaf");

    let refused = [
        a_group.add_member(&kp).expect_err("an Add is refused"),
        a_group
            .remove_member(r_index)
            .expect_err("a Remove is refused"),
        a_group
            .commit_update(&a.seed(1))
            .expect_err("a second update is refused"),
    ];
    for error in refused {
        assert_eq!(
            error.code(),
            RineMlsErrorCode::CommitPending,
            "got {error:?}"
        );
    }

    assert_eq!(a_group.epoch(), 1);
    assert_eq!(own_key(&a_group), a.public_key(0).to_vec());
    assert_eq!(a_group.pending_commit_epoch(), Some(2));
}

#[test]
fn self_update_pending_group_info_joins() {
    let id = group_id(0xD8);
    let a = Seat::new("agent-a", 16);
    let r = Seat::new("agent-r", 48);
    let s = Seat::new("agent-s", 80);
    let (mut a_group, mut r_group, set) = pair_with(&id, &a, &r, &[&s]);

    let bundle = a_group.commit_update(&a.seed(1)).expect("commit update");
    assert_eq!(bundle.epoch, 2);
    assert!(
        !bundle.group_info.is_empty(),
        "the bundle carries a GroupInfo"
    );

    assert_eq!(a_group.apply_pending_commit().expect("apply"), 2);
    assert_eq!(
        r_group.apply_commit(&bundle.commit).expect("peer applies"),
        2
    );

    let (s_group, join) = s
        .open(&set, 0)
        .join_by_external_commit(&bundle.group_info)
        .expect("the fresh seat joins from the pending bundle's GroupInfo");
    assert_eq!(join.epoch, 3);
    assert_eq!(s_group.epoch(), 3);
    r_group
        .apply_commit(&join.commit)
        .expect("peer applies the join");
}

#[test]
fn apply_pending_commit_without_pending_refused() {
    let id = group_id(0xD9);
    let (_a, _r, mut a_group, _, _) = pair(&id);

    let error = a_group
        .apply_pending_commit()
        .expect_err("nothing is pending");
    assert_eq!(
        error.code(),
        RineMlsErrorCode::NoPendingCommit,
        "got {error:?}"
    );
}

#[test]
fn commit_bundle_group_info_from_output() {
    let id = group_id(0xDA);
    let a = Seat::new("agent-a", 16);
    let r = Seat::new("agent-r", 48);
    let s = Seat::new("agent-s", 80);
    let t = Seat::new("agent-t", 112);
    let (mut a_group, mut r_group, set) = pair_with(&id, &a, &r, &[&s, &t]);

    let kp = s.open(&set, 0).generate_key_package().expect("key package");
    let add = a_group.add_member(&kp).expect("add the member");
    r_group
        .apply_commit(&add.commit)
        .expect("the peer applies the Add");

    let (_, join) = t
        .open(&set, 0)
        .join_by_external_commit(&add.group_info)
        .expect("the fresh seat joins from the Add bundle's GroupInfo");
    assert_eq!(join.epoch, 3);
    a_group
        .apply_commit(&join.commit)
        .expect("the adder applies the join");

    let info = a_group.group_info().expect("group info");
    let stale = r_group.current_member_index().expect("the peer's leaf");
    let (resynced, resync) = r
        .open(&set, 0)
        .resync_by_external_commit(&info, stale)
        .expect("the peer resyncs at equality");
    assert_eq!(resynced.epoch(), 4);
    a_group
        .apply_commit(&resync.commit)
        .expect("the adder applies the resync");
}
