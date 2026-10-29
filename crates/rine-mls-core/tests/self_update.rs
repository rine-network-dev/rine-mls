//! A member moves its own leaf to a new key; peers apply it only when their allowed set vouches for the move.

mod common;

use common::group_id;
use common::rotation::rotating_pair;
use common::seat::{allowing, found_pair, Seat};
use rine_mls_core::RineMlsErrorCode;

#[test]
fn self_update_moves_leaf_and_peer_applies() {
    let (a, _r, _a_set, _r_set, mut a_group, mut r_group, _id) = rotating_pair(0xC1);

    let bundle = a_group.commit_update(&a.seed(1)).expect("commit update");
    assert_eq!(
        r_group.apply_commit(&bundle.commit).expect("apply"),
        bundle.epoch,
    );
    assert_eq!(
        a_group.apply_pending_commit().expect("apply pending"),
        bundle.epoch,
    );

    let roster = r_group.member_identities().expect("enumerate tree");
    let leaf = roster
        .iter()
        .find(|leaf| leaf.identity == a.agent_id())
        .expect("a is seated");
    assert_eq!(leaf.signature_key, a.public_key(1));

    let payload = a_group.encrypt_application_message(b"after").expect("send");
    assert_eq!(
        r_group
            .decrypt_application_message(&payload)
            .expect("read")
            .envelope,
        b"after",
    );
}

#[test]
fn self_update_applies_after_receiver_learns_newer_generation() {
    let id = group_id(0xC2);
    let a = Seat::new("agent-a", 16);
    let r = Seat::new("agent-r", 48);
    let a_set = allowing(&[(&a, 0), (&a, 1), (&r, 0)]);
    let r_set = allowing(&[(&a, 0), (&a, 1), (&a, 2), (&r, 0)]);
    let (mut a_group, mut r_group) = found_pair(&id, &a, &a_set, &r, &r_set);

    let bundle = a_group.commit_update(&a.seed(1)).expect("commit update");
    assert_eq!(
        r_group.apply_commit(&bundle.commit).expect("apply"),
        bundle.epoch,
    );
}

#[test]
fn self_update_to_older_generation_refused() {
    let (a, _r, _a_set, _r_set, mut a_group, mut r_group, _id) = rotating_pair(0xC3);

    let first = a_group.commit_update(&a.seed(1)).expect("commit update");
    a_group.apply_pending_commit().expect("apply pending");
    r_group.apply_commit(&first.commit).expect("apply");

    let older = a_group
        .commit_update(&a.seed(0))
        .expect("the older-key commit is built locally");
    let error = r_group
        .apply_commit(&older.commit)
        .expect_err("an older key is refused");
    assert_eq!(error.code(), RineMlsErrorCode::Protocol, "got {error:?}");
}

#[test]
fn self_update_lagging_receiver_admits_then_applies() {
    let id = group_id(0xC4);
    let a = Seat::new("agent-a", 16);
    let r = Seat::new("agent-r", 48);
    let a_set = allowing(&[(&a, 0), (&a, 1), (&r, 0)]);
    let r_set = allowing(&[(&a, 0), (&r, 0)]);
    let (mut a_group, mut r_group) = found_pair(&id, &a, &a_set, &r, &r_set);

    let bundle = a_group.commit_update(&a.seed(1)).expect("commit update");
    let error = r_group
        .apply_commit(&bundle.commit)
        .expect_err("a:1 is unverified");
    assert_eq!(
        error.code(),
        RineMlsErrorCode::PeerNotAdmitted,
        "got {error:?}",
    );
    assert_eq!(error.refused_peer(), Some(a.agent_id()));

    a.allow(&r_set, 1);
    assert_eq!(
        r_group.apply_commit(&bundle.commit).expect("retry"),
        bundle.epoch,
    );
}

#[test]
fn self_update_same_key_refused() {
    let (a, _r, _a_set, _r_set, mut a_group, _r_group, _id) = rotating_pair(0xC5);

    let epoch = a_group.epoch();
    let error = a_group
        .commit_update(&a.seed(0))
        .expect_err("the leaf already carries that key");
    assert_eq!(
        error.code(),
        RineMlsErrorCode::LeafAlreadyCurrent,
        "got {error:?}",
    );
    assert_eq!(a_group.pending_commit_epoch(), None);
    assert_eq!(a_group.epoch(), epoch);
}

#[test]
fn self_update_signer_leaf_mismatch_refused() {
    let id = group_id(0xC6);
    let a = Seat::new("agent-a", 16);
    let r = Seat::new("agent-r", 48);
    let a_set = allowing(&[(&a, 0), (&a, 1), (&r, 0)]);
    let r_set = allowing(&[(&a, 0), (&a, 1), (&r, 0)]);

    let a_kp = a
        .open(&a_set, 0)
        .generate_key_package()
        .expect("key package");
    let (_, bundle) = r
        .open(&r_set, 0)
        .create_group_with_members(&id, &[a_kp])
        .expect("r founds with a");
    let mut a_group = a
        .open(&a_set, 1)
        .join_from_welcome(&bundle.welcomes[0])
        .expect("a joins signing with gen1");

    let error = a_group
        .commit_update(&a.seed(1))
        .expect_err("the signer is not the leaf key");
    assert_eq!(
        error.code(),
        RineMlsErrorCode::SignerLeafMismatch,
        "got {error:?}",
    );
    assert_eq!(a_group.pending_commit_epoch(), None);
}
