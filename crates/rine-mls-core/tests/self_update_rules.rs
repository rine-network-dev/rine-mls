//! What a receiver refuses: a resync that changes the key, and the roster that
//! a resync or a new group seats.

mod common;

use common::group_id;
use common::seat::{allowing, found_pair, Seat};
use mls_rs::MlsMessage;
use rine_mls_core::{MemberLeaf, RineMlsError, RineMlsErrorCode};

/// Assert that `seat` occupies a leaf of `roster` at `generation`'s key.
fn assert_seated(roster: &[MemberLeaf], seat: &Seat, generation: u32) {
    let seated = roster.iter().any(|leaf| {
        leaf.identity == seat.agent_id() && leaf.signature_key == seat.public_key(generation)
    });
    assert!(
        seated,
        "{} is not seated at generation {generation}: {roster:?}",
        String::from_utf8_lossy(seat.agent_id()),
    );
}

fn assert_resync_changes_key(error: RineMlsError) {
    assert_eq!(
        error.code(),
        RineMlsErrorCode::ResyncChangesKey,
        "got {error:?}"
    );
}

#[test]
fn external_resync_same_key_applies() {
    let id = group_id(0xE1);
    let a = Seat::new("agent-a", 16);
    let r = Seat::new("agent-r", 48);
    let set = allowing(&[(&a, 0), (&r, 0)]);
    let (mut a_group, r_group) = found_pair(&id, &a, &set, &r, &set);

    let r_index = r_group.current_member_index().expect("r's leaf");
    let (_, bundle) = r
        .open(&set, 0)
        .resync_by_external_commit(&a_group.group_info().expect("group info"), r_index)
        .expect("a resync at equality keeps r's key");

    a_group
        .apply_commit(&bundle.commit)
        .expect("a applies the resync commit");
}

#[test]
fn external_resync_new_key_refused_by_receiver() {
    let id = group_id(0xE2);
    let a = Seat::new("agent-a", 16);
    let r = Seat::new("agent-r", 48);
    let set = allowing(&[(&a, 0), (&a, 1), (&r, 0)]);
    let (a_group, mut r_group) = found_pair(&id, &a, &set, &r, &set);

    // A bare mls-rs client under stock rules enforces nothing about a resync,
    // so it will happily replace a's gen0 leaf with a gen1 leaf.
    let a_index = a_group.current_member_index().expect("a's leaf");
    let info = MlsMessage::from_bytes(&r_group.group_info().expect("group info")).expect("framed");
    let (_, commit) = a
        .stock(&set, 1)
        .external_commit_builder()
        .expect("builder")
        .with_removal(a_index)
        .build(info)
        .expect("stock external commit");
    let commit = commit.to_bytes().expect("commit bytes");

    let error = r_group
        .apply_commit(&commit)
        .expect_err("a resync that changes the key is refused");
    assert_resync_changes_key(error);
}

#[test]
fn external_resync_new_key_refused_by_sender() {
    let id = group_id(0xE3);
    let a = Seat::new("agent-a", 16);
    let r = Seat::new("agent-r", 48);
    let set = allowing(&[(&a, 0), (&a, 1), (&r, 0)]);
    let (a_group, r_group) = found_pair(&id, &a, &set, &r, &set);

    let a_index = a_group.current_member_index().expect("a's leaf");
    let group_info = r_group.group_info().expect("group info");

    let error = a
        .open(&set, 1)
        .resync_by_external_commit(&group_info, a_index)
        .map(|_| ())
        .expect_err("a resync that changes the key is refused");
    assert_resync_changes_key(error);

    let error = a
        .open(&set, 1)
        .resync_from_group_info(&group_info)
        .map(|_| ())
        .expect_err("a resync that changes the key is refused");
    assert_resync_changes_key(error);
}

#[test]
fn rolled_back_update_peer_resyncs_at_equality() {
    let id = group_id(0xE4);
    let a = Seat::new("agent-a", 16);
    let r = Seat::new("agent-r", 48);
    let s = Seat::new("agent-s", 80);
    let t = Seat::new("agent-t", 112);
    let everyone = allowing(&[(&a, 0), (&a, 1), (&r, 0), (&s, 0), (&t, 0)]);

    let (mut a_group, bundle) = a
        .open(&everyone, 0)
        .create_group_with_members(
            &id,
            &[
                r.open(&everyone, 0).generate_key_package().expect("r"),
                s.open(&everyone, 0).generate_key_package().expect("s"),
            ],
        )
        .expect("create with r and s");
    let mut r_group = r
        .open(&everyone, 0)
        .join_from_welcome(&bundle.welcomes[0])
        .expect("r joins");
    let mut s_group = s
        .open(&everyone, 0)
        .join_from_welcome(&bundle.welcomes[1])
        .expect("s joins");

    let bundle_a = a_group.commit_update(&a.seed(1)).expect("a's update");
    r_group
        .apply_commit(&bundle_a.commit)
        .expect("r applies a's update");

    let t_key_package = t.open(&everyone, 0).generate_key_package().expect("t");
    let bundle_s = s_group.add_member(&t_key_package).expect("s adds t");
    a_group
        .apply_commit(&bundle_s.commit)
        .expect("a drops its pending and follows s");

    let r_index = r_group.current_member_index().expect("r's leaf");
    drop(r_group);

    let (_, resync) = r
        .open(&everyone, 0)
        .resync_by_external_commit(&s_group.group_info().expect("s's group info"), r_index)
        .expect("r resyncs at equality");
    s_group
        .apply_commit(&resync.commit)
        .expect("s applies the resync commit");

    let roster = s_group.member_identities().expect("enumerate tree");
    assert_seated(&roster, &a, 0);
    assert_seated(&roster, &r, 0);
}

#[test]
fn member_identities_carry_signature_key() {
    let id = group_id(0xE7);
    let a = Seat::new("agent-a", 16);
    let r = Seat::new("agent-r", 48);
    let set = allowing(&[(&a, 0), (&r, 0)]);
    let (a_group, _r_group) = found_pair(&id, &a, &set, &r, &set);

    let roster = a_group.member_identities().expect("enumerate tree");
    assert_seated(&roster, &a, 0);
    assert_seated(&roster, &r, 0);
}
