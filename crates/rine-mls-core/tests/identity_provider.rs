//! Who a group may seat: the allowed-set identity provider and the resync rule.
//!
//! The shared `TestAgent` harness trusts every agent it makes, so these tests
//! open their clients by hand, each with the allowed set it is meant to have.

use rine_mls_core::{LeafIdentity, RineMlsError, RineMlsErrorCode};

mod common;

use common::member::{allowing, group_id, Member};

#[test]
fn test_add_member_when_the_key_package_is_outside_the_allowed_set_is_refused_until_it_is_added() {
    let alice = Member::new("alice", 1);
    let bob = Member::new("bob", 2);
    let alices_view = allowing(&[&alice]);

    let (mut group, _) = alice
        .open(&alices_view)
        .create_group(&group_id(0x10))
        .expect("create");
    let key_package = bob
        .open(&allowing(&[&alice, &bob]))
        .generate_key_package()
        .expect("key package");

    let error = group
        .add_member(&key_package)
        .expect_err("alice's set does not hold bob");
    assert_eq!(error.refused_peer(), Some(&b"bob"[..]), "got {error:?}");

    bob.allow(&alices_view);
    group
        .add_member(&key_package)
        .expect("the set grows under a client that is already open");
}

#[test]
fn test_add_member_when_the_agent_id_is_allowed_but_the_leaf_key_is_not_is_refused() {
    let alice = Member::new("alice", 1);
    let bob = Member::new("bob", 2);
    let impostor = Member::new("bob", 3);
    let alices_view = allowing(&[&alice, &bob]);

    let (mut group, _) = alice
        .open(&alices_view)
        .create_group(&group_id(0x11))
        .expect("create");
    let key_package = impostor
        .open(&allowing(&[&alice, &impostor]))
        .generate_key_package()
        .expect("key package");

    let error = group
        .add_member(&key_package)
        .expect_err("the pair is what is allowed, not the agent id alone");
    assert_eq!(error.refused_peer(), Some(&b"bob"[..]), "got {error:?}");
}

#[test]
fn test_join_from_welcome_when_the_tree_holds_a_leaf_outside_the_set_is_refused() {
    let alice = Member::new("alice", 1);
    let bob = Member::new("bob", 2);
    let carol = Member::new("carol", 3);
    let everyone = allowing(&[&alice, &bob, &carol]);

    let (mut group, _) = alice
        .open(&everyone)
        .create_group(&group_id(0x12))
        .expect("create");
    let bundle = group
        .add_members(&[
            bob.open(&everyone).generate_key_package().expect("bob"),
            carol.open(&everyone).generate_key_package().expect("carol"),
        ])
        .expect("add bob and carol");

    let error = bob
        .open(&allowing(&[&alice, &bob]))
        .join_from_welcome(&bundle.welcomes[0])
        .map(|_| ())
        .expect_err("bob has not verified carol");
    assert_eq!(
        error.code(),
        RineMlsErrorCode::PeerNotAdmitted,
        "got {error:?}"
    );
    assert_eq!(error.refused_peer(), Some(&b"carol"[..]));

    bob.open(&everyone)
        .join_from_welcome(&bundle.welcomes[0])
        .expect("with carol allowed the same Welcome joins");
}

#[test]
fn test_resync_by_external_commit_when_the_credential_is_unchanged_replaces_the_leaf() {
    let alice = Member::new("alice", 1);
    let bob = Member::new("bob", 2);
    let everyone = allowing(&[&alice, &bob]);

    let (mut group, _) = alice
        .open(&everyone)
        .create_group(&group_id(0x13))
        .expect("create");
    group
        .add_member(&bob.open(&everyone).generate_key_package().expect("bob"))
        .expect("add bob");
    let stale_leaf = group.member_index(b"bob").expect("bob seated");

    let recovered = bob.on_a_fresh_device();
    let (_, bundle) = recovered
        .open(&everyone)
        .resync_by_external_commit(&group.group_info().expect("group info"), stale_leaf)
        .expect("same credential resyncs");

    group
        .apply_commit(&bundle.commit)
        .expect("alice applies it");
}

#[test]
fn test_resync_by_external_commit_when_the_leaf_key_changed_is_refused() {
    let alice = Member::new("alice", 1);
    let bob = Member::new("bob", 2);
    let bob_rotated = Member::new("bob", 3);
    let everyone = allowing(&[&alice, &bob, &bob_rotated]);

    let (mut group, _) = alice
        .open(&everyone)
        .create_group(&group_id(0x14))
        .expect("create");
    group
        .add_member(&bob.open(&everyone).generate_key_package().expect("bob"))
        .expect("add bob");
    let stale_leaf = group.member_index(b"bob").expect("bob seated");

    let error = bob_rotated
        .open(&everyone)
        .resync_by_external_commit(&group.group_info().expect("group info"), stale_leaf)
        .map(|_| ())
        .expect_err("a rotated leaf key cannot take over the seat");
    assert_eq!(
        error.code(),
        RineMlsErrorCode::ResyncChangesKey,
        "got {error:?}"
    );
}

#[test]
fn test_leaf_identity_when_the_agent_id_is_empty_or_the_seed_is_short_is_refused() {
    assert!(matches!(
        LeafIdentity::new(b"", &[1u8; 32]),
        Err(RineMlsError::EmptyAgentId)
    ));
    assert!(matches!(
        LeafIdentity::new(b"alice", &[1u8; 31]),
        Err(RineMlsError::InvalidSigningSeed { len: 31 })
    ));
}
