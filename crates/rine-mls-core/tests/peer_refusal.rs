//! A peer the allowed set has not admitted yet is refused by name, and the
//! refusal leaves the handle exactly as it was: the caller verifies the agent,
//! adds it to the set, and retries the same bytes on the same handle.

mod common;

use common::member::{allowing, group_id, stock_client, StockWire};
use common::trio::{add_carol, alice_and_bob_without_carol, Scene, Trio};
use mls_rs::{ExtensionList, MlsMessage};
use rine_mls_core::RineMlsErrorCode;

#[test]
fn test_apply_commit_when_it_adds_a_peer_outside_the_set_then_the_refusal_names_it_and_the_retry_applies(
) {
    let Scene {
        trio,
        mut alice_group,
        mut bob_group,
        bobs_view,
    } = alice_and_bob_without_carol(0x20);
    let commit = add_carol(&mut alice_group, &trio.carol, &bobs_view);
    let epoch = bob_group.epoch();

    let error = bob_group
        .apply_commit(&commit)
        .expect_err("carol is unverified");
    assert_eq!(
        error.code(),
        RineMlsErrorCode::PeerNotAdmitted,
        "got {error:?}"
    );
    assert_eq!(error.refused_peer(), Some(&b"carol"[..]));
    assert_eq!(bob_group.epoch(), epoch, "a refused commit moves nothing");

    trio.carol.allow(&bobs_view);
    assert_eq!(bob_group.apply_commit(&commit).expect("retry"), epoch + 1);
}

#[test]
fn test_apply_commit_when_the_committer_is_outside_the_set_then_the_refusal_names_the_committer() {
    let Scene {
        trio,
        mut alice_group,
        mut bob_group,
        ..
    } = alice_and_bob_without_carol(0x21);
    bob_group.save().expect("save");
    let strangers_view = allowing(&[&trio.bob, &trio.carol]);
    let mut bob_group = trio
        .bob
        .open(&strangers_view)
        .load_group(&group_id(0x21))
        .expect("reload under a set without alice");
    let commit = alice_group.add_members(&[]).expect("empty commit").commit;

    let error = bob_group
        .apply_commit(&commit)
        .expect_err("alice is unverified");
    assert_eq!(error.refused_peer(), Some(&b"alice"[..]), "got {error:?}");

    trio.alice.allow(&strangers_view);
    bob_group.apply_commit(&commit).expect("retry");
}

#[test]
fn test_apply_commit_when_an_external_commit_replaces_a_peer_outside_the_set_then_it_is_refused_by_name(
) {
    let trio = Trio::new();
    let everyone = trio.everyone();
    let (mut alice_group, _) = trio
        .alice
        .open(&everyone)
        .create_group(&group_id(0x22))
        .expect("create");
    let bundle = alice_group
        .add_members(&[
            trio.bob
                .open(&everyone)
                .generate_key_package()
                .expect("bob"),
            trio.carol
                .open(&everyone)
                .generate_key_package()
                .expect("carol"),
        ])
        .expect("add bob and carol");
    let mut bob_group = trio
        .bob
        .open(&everyone)
        .join_from_welcome(&bundle.welcomes[0])
        .expect("bob joins");
    bob_group.save().expect("save");
    let bobs_view = trio.bobs_view();
    let mut bob_group = trio
        .bob
        .open(&bobs_view)
        .load_group(&group_id(0x22))
        .expect("reload under a set without carol");

    let stale = alice_group.member_index(b"carol").expect("seated");
    let rejoin = trio.carol.on_a_fresh_device();
    let (_, bundle) = rejoin
        .open(&everyone)
        .resync_by_external_commit(&alice_group.group_info().expect("info"), stale)
        .expect("carol rebuilds her seat");

    let error = bob_group
        .apply_commit(&bundle.commit)
        .expect_err("unverified");
    assert_eq!(error.refused_peer(), Some(&b"carol"[..]), "got {error:?}");

    trio.carol.allow(&bobs_view);
    bob_group.apply_commit(&bundle.commit).expect("retry");
}

#[test]
fn test_apply_commit_when_a_private_commit_is_refused_then_the_same_handle_applies_the_retry() {
    let Trio { alice, bob, carol } = Trio::new();
    let bobs_view = allowing(&[&alice, &bob]);
    let committer = stock_client(
        &alice,
        allowing(&[&alice, &bob, &carol]),
        StockWire::EncryptedCommits,
    );
    let mut founder = committer
        .create_group_with_id(
            group_id(0x23).to_vec(),
            ExtensionList::new(),
            ExtensionList::new(),
            None,
        )
        .expect("create");
    let bob_key_package =
        MlsMessage::from_bytes(&bob.open(&bobs_view).generate_key_package().expect("bob"))
            .expect("framed");
    let welcome = founder
        .commit_builder()
        .add_member(bob_key_package)
        .expect("add bob")
        .build()
        .expect("commit");
    founder.apply_pending_commit().expect("apply");
    let mut bob_group = bob
        .open(&bobs_view)
        .join_from_welcome(&welcome.welcome_messages[0].to_bytes().expect("welcome"))
        .expect("bob joins");

    let carol_key_package = MlsMessage::from_bytes(
        &carol
            .open(&bobs_view)
            .generate_key_package()
            .expect("carol"),
    )
    .expect("framed");
    let commit = founder
        .commit_builder()
        .add_member(carol_key_package)
        .expect("add carol")
        .build()
        .expect("commit")
        .commit_message
        .to_bytes()
        .expect("commit bytes");
    assert_eq!(
        MlsMessage::from_bytes(&commit)
            .expect("framed")
            .wire_format(),
        mls_rs::WireFormat::PrivateMessage,
    );
    let epoch = bob_group.epoch();

    let error = bob_group
        .apply_commit(&commit)
        .expect_err("carol is unverified");
    assert_eq!(error.refused_peer(), Some(&b"carol"[..]), "got {error:?}");

    carol.allow(&bobs_view);
    assert_eq!(
        bob_group
            .apply_commit(&commit)
            .expect("the handshake key was not spent"),
        epoch + 1,
    );
}

#[test]
fn test_apply_commit_when_the_commit_is_forged_then_it_is_a_protocol_error_naming_no_peer() {
    let Scene {
        trio,
        mut alice_group,
        mut bob_group,
        bobs_view,
    } = alice_and_bob_without_carol(0x24);
    let commit = add_carol(&mut alice_group, &trio.carol, &bobs_view);

    for from_end in 1..=120 {
        let mut forged = commit.clone();
        let at = forged.len() - from_end;
        forged[at] ^= 0x01;

        let Err(error) = bob_group.apply_commit(&forged) else {
            panic!("byte {from_end} from the end: a forged commit applied");
        };
        assert_eq!(error.refused_peer(), None, "byte {from_end}: {error:?}");
        assert_eq!(
            error.code(),
            RineMlsErrorCode::Protocol,
            "byte {from_end}: {error:?}"
        );
    }
}
