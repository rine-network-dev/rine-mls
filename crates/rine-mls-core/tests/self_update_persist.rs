//! A moved leaf survives a reload and exports its epoch.

mod common;

use common::escrow::{export, reader, take};
use common::rotation::rotating_pair;

#[test]
fn self_update_survives_reload() {
    let (a, _r, a_set, _r_set, mut a_group, mut r_group, id) = rotating_pair(0xC7);

    let bundle = a_group.commit_update(&a.seed(1)).expect("commit update");
    r_group.apply_commit(&bundle.commit).expect("apply");
    a_group.apply_pending_commit().expect("apply pending");
    a_group.save().expect("save");

    let mut reloaded = a
        .open(&a_set, 1)
        .load_group(&id)
        .expect("reload the updated handle");
    let payload = reloaded
        .encrypt_application_message(b"after reload")
        .expect("send");
    assert_eq!(
        r_group
            .decrypt_application_message(&payload)
            .expect("read")
            .envelope,
        b"after reload",
    );

    let roster = r_group.member_identities().expect("enumerate tree");
    let leaf = roster
        .iter()
        .find(|leaf| leaf.identity == a.agent_id())
        .expect("a is seated");
    assert_eq!(leaf.signature_key, a.public_key(1));
}

#[test]
fn self_update_exports_epoch() {
    let (a, _r, _a_set, _r_set, mut a_group, mut r_group, id) = rotating_pair(0xC8);

    let bundle = a_group.commit_update(&a.seed(1)).expect("commit update");
    r_group.apply_commit(&bundle.commit).expect("apply");

    let founding = take(&mut a_group);
    assert!(
        founding.iter().all(|held| held.epoch != bundle.epoch),
        "the new epoch is not escrowed until the commit is applied",
    );

    a_group.apply_pending_commit().expect("apply pending");
    let exports = take(&mut a_group);
    let epoch_export = export(&exports, bundle.epoch);

    let payload = a_group.encrypt_application_message(b"after").expect("send");
    let mut reader = reader(&id, bundle.epoch, &epoch_export.plaintext);
    assert_eq!(reader.open(&payload[1..]).expect("open").envelope, b"after");
}
