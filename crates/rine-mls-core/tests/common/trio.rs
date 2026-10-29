//! Three agents and a two-member group, for the scenarios in which a third agent
//! the allowed set has not admitted yet is added to it.

use super::member::{allowing, group_id, Member};
use rine_mls_core::{AllowedIdentities, RineMlsGroup};

/// The three agents every scenario here uses.
pub struct Trio {
    pub alice: Member,
    pub bob: Member,
    pub carol: Member,
}

impl Trio {
    pub fn new() -> Self {
        Self {
            alice: Member::new("alice", 1),
            bob: Member::new("bob", 2),
            carol: Member::new("carol", 3),
        }
    }

    pub fn everyone(&self) -> AllowedIdentities {
        allowing(&[&self.alice, &self.bob, &self.carol])
    }

    /// What bob has verified so far: alice and himself, not carol.
    pub fn bobs_view(&self) -> AllowedIdentities {
        allowing(&[&self.alice, &self.bob])
    }
}

/// Alice and bob share a group at epoch 1; alice's set holds carol, bob's does not.
pub struct Scene {
    pub trio: Trio,
    pub alice_group: RineMlsGroup,
    pub bob_group: RineMlsGroup,
    pub bobs_view: AllowedIdentities,
}

pub fn alice_and_bob_without_carol(tag: u8) -> Scene {
    let trio = Trio::new();
    let bobs_view = trio.bobs_view();
    let (mut alice_group, _) = trio
        .alice
        .open(&trio.everyone())
        .create_group(&group_id(tag))
        .expect("create");
    let bundle = alice_group
        .add_member(
            &trio
                .bob
                .open(&bobs_view)
                .generate_key_package()
                .expect("bob"),
        )
        .expect("add bob");
    let bob_group = trio
        .bob
        .open(&bobs_view)
        .join_from_welcome(&bundle.welcomes[0])
        .expect("bob joins");

    Scene {
        trio,
        alice_group,
        bob_group,
        bobs_view,
    }
}

pub fn add_carol(
    alice_group: &mut RineMlsGroup,
    carol: &Member,
    view: &AllowedIdentities,
) -> Vec<u8> {
    let key_package = carol.open(view).generate_key_package().expect("carol");

    alice_group
        .add_member(&key_package)
        .expect("add carol")
        .commit
}
