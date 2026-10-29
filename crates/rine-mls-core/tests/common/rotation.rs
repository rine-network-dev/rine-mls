//! Pairs that rotate: two seats founding a group whose allowed sets already
//! hold the generations a self-update moves through.

use rine_mls_core::{AllowedIdentities, RineMlsGroup};

use super::group_id;
use super::seat::{allowing, found_pair, Seat};

/// A pair at epoch 1 and the allowed set both sides share: every generation of
/// `a`, generation 0 of `r`, and generation 0 of each extra seat.
pub fn pair_with(
    id: &[u8],
    a: &Seat,
    r: &Seat,
    extra: &[&Seat],
) -> (RineMlsGroup, RineMlsGroup, AllowedIdentities) {
    let mut pairs = vec![(a, 0), (a, 1), (r, 0)];
    pairs.extend(extra.iter().map(|seat| (*seat, 0)));
    let set = allowing(&pairs);
    let (a_group, r_group) = found_pair(id, a, &set, r, &set);

    (a_group, r_group, set)
}

/// A pair at epoch 1 with the shared allowed set: every generation of `a` and
/// generation 0 of `r`.
pub fn pair(id: &[u8]) -> (Seat, Seat, RineMlsGroup, RineMlsGroup, AllowedIdentities) {
    let a = Seat::new("agent-a", 16);
    let r = Seat::new("agent-r", 48);
    let (a_group, r_group, set) = pair_with(id, &a, &r, &[]);

    (a, r, a_group, r_group, set)
}

/// A and R found a group at generation 0, with both allowed sets holding A's
/// first two generations and R's founding leaf. Returns the seats, the sets,
/// the two handles and the group id.
pub fn rotating_pair(
    tag: u8,
) -> (
    Seat,
    Seat,
    AllowedIdentities,
    AllowedIdentities,
    RineMlsGroup,
    RineMlsGroup,
    Vec<u8>,
) {
    let id = group_id(tag).to_vec();
    let a = Seat::new("agent-a", 16);
    let r = Seat::new("agent-r", 48);
    let a_set = allowing(&[(&a, 0), (&a, 1), (&r, 0)]);
    let r_set = allowing(&[(&a, 0), (&a, 1), (&r, 0)]);
    let (a_group, r_group) = found_pair(&id, &a, &a_set, &r, &r_set);

    (a, r, a_set, r_set, a_group, r_group, id)
}
