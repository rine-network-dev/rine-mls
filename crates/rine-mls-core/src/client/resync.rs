//! Resync from a GroupInfo alone, for an agent that has lost its local group
//! state and with it every handle that knew which leaf it occupies.

use mls_rs::error::MlsError;
use mls_rs::extension::built_in::RatchetTreeExt;

use crate::error::{MlsBlobKind, Result, RineMlsError};
use crate::group::{CommitBundle, RineMlsGroup};
use crate::wire;

use super::RineMlsClient;

impl RineMlsClient {
    /// Rejoin a group this agent already holds a seat in, finding that seat in
    /// the GroupInfo's ratchet tree: an external commit that removes the one
    /// leaf whose basic credential equals this agent's id, and adds a fresh
    /// leaf under the same credential.
    ///
    /// It differs from [`RineMlsClient::resync_by_external_commit`] only in
    /// where the leaf comes from. That call needs the stale handle's
    /// [`RineMlsGroup::current_member_index`]; a recovered agent has no handle.
    ///
    /// The new leaf must carry the same credential **and** signature key as the
    /// one it replaces: a resync rejoins a seat, it never moves it to another
    /// key, and one that tries is refused with
    /// `RINE_MLS_RESYNC_CHANGES_KEY`.
    /// An agent whose leaf key rotated moves its seat with
    /// [`RineMlsGroup::commit_update`] instead.
    /// A tree with no leaf for this agent is refused with
    /// [`RineMlsError::NoSeatToReplace`], and one with several with
    /// [`RineMlsError::AmbiguousSeat`]: removing either guess would hand the
    /// wrong seat to the commit.
    pub fn resync_from_group_info(
        &self,
        group_info: &[u8],
    ) -> Result<(RineMlsGroup, CommitBundle)> {
        let message = wire::decode(group_info, MlsBlobKind::GroupInfo, self.suite)?;
        let seat = self.seat_in(&message)?;

        self.external_commit_message(message, Some(seat))
    }

    fn seat_in(&self, group_info: &mls_rs::MlsMessage) -> Result<u32> {
        let tree = group_info
            .as_group_info()
            .ok_or(RineMlsError::UnexpectedMessageContent {
                expected: MlsBlobKind::GroupInfo,
            })?
            .extensions()
            .get_as::<RatchetTreeExt>()
            .map_err(MlsError::from)?
            .ok_or(RineMlsError::GroupInfoWithoutTree)?;

        only_seat(
            tree.tree_data()
                .roster()
                .members_iter()
                .filter(|member| {
                    member
                        .signing_identity
                        .credential
                        .as_basic()
                        .is_some_and(|basic| basic.identifier == self.agent_id())
                })
                .map(|member| member.index),
        )
    }
}

/// The one leaf a resync replaces: zero or several candidates are refused,
/// because removing a guess would hand the commit the wrong seat.
fn only_seat(mut seats: impl Iterator<Item = u32>) -> Result<u32> {
    match (seats.next(), seats.next()) {
        (None, _) => Err(RineMlsError::NoSeatToReplace),
        (Some(seat), None) => Ok(seat),
        (Some(_), Some(_)) => Err(RineMlsError::AmbiguousSeat {
            count: 2 + seats.count(),
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_only_seat_when_the_tree_holds_one_returns_it() {
        assert_eq!(only_seat([4].into_iter()).expect("one seat"), 4);
    }

    #[test]
    fn test_only_seat_when_the_tree_holds_none_is_refused() {
        assert!(matches!(
            only_seat(std::iter::empty()),
            Err(RineMlsError::NoSeatToReplace)
        ));
    }

    #[test]
    fn test_only_seat_when_the_tree_holds_two_or_more_is_refused_with_the_count() {
        assert!(matches!(
            only_seat([1, 5, 9].into_iter()),
            Err(RineMlsError::AmbiguousSeat { count: 3 })
        ));
    }
}
