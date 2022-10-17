//! Logic and data types relating to tracking validators' votes for pieces of
//! data stored in the ledger, where those pieces of data should only be acted
//! on once they have received enough votes
use std::collections::BTreeSet;

use borsh::{BorshDeserialize, BorshSchema, BorshSerialize};
use namada::types::address::Address;
use namada::types::voting_power::FractionalVotingPower;

#[derive(
    Clone, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize, BorshSchema,
)]
/// Represents all the information needed to track a piece of data that may be
/// voted for over multiple epochs
pub struct VoteTracking {
    /// The total voting power that's voted for this event across all epochs
    pub voting_power: FractionalVotingPower,
    /// The addresses of validators that voted for this event. We use a
    /// set type as validators should only be able to vote at most once,
    /// and [`BTreeSet`] specifically as we want this field to be
    /// deterministically ordered for storage.
    pub seen_by: BTreeSet<Address>,
    /// Whether this event has been acted on or not - this should only ever
    /// transition from `false` to `true`, once there is enough voting power
    // TODO: this field is redundant - we can derive whether an event is seen
    // or not from looking at `voting_power`
    pub seen: bool,
}
