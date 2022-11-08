use std::collections::{BTreeSet, HashSet};

use borsh::{BorshDeserialize, BorshSchema, BorshSerialize};

use crate::ledger::protocol::transactions::votes::{Tally, Votes};
use crate::types::address::Address;
use crate::types::ethereum_events::EthereumEvent;
use crate::types::storage::BlockHeight;
use crate::types::vote_extensions::ethereum_events::MultiSignedEthEvent;

/// Represents an Ethereum event being seen by some validators
#[derive(
    Debug,
    Clone,
    Ord,
    PartialOrd,
    PartialEq,
    Eq,
    Hash,
    BorshSerialize,
    BorshDeserialize,
)]
pub struct EthMsgUpdate {
    /// The event being seen.
    pub body: EthereumEvent,
    /// New votes for this event.
    // NOTE(feature = "abcipp"): This can just become BTreeSet<Address> because
    // BlockHeight will always be the previous block
    pub seen_by: Votes,
}

impl From<MultiSignedEthEvent> for EthMsgUpdate {
    fn from(
        MultiSignedEthEvent { event, signers }: MultiSignedEthEvent,
    ) -> Self {
        Self {
            body: event,
            seen_by: dedupe(&signers),
        }
    }
}

/// Deterministically constructs a `Votes` map from a set of validator addresses
/// and the block heights they signed something at. We arbitrarily take the
/// earliest block height for each validator address encountered.
// TODO: consume `signers` instead of cloning stuff
fn dedupe(signers: &BTreeSet<(Address, BlockHeight)>) -> Votes {
    let unique_voters: HashSet<_> =
        signers.iter().map(|(addr, _)| addr.to_owned()).collect();
    let mut earliest_votes = Votes::default();
    for voter in unique_voters {
        let earliest_vote_height = signers
            .iter()
            .filter_map(
                |(addr, height)| {
                    if *addr == voter { Some(*height) } else { None }
                },
            )
            .min()
            .unwrap_or_else(|| {
                unreachable!(
                    "we will always have at least one block height per voter"
                )
            });
        _ = earliest_votes.insert(voter, earliest_vote_height);
    }
    earliest_votes
}

/// Represents an event stored under `eth_msgs`
#[derive(
    Clone, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize, BorshSchema,
)]
pub struct EthMsg {
    /// The event being stored
    pub body: EthereumEvent,
    /// Tallying of votes for this event
    pub votes: Tally,
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use super::*;
    use crate::types::address;
    use crate::types::ethereum_events::testing::{
        arbitrary_nonce, arbitrary_single_transfer,
    };
    use crate::types::storage::BlockHeight;

    #[test]
    /// Tests [`From<MultiSignedEthEvent>`] for [`EthMsgUpdate`]
    fn test_from_multi_signed_eth_event_for_eth_msg_update() {
        let sole_validator = address::testing::established_address_1();
        let receiver = address::testing::established_address_2();
        let event = arbitrary_single_transfer(arbitrary_nonce(), receiver);
        let with_signers = MultiSignedEthEvent {
            event: event.clone(),
            signers: BTreeSet::from([(
                sole_validator.clone(),
                BlockHeight(100),
            )]),
        };
        let expected = EthMsgUpdate {
            body: event,
            seen_by: Votes::from([(sole_validator, BlockHeight(100))]),
        };

        let update: EthMsgUpdate = with_signers.into();

        assert_eq!(update, expected);
    }

    #[test]
    fn test_dedupe_empty() {
        let signers = BTreeSet::new();

        let deduped = dedupe(&signers);

        assert_eq!(deduped, Votes::new());
    }

    #[test]
    fn test_dedupe_single_vote() {
        let sole_validator = address::testing::established_address_1();
        let votes = [(sole_validator, BlockHeight(100))];
        let signers = BTreeSet::from(votes.clone());

        let deduped = dedupe(&signers);

        assert_eq!(deduped, Votes::from(votes));
    }

    #[test]
    fn test_dedupe_multiple_votes_same_voter() {
        let sole_validator = address::testing::established_address_1();
        let earliest_vote_height = 100;
        let earliest_vote =
            (sole_validator.clone(), BlockHeight(earliest_vote_height));
        let votes = [
            earliest_vote.clone(),
            (
                sole_validator.clone(),
                BlockHeight(earliest_vote_height + 1),
            ),
            (sole_validator, BlockHeight(earliest_vote_height + 100)),
        ];
        let signers = BTreeSet::from(votes);

        let deduped = dedupe(&signers);

        assert_eq!(deduped, Votes::from([earliest_vote]));
    }

    #[test]
    fn test_dedupe_multiple_votes_multiple_voters() {
        let validator_1 = address::testing::established_address_1();
        let validator_2 = address::testing::established_address_2();
        let validator_1_earliest_vote_height = 100;
        let validator_1_earliest_vote = (
            validator_1.clone(),
            BlockHeight(validator_1_earliest_vote_height),
        );
        let validator_2_earliest_vote_height = 200;
        let validator_2_earliest_vote = (
            validator_2.clone(),
            BlockHeight(validator_2_earliest_vote_height),
        );
        let votes = [
            validator_1_earliest_vote.clone(),
            (
                validator_1.clone(),
                BlockHeight(validator_1_earliest_vote_height + 1),
            ),
            (
                validator_1,
                BlockHeight(validator_1_earliest_vote_height + 100),
            ),
            validator_2_earliest_vote.clone(),
            (
                validator_2.clone(),
                BlockHeight(validator_2_earliest_vote_height + 1),
            ),
            (
                validator_2,
                BlockHeight(validator_2_earliest_vote_height + 100),
            ),
        ];
        let signers = BTreeSet::from(votes);

        let deduped = dedupe(&signers);

        assert_eq!(
            deduped,
            Votes::from([validator_1_earliest_vote, validator_2_earliest_vote])
        );
    }
}
