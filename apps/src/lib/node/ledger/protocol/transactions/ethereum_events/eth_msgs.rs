use std::collections::BTreeSet;

use borsh::{BorshDeserialize, BorshSchema, BorshSerialize};
use namada::types::address::Address;
use namada::types::ethereum_events::EthereumEvent;
use namada::types::storage::BlockHeight;
use namada::types::vote_extensions::ethereum_events::MultiSignedEthEvent;

use crate::node::ledger::protocol::transactions::votes::Tally;

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
    /// The event being seen
    pub body: EthereumEvent,
    /// Addresses of the validators who have just seen this event. We use
    /// [`BTreeSet`] even though ordering is not important here, so that we
    /// can derive [`Hash`] for [`EthMsgUpdate`].
    // NOTE(feature = "abcipp"): This can just become BTreeSet<Address> because
    // BlockHeight will always be the previous block
    pub seen_by: BTreeSet<(Address, BlockHeight)>,
}

impl From<MultiSignedEthEvent> for EthMsgUpdate {
    fn from(
        MultiSignedEthEvent { event, signers }: MultiSignedEthEvent,
    ) -> Self {
        Self {
            body: event,
            seen_by: signers.into_iter().collect(),
        }
    }
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

    use namada::types::address;
    use namada::types::ethereum_events::testing::{
        arbitrary_nonce, arbitrary_single_transfer,
    };
    use namada::types::storage::BlockHeight;

    use super::*;

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
            seen_by: BTreeSet::from_iter(vec![(
                sole_validator,
                BlockHeight(100),
            )]),
        };

        let update: EthMsgUpdate = with_signers.into();

        assert_eq!(update, expected);
    }
}
