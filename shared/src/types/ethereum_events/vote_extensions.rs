//! Contains types necessary for processing Ethereum events
//! in vote extensions.

use std::collections::HashSet;

use borsh::{BorshDeserialize, BorshSchema, BorshSerialize};
use eyre::{eyre, Result};
use num_rational::Ratio;

use super::EthereumEvent;
use crate::proto::MultiSigned;
use crate::types::address::Address;
use crate::types::key::common::Signature;
use crate::types::storage::BlockHeight;
use crate::proto::types::Signed;
use crate::ledger::storage::{
    DB, DBIter, Storage, StorageHasher,
};

/// This struct will be created and signed over by each
/// validator as their vote extension.
pub struct VoteExtension {
    /// The current height of Anoma.
    pub block_height: BlockHeight,
    /// The new ethereum events seen. These should be
    /// deterministically ordered.
    pub ethereum_events: Vec<EthereumEvent>
}

impl VoteExtension {
    /// Order `ethereum_events` deterministically and wrap them
    /// up in this `VoteExtension` instance, along with the block height
    /// they were observed at.
    pub fn from_ethereum_events(
        _ethereum_events: Vec<EthereumEvent>,
        _block_height: BlockHeight
    ) -> Self {
        todo!()
    }
}

/// A fraction of the total voting power. This should always be a reduced
/// fraction that is between zero and one inclusive.
#[derive(Clone, PartialOrd, Ord, PartialEq, Eq, Debug)]
pub struct FractionalVotingPower(Ratio<u64>);

impl FractionalVotingPower {
    /// Create a new FractionalVotingPower. It must be between zero and one
    /// inclusive.
    pub fn new(numer: u64, denom: u64) -> Result<Self> {
        if denom == 0 {
            return Err(eyre!("denominator can't be zero"));
        }
        let ratio: Ratio<u64> = (numer, denom).into();
        if ratio > 1.into() {
            return Err(eyre!(
                "fractional voting power cannot be greater than one"
            ));
        }
        Ok(Self(ratio))
    }
}

impl From<&FractionalVotingPower> for (u64, u64) {
    fn from(ratio: &FractionalVotingPower) -> Self {
        (ratio.0.numer().to_owned(), ratio.0.denom().to_owned())
    }
}

impl BorshSerialize for FractionalVotingPower {
    fn serialize<W: ark_serialize::Write>(
        &self,
        writer: &mut W,
    ) -> std::io::Result<()> {
        let (numer, denom): (u64, u64) = self.into();
        (numer, denom).serialize(writer)
    }
}

impl BorshDeserialize for FractionalVotingPower {
    fn deserialize(buf: &mut &[u8]) -> std::io::Result<Self> {
        let (numer, denom): (u64, u64) =
            BorshDeserialize::deserialize(buf)?;
        Ok(FractionalVotingPower(Ratio::<u64>::new(numer, denom)))
    }
}

impl BorshSchema for FractionalVotingPower {
    fn add_definitions_recursively(
        definitions: &mut std::collections::HashMap<
            borsh::schema::Declaration,
            borsh::schema::Definition,
        >,
    ) {
        let fields =
            borsh::schema::Fields::UnnamedFields(borsh::maybestd::vec![
                u64::declaration(),
                u64::declaration()
            ]);
        let definition = borsh::schema::Definition::Struct { fields };
        Self::add_definition(Self::declaration(), definition, definitions);
    }

    fn declaration() -> borsh::schema::Declaration {
        "FractionalVotingPower".into()
    }
}

/// Aggregates an Ethereum event with the corresponding
// validators who saw this event.
#[derive(BorshSerialize, BorshDeserialize)]
pub struct MultiSignedEthEvent {
    /// The Ethereum event that was signed.
    pub event: EthereumEvent,
    /// List of addresses of validators who signed this event
    pub signers: HashSet<Address>,
}

/// Compresses a set of signed `VoteExtension` instances, to save
/// space on a block.
#[derive(BorshSerialize, BorshDeserialize)]
pub struct VoteExtensionDigest {
    /// The signatures and signing address of each VoteExtension
    pub signatures: Vec<(Signature, Address)>,
    /// The events that were reported
    pub events: Vec<MultiSignedEthEvent>,
    /// The validators who saw no events
    pub nulls: HashSet<Address>
}

impl VoteExtensionDigest {
    /// Decompresses a set of signed `VoteExtension` instances.
    pub fn decompress<D, H>(self, storage: &Storage<D, H>) -> Vec<Signed<VoteExtension>>
    where
        D: DB + for<'iter> DBIter<'iter> + Sync + 'static,
        H: StorageHasher + Sync + 'static,
    {
        let VoteExtensionDigest {
            signatures,
            events,
            nulls,
        } = digest;

        let mut extensions = vec![];

        for (sig, addr) in signatures.into_iter() {
            let mut ext = VoteExtension {
                block_height: self.storage.last_height,
                events: vec![],
            };

            let ext = if nulls.contains(&addr) {
                ext
            } else {
                for event in events {
                    if event.signers.contains(&addr) {
                        ext.events.push(event.clone());
                    }
                }
                ext.events.sort();
            };

            let signed = Signed {
                data: ext,
                sig,
            };
            extensions.push(sig);
        }
        extensions
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::ethereum_events::Uint;
    use crate::types::hash::Hash;

    /// Test the hashing of an Ethereum event
    #[test]
    fn test_ethereum_event_hash() {
        let nonce = Uint::from(123u64);
        let event = EthereumEvent::TransfersToNamada {
            nonce,
            transfers: vec![],
        };
        let hash = event.hash().unwrap();

        assert_eq!(
            hash,
            Hash([
                94, 131, 116, 129, 41, 204, 178, 144, 24, 8, 185, 16, 103,
                236, 209, 191, 20, 89, 145, 17, 41, 233, 31, 98, 185, 6,
                217, 204, 80, 38, 224, 23
            ])
        );
    }

    /// This test is ultimately just exercising the underlying
    /// library we use for fractions, we want to make sure
    /// operators work as expected with our FractionalVotingPower
    /// type itself
    #[test]
    fn test_fractional_voting_power_ord_eq() {
        assert!(
            FractionalVotingPower::new(2, 3).unwrap()
                > FractionalVotingPower::new(1, 4).unwrap()
        );
        assert!(
            FractionalVotingPower::new(1, 3).unwrap()
                > FractionalVotingPower::new(1, 4).unwrap()
        );
        assert!(
            FractionalVotingPower::new(1, 3).unwrap()
                == FractionalVotingPower::new(2, 6).unwrap()
        );
    }

    /// Test error handling on the FractionalVotingPower type
    #[test]
    fn test_fractional_voting_power_valid_fractions() {
        assert!(FractionalVotingPower::new(0, 0).is_err());
        assert!(FractionalVotingPower::new(1, 0).is_err());
        assert!(FractionalVotingPower::new(0, 1).is_ok());
        assert!(FractionalVotingPower::new(1, 1).is_ok());
        assert!(FractionalVotingPower::new(1, 2).is_ok());
        assert!(FractionalVotingPower::new(3, 2).is_err());
    }
}
