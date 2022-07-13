//! Contains types necessary for processing Ethereum events
//! in vote extensions

use std::cmp::Ordering;
use std::hash::Hasher;
use std::collections::{
    BTreeMap,
    btree_map,
};

use borsh::{BorshDeserialize, BorshSchema, BorshSerialize};
use eyre::{eyre, Result};
use num_rational::Ratio;

use super::EthereumEvent;
use crate::proto::{MultiSigned, Signed};
use crate::types::address::Address;
use crate::types::key::common::PublicKey;
use crate::types::key::{common, VerifySigError};
use crate::types::storage::BlockHeight;
use crate::types::transaction::hash_tx;
use crate::types::hash::Hash;


/// A fraction of the total voting power. This should always be a reduced
/// fraction that is between zero and one inclusive.
#[derive(Clone, PartialOrd, Ord, PartialEq, Eq, Debug)]
pub struct FractionalVotingPower(Ratio<u64>);

impl FractionalVotingPower {
    /// Create a new FractionalVotingPower. It must be between zero and one
    /// inclusive.
    pub fn new(
        numer: impl Into<u64>,
        denom: impl Into<u64>,
    ) -> Result<Self> {
        let numer = numer.into();
        let denom = denom.into();
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

impl From<FractionalVotingPower> for (u64, u64) {
    fn from(ratio: FractionalVotingPower) -> Self {
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

#[derive(Clone, Debug, BorshSerialize, BorshDeserialize)]
/// Struct that represents the voting power
/// of a validator at given block height
pub struct EpochPower {
    /// Address of a validator
    pub validator: Address,
    /// voting power of validator at block `block_height`
    pub voting_power: FractionalVotingPower,
    /// The height of the block at which the validator has this voting
    /// power
    pub block_height: BlockHeight,
}

impl PartialOrd for EpochPower {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        self.validator.partial_cmp(&other.validator)
    }
}

impl PartialEq for EpochPower {
    fn eq(&self, other: &Self) -> bool {
        self.validator.eq(&other.validator)
    }
}

impl Eq for EpochPower {}

impl core::hash::Hash for EpochPower {
    fn hash<H: Hasher>(&self, state: &mut H) {
        <str as core::hash::Hash>::hash(
            self.validator.encode().as_str(),
            state,
        )
    }
}

/// A uniform interface for signed and multi-signed ethereum events
pub trait SignedEvent {
    /// Get the block height at which this event was seen
    fn get_height(&self) -> BlockHeight;
    /// Get the normalized voting power of each signer
    fn get_voting_powers(&self) -> Vec<EpochPower>;
    /// Get the number of signers whose signature is included
    fn number_of_signers(&self) -> usize;
    /// Verify the signatures of a signed event
    fn verify_signatures(
        &self,
        public_keys: &[common::PublicKey],
    ) -> Result<(), VerifySigError>;
    /// Get the hash of the inner signed event and height seen
    fn hash(&self) -> Hash;
}

/// A struct used by validators to sign that they have seen a particular
/// ethereum event. These are included in vote extensions
#[derive(Debug, Clone, BorshSerialize, BorshDeserialize, BorshSchema)]
pub struct SignedEthEvent {
    /// The address of the signing validator
    pub signer: Address,
    /// The proportion of the total voting power held by the validator
    pub power: FractionalVotingPower,
    /// The event being signed and the block height at which
    /// it was seen. We include the height as part of enforcing
    /// that a block proposer submits vote extensions from
    /// **the previous round only**
    pub event: Signed<(EthereumEvent, BlockHeight)>,
}

impl SignedEthEvent {
    /// Sign an Ethereum event + block height
    pub fn new(
        event: EthereumEvent,
        signer: Address,
        power: FractionalVotingPower,
        height: BlockHeight,
        key: &common::SecretKey,
    ) -> Self {
        Self {
            signer,
            power,
            event: Signed::new(key, (event, height)),
        }
    }
}

impl SignedEvent for SignedEthEvent {
    fn get_height(&self) -> BlockHeight {
        let Signed {
            data: (_, height), ..
        } = self.event;
        height
    }

    fn get_voting_powers(&self) -> Vec<EpochPower> {
        vec![EpochPower {
            validator: self.signer.clone(),
            voting_power: self.power.clone(),
            block_height: self.get_height(),
        }]
    }

    fn number_of_signers(&self) -> usize {
        1
    }

    fn verify_signatures(
        &self,
        public_keys: &[PublicKey],
    ) -> Result<(), VerifySigError> {
        self.event.verify(&public_keys[0])
    }

    fn hash(&self) -> Hash {
        let Signed { data, .. } = &self.event;
        hash_tx(&data.try_to_vec().unwrap())
    }
}

/// This is created by the block proposer based on the Ethereum events
/// included in the vote extensions of the previous Tendermint round.
/// This is an aggregation meant to reduce space taken up in blocks.
#[derive(Debug, Clone, BorshSerialize, BorshDeserialize, BorshSchema)]
pub struct MultiSignedEthEvent {
    /// Address and voting power of the signing validators
    pub signers: Vec<(Address, FractionalVotingPower)>,
    /// Events as signed by validators
    pub event: MultiSigned<(EthereumEvent, BlockHeight)>,
}

impl MultiSignedEthEvent {
    /// Add a new signature for the same (block header, block height)
    /// to this instance.
    ///
    /// This method is unsafe because we do not check the following:
    ///
    /// ```ignore
    /// self.hash() == other.hash()
    /// ```
    unsafe fn add_unchecked(&mut self, other: SignedEthEvent) {
        self.signers.push((other.signer, other.power));
        self.event.sigs.push(other.event.sig);
    }

    /// Compresses many [`SignedEthEvent`] instances into different [`MultiSignedEthEvent`]
    /// instances, for matching block height and event kinds.
    pub fn from_signed_eth_events(events: Vec<SignedEthEvent>) -> Vec<Self> {
        let mut multi_events: BTreeMap<_, MultiSignedEthEvent> = BTreeMap::new();

        for ev in events {
            match multi_events.entry(ev.hash()) {
                btree_map::Entry::Vacant(entry) => {
                    // convert `SignedEthEvent` to `MultiSignedEthEvent`
                    entry.insert(ev.into());
                },
                btree_map::Entry::Occupied(mut entry) => {
                    // append `SignedEthEvent` to `MultiSignedEthEvent`
                    //
                    // SAFETY: we know the `SignedEthEvent` and `MultiSignedEthEvent`
                    // have the same hash, so it's safe to add `ev` to the `MultiSignedEthEvent`
                    unsafe {
                        entry.get_mut().add_unchecked(ev);
                    }
                },
            }
        }

        multi_events
            .into_values()
            .collect()
    }
}

impl SignedEvent for MultiSignedEthEvent {
    fn get_height(&self) -> BlockHeight {
        let MultiSigned {
            data: (_, height), ..
        } = self.event;
        height
    }

    fn get_voting_powers(&self) -> Vec<EpochPower> {
        let height = self.get_height();
        self.signers
            .iter()
            .map(|(addr, power)| EpochPower {
                validator: addr.clone(),
                voting_power: power.clone(),
                block_height: height,
            })
            .collect()
    }

    fn number_of_signers(&self) -> usize {
        self.signers.len()
    }

    fn verify_signatures(
        &self,
        public_keys: &[PublicKey],
    ) -> Result<(), VerifySigError> {
        self.event.verify(public_keys)
    }

    fn hash(&self) -> Hash {
        let MultiSigned { data, .. } = &self.event;
        hash_tx(&data.try_to_vec().unwrap())
    }
}

impl From<SignedEthEvent> for MultiSignedEthEvent {
    fn from(event: SignedEthEvent) -> Self {
        Self {
            signers: vec![(event.signer, event.power)],
            event: MultiSigned {
                data: event.event.data,
                sigs: vec![event.event.sig],
            },
        }
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
            FractionalVotingPower::new(2u64, 3u64).unwrap()
                > FractionalVotingPower::new(1u64, 4u64).unwrap()
        );
        assert!(
            FractionalVotingPower::new(1u64, 3u64).unwrap()
                > FractionalVotingPower::new(1u64, 4u64).unwrap()
        );
        assert_eq!(
            FractionalVotingPower::new(1u64, 3u64).unwrap(),
            FractionalVotingPower::new(2u64, 6u64).unwrap()
        );
    }

    /// Test error handling on the FractionalVotingPower type
    #[test]
    fn test_fractional_voting_power_valid_fractions() {
        assert!(FractionalVotingPower::new(0u64, 0u64).is_err());
        assert!(FractionalVotingPower::new(1u64, 0u64).is_err());
        assert!(FractionalVotingPower::new(0u64, 1u64).is_ok());
        assert!(FractionalVotingPower::new(1u64, 1u64).is_ok());
        assert!(FractionalVotingPower::new(1u64, 2u64).is_ok());
        assert!(FractionalVotingPower::new(3u64, 2u64).is_err());
    }
}
