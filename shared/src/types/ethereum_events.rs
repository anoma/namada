//! Types representing data intended for Anoma via Ethereum events

use borsh::{BorshDeserialize, BorshSchema, BorshSerialize};
use ethabi::Uint as ethUint;

use crate::types::address::Address;
use crate::types::hash::Hash;
use crate::types::token::Amount;

/// Anoma native type to replace the ethabi::Uint type
#[derive(
    Clone, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize, BorshSchema,
)]
pub struct Uint(pub [u64; 4]);

impl From<ethUint> for Uint {
    fn from(value: ethUint) -> Self {
        Self(value.0)
    }
}

impl From<Uint> for ethUint {
    fn from(value: Uint) -> Self {
        Self(value.0)
    }
}

impl From<u64> for Uint {
    fn from(value: u64) -> Self {
        ethUint::from(value).into()
    }
}

/// Representation of address on Ethereum
#[derive(
    Clone, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize, BorshSchema,
)]
pub struct EthAddress(pub [u8; 20]);

/// A Keccak hash
#[derive(
    Clone, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize, BorshSchema,
)]
pub struct KeccakHash(pub [u8; 32]);

/// An Ethereum event to be processed by the Anoma ledger
#[derive(
    Clone, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize, BorshSchema,
)]
pub enum EthereumEvent {
    /// Event transferring batches of ether or Ethereum based ERC20 tokens
    /// from Ethereum to wrapped assets on Anoma
    TransfersToNamada {
        /// Monotonically increasing nonce
        #[allow(dead_code)]
        nonce: Uint,
        /// The batch of transfers
        #[allow(dead_code)]
        transfers: Vec<TransferToNamada>,
    },
    /// A confirmation event that a batch of transfers have been made
    /// from Anoma to Ethereum
    TransfersToEthereum {
        /// Monotonically increasing nonce
        #[allow(dead_code)]
        nonce: Uint,
        /// The batch of transfers
        #[allow(dead_code)]
        transfers: Vec<TransferToEthereum>,
    },
    /// Event indication that the validator set has been updated
    /// in the governance contract
    ValidatorSetUpdate {
        /// Monotonically increasing nonce
        #[allow(dead_code)]
        nonce: Uint,
        /// Hash of the validators in the bridge contract
        #[allow(dead_code)]
        bridge_validator_hash: KeccakHash,
        /// Hash of the validators in the governance contract
        #[allow(dead_code)]
        governance_validator_hash: KeccakHash,
    },
    /// Event indication that a new smart contract has been
    /// deployed
    NewContract {
        /// Name of the contract
        #[allow(dead_code)]
        name: String,
        /// Address of the contract on Ethereum
        #[allow(dead_code)]
        address: EthAddress,
    },
    /// Event indicating that a smart contract has been updated
    UpgradedContract {
        /// Name of the contract
        #[allow(dead_code)]
        name: String,
        /// Address of the contract on Ethereum
        #[allow(dead_code)]
        address: EthAddress,
    },
    /// Event indication a new Ethereum based token has been whitelisted for
    /// transfer across the bridge
    UpdateBridgeWhitelist {
        /// Monotonically increasing nonce
        #[allow(dead_code)]
        nonce: Uint,
        /// Tokens to be allowed to be transferred across the bridge
        #[allow(dead_code)]
        whitelist: Vec<TokenWhitelist>,
    },
}

impl EthereumEvent {
    /// SHA256 of the Borsh serialization of the [`EthereumEvent`].
    #[allow(dead_code)]
    fn hash(&self) -> Result<Hash, std::io::Error> {
        let bytes = self.try_to_vec()?;
        Ok(Hash::sha256(&bytes))
    }
}

/// An event transferring some kind of value from Ethereum to Anoma
#[derive(
    Clone, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize, BorshSchema,
)]
pub struct TransferToNamada {
    /// Quantity of the ERC20 token in the transfer
    pub amount: Amount,
    /// Address of the smart contract issuing the token
    pub asset: EthAddress,
    /// The address receiving wrapped assets on Anoma
    pub receiver: Address,
}

/// An event transferring some kind of value from Anoma to Ethereum
#[derive(
    Clone, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize, BorshSchema,
)]
pub struct TransferToEthereum {
    /// Quantity of wrapped Asset in the transfer
    pub amount: Amount,
    /// Address of the smart contract issuing the token
    pub asset: EthAddress,
    /// The address receiving assets on Ethereum
    pub receiver: EthAddress,
}

/// struct for whitelisting a token from Ethereum.
/// Includes the address of issuing contract and
/// a cap on the max amount of this token allowed to be
/// held by the bridge.
#[derive(
    Clone, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize, BorshSchema,
)]
#[allow(dead_code)]
pub struct TokenWhitelist {
    /// Address of Ethereum smart contract issuing token
    pub token: EthAddress,
    /// Maximum amount of token allowed on the bridge
    pub cap: Amount,
}

/// Contains types necessary for processing Ethereum events
/// in vote extensions
pub mod vote_extensions {
    use std::cmp::Ordering;
    use std::convert::TryFrom;
    use std::hash::Hasher;

    use borsh::{BorshDeserialize, BorshSchema, BorshSerialize};
    use eyre::{eyre, Result};
    use num_rational::Ratio;

    use super::EthereumEvent;
    use crate::proto::{MultiSigned, Signed};
    use crate::types::address::Address;
    use crate::types::key::common::PublicKey;
    use crate::types::key::{common, VerifySigError};
    use crate::types::storage::BlockHeight;

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
            let (numer, denom): (u64, u64) =
                TryFrom::<&FractionalVotingPower>::try_from(self).map_err(
                    |err| {
                        std::io::Error::new(
                            std::io::ErrorKind::InvalidData,
                            format!(
                                "Could not serialize {:?} to Borsh: {:?}",
                                self, err
                            ),
                        )
                    },
                )?;
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
}
