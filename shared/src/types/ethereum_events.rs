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

    /// Whether the event is valid or not. Validators should be slashed if they
    /// included a signed invalid event in their vote extension.
    pub fn is_valid(&self) -> bool {
        match self {
            EthereumEvent::TransfersToNamada { transfers, .. } => {
                !transfers.is_empty()
            }
            _ => true,
        }
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
    use std::ops::Deref;

    use borsh::{BorshDeserialize, BorshSchema, BorshSerialize};
    use eyre::{eyre, Result};
    use num_rational::Ratio;

    use super::EthereumEvent;
    use crate::proto::MultiSigned;
    use crate::types::address::Address;
    use crate::types::storage::BlockHeight;

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

        /// Convenience function for returning zero [`FractionalVotingPower`]
        pub fn zero() -> Self {
            Self(Ratio::new(0, 1))
        }

        /// Convenience function for returning full [`FractionalVotingPower`]
        pub fn full() -> Self {
            Self(Ratio::new(1, 1))
        }
    }

    impl Deref for FractionalVotingPower {
        type Target = Ratio<u64>;

        fn deref(&self) -> &Self::Target {
            &self.0
        }
    }

    impl From<&FractionalVotingPower> for (u64, u64) {
        fn from(ratio: &FractionalVotingPower) -> Self {
            (ratio.0.numer().to_owned(), ratio.0.denom().to_owned())
        }
    }

    impl TryFrom<Ratio<u64>> for FractionalVotingPower {
        type Error = eyre::Report;

        fn try_from(value: Ratio<u64>) -> Result<Self, Self::Error> {
            // TODO: check ratio is > 0 and <= 1
            Ok(Self(value))
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

    /// This is created by the block proposer based on the Ethereum events
    /// included in the vote extensions of the previous Tendermint round
    #[derive(Debug, Clone, BorshSerialize, BorshDeserialize, BorshSchema)]
    pub struct MultiSignedEthEvent {
        /// Address and voting power of the signing validators
        pub signers: Vec<(Address, FractionalVotingPower)>,
        /// Events as signed by validators
        pub event: MultiSigned<(EthereumEvent, BlockHeight)>,
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
}
