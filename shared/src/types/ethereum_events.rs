//! Types representing data intended for Anoma via Ethereum events

pub mod vote_extensions;

use borsh::{BorshDeserialize, BorshSchema, BorshSerialize};
use ethabi::Uint as ethUint;

use crate::types::address::Address;
use crate::types::hash::Hash;
use crate::types::token::Amount;

/// Anoma native type to replace the ethabi::Uint type
#[derive(
    Clone,
    Debug,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    BorshSerialize,
    BorshDeserialize,
    BorshSchema,
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
    Clone,
    Debug,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    BorshSerialize,
    BorshDeserialize,
    BorshSchema,
)]
pub struct EthAddress(pub [u8; 20]);

/// A Keccak hash
#[derive(
    Clone,
    Debug,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    BorshSerialize,
    BorshDeserialize,
    BorshSchema,
)]
pub struct KeccakHash(pub [u8; 32]);

/// An Ethereum event to be processed by the Anoma ledger
#[derive(
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Clone,
    Debug,
    BorshSerialize,
    BorshDeserialize,
    BorshSchema,
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
    pub fn hash(&self) -> Result<Hash, std::io::Error> {
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
    Clone,
    Debug,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    BorshSerialize,
    BorshDeserialize,
    BorshSchema,
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
    Clone,
    Debug,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    BorshSerialize,
    BorshDeserialize,
    BorshSchema,
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
    Clone,
    Debug,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    BorshSerialize,
    BorshDeserialize,
    BorshSchema,
)]
#[allow(dead_code)]
pub struct TokenWhitelist {
    /// Address of Ethereum smart contract issuing token
    pub token: EthAddress,
    /// Maximum amount of token allowed on the bridge
    pub cap: Amount,
}

/// Represents an Ethereum event being seen by some validators
#[derive(Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct EthMsgDiff {
    /// the event being seen
    pub body: EthereumEvent,
    /// addresses of the validators who have just seen this event
    pub seen_by: Vec<Address>,
}

#[allow(missing_docs)]
/// Test helpers
#[cfg(any(test, feature = "testing"))]
pub mod testing {
    use rand::prelude::ThreadRng;

    use super::vote_extensions::*;
    use super::*;
    use crate::types::key::{common, ed25519, SigScheme};
    use crate::types::storage::BlockHeight;
    use crate::types::token::Amount;

    const DAI_ERC20_ETH_ADDRESS: &str =
        "0x6B175474E89094C44Da98b954EedeAC495271d0F";

    pub fn arbitrary_eth_address() -> EthAddress {
        let bytes: [u8; 20] =
            hex::decode(DAI_ERC20_ETH_ADDRESS[2..].as_bytes())
                .unwrap()
                .try_into()
                .unwrap();

        EthAddress(bytes)
    }

    pub fn arbitrary_fractional_voting_power() -> FractionalVotingPower {
        FractionalVotingPower::new(1, 3).unwrap()
    }

    pub fn arbitrary_nonce() -> Uint {
        123.into()
    }

    pub fn arbitrary_amount() -> Amount {
        Amount::from(1_000)
    }

    pub fn arbitrary_block_height() -> BlockHeight {
        BlockHeight(100)
    }

    /// This will actually generate a new random secret key each time it's
    /// called
    pub fn arbitrary_secret_key() -> common::SecretKey {
        let mut rng: ThreadRng = rand::thread_rng();
        let sk: common::SecretKey = {
            use crate::types::key::SecretKey;
            ed25519::SigScheme::generate(&mut rng).try_to_sk().unwrap()
        };
        sk
    }
}
