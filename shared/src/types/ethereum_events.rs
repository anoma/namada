//! Types representing data intended for Anoma via Ethereum events

use borsh::{BorshDeserialize, BorshSerialize, BorshSchema};
use ethabi::Uint as ethUint;

use crate::types::address::Address;
use crate::types::token::Amount;

/// Anoma native type to replace the ethabi::Uint type
#[derive(Clone, Debug, BorshSerialize, BorshDeserialize, BorshSchema)]
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
#[derive(Clone, Debug, PartialEq, BorshSerialize, BorshDeserialize, BorshSchema)]
pub struct EthAddress(pub [u8; 20]);

/// A Keccak hash
#[derive(Clone, Debug, PartialEq, BorshSerialize, BorshDeserialize, BorshSchema)]
pub struct KeccakHash(pub [u8; 32]);

/// An Ethereum event to be processed by the Anoma ledger
#[derive(Clone, Debug, BorshSerialize, BorshDeserialize, BorshSchema)]
pub enum EthereumEvent {
    /// Event transferring batches of ether or Ethereum based ERC20 tokens
    /// from Ethereum to wrapped assets on Anoma
    TransfersToNamada(Vec<TransferToNamada>),
    /// A confirmation event that a batch of transfers have been made
    /// from Anoma to Ethereum
    TransfersToEthereum(Vec<TransferToEthereum>),
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

/// An event transferring some kind of value from Ethereum to Anoma
#[derive(Clone, Debug, PartialEq, BorshSerialize, BorshDeserialize, BorshSchema)]
pub struct TransferToNamada {
    /// Quantity of the ERC20 token in the transfer
    pub amount: Amount,
    /// Address of the smart contract issuing the token
    pub asset: EthAddress,
    /// The address receiving wrapped assets on Anoma
    pub receiver: Address,
}

/// An event transferring some kind of value from Ethereum to Anoma
#[derive(Clone, Debug, PartialEq, BorshSerialize, BorshDeserialize, BorshSchema)]
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
#[derive(Clone, Debug, BorshSerialize, BorshDeserialize, BorshSchema)]
#[allow(dead_code)]
pub struct TokenWhitelist {
    /// Address of Ethereum smart contract issuing token
    pub token: EthAddress,
    /// Maximum amount of token allowed on the bridge
    pub cap: Amount,
}