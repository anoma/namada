//! The necessary type definitions for the contents of the
//! Ethereum bridge pool

use borsh::{BorshDeserialize, BorshSchema, BorshSerialize};
use ethabi::token::Token;
use serde::{Deserialize, Serialize};

use crate::types::address::{Address, InternalAddress};
use crate::types::eth_abi::Encode;
use crate::types::ethereum_events::{
    EthAddress, TransferToEthereum as TransferToEthereumEvent,
};
use crate::types::storage::{DbKeySeg, Key};
use crate::types::token::Amount;

/// A namespace used in our Ethereuem smart contracts
const NAMESPACE: &str = "transfer";

/// A transfer message to be submitted to Ethereum
/// to move assets from Namada across the bridge.
#[derive(
    Debug,
    Clone,
    Hash,
    PartialOrd,
    PartialEq,
    Ord,
    Eq,
    Serialize,
    Deserialize,
    BorshSerialize,
    BorshDeserialize,
    BorshSchema,
)]
pub struct TransferToEthereum {
    /// The type of token
    pub asset: EthAddress,
    /// The recipient address
    pub recipient: EthAddress,
    /// The sender of the transfer
    pub sender: Address,
    /// The amount to be transferred
    pub amount: Amount,
}

/// A transfer message to Ethereum sitting in the
/// bridge pool, waiting to be relayed
#[derive(
    Debug,
    Clone,
    Hash,
    PartialOrd,
    PartialEq,
    Ord,
    Eq,
    Serialize,
    Deserialize,
    BorshSerialize,
    BorshDeserialize,
    BorshSchema,
)]
pub struct PendingTransfer {
    /// The message to send to Ethereum to
    pub transfer: TransferToEthereum,
    /// The amount of gas fees (in NAM)
    /// paid by the user sending this transfer
    pub gas_fee: GasFee,
}

impl Encode<7> for PendingTransfer {
    fn tokenize(&self) -> [Token; 7] {
        // TODO: This version should be looked up from storage
        let version = Token::Uint(1.into());
        let namespace = Token::String(NAMESPACE.into());
        let from = Token::Address(self.transfer.asset.0.into());
        let fee = Token::Uint(u64::from(self.gas_fee.amount).into());
        let to = Token::Address(self.transfer.recipient.0.into());
        let amount = Token::Uint(u64::from(self.transfer.amount).into());
        let fee_from = Token::String(self.gas_fee.payer.to_string());
        [version, namespace, from, to, amount, fee, fee_from]
    }
}

impl From<&TransferToEthereumEvent> for PendingTransfer {
    fn from(event: &TransferToEthereumEvent) -> Self {
        let transfer = TransferToEthereum {
            asset: event.asset,
            recipient: event.receiver,
            // The sender is dummy because it doesn't affect the hash
            sender: Address::Internal(InternalAddress::EthBridgePool),
            amount: event.amount,
        };
        let gas_fee = GasFee {
            amount: event.gas_amount,
            payer: event.gas_payer.clone(),
        };
        Self { transfer, gas_fee }
    }
}

impl From<&PendingTransfer> for Key {
    fn from(transfer: &PendingTransfer) -> Self {
        Key {
            segments: vec![DbKeySeg::StringSeg(
                transfer.keccak256().to_string(),
            )],
        }
    }
}

/// The amount of NAM to be payed to the relayer of
/// a transfer across the Ethereum Bridge to compensate
/// for Ethereum gas fees.
#[derive(
    Debug,
    Clone,
    Hash,
    PartialOrd,
    PartialEq,
    Ord,
    Eq,
    Serialize,
    Deserialize,
    BorshSerialize,
    BorshDeserialize,
    BorshSchema,
)]
pub struct GasFee {
    /// The amount of fees (in NAM)
    pub amount: Amount,
    /// The account of fee payer.
    pub payer: Address,
}
