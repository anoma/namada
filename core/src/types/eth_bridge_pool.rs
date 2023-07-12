//! The necessary type definitions for the contents of the
//! Ethereum bridge pool

use borsh::{BorshDeserialize, BorshSchema, BorshSerialize};
use ethabi::token::Token;
use serde::{Deserialize, Serialize};

use crate::types::address::Address;
use crate::types::eth_abi::Encode;
pub use crate::types::ethereum_events::TransferToEthereumKind;
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
    /// The kind of transfer to Ethereum.
    pub kind: TransferToEthereumKind,
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

impl From<PendingTransfer> for ethbridge_structs::Erc20Transfer {
    fn from(pending: PendingTransfer) -> Self {
        Self {
            kind: pending.transfer.kind as u8,
            from: pending.transfer.asset.0.into(),
            to: pending.transfer.recipient.0.into(),
            amount: pending.transfer.amount.into(),
            fee_from: pending.gas_fee.payer.to_string(),
            fee: pending.gas_fee.amount.into(),
            sender: pending.transfer.sender.to_string(),
        }
    }
}

impl Encode<8> for PendingTransfer {
    fn tokenize(&self) -> [Token; 8] {
        // TODO: This version should be looked up from storage
        let version = Token::Uint(1.into());
        let namespace = Token::String(NAMESPACE.into());
        let from = Token::Address(self.transfer.asset.0.into());
        let fee = Token::Uint(self.gas_fee.amount.into());
        let to = Token::Address(self.transfer.recipient.0.into());
        let amount = Token::Uint(self.transfer.amount.into());
        let fee_from = Token::String(self.gas_fee.payer.to_string());
        let sender = Token::String(self.transfer.sender.to_string());
        [version, namespace, from, to, amount, fee_from, fee, sender]
    }
}

impl From<&TransferToEthereumEvent> for PendingTransfer {
    fn from(event: &TransferToEthereumEvent) -> Self {
        let transfer = TransferToEthereum {
            kind: event.kind,
            asset: event.asset,
            recipient: event.receiver,
            sender: event.sender.clone(),
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
