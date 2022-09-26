//! The necessary type definitions for the contents of the
//! Ethereum bridge pool
use borsh::{BorshDeserialize, BorshSerialize, BorshSchema};
use ethabi::token::Token;

use crate::types::address::Address;
use crate::types::ethereum_events::{EthAddress, Uint, KeccakHash};
use crate::types::keccak;
use crate::types::token::Amount;

/// A transfer message to be submitted to Ethereum
/// to move assets from Namada across the bridge.
#[derive(
    Debug,
    Clone,
    Hash,
    PartialOrd,
    PartialEq,
    Eq,
    BorshSerialize,
    BorshDeserialize,
    BorshSchema,
)]
pub struct TransferToEthereum {
    /// The type of token
    pub asset: EthAddress,
    /// The recipient address
    pub recipient: EthAddress,
    /// The amount to be transferred
    pub amount: Amount,
    /// a nonce for replay protection
    pub nonce: Uint,
}

/// A transfer message to Ethereum sitting in the
/// bridge pool, waiting to be relayed
#[derive(
    Debug,
    Clone,
    Hash,
    PartialOrd,
    PartialEq,
    Eq,
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

impl keccak::encode::Encode for PendingTransfer {

    fn tokenize(&self) -> Vec<Token> {
        let from = Token::String(self.gas_fee.payer.to_string());
        let fee = Token::Uint(u64::from(self.gas_fee.amount).into());
        let to = Token::Address(self.transfer.recipient.0.into());
        let amount = Token::Uint(u64::from(self.transfer.amount).into());
        let nonce = Token::Uint(self.transfer.nonce.into());
        vec![
            from,
            fee,
            to,
            amount,
            nonce,
        ]
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
    Eq,
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
