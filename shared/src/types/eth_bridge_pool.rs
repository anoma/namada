//! The necessary type definitions for the contents of the
//! Ethereum bridge pool
use borsh::{BorshDeserialize, BorshSerialize};

use crate::types::address::Address;
use crate::types::ethereum_events::{EthAddress, Uint};
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
)]
pub struct PendingTransfer {
    /// The message to send to Ethereum to
    pub transfer: TransferToEthereum,
    /// The amount of gas fees (in NAM)
    /// paid by the user sending this transfer
    pub gas_fee: GasFee,
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
)]
pub struct GasFee {
    /// The amount of fess (in NAM)
    pub amount: Amount,
    /// The account of fee payer.
    pub payer: Address,
}
