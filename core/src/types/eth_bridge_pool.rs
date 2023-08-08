//! The necessary type definitions for the contents of the
//! Ethereum bridge pool

use std::borrow::Cow;

use borsh::{BorshDeserialize, BorshSchema, BorshSerialize};
use ethabi::token::Token;
use serde::{Deserialize, Serialize};

use crate::ledger::eth_bridge::storage::wrapped_erc20s;
use crate::types::address::Address;
use crate::types::eth_abi::Encode;
use crate::types::ethereum_events::{
    EthAddress, TransferToEthereum as TransferToEthereumEvent,
};
use crate::types::hash::Hash as HashDigest;
use crate::types::storage::{DbKeySeg, Key};
use crate::types::token::Amount;

/// A version used in our Ethereuem smart contracts
const VERSION: u8 = 1;

/// A namespace used in our Ethereuem smart contracts
const NAMESPACE: &str = "transfer";

/// Transfer to Ethereum kinds.
#[derive(
    Copy,
    Clone,
    Debug,
    PartialEq,
    Eq,
    Hash,
    PartialOrd,
    Ord,
    BorshSerialize,
    BorshDeserialize,
    BorshSchema,
    Serialize,
    Deserialize,
)]
pub enum TransferToEthereumKind {
    /// Transfer ERC20 assets from Namada to Ethereum.
    ///
    /// These transfers burn wrapped ERC20 assets in Namada, once
    /// they have been confirmed.
    Erc20,
    /// Refund non-usable tokens.
    ///
    /// These Bridge pool transfers should be crafted for assets
    /// that have been transferred to Namada, that had either not
    /// been whitelisted or whose token caps had been exceeded in
    /// Namada at the time of the transfer.
    Nut,
}

/// Additional data appended to a [`TransferToEthereumEvent`] to
/// construct a [`PendingTransfer`].
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
pub struct PendingTransferAppendix<'transfer> {
    /// The kind of the pending transfer to Ethereum.
    pub kind: Cow<'transfer, TransferToEthereumKind>,
    /// The sender of the transfer.
    pub sender: Cow<'transfer, Address>,
    /// The amount of gas fees paid by the user
    /// sending this transfer.
    pub gas_fee: Cow<'transfer, GasFee>,
}

impl From<PendingTransfer> for PendingTransferAppendix<'static> {
    #[inline]
    fn from(pending: PendingTransfer) -> Self {
        Self {
            kind: Cow::Owned(pending.transfer.kind),
            sender: Cow::Owned(pending.transfer.sender),
            gas_fee: Cow::Owned(pending.gas_fee),
        }
    }
}

impl<'t> From<&'t PendingTransfer> for PendingTransferAppendix<'t> {
    #[inline]
    fn from(pending: &'t PendingTransfer) -> Self {
        Self {
            kind: Cow::Borrowed(&pending.transfer.kind),
            sender: Cow::Borrowed(&pending.transfer.sender),
            gas_fee: Cow::Borrowed(&pending.gas_fee),
        }
    }
}

impl<'transfer> PendingTransferAppendix<'transfer> {
    /// Calculate the checksum of this [`PendingTransferAppendix`].
    pub fn checksum(&self) -> HashDigest {
        let serialized = self
            .try_to_vec()
            .expect("Serializing a PendingTransferAppendix should not fail");
        HashDigest::sha256(serialized)
    }
}

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
    /// Transfer to Ethereum data.
    pub transfer: TransferToEthereum,
    /// Amount of gas fees paid by the user
    /// sending the transfer.
    pub gas_fee: GasFee,
}

impl PendingTransfer {
    /// Get a token [`Address`] from this [`PendingTransfer`].
    #[inline]
    pub fn token_address(&self) -> Address {
        match &self.transfer.kind {
            TransferToEthereumKind::Erc20 => {
                wrapped_erc20s::token(&self.transfer.asset)
            }
            TransferToEthereumKind::Nut => {
                wrapped_erc20s::nut(&self.transfer.asset)
            }
        }
    }

    /// Retrieve a reference to the appendix of this [`PendingTransfer`].
    #[inline]
    pub fn appendix(&self) -> PendingTransferAppendix<'_> {
        self.into()
    }

    /// Retrieve the owned appendix of this [`PendingTransfer`].
    #[inline]
    pub fn into_appendix(self) -> PendingTransferAppendix<'static> {
        self.into()
    }

    /// Craft a [`PendingTransfer`] from its constituents.
    pub fn from_parts(
        event: &TransferToEthereumEvent,
        appendix: PendingTransferAppendix<'_>,
    ) -> Self {
        let transfer = TransferToEthereum {
            kind: *appendix.kind,
            asset: event.asset,
            recipient: event.receiver,
            sender: (*appendix.sender).clone(),
            amount: event.amount,
        };
        let gas_fee = (*appendix.gas_fee).clone();
        Self { transfer, gas_fee }
    }
}

impl From<&PendingTransfer> for ethbridge_structs::Erc20Transfer {
    fn from(pending: &PendingTransfer) -> Self {
        let HashDigest(namada_data_digest) = pending.appendix().checksum();
        Self {
            from: pending.transfer.asset.0.into(),
            to: pending.transfer.recipient.0.into(),
            amount: pending.transfer.amount.into(),
            namada_data_digest,
        }
    }
}

impl From<&PendingTransfer> for TransferToEthereumEvent {
    fn from(pending: &PendingTransfer) -> Self {
        Self {
            amount: pending.transfer.amount,
            asset: pending.transfer.asset,
            receiver: pending.transfer.recipient,
            checksum: pending.appendix().checksum(),
        }
    }
}

impl Encode<6> for PendingTransfer {
    fn tokenize(&self) -> [Token; 6] {
        // TODO: This version should be looked up from storage
        let version = Token::Uint(VERSION.into());
        let namespace = Token::String(NAMESPACE.into());
        let from = Token::Address(self.transfer.asset.0.into());
        let to = Token::Address(self.transfer.recipient.0.into());
        let amount = Token::Uint(self.transfer.amount.into());
        let checksum = Token::FixedBytes(self.appendix().checksum().0.into());
        [version, namespace, from, to, amount, checksum]
    }
}

impl Encode<6> for TransferToEthereumEvent {
    fn tokenize(&self) -> [Token; 6] {
        // TODO: This version should be looked up from storage
        let version = Token::Uint(VERSION.into());
        let namespace = Token::String(NAMESPACE.into());
        let from = Token::Address(self.asset.0.into());
        let to = Token::Address(self.receiver.0.into());
        let amount = Token::Uint(self.amount.into());
        let checksum = Token::FixedBytes(self.checksum.0.into());
        [version, namespace, from, to, amount, checksum]
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

/// The amount of fees to be payed, in Namada, to the relayer
/// of a transfer across the Ethereum Bridge, compensating
/// for Ethereum gas costs.
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
    /// The amount of fees.
    pub amount: Amount,
    /// The account of fee payer.
    pub payer: Address,
    /// The address of the fungible token to draw
    /// gas fees from.
    pub token: Address,
}

#[cfg(test)]
mod test_eth_bridge_pool_types {
    use super::*;
    use crate::types::address::testing::established_address_1;

    /// Test that [`PendingTransfer`] and [`TransferToEthereum`]
    /// have the same keccak hash, after being ABI encoded.
    #[test]
    fn test_same_keccak_hash() {
        let pending = PendingTransfer {
            transfer: TransferToEthereum {
                kind: TransferToEthereumKind::Erc20,
                amount: 10u64.into(),
                asset: EthAddress([0xaa; 20]),
                recipient: EthAddress([0xbb; 20]),
                sender: established_address_1(),
            },
            gas_fee: GasFee {
                amount: 10u64.into(),
                payer: established_address_1(),
            },
        };
        let event: TransferToEthereumEvent = (&pending).into();
        assert_eq!(pending.keccak256(), event.keccak256());
    }
}
