//! The necessary type definitions for the contents of the
//! Ethereum bridge pool

use std::borrow::Cow;

use borsh::{BorshDeserialize, BorshSchema, BorshSerialize};
use borsh_ext::BorshSerializeExt;
use ethabi::token::Token;
use namada_macros::StorageKeys;
use serde::{Deserialize, Serialize};

use super::address::InternalAddress;
use super::keccak::KeccakHash;
use super::storage::{self, KeySeg};
use crate as namada_core; // This is needed for `StorageKeys` macro
use crate::address::Address;
use crate::eth_abi::Encode;
use crate::ethereum_events::{
    EthAddress, TransferToEthereum as TransferToEthereumEvent,
};
use crate::hash::Hash as HashDigest;
use crate::storage::{DbKeySeg, Key};
use crate::token::Amount;

/// The main address of the Ethereum bridge pool
pub const BRIDGE_POOL_ADDRESS: Address =
    Address::Internal(InternalAddress::EthBridgePool);

/// Bridge pool key segments.
#[derive(StorageKeys)]
pub struct Segments {
    /// Signed root storage key
    pub signed_root: &'static str,
    /// Bridge pool nonce storage key
    pub bridge_pool_nonce: &'static str,
}

/// Check if a key is for a pending transfer
pub fn is_pending_transfer_key(key: &storage::Key) -> bool {
    let segment = match &key.segments[..] {
        [DbKeySeg::AddressSeg(addr), DbKeySeg::StringSeg(segment)]
            if addr == &BRIDGE_POOL_ADDRESS =>
        {
            segment.as_str()
        }
        _ => return false,
    };
    !Segments::ALL.iter().any(|s| s == &segment)
}

/// Get the storage key for the transfers in the pool
pub fn get_pending_key(transfer: &PendingTransfer) -> Key {
    get_key_from_hash(&transfer.keccak256())
}

/// Get the storage key for the transfers using the hash
pub fn get_key_from_hash(hash: &KeccakHash) -> Key {
    Key {
        segments: vec![
            DbKeySeg::AddressSeg(BRIDGE_POOL_ADDRESS),
            hash.to_db_key(),
        ],
    }
}

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

impl std::fmt::Display for TransferToEthereumKind {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            Self::Erc20 => write!(f, "ERC20"),
            Self::Nut => write!(f, "NUT"),
        }
    }
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
    /* BorshSchema, */
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
        let serialized = self.serialize_to_vec();
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

/// Construct a token address from an ERC20 address.
pub fn erc20_token_address(address: &EthAddress) -> Address {
    Address::Internal(InternalAddress::Erc20(*address))
}

/// Construct a NUT token address from an ERC20 address.
pub fn erc20_nut_address(address: &EthAddress) -> Address {
    Address::Internal(InternalAddress::Nut(*address))
}

impl PendingTransfer {
    /// Get a token [`Address`] from this [`PendingTransfer`].
    #[inline]
    pub fn token_address(&self) -> Address {
        match &self.transfer.kind {
            TransferToEthereumKind::Erc20 => {
                erc20_token_address(&self.transfer.asset)
            }
            TransferToEthereumKind::Nut => {
                erc20_nut_address(&self.transfer.asset)
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
        let HashDigest(data_digest) = pending.appendix().checksum();
        Self {
            from: pending.transfer.asset.0.into(),
            to: pending.transfer.recipient.0.into(),
            amount: pending.transfer.amount.into(),
            data_digest,
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

/// The amount of fees to be paid, in Namada, to the relayer
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

#[cfg(any(test, feature = "testing"))]
/// Testing helpers and strategies for the Ethereum bridge pool
pub mod testing {
    use proptest::prop_compose;
    use proptest::strategy::Strategy;

    use super::*;
    use crate::address::testing::{
        arb_established_address, arb_non_internal_address,
    };
    use crate::ethereum_events::testing::arb_eth_address;
    use crate::token::testing::arb_amount;

    prop_compose! {
        /// Generate an arbitrary pending transfer
        pub fn arb_pending_transfer()(
            transfer in arb_transfer_to_ethereum(),
            gas_fee in arb_gas_fee(),
        ) -> PendingTransfer {
            PendingTransfer {
                transfer,
                gas_fee,
            }
        }
    }

    prop_compose! {
        /// Generate an arbitrary Ethereum gas fee
        pub fn arb_gas_fee()(
            amount in arb_amount(),
            payer in arb_non_internal_address(),
            token in arb_established_address().prop_map(Address::Established),
        ) -> GasFee {
            GasFee {
                amount,
                payer,
                token,
            }
        }
    }

    prop_compose! {
        /// Generate the kind of a transfer to ethereum
        pub fn arb_transfer_to_ethereum_kind()(
            discriminant in 0..2,
        ) -> TransferToEthereumKind {
            match discriminant {
                0 => TransferToEthereumKind::Erc20,
                1 => TransferToEthereumKind::Nut,
                _ => unreachable!(),
            }
        }
    }

    prop_compose! {
        /// Generate an arbitrary transfer to Ethereum
        pub fn arb_transfer_to_ethereum()(
            kind in arb_transfer_to_ethereum_kind(),
            asset in arb_eth_address(),
            recipient in arb_eth_address(),
            sender in arb_non_internal_address(),
            amount in arb_amount(),
        ) -> TransferToEthereum {
            TransferToEthereum {
                kind,
                asset,
                recipient,
                sender,
                amount,
            }
        }
    }
}

#[cfg(test)]
mod test_eth_bridge_pool_types {
    use super::*;
    use crate::address::testing::{established_address_1, nam};

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
                token: nam(),
                amount: 10u64.into(),
                payer: established_address_1(),
            },
        };
        let event: TransferToEthereumEvent = (&pending).into();
        assert_eq!(pending.keccak256(), event.keccak256());
    }
}
