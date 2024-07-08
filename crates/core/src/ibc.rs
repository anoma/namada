//! IBC-related data types

use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Display;
use std::str::FromStr;

use borsh::{BorshDeserialize, BorshSchema, BorshSerialize};
use data_encoding::{DecodePartial, HEXLOWER, HEXLOWER_PERMISSIVE};
pub use ibc::*;
use masp_primitives::transaction::components::ValueSum;
use masp_primitives::transaction::TransparentAddress;
use namada_macros::BorshDeserializer;
#[cfg(feature = "migrations")]
use namada_migrations::*;
use serde::{Deserialize, Serialize};

use super::address::HASH_LEN;
use crate::address::Address;
use crate::hash::Hash;
use crate::masp::TAddrData;
use crate::{storage, token};

/// Abstract IBC storage read interface
pub trait Read<S> {
    /// Storage error
    type Err;

    /// Extract MASP transaction from IBC envelope
    fn try_extract_masp_tx_from_envelope(
        tx_data: &[u8],
    ) -> Result<Option<masp_primitives::transaction::Transaction>, Self::Err>;

    /// Apply relevant IBC packets to the changed balances structure
    fn apply_ibc_packet(
        storage: &S,
        tx_data: &[u8],
        acc: ChangedBalances,
        keys_changed: &BTreeSet<storage::Key>,
    ) -> Result<ChangedBalances, Self::Err>;
}

/// Balances changed by a transaction
#[derive(Default, Debug, Clone)]
pub struct ChangedBalances {
    /// Map between MASP transparent address and namada types
    pub decoder: BTreeMap<TransparentAddress, TAddrData>,
    /// Balances before the tx
    pub pre: BTreeMap<TransparentAddress, ValueSum<Address, token::Amount>>,
    /// Balances after the tx
    pub post: BTreeMap<TransparentAddress, ValueSum<Address, token::Amount>>,
}

/// IBC token hash derived from a denomination.
#[derive(
    Debug,
    Clone,
    Serialize,
    Deserialize,
    BorshSerialize,
    BorshDeserialize,
    BorshDeserializer,
    BorshSchema,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
)]
#[repr(transparent)]
pub struct IbcTokenHash(pub [u8; HASH_LEN]);

impl std::fmt::Display for IbcTokenHash {
    #[inline(always)]
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", HEXLOWER.encode(&self.0))
    }
}

impl FromStr for IbcTokenHash {
    type Err = DecodePartial;

    fn from_str(h: &str) -> Result<Self, Self::Err> {
        let mut output = [0u8; HASH_LEN];
        HEXLOWER_PERMISSIVE.decode_mut(h.as_ref(), &mut output)?;
        Ok(IbcTokenHash(output))
    }
}

/// IBC transaction data section hash
pub type IbcTxDataHash = Hash;

/// IBC transaction data references to retrieve IBC messages
#[derive(Default, Clone, Serialize, Deserialize)]
pub struct IbcTxDataRefs(pub Vec<IbcTxDataHash>);

impl Display for IbcTxDataRefs {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", serde_json::to_string(self).unwrap())
    }
}

impl FromStr for IbcTxDataRefs {
    type Err = serde_json::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        serde_json::from_str(s)
    }
}
