//! IBC abstract interfaces

use std::collections::{BTreeMap, BTreeSet};

use masp_primitives::transaction::components::ValueSum;
use masp_primitives::transaction::TransparentAddress;
use namada_core::address::Address;
use namada_core::masp::TAddrData;
use namada_core::{masp_primitives, storage, token};

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
