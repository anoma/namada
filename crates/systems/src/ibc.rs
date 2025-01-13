//! IBC abstract interfaces

use std::collections::BTreeMap;

use masp_primitives::transaction::components::ValueSum;
use masp_primitives::transaction::TransparentAddress;
use namada_core::address::Address;
use namada_core::borsh::BorshDeserialize;
use namada_core::masp::{MaspEpoch, TAddrData};
use namada_core::{masp_primitives, token};
pub use namada_storage::Result;

/// Abstract IBC storage read interface
pub trait Read<S> {
    /// Extract MASP transaction from IBC envelope
    fn try_extract_masp_tx_from_envelope<Transfer: BorshDeserialize>(
        tx_data: &[u8],
    ) -> Result<Option<masp_primitives::transaction::Transaction>>;

    /// Try to read a MASP transaction for the refund
    fn try_get_refund_masp_tx<Transfer: BorshDeserialize>(
        storage: &S,
        tx_data: &[u8],
        masp_epoch: MaspEpoch,
    ) -> Result<Option<masp_primitives::transaction::Transaction>>;

    /// Apply relevant IBC packets to the changed balances structure
    fn apply_ibc_packet<Transfer: BorshDeserialize>(
        tx_data: &[u8],
        acc: ChangedBalances,
    ) -> Result<ChangedBalances>;
}

/// Balances changed by a transaction
#[derive(Default, Debug, Clone)]
pub struct ChangedBalances {
    /// Map between MASP transparent address and Namada types
    pub decoder: BTreeMap<TransparentAddress, TAddrData>,
    /// Balances before the tx
    pub pre: BTreeMap<TransparentAddress, ValueSum<Address, token::Amount>>,
    /// Balances after the tx
    pub post: BTreeMap<TransparentAddress, ValueSum<Address, token::Amount>>,
}
