use std::collections::BTreeSet;

use borsh::{BorshDeserialize, BorshSerialize};
use rust_decimal::Decimal;
use rust_decimal_macros::dec;

use super::storage::keys as pgf_storage;
use crate::ledger::storage_api::{self, StorageRead, StorageWrite};
use crate::types::address::Address;

#[derive(
    Clone,
    Debug,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
    BorshSerialize,
    BorshDeserialize,
)]
/// Pgf parameter structure
pub struct PgfParams {
    /// The set of stewards
    pub stewards: BTreeSet<Address>,
    /// The set of continous payments
    pub payments: BTreeSet<u64>,
    /// The pgf funding inflation rate
    pub pgf_inflation_rate: Decimal,
    /// The pgf stewards inflation rate
    pub stewards_inflation_rate: Decimal,
}

impl Default for PgfParams {
    fn default() -> Self {
        Self {
            stewards: BTreeSet::default(),
            payments: BTreeSet::default(),
            pgf_inflation_rate: dec!(0.05),
            stewards_inflation_rate: dec!(0.01),
        }
    }
}

impl PgfParams {
    /// Initialize governance parameters into storage
    pub fn init_storage<S>(&self, storage: &mut S) -> storage_api::Result<()>
    where
        S: StorageRead + StorageWrite,
    {
        let Self {
            stewards,
            payments,
            pgf_inflation_rate,
            stewards_inflation_rate,
        } = self;

        let stewards_key = pgf_storage::get_stewards_key();
        storage.write(&stewards_key, stewards)?;

        let payments_key = pgf_storage::get_payments_key();
        storage.write(&payments_key, payments)?;

        let pgf_inflation_rate_key = pgf_storage::get_pgf_inflation_rate_key();
        storage.write(&pgf_inflation_rate_key, pgf_inflation_rate)?;

        let steward_inflation_rate_key =
            pgf_storage::get_steward_inflation_rate_key();
        storage.write(&steward_inflation_rate_key, stewards_inflation_rate)
    }
}
