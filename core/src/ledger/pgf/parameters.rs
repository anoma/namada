use std::collections::BTreeSet;

use borsh::{BorshDeserialize, BorshSerialize};
use rust_decimal::Decimal;
use rust_decimal_macros::dec;

use super::storage::keys as pgf_storage;
use crate::ledger::storage::types::encode;
use crate::ledger::storage::{self, Storage};
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
    /// The pgf inflation rate
    pub inflation_rate: Decimal,
}

impl Default for PgfParams {
    fn default() -> Self {
        Self {
            stewards: BTreeSet::default(),
            payments: BTreeSet::default(),
            inflation_rate: dec!(0.05),
        }
    }
}

impl PgfParams {
    /// Initialize governance parameters into storage
    pub fn init_storage<DB, H>(&self, storage: &mut Storage<DB, H>)
    where
        DB: storage::DB + for<'iter> storage::DBIter<'iter>,
        H: storage::StorageHasher,
    {
        let Self {
            stewards,
            payments,
            inflation_rate,
        } = self;

        let stewards_key = pgf_storage::get_stewards_key();
        storage
            .write(&stewards_key, encode(&stewards))
            .expect("Should be able to write to storage.");

        let payments_key = pgf_storage::get_payments_key();
        storage
            .write(&payments_key, encode(&payments))
            .expect("Should be able to write to storage.");

        let inflation_rate_key = pgf_storage::get_inflation_rate_key();
        storage
            .write(&inflation_rate_key, encode(&inflation_rate))
            .expect("Should be able to write to storage.");
    }
}
