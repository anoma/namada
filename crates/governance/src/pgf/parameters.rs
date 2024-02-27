use std::collections::BTreeSet;

use namada_core::address::Address;
use namada_core::borsh::{BorshDeserialize, BorshSerialize};
use namada_core::dec::Dec;
use namada_storage::{Result, StorageRead, StorageWrite};
use serde::{Deserialize, Serialize};

use super::storage::keys as pgf_storage;
use super::storage::steward::StewardDetail;

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
    Serialize,
    Deserialize,
)]
/// Pgf parameter structure
pub struct PgfParameters {
    /// The set of stewards
    pub stewards: BTreeSet<Address>,
    /// The pgf funding inflation rate
    pub pgf_inflation_rate: Dec,
    /// The pgf stewards inflation rate
    pub stewards_inflation_rate: Dec,
}

impl Default for PgfParameters {
    fn default() -> Self {
        Self {
            stewards: BTreeSet::default(),
            pgf_inflation_rate: Dec::new(10, 2).unwrap(),
            stewards_inflation_rate: Dec::new(1, 2).unwrap(),
        }
    }
}

impl PgfParameters {
    /// Initialize governance parameters into storage
    pub fn init_storage<S>(&self, storage: &mut S) -> Result<()>
    where
        S: StorageRead + StorageWrite,
    {
        let Self {
            stewards,
            pgf_inflation_rate,
            stewards_inflation_rate,
        } = self;

        for steward in stewards {
            pgf_storage::stewards_handle().insert(
                storage,
                steward.to_owned(),
                StewardDetail::base(steward.clone()),
            )?;
        }

        let pgf_inflation_rate_key = pgf_storage::get_pgf_inflation_rate_key();
        storage.write(&pgf_inflation_rate_key, pgf_inflation_rate)?;

        let steward_inflation_rate_key =
            pgf_storage::get_steward_inflation_rate_key();
        storage.write(&steward_inflation_rate_key, stewards_inflation_rate)
    }
}
