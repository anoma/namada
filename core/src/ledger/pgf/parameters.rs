use std::fmt::Display;

use borsh::{BorshDeserialize, BorshSerialize};

use super::storage as pgf_storage;
use crate::ledger::storage::types::encode;
use crate::ledger::storage_api::{self, StorageWrite};

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
/// Governance parameter structure
pub struct PgfParams {
    /// Duration of a PGF candidacy in Epochs
    pub candidacy_expiration: u64,
}

impl Display for PgfParams {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Candidacy expiration: {}", self.candidacy_expiration)
    }
}

impl Default for PgfParams {
    fn default() -> Self {
        Self {
            candidacy_expiration: 30,
        }
    }
}

impl PgfParams {
    /// Initialize pgf parameters into storage
    pub fn init_storage<S>(&self, storage: &mut S) -> storage_api::Result<()>
    where
        S: StorageWrite,
    {
        let Self {
            candidacy_expiration,
        } = self;

        let candidaci_expiraton_key =
            pgf_storage::get_candidacy_expiration_key();
        storage.write(&candidaci_expiraton_key, encode(&candidacy_expiration))
    }
}
