//! Pgf VP

/// Pgf utility functions and structures
pub mod utils;

use std::collections::BTreeSet;

use namada_core::ledger::pgf::storage::keys as pgf_storage;
use namada_core::ledger::storage;
use namada_core::ledger::storage_api::governance::is_proposal_accepted;
use thiserror::Error;

use crate::ledger::native_vp;
use crate::ledger::native_vp::{Ctx, NativeVp};
use crate::types::address::{Address, InternalAddress};
use crate::types::storage::Key;
use crate::vm::WasmCacheAccess;

/// for handling Pgf NativeVP errors
pub type Result<T> = std::result::Result<T, Error>;

/// The PGF internal address
pub const ADDRESS: Address = Address::Internal(InternalAddress::Pgf);

#[allow(missing_docs)]
#[derive(Error, Debug)]
pub enum Error {
    #[error("Native VP error: {0}")]
    NativeVpError(#[from] native_vp::Error),
}

/// Pgf VP
pub struct PgfVp<'a, DB, H, CA>
where
    DB: storage::DB + for<'iter> storage::DBIter<'iter>,
    H: storage::StorageHasher,
    CA: WasmCacheAccess,
{
    /// Context to interact with the host structures.
    pub ctx: Ctx<'a, DB, H, CA>,
}

impl<'a, DB, H, CA> NativeVp for PgfVp<'a, DB, H, CA>
where
    DB: 'static + storage::DB + for<'iter> storage::DBIter<'iter>,
    H: 'static + storage::StorageHasher,
    CA: 'static + WasmCacheAccess,
{
    type Error = Error;

    const ADDR: InternalAddress = InternalAddress::Pgf;

    fn validate_tx(
        &self,
        tx_data: &[u8],
        keys_changed: &BTreeSet<Key>,
        _verifiers: &BTreeSet<Address>,
    ) -> Result<bool> {
        let result = keys_changed.iter().all(|key| {
            let key_type = KeyType::from(key);

            let result = match key_type {
                KeyType::STEWARDS => Ok(false),
                KeyType::PAYMENTS => Ok(false),
                KeyType::INFLATION_RATE => {
                    self.is_valid_parameter_change(tx_data)
                }
                KeyType::UNKNOWN_PGF => Ok(false),
                KeyType::UNKNOWN => Ok(true),
            };
            result.unwrap_or(false)
        });
        Ok(result)
    }
}

impl<'a, DB, H, CA> PgfVp<'a, DB, H, CA>
where
    DB: 'static + storage::DB + for<'iter> storage::DBIter<'iter>,
    H: 'static + storage::StorageHasher,
    CA: 'static + WasmCacheAccess,
{
    /// Validate a governance parameter
    pub fn is_valid_parameter_change(&self, tx_data: &[u8]) -> Result<bool> {
        is_proposal_accepted(&self.ctx.pre(), tx_data)
            .map_err(Error::NativeVpError)
    }
}

#[allow(clippy::upper_case_acronyms)]
#[derive(Debug)]
enum KeyType {
    #[allow(non_camel_case_types)]
    STEWARDS,
    #[allow(non_camel_case_types)]
    PAYMENTS,
    #[allow(non_camel_case_types)]
    INFLATION_RATE,
    #[allow(non_camel_case_types)]
    UNKNOWN_PGF,
    #[allow(non_camel_case_types)]
    UNKNOWN,
}

impl From<&Key> for KeyType {
    fn from(key: &Key) -> Self {
        if pgf_storage::is_stewards_key(key) {
            Self::STEWARDS
        } else if pgf_storage::is_payments_key(key) {
            KeyType::PAYMENTS
        } else if pgf_storage::is_inflation_rate_key(key) {
            Self::INFLATION_RATE
        } else if pgf_storage::is_pgf_key(key) {
            KeyType::UNKNOWN_PGF
        } else {
            KeyType::UNKNOWN
        }
    }
}
