//! Governance VP
use std::collections::BTreeSet;

use namada_core::ledger::pgf::storage as pgf_storage;
use namada_core::ledger::vp_env::VpEnv;
use thiserror::Error;

use crate::ledger::native_vp::{Ctx, NativeVp};
use crate::ledger::storage_api::StorageRead;
use crate::ledger::{native_vp, storage};
use crate::types::address::{Address, InternalAddress};
use crate::types::storage::{Epoch, Key};
use crate::types::token;
use crate::vm::WasmCacheAccess;

/// for handling Pgf NativeVP errors
pub type Result<T> = std::result::Result<T, Error>;

#[allow(missing_docs)]
#[derive(Error, Debug)]
pub enum Error {
    #[error("Native VP error: {0}")]
    NativeVpError(#[from] native_vp::Error),
}

/// Governance VP
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
        verifiers: &BTreeSet<Address>,
    ) -> Result<bool> {
        let native_token = self.ctx.pre().get_native_token()?;

        let result = keys_changed.iter().all(|key| {
            let key_type = KeyType::from_key(key, &native_token);

            let result: Result<bool> = match (key_type) {
                KeyType::BALANCE => todo!(),
                KeyType::SPENT_AMOUNT => todo!(),
                KeyType::UNKNOWN_PGF => todo!(),
                KeyType::CANDIDACY => todo!(),
                KeyType::UNKNOWN => todo!(),
            };
            result.unwrap_or(false)
        });
        Ok(result)
    }
}


#[allow(clippy::upper_case_acronyms)]
#[derive(Debug)]
enum KeyType {
    #[allow(non_camel_case_types)]
    BALANCE,
    #[allow(non_camel_case_types)]
    SPENT_AMOUNT,
    #[allow(non_camel_case_types)]
    CANDIDACY,
    #[allow(non_camel_case_types)]
    UNKNOWN_PGF,
    #[allow(non_camel_case_types)]
    UNKNOWN,
}

impl KeyType {
    fn from_key(key: &Key, native_token: &Address) -> Self {
        if pgf_storage::is_spent_amount_key(key) {
            Self::SPENT_AMOUNT
        } else if pgf_storage::is_candidates_key(key) {
            Self::CANDIDACY
        } else if token::is_balance_key(native_token, key).is_some() {
            KeyType::BALANCE
        } else if pgf_storage::is_pgf_key(key) {
            KeyType::UNKNOWN_PGF
        } else {
            KeyType::UNKNOWN
        }
    }
}
