//! SlashFund VP

use std::collections::BTreeSet;

/// SlashFund storage
pub mod storage;

use borsh::BorshDeserialize;
use thiserror::Error;

use self::storage as slash_fund_storage;
use super::governance::vp::is_proposal_accepted;
use crate::ledger::native_vp::{self, Ctx, NativeVp};
use crate::ledger::storage::{self as ledger_storage, StorageHasher};
use crate::types::address::{xan as nam, Address, InternalAddress};
use crate::types::storage::Key;
use crate::types::token;
use crate::vm::WasmCacheAccess;

/// Internal SlashFund address
pub const ADDRESS: Address = Address::Internal(InternalAddress::SlashFund);

#[allow(missing_docs)]
#[derive(Error, Debug)]
pub enum Error {
    #[error("Native VP error: {0}")]
    NativeVpError(native_vp::Error),
}

/// SlashFund functions result
pub type Result<T> = std::result::Result<T, Error>;

/// SlashFund VP
pub struct SlashFundVp<'a, DB, H, CA>
where
    DB: ledger_storage::DB + for<'iter> ledger_storage::DBIter<'iter>,
    H: StorageHasher,
    CA: WasmCacheAccess,
{
    /// Context to interact with the host structures.
    pub ctx: Ctx<'a, DB, H, CA>,
}

impl<'a, DB, H, CA> NativeVp for SlashFundVp<'a, DB, H, CA>
where
    DB: 'static + ledger_storage::DB + for<'iter> ledger_storage::DBIter<'iter>,
    H: 'static + StorageHasher,
    CA: 'static + WasmCacheAccess,
{
    type Error = Error;

    const ADDR: InternalAddress = InternalAddress::SlashFund;

    fn validate_tx(
        &self,
        tx_data: &[u8],
        keys_changed: &BTreeSet<Key>,
        _verifiers: &BTreeSet<Address>,
    ) -> Result<bool> {
        let result = keys_changed.iter().all(|key| {
            let key_type: KeyType = key.into();
            match key_type {
                KeyType::BALANCE(addr) => {
                    if addr.ne(&ADDRESS) {
                        return true;
                    }

                    let proposal_id = u64::try_from_slice(tx_data).ok();
                    match proposal_id {
                        Some(id) => is_proposal_accepted(&self.ctx, id),
                        None => false,
                    }
                }
                KeyType::UNKNOWN_SLASH_FUND => false,
                KeyType::UNKNOWN => true,
            }
        });
        Ok(result)
    }
}

#[allow(clippy::upper_case_acronyms)]
enum KeyType {
    #[allow(clippy::upper_case_acronyms)]
    BALANCE(Address),
    #[allow(clippy::upper_case_acronyms)]
    #[allow(non_camel_case_types)]
    UNKNOWN_SLASH_FUND,
    #[allow(clippy::upper_case_acronyms)]
    UNKNOWN,
}

impl From<&Key> for KeyType {
    fn from(value: &Key) -> Self {
        if slash_fund_storage::is_slash_fund_key(value) {
            KeyType::UNKNOWN_SLASH_FUND
        } else if token::is_any_token_balance_key(value).is_some() {
            match token::is_balance_key(&nam(), value) {
                Some(addr) => KeyType::BALANCE(addr.clone()),
                None => KeyType::UNKNOWN,
            }
        } else {
            KeyType::UNKNOWN
        }
    }
}
