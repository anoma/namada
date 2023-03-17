//! PGF council treasury VP

use namada_core::ledger::counsil_treasury::storage as pgf_counsil_treasury_storage;
use namada_core::ledger::storage_api::StorageRead;
use namada_core::types::token;
use crate::ledger::native_vp::{Ctx, NativeVp};
use crate::ledger::{native_vp, storage};
use crate::types::address::{Address, InternalAddress};
use crate::types::storage::Key;
use crate::vm::WasmCacheAccess;
use std::collections::BTreeSet;
use thiserror::Error;


/// PGF council treasury NativeVP error
pub type Result<T> = std::result::Result<T, Error>;

#[allow(missing_docs)]
#[derive(Error, Debug)]
pub enum Error {
    #[error("Native VP error: {0}")]
    NativeVpError(#[from] native_vp::Error),
}

/// PGFi CouncilTreasury VP
pub struct PgfCouncilTreasuryVp<'a, DB, H, CA>
where
    DB: storage::DB + for<'iter> storage::DBIter<'iter>,
    H: storage::StorageHasher,
    CA: WasmCacheAccess,
{
    /// Context to interact with the host structures.
    pub ctx: Ctx<'a, DB, H, CA>,
}

impl<'a, DB, H, CA> NativeVp for PgfCouncilTreasuryVp<'a, DB, H, CA>
where
    DB: 'static + storage::DB + for<'iter> storage::DBIter<'iter>,
    H: 'static + storage::StorageHasher,
    CA: 'static + WasmCacheAccess,
{
    type Error = Error;

    const ADDR: InternalAddress = InternalAddress::Pgf;

    fn validate_tx(
        &self,
        _tx_data: &[u8],
        keys_changed: &BTreeSet<Key>,
        verifiers: &BTreeSet<Address>,
    ) -> Result<bool> {
        let native_token = self.ctx.pre().get_native_token()?;

        let result = keys_changed.iter().all(|key| {
            let key_type = KeyType::from_key(key, &native_token);

            let result: Result<bool> = match key_type {
                KeyType::COUNSIL_MEMBER_REWARD_ADDRESS => {
                    self.is_signed_by_active_counsil(verifiers)
                }
                KeyType::BALANCE => {
                    self.is_signed_by_active_counsil(verifiers)
                }
                KeyType::UNKNOWN_PGF_COUNSIL_TREASURY => Ok(false),
                KeyType::UNKNOWN => Ok(true),
            };
            result.unwrap_or(false)
        });
        Ok(result)
    }
}

impl<'a, DB, H, CA> PgfCouncilTreasuryVp<'a, DB, H, CA>
where
    DB: 'static + storage::DB + for<'iter> storage::DBIter<'iter>,
    H: 'static + storage::StorageHasher,
    CA: 'static + WasmCacheAccess,
{
    // Check if the signature is valid for the active counsil
    fn is_signed_by_active_counsil(
        &self,
        verifiers: &BTreeSet<Address>,
    ) -> Result<bool> {
        let active_counsil_address_key = pgf_counsil_treasury_storage::get_counsil_address_key();
        let active_counsil_address: Option<Address> =
            self.ctx.pre().read(&active_counsil_address_key)?;
        match active_counsil_address {
            Some(address) => {
                let is_signed_by_active_counsil = verifiers.contains(&address);
                Ok(is_signed_by_active_counsil)
            }
            None => Ok(false),
        }
    }
}

#[allow(clippy::upper_case_acronyms)]
#[derive(Debug)]
enum KeyType {
    #[allow(non_camel_case_types)]
    COUNSIL_MEMBER_REWARD_ADDRESS,
    #[allow(non_camel_case_types)]
    BALANCE,
    #[allow(non_camel_case_types)]
    UNKNOWN_PGF_COUNSIL_TREASURY,
    #[allow(non_camel_case_types)]
    UNKNOWN,
}

impl KeyType {
    fn from_key(key: &Key, native_token: &Address) -> Self {
        if pgf_counsil_treasury_storage::is_counsil_members_key(key) {
            Self::COUNSIL_MEMBER_REWARD_ADDRESS
        } else if token::is_balance_key(native_token, key).is_some() {
            Self::BALANCE
        } else if pgf_counsil_treasury_storage::is_counsil_treasury_key(key) {
            Self::UNKNOWN_PGF_COUNSIL_TREASURY
        } else {
            Self::UNKNOWN
        }
    }
}
