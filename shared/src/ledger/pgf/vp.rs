//! Governance VP
use std::collections::BTreeSet;

use namada_core::ledger::pgf::{storage as pgf_storage, CounsilData};
use namada_core::ledger::vp_env::VpEnv;
use namada_core::types::token::Amount;
use thiserror::Error;

use super::MAX_COUNSIL_DATA;
use crate::ledger::native_vp::{Ctx, NativeVp};
use crate::ledger::storage_api::StorageRead;
use crate::ledger::{native_vp, storage};
use crate::types::address::{Address, InternalAddress};
use crate::types::storage::Key;
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
        _tx_data: &[u8],
        keys_changed: &BTreeSet<Key>,
        verifiers: &BTreeSet<Address>,
    ) -> Result<bool> {
        let native_token = self.ctx.pre().get_native_token()?;
        let res = self
            .is_valid_key_set(keys_changed, &native_token)
            .unwrap_or(false);
        if !res {
            return Ok(false);
        }

        let result = keys_changed.iter().all(|key| {
            let key_type = KeyType::from_key(key, &native_token);

            let result: Result<bool> = match key_type {
                KeyType::BALANCE => {
                    self.is_valid_transfer(verifiers, &native_token)
                }
                KeyType::SPENT_AMOUNT => {
                    self.is_valid_spent_amount(key, &native_token)
                }
                KeyType::CANDIDACY => self.is_valid_candidacy(key, verifiers),
                KeyType::RECEIPIENTS => {
                    self.is_valid_project(verifiers, &native_token)
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
    fn is_valid_candidacy(
        &self,
        key: &Key,
        verifiers: &BTreeSet<Address>,
    ) -> Result<bool> {
        let current_epoch = self.ctx.get_block_epoch().ok();
        let condidate_address = pgf_storage::get_candidate_address(key);
        let candidate_spending_cap =
            pgf_storage::get_candidate_spending_cap(key);
        let counsil_data: Option<CounsilData> = self.ctx.post().read(key)?;

        match (
            counsil_data,
            candidate_spending_cap,
            condidate_address,
            current_epoch,
        ) {
            (
                Some(data),
                Some(spending_cap),
                Some(address),
                Some(current_epoch),
            ) => {
                // TODO: maybe max charatecter should be a pgf vp parameter
                let is_valid_amount = spending_cap.is_greater_than_zero();
                let is_valid_data = data.data_is_less_than(MAX_COUNSIL_DATA)
                    && data.epoch.eq(&current_epoch);
                let is_valid_address =
                    self.is_valid_counsil_address(address, verifiers)?;
                Ok(is_valid_address && is_valid_data && is_valid_amount)
            }
            _ => Ok(false),
        }
    }

    /// Validate counsil address
    pub fn is_valid_counsil_address(
        &self,
        address: &Address,
        verifiers: &BTreeSet<Address>,
    ) -> Result<bool> {
        let address_exist_key = Key::validity_predicate(address);
        let address_exist = self.ctx.has_key_pre(&address_exist_key)?;
        Ok(address_exist && verifiers.contains(address))
    }

    /// Validate transfer from pgf
    pub fn is_valid_transfer(
        &self,
        verifiers: &BTreeSet<Address>,
        native_token: &Address,
    ) -> Result<bool> {
        self.is_signed_by_active_counsil(native_token, verifiers)
    }

    /// Validate spent amount
    pub fn is_valid_spent_amount(
        &self,
        _key: &Key,
        native_token: &Address,
    ) -> Result<bool> {
        let pgf_balance_amount =
            token::balance_key(native_token, self.ctx.address);
        let pre_balance: Option<Amount> =
            self.ctx.pre().read(&pgf_balance_amount)?;
        let post_balance: Option<Amount> =
            self.ctx.post().read(&pgf_balance_amount)?;

        let spending_cap_key = pgf_storage::get_spending_cap_key();
        let pre_spending_cap: Option<Amount> =
            self.ctx.pre().read(&spending_cap_key)?;
        let spend_amount_key = pgf_storage::get_spent_amount_key();
        let post_spent_amount: Option<Amount> =
            self.ctx.post().read(&spend_amount_key)?;
        let pre_spent_amount: Option<Amount> =
            self.ctx.pre().read(&spend_amount_key)?;

        match (
            pre_balance,
            post_balance,
            pre_spending_cap,
            pre_spent_amount,
            post_spent_amount,
        ) {
            (
                Some(pre_balance),
                Some(post_balance),
                Some(spending_cap),
                Some(pre_spent_amount),
                Some(post_spent_amount),
            ) => {
                let amount_transfered = pre_balance.checked_sub(post_balance);
                if let Some(amount) = amount_transfered {
                    let is_valid_post_spent_amount =
                        post_spent_amount == pre_spent_amount + amount;
                    let is_not_over_spending_cap =
                        post_spent_amount <= spending_cap;
                    Ok(is_valid_post_spent_amount && is_not_over_spending_cap)
                } else {
                    Ok(false)
                }
            }
            _ => Ok(false),
        }
    }

    // check if the set of keys is valid
    fn is_valid_key_set(
        &self,
        keys: &BTreeSet<Key>,
        native_token: &Address,
    ) -> Result<bool> {
        let mandatory_transfer_group = BTreeSet::from([
            token::balance_key(native_token, self.ctx.address),
            pgf_storage::get_spent_amount_key(),
        ]);
        let total_sets_diff = mandatory_transfer_group.difference(keys).count();
        Ok(total_sets_diff == 0
            || total_sets_diff == mandatory_transfer_group.len())
    }

    // Validate project key
    fn is_valid_project(
        &self,
        verifiers: &BTreeSet<Address>,
        native_token: &Address,
    ) -> Result<bool> {
        self.is_signed_by_active_counsil(native_token, verifiers)
    }

    // Check if thesignature is valid for the active counsil
    fn is_signed_by_active_counsil(
        &self,
        _native_token: &Address,
        verifiers: &BTreeSet<Address>,
    ) -> Result<bool> {
        let active_counsil_address_key = pgf_storage::get_active_counsil_key();
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
    BALANCE,
    #[allow(non_camel_case_types)]
    SPENT_AMOUNT,
    #[allow(non_camel_case_types)]
    CANDIDACY,
    #[allow(non_camel_case_types)]
    RECEIPIENTS,
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
            Self::BALANCE
        } else if pgf_storage::is_cpgf_recipient_key(key) {
            Self::RECEIPIENTS
        } else if pgf_storage::is_pgf_key(key) {
            Self::UNKNOWN_PGF
        } else {
            Self::UNKNOWN
        }
    }
}
