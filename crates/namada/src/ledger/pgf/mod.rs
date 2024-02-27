//! Pgf VP

/// Pgf utility functions and structures
pub mod utils;

use std::collections::BTreeSet;

use namada_governance::pgf::storage::keys as pgf_storage;
use namada_governance::{is_proposal_accepted, pgf};
use namada_state::StateRead;
use namada_tx::Tx;
use thiserror::Error;

use crate::address::{Address, InternalAddress};
use crate::ledger::native_vp;
use crate::ledger::native_vp::{Ctx, NativeVp};
use crate::storage::Key;
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
pub struct PgfVp<'a, S, CA>
where
    S: StateRead,
    CA: WasmCacheAccess,
{
    /// Context to interact with the host structures.
    pub ctx: Ctx<'a, S, CA>,
}

impl<'a, S, CA> NativeVp for PgfVp<'a, S, CA>
where
    S: StateRead,
    CA: 'static + WasmCacheAccess,
{
    type Error = Error;

    fn validate_tx(
        &self,
        tx_data: &Tx,
        keys_changed: &BTreeSet<Key>,
        verifiers: &BTreeSet<Address>,
    ) -> Result<bool> {
        let result = keys_changed.iter().all(|key| {
            let key_type = KeyType::from(key);

            let result = match key_type {
                KeyType::STEWARDS => {
                    let total_stewards_pre = pgf_storage::stewards_handle()
                        .len(&self.ctx.pre())
                        .unwrap_or_default();
                    let total_stewards_post = pgf_storage::stewards_handle()
                        .len(&self.ctx.post())
                        .unwrap_or_default();

                    // stewards can only be added via governance proposals
                    let is_valid = if total_stewards_pre < total_stewards_post {
                        false
                    } else {
                        // if a steward resign, check the signature
                        // if a steward update the reward distribution (so
                        // total_stewards_pre == total_stewards_post) check
                        // signature and if commission are valid
                        let steward_address = pgf_storage::is_stewards_key(key);
                        if let Some(address) = steward_address {
                            let steward_post = pgf::storage::get_steward(
                                &self.ctx.post(),
                                address,
                            );
                            match steward_post {
                                Ok(Some(steward)) => {
                                    steward.is_valid_reward_distribution()
                                        && verifiers.contains(address)
                                }
                                Ok(None) => verifiers.contains(address),
                                // if reading from storage returns an error,
                                // just return false
                                Err(_) => false,
                            }
                        } else {
                            false
                        }
                    };

                    Ok(is_valid)
                }
                KeyType::FUNDINGS => Ok(false),
                KeyType::PGF_INFLATION_RATE
                | KeyType::STEWARD_INFLATION_RATE => {
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

impl<'a, S, CA> PgfVp<'a, S, CA>
where
    S: StateRead,
    CA: 'static + WasmCacheAccess,
{
    /// Validate a governance parameter
    pub fn is_valid_parameter_change(&self, tx: &Tx) -> Result<bool> {
        match tx.data() {
            Some(data) => is_proposal_accepted(&self.ctx.pre(), data.as_ref())
                .map_err(Error::NativeVpError),
            None => Ok(false),
        }
    }
}

#[allow(clippy::upper_case_acronyms)]
#[derive(Debug)]
enum KeyType {
    #[allow(non_camel_case_types)]
    STEWARDS,
    #[allow(non_camel_case_types)]
    FUNDINGS,
    #[allow(non_camel_case_types)]
    PGF_INFLATION_RATE,
    #[allow(non_camel_case_types)]
    STEWARD_INFLATION_RATE,
    #[allow(non_camel_case_types)]
    UNKNOWN_PGF,
    #[allow(non_camel_case_types)]
    UNKNOWN,
}

impl From<&Key> for KeyType {
    fn from(key: &Key) -> Self {
        if pgf_storage::is_stewards_key(key).is_some() {
            Self::STEWARDS
        } else if pgf_storage::is_fundings_key(key) {
            KeyType::FUNDINGS
        } else if pgf_storage::is_pgf_inflation_rate_key(key) {
            Self::PGF_INFLATION_RATE
        } else if pgf_storage::is_steward_inflation_rate_key(key) {
            Self::STEWARD_INFLATION_RATE
        } else if pgf_storage::is_pgf_key(key) {
            KeyType::UNKNOWN_PGF
        } else {
            KeyType::UNKNOWN
        }
    }
}
