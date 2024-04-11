//! Pgf VP

/// Pgf utility functions and structures
pub mod utils;

use std::collections::BTreeSet;

use namada_core::booleans::BoolResultUnitExt;
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
    #[error("PGF VP error: Native VP error: {0}")]
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
    ) -> Result<()> {
        keys_changed.iter().try_for_each(|key| {
            let key_type = KeyType::from(key);

            match key_type {
                KeyType::Stewards(steward_address) => {
                    let stewards_have_increased = {
                        // TODO: maybe we should check errors here, which could
                        // be out-of-gas related?
                        let total_stewards_pre = pgf_storage::stewards_handle()
                            .len(&self.ctx.pre())
                            .unwrap_or_default();
                        let total_stewards_post =
                            pgf_storage::stewards_handle()
                                .len(&self.ctx.post())
                                .unwrap_or_default();

                        total_stewards_pre < total_stewards_post
                    };

                    if stewards_have_increased {
                        return Err(native_vp::Error::new_const(
                            "Stewards can only be added via governance \
                             proposals",
                        )
                        .into());
                    }

                    pgf::storage::get_steward(
                        &self.ctx.post(),
                        steward_address,
                    )?
                    .map_or_else(
                        // if a steward resigns, check their signature
                        || {
                            verifiers.contains(steward_address).ok_or_else(
                                || {
                                    native_vp::Error::new_alloc(format!(
                                        "The VP of the steward \
                                         {steward_address} should have been \
                                         triggered to check their signature"
                                    ))
                                    .into()
                                },
                            )
                        },
                        // if a steward updates the reward distribution (so
                        // total_stewards_pre == total_stewards_post) check
                        // their signature and if commissions are valid
                        |steward| {
                            if !verifiers.contains(steward_address) {
                                return Err(native_vp::Error::new_alloc(
                                    format!(
                                        "The VP of the steward \
                                         {steward_address} should have been \
                                         triggered to check their signature"
                                    ),
                                )
                                .into());
                            }
                            steward.is_valid_reward_distribution().ok_or_else(
                                || {
                                    native_vp::Error::new_const(
                                        "Steward commissions are invalid",
                                    )
                                    .into()
                                },
                            )
                        },
                    )
                }
                KeyType::Fundings => Err(native_vp::Error::new_alloc(format!(
                    "Cannot update PGF fundings key: {key}"
                ))
                .into()),
                KeyType::PgfInflationRate | KeyType::StewardInflationRate => {
                    self.is_valid_parameter_change(tx_data)
                }
                KeyType::UnknownPgf => Err(native_vp::Error::new_alloc(
                    format!("Unknown PGF state update on key: {key}"),
                )
                .into()),
                KeyType::Unknown => Ok(()),
            }
        })
    }
}

impl<'a, S, CA> PgfVp<'a, S, CA>
where
    S: StateRead,
    CA: 'static + WasmCacheAccess,
{
    /// Validate a governance parameter
    pub fn is_valid_parameter_change(&self, tx: &Tx) -> Result<()> {
        tx.data().map_or_else(
            || {
                Err(native_vp::Error::new_const(
                    "PGF parameter changes require tx data to be present",
                )
                .into())
            },
            |data| {
                is_proposal_accepted(&self.ctx.pre(), data.as_ref())
                    .map_err(Error::NativeVpError)?
                    .ok_or_else(|| {
                        native_vp::Error::new_const(
                            "PGF parameter changes can only be performed by a \
                             governance proposal that has been accepted",
                        )
                        .into()
                    })
            },
        )
    }
}

#[allow(clippy::upper_case_acronyms)]
#[derive(Debug)]
enum KeyType<'a> {
    Stewards(&'a Address),
    Fundings,
    PgfInflationRate,
    StewardInflationRate,
    UnknownPgf,
    Unknown,
}

impl<'k> From<&'k Key> for KeyType<'k> {
    fn from(key: &'k Key) -> Self {
        if let Some(addr) = pgf_storage::is_stewards_key(key) {
            Self::Stewards(addr)
        } else if pgf_storage::is_fundings_key(key) {
            KeyType::Fundings
        } else if pgf_storage::is_pgf_inflation_rate_key(key) {
            Self::PgfInflationRate
        } else if pgf_storage::is_steward_inflation_rate_key(key) {
            Self::StewardInflationRate
        } else if pgf_storage::is_pgf_key(key) {
            KeyType::UnknownPgf
        } else {
            KeyType::Unknown
        }
    }
}
