//! Pgf VP

use std::collections::BTreeSet;
use std::marker::PhantomData;

use namada_core::booleans::BoolResultUnitExt;
use namada_core::storage::Key;
use namada_tx::BatchedTxRef;
use namada_tx::action::{Action, PgfAction};
use namada_vp_env::{Error, Result, VpEnv};
use thiserror::Error;

use crate::address::{Address, InternalAddress};
use crate::pgf::storage::keys as pgf_storage;
use crate::{is_proposal_accepted, pgf};

/// The PGF internal address
pub const ADDRESS: Address = Address::Internal(InternalAddress::Pgf);

#[allow(missing_docs)]
#[derive(Error, Debug)]
pub enum VpError {
    #[error(
        "Action {0} not authorized by {1} which is not part of verifier set"
    )]
    Unauthorized(&'static str, Address),
}

impl From<VpError> for Error {
    fn from(value: VpError) -> Self {
        Error::new(value)
    }
}

/// Pgf VP
pub struct PgfVp<'ctx, CTX> {
    /// Generic types for DI
    pub _marker: PhantomData<&'ctx CTX>,
}

impl<'ctx, CTX> PgfVp<'ctx, CTX>
where
    CTX: VpEnv<'ctx> + namada_tx::action::Read<Err = Error>,
{
    /// Run the validity predicate
    pub fn validate_tx(
        ctx: &'ctx CTX,
        batched_tx: &BatchedTxRef<'_>,
        keys_changed: &BTreeSet<Key>,
        verifiers: &BTreeSet<Address>,
    ) -> Result<()> {
        // Find the actions applied in the tx
        let actions = ctx.read_actions()?;

        // Is VP triggered by a governance proposal?
        if is_proposal_accepted(
            &ctx.pre(),
            batched_tx
                .tx
                .data(batched_tx.cmt)
                .unwrap_or_default()
                .as_ref(),
        )? {
            return Ok(());
        }

        // There must be at least one action if any of the keys belong to PGF
        if actions.is_empty()
            && keys_changed.iter().any(pgf_storage::is_pgf_key)
        {
            tracing::info!(
                "Rejecting tx without any action written to temp storage"
            );
            return Err(Error::new_const(
                "Rejecting tx without any action written to temp storage",
            ));
        }

        // Check action authorization
        for action in actions {
            match action {
                Action::Pgf(pgf_action) => match pgf_action {
                    PgfAction::UpdateStewardCommission(address) => {
                        if !verifiers.contains(&address) {
                            tracing::info!(
                                "Unauthorized \
                                 PgfAction::UpdateStewardCommission"
                            );
                            return Err(VpError::Unauthorized(
                                "UpdateStewardCommission",
                                address,
                            )
                            .into());
                        }
                    }
                    PgfAction::ResignSteward(address) => {
                        if !verifiers.contains(&address) {
                            tracing::info!(
                                "Unauthorized PgfAction::ResignSteward"
                            );
                            return Err(VpError::Unauthorized(
                                "ResignSteward",
                                address,
                            )
                            .into());
                        }
                    }
                },
                _ => {
                    // Other actions are not relevant to PoS VP
                    continue;
                }
            }
        }

        keys_changed.iter().try_for_each(|key| {
            let key_type = KeyType::from(key);

            match key_type {
                KeyType::Stewards(steward_address) => {
                    let stewards_have_increased = {
                        let total_stewards_pre =
                            pgf_storage::stewards_handle().len(&ctx.pre())?;
                        let total_stewards_post =
                            pgf_storage::stewards_handle().len(&ctx.post())?;

                        total_stewards_pre < total_stewards_post
                    };

                    if stewards_have_increased {
                        return Err(Error::new_const(
                            "Stewards can only be added via governance \
                             proposals",
                        ));
                    }

                    pgf::storage::get_steward(&ctx.post(), steward_address)?
                        .map_or_else(
                            // if a steward resigns, check their signature
                            || {
                                verifiers.contains(steward_address).ok_or_else(
                                    || {
                                        Error::new_alloc(format!(
                                            "The VP of the steward \
                                             {steward_address} should have \
                                             been triggered to check their \
                                             signature"
                                        ))
                                    },
                                )
                            },
                            // if a steward updates the reward distribution (so
                            // total_stewards_pre == total_stewards_post) check
                            // their signature and if commissions are valid
                            |steward| {
                                if !verifiers.contains(steward_address) {
                                    return Err(Error::new_alloc(format!(
                                        "The VP of the steward \
                                         {steward_address} should have been \
                                         triggered to check their signature"
                                    )));
                                }
                                steward
                                    .is_valid_reward_distribution()
                                    .ok_or_else(|| {
                                        Error::new_const(
                                            "Steward commissions are invalid",
                                        )
                                    })
                            },
                        )
                }
                KeyType::Fundings => Err(Error::new_alloc(format!(
                    "Cannot update PGF fundings key: {key}"
                ))),
                KeyType::PgfInflationRate | KeyType::StewardInflationRate => {
                    Self::is_valid_parameter_change(ctx, batched_tx)
                }
                KeyType::UnknownPgf => Err(Error::new_alloc(format!(
                    "Unknown PGF state update on key: {key}"
                ))),
                KeyType::Unknown => Ok(()),
            }
        })
    }

    /// Validate a governance parameter
    pub fn is_valid_parameter_change(
        ctx: &'ctx CTX,
        batched_tx: &BatchedTxRef<'_>,
    ) -> Result<()> {
        batched_tx.tx.data(batched_tx.cmt).map_or_else(
            || {
                Err(Error::new_const(
                    "PGF parameter changes require tx data to be present",
                ))
            },
            |data| {
                is_proposal_accepted(&ctx.pre(), data.as_ref())?.ok_or_else(
                    || {
                        Error::new_const(
                            "PGF parameter changes can only be performed by a \
                             governance proposal that has been accepted",
                        )
                    },
                )
            },
        )
    }
}

#[allow(clippy::upper_case_acronyms)]
#[derive(Debug)]
enum KeyType<'ctx> {
    Stewards(&'ctx Address),
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
