//! Pgf VP

use std::collections::BTreeSet;

use namada_core::booleans::BoolResultUnitExt;
use namada_core::storage::Key;
use namada_state::StateRead;
use namada_tx::action::{Action, PgfAction, Read};
use namada_tx::BatchedTxRef;
use namada_vp::native_vp::{self, Ctx, NativeVp, VpEvaluator};
use thiserror::Error;

use crate::address::{Address, InternalAddress};
use crate::pgf::storage::keys as pgf_storage;
use crate::{is_proposal_accepted, pgf};

/// for handling Pgf NativeVP errors
pub type Result<T> = std::result::Result<T, Error>;

/// The PGF internal address
pub const ADDRESS: Address = Address::Internal(InternalAddress::Pgf);

#[allow(missing_docs)]
#[derive(Error, Debug)]
pub enum Error {
    #[error("PGF VP error: Native VP error: {0}")]
    NativeVpError(#[from] native_vp::Error),
    #[error(
        "Action {0} not authorized by {1} which is not part of verifier set"
    )]
    Unauthorized(&'static str, Address),
}

/// Pgf VP
pub struct PgfVp<'ctx, S, CA, EVAL>
where
    S: 'static + StateRead,
    EVAL: VpEvaluator<'ctx, S, CA, EVAL>,
{
    /// Context to interact with the host structures.
    pub ctx: Ctx<'ctx, S, CA, EVAL>,
}

impl<'view, 'ctx, S, CA, EVAL> NativeVp<'view> for PgfVp<'ctx, S, CA, EVAL>
where
    S: 'static + StateRead,
    CA: 'static + Clone,
    EVAL: 'static + VpEvaluator<'ctx, S, CA, EVAL>,
{
    type Error = Error;

    fn validate_tx(
        &'view self,
        batched_tx: &BatchedTxRef<'_>,
        keys_changed: &BTreeSet<Key>,
        verifiers: &BTreeSet<Address>,
    ) -> Result<()> {
        // Find the actions applied in the tx
        let actions = self.ctx.read_actions()?;

        // Is VP triggered by a governance proposal?
        if is_proposal_accepted(
            &self.ctx.pre(),
            batched_tx
                .tx
                .data(batched_tx.cmt)
                .unwrap_or_default()
                .as_ref(),
        )
        .unwrap_or_default()
        {
            return Ok(());
        }

        // There must be at least one action if any of the keys belong to PGF
        if actions.is_empty()
            && keys_changed.iter().any(pgf_storage::is_pgf_key)
        {
            tracing::info!(
                "Rejecting tx without any action written to temp storage"
            );
            return Err(native_vp::Error::new_const(
                "Rejecting tx without any action written to temp storage",
            )
            .into());
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
                            return Err(Error::Unauthorized(
                                "UpdateStewardCommission",
                                address,
                            ));
                        }
                    }
                    PgfAction::ResignSteward(address) => {
                        if !verifiers.contains(&address) {
                            tracing::info!(
                                "Unauthorized PgfAction::ResignSteward"
                            );
                            return Err(Error::Unauthorized(
                                "ResignSteward",
                                address,
                            ));
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
                        // TODO(namada#3238): we should check errors here, which
                        // could be out-of-gas related
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
                    self.is_valid_parameter_change(batched_tx)
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

impl<'view, 'ctx, S, CA, EVAL> PgfVp<'ctx, S, CA, EVAL>
where
    S: 'static + StateRead,
    CA: 'static + Clone,
    EVAL: 'static + VpEvaluator<'ctx, S, CA, EVAL>,
{
    /// Instantiate PGF VP
    pub fn new(ctx: Ctx<'ctx, S, CA, EVAL>) -> Self {
        Self { ctx }
    }

    /// Validate a governance parameter
    pub fn is_valid_parameter_change(
        &'view self,
        batched_tx: &BatchedTxRef<'_>,
    ) -> Result<()> {
        batched_tx.tx.data(batched_tx.cmt).map_or_else(
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
