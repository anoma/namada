//! Proof-of-Stake native validity predicate.

use std::collections::{BTreeMap, BTreeSet};
use std::marker::PhantomData;

use namada_core::address::Address;
use namada_core::booleans::BoolResultUnitExt;
use namada_core::storage::Key;
use namada_state::StateRead;
use namada_systems::governance;
use namada_tx::action::{
    Action, Bond, ClaimRewards, PosAction, Read, Redelegation, Unbond, Withdraw,
};
use namada_tx::BatchedTxRef;
use namada_vp::native_vp::{
    Ctx, CtxPreStorageRead, Error, NativeVp, Result, VpEvaluator,
};
use thiserror::Error;

use crate::storage::read_owned_pos_params;
use crate::storage_key::is_params_key;
use crate::types::BondId;
use crate::{storage_key, token};

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

/// Proof-of-Stake validity predicate
pub struct PosVp<'ctx, S, CA, EVAL, Gov>
where
    S: StateRead,
{
    /// Context to interact with the host structures.
    pub ctx: Ctx<'ctx, S, CA, EVAL>,
    /// Generic types for DI
    pub _marker: PhantomData<Gov>,
}

impl<'view, 'ctx: 'view, S, CA, EVAL, Gov> NativeVp<'view>
    for PosVp<'ctx, S, CA, EVAL, Gov>
where
    S: StateRead,
    CA: 'static + Clone,
    EVAL: 'static + VpEvaluator<'ctx, S, CA, EVAL>,
    Gov: governance::Read<CtxPreStorageRead<'view, 'ctx, S, CA, EVAL>>,
{
    fn validate_tx(
        &'view self,
        batched_tx: &BatchedTxRef<'_>,
        keys_changed: &BTreeSet<Key>,
        verifiers: &BTreeSet<Address>,
    ) -> Result<()> {
        tracing::debug!("\nValidating PoS Tx\n");

        // Check if this is a governance proposal first
        if batched_tx
            .tx
            .data(batched_tx.cmt)
            .map(|tx_data| Gov::is_proposal_accepted(&self.ctx.pre(), &tx_data))
            .transpose()?
            .unwrap_or(false)
        {
            for key in keys_changed {
                if is_params_key(key) {
                    // If governance changes PoS params, the params have to be
                    // valid
                    self.is_valid_parameter_change()?;
                }
                // Any other change from governance is allowed without further
                // checks
            }
            return Ok(());
        }

        // Find the actions applied in the tx
        let actions = self.ctx.read_actions()?;

        // There must be at least one action
        if actions.is_empty()
            && keys_changed.iter().any(storage_key::is_pos_key)
        {
            tracing::info!(
                "Rejecting tx without any action written to temp storage"
            );
            return Err(Error::new_const(
                "Rejecting tx without any action written to temp storage",
            ));
        }

        let mut became_validator: BTreeSet<Address> = Default::default();
        let mut deactivated: BTreeSet<Address> = Default::default();
        let mut reactivated: BTreeSet<Address> = Default::default();
        let mut unjailed: BTreeSet<Address> = Default::default();
        let mut bonds: BTreeMap<BondId, token::Amount> = Default::default();
        let mut unbonds: BTreeMap<BondId, token::Amount> = Default::default();
        let mut withdrawals: BTreeSet<BondId> = Default::default();
        // The key is src bond ID and value is pair of (dest_validator, amount)
        let mut redelegations: BTreeMap<BondId, (Address, token::Amount)> =
            Default::default();
        let mut claimed_rewards: BTreeSet<BondId> = Default::default();
        let mut changed_commission: BTreeSet<Address> = Default::default();
        let mut changed_metadata: BTreeSet<Address> = Default::default();
        let mut changed_consensus_key: BTreeSet<Address> = Default::default();

        // Accumulate changes from the actions
        for action in actions {
            match action {
                Action::Pos(pos_action) => match pos_action {
                    PosAction::BecomeValidator(address) => {
                        if !verifiers.contains(&address) {
                            tracing::info!(
                                "Unauthorized PosAction::BecomeValidator"
                            );
                            return Err(VpError::Unauthorized(
                                "BecomeValidator",
                                address,
                            )
                            .into());
                        }
                        became_validator.insert(address);
                    }
                    PosAction::DeactivateValidator(validator) => {
                        if !verifiers.contains(&validator) {
                            tracing::info!(
                                "Unauthorized PosAction::DeactivateValidator"
                            );
                            return Err(VpError::Unauthorized(
                                "DeactivateValidator",
                                validator,
                            )
                            .into());
                        }
                        deactivated.insert(validator);
                    }
                    PosAction::ReactivateValidator(validator) => {
                        if !verifiers.contains(&validator) {
                            tracing::info!(
                                "Unauthorized PosAction::ReactivateValidator"
                            );
                            return Err(VpError::Unauthorized(
                                "ReactivateValidator",
                                validator,
                            )
                            .into());
                        }
                        reactivated.insert(validator);
                    }
                    PosAction::Unjail(validator) => {
                        if !verifiers.contains(&validator) {
                            tracing::info!("Unauthorized PosAction::Unjail");
                            return Err(VpError::Unauthorized(
                                "Unjail", validator,
                            )
                            .into());
                        }
                        unjailed.insert(validator);
                    }
                    PosAction::Bond(Bond {
                        validator,
                        amount,
                        source,
                    }) => {
                        let bond_id = BondId {
                            source: source.unwrap_or_else(|| validator.clone()),
                            validator,
                        };
                        if !verifiers.contains(&bond_id.source) {
                            tracing::info!("Unauthorized PosAction::Bond");
                            return Err(VpError::Unauthorized(
                                "Bond",
                                bond_id.source,
                            )
                            .into());
                        }
                        bonds.insert(bond_id, amount);
                    }
                    PosAction::Unbond(Unbond {
                        validator,
                        amount,
                        source,
                    }) => {
                        let bond_id = BondId {
                            source: source.unwrap_or_else(|| validator.clone()),
                            validator,
                        };
                        if !verifiers.contains(&bond_id.source) {
                            tracing::info!("Unauthorized PosAction::Unbond");
                            return Err(VpError::Unauthorized(
                                "Unbond",
                                bond_id.source,
                            )
                            .into());
                        }
                        unbonds.insert(bond_id, amount);
                    }
                    PosAction::Withdraw(Withdraw { validator, source }) => {
                        let bond_id = BondId {
                            source: source.unwrap_or_else(|| validator.clone()),
                            validator,
                        };
                        if !verifiers.contains(&bond_id.source) {
                            tracing::info!("Unauthorized PosAction::Withdraw");
                            return Err(VpError::Unauthorized(
                                "Withdraw",
                                bond_id.source,
                            )
                            .into());
                        }
                        withdrawals.insert(bond_id);
                    }
                    PosAction::Redelegation(Redelegation {
                        src_validator,
                        dest_validator,
                        owner,
                        amount,
                    }) => {
                        if !verifiers.contains(&owner) {
                            tracing::info!(
                                "Unauthorized PosAction::Redelegation"
                            );
                            return Err(VpError::Unauthorized(
                                "Redelegation",
                                owner,
                            )
                            .into());
                        }
                        let bond_id = BondId {
                            source: owner,
                            validator: src_validator,
                        };
                        redelegations.insert(bond_id, (dest_validator, amount));
                    }
                    PosAction::ClaimRewards(ClaimRewards {
                        validator,
                        source,
                    }) => {
                        let bond_id = BondId {
                            source: source.unwrap_or_else(|| validator.clone()),
                            validator,
                        };
                        if !verifiers.contains(&bond_id.source) {
                            tracing::info!(
                                "Unauthorized PosAction::ClaimRewards"
                            );
                            return Err(VpError::Unauthorized(
                                "ClaimRewards",
                                bond_id.source,
                            )
                            .into());
                        }
                        claimed_rewards.insert(bond_id);
                    }
                    PosAction::CommissionChange(validator) => {
                        if !verifiers.contains(&validator) {
                            tracing::info!(
                                "Unauthorized PosAction::CommissionChange"
                            );
                            return Err(VpError::Unauthorized(
                                "CommissionChange",
                                validator,
                            )
                            .into());
                        }
                        changed_commission.insert(validator);
                    }
                    PosAction::MetadataChange(validator) => {
                        if !verifiers.contains(&validator) {
                            tracing::info!(
                                "Unauthorized PosAction::MetadataChange"
                            );
                            return Err(VpError::Unauthorized(
                                "MetadataChange",
                                validator,
                            )
                            .into());
                        }
                        changed_metadata.insert(validator);
                    }
                    PosAction::ConsensusKeyChange(validator) => {
                        if !verifiers.contains(&validator) {
                            tracing::info!(
                                "Unauthorized PosAction::ConsensusKeyChange"
                            );
                            return Err(VpError::Unauthorized(
                                "ConsensusKeyChange",
                                validator,
                            )
                            .into());
                        }
                        changed_consensus_key.insert(validator);
                    }
                },
                _ => {
                    // Other actions are not relevant to PoS VP
                    continue;
                }
            }
        }

        for key in keys_changed {
            if is_params_key(key) {
                return Err(Error::new_const(
                    "PoS parameter changes can only be performed by a \
                     governance proposal that has been accepted",
                ));
            }
            // TODO: validate changes keys against the accumulated changes
        }
        Ok(())
    }
}

impl<'view, 'ctx: 'view, S, CA, EVAL, Gov> PosVp<'ctx, S, CA, EVAL, Gov>
where
    S: StateRead,
    CA: 'static + Clone,
    EVAL: 'static + VpEvaluator<'ctx, S, CA, EVAL>,
{
    /// Instantiate a `PosVP`.
    pub fn new(ctx: Ctx<'ctx, S, CA, EVAL>) -> Self {
        Self {
            ctx,
            _marker: PhantomData,
        }
    }

    /// Return `Ok` if the changed parameters are valid
    fn is_valid_parameter_change(&self) -> Result<()> {
        let validation_errors: Vec<crate::parameters::ValidationError> =
            read_owned_pos_params(&self.ctx.post())?.validate();
        validation_errors.is_empty().ok_or_else(|| {
            let validation_errors_str =
                itertools::join(validation_errors, ", ");
            Error::new_alloc(format!(
                "PoS parameter changes were invalid: {validation_errors_str}",
            ))
        })
    }
}
