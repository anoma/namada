//! Proof of Stake system.
//!
//! TODO: We might need to storage both active and total validator set voting
//! power. For consensus, we only consider active validator set voting power,
//! but for other activities in which inactive validators can participate (e.g.
//! voting on a protocol parameter changes, upgrades, default VP changes) we
//! should use the total validator set voting power.

#![doc(html_favicon_url = "https://dev.namada.net/master/favicon.png")]
#![doc(html_logo_url = "https://dev.namada.net/master/rustdoc-logo.png")]
#![warn(missing_docs)]
#![deny(rustdoc::broken_intra_doc_links)]
#![deny(rustdoc::private_intra_doc_links)]

pub mod btree_set;
pub mod epoched;
pub mod parameters;
pub mod rewards;
pub mod storage;
pub mod types;
pub mod validation;

use core::fmt::Debug;
use std::collections::{BTreeSet, HashMap, HashSet};
use std::convert::TryFrom;
use std::num::TryFromIntError;

use epoched::{
    DynEpochOffset, EpochOffset, Epoched, EpochedDelta, OffsetPipelineLen,
};
use namada_core::ledger::storage_api;
use namada_core::types::address::{self, Address, InternalAddress};
use namada_core::types::key::common;
use namada_core::types::storage::Epoch;
use namada_core::types::token;
pub use parameters::PosParams;
use rust_decimal::Decimal;
use thiserror::Error;
use types::{
    ActiveValidator, Bonds, CommissionRates, GenesisValidator, RewardsProducts,
    Slash, SlashType, Slashes, TotalDeltas, Unbond, Unbonds,
    ValidatorConsensusKeys, ValidatorDeltas, ValidatorSet, ValidatorSetUpdate,
    ValidatorSets, ValidatorState, ValidatorStates,
};

use crate::btree_set::BTreeSetShims;
use crate::rewards::PosRewardsCalculator;
use crate::types::{
    decimal_mult_i128, decimal_mult_u64, Bond, BondId, VoteInfo,
    WeightedValidator,
};

/// Address of the PoS account implemented as a native VP
pub const ADDRESS: Address = Address::Internal(InternalAddress::PoS);

/// Address of the PoS slash pool account
pub const SLASH_POOL_ADDRESS: Address =
    Address::Internal(InternalAddress::PosSlashPool);

/// Address of the staking token (NAM)
pub fn staking_token_address() -> Address {
    address::nam()
}

/// Read-only part of the PoS system
pub trait PosReadOnly {
    /// Address of the PoS account
    const POS_ADDRESS: Address;

    /// Address of the staking token
    fn staking_token_address(&self) -> Address;

    /// Read PoS parameters.
    fn read_pos_params(&self) -> Result<PosParams, storage_api::Error>;
    /// Read PoS validator's consensus key (used for signing block votes).
    fn read_validator_consensus_key(
        &self,
        key: &Address,
    ) -> Result<Option<ValidatorConsensusKeys>, storage_api::Error>;
    /// Read PoS validator's state.
    fn read_validator_state(
        &self,
        key: &Address,
    ) -> Result<Option<ValidatorStates>, storage_api::Error>;
    /// Read PoS validator's total deltas of their bonds (validator self-bonds
    /// and delegations).
    fn read_validator_deltas(
        &self,
        key: &Address,
    ) -> Result<Option<ValidatorDeltas>, storage_api::Error>;

    /// Read PoS slashes applied to a validator.
    fn read_validator_slashes(
        &self,
        key: &Address,
    ) -> Result<Vec<Slash>, storage_api::Error>;
    /// Read PoS validator's commission rate for delegation rewards
    fn read_validator_commission_rate(
        &self,
        key: &Address,
    ) -> Result<Option<CommissionRates>, storage_api::Error>;
    /// Read PoS validator's maximum change in the commission rate for
    /// delegation rewards
    fn read_validator_max_commission_rate_change(
        &self,
        key: &Address,
    ) -> Result<Option<Decimal>, storage_api::Error>;
    /// Read PoS bond (validator self-bond or a delegation).
    fn read_bond(
        &self,
        key: &BondId,
    ) -> Result<Option<Bonds>, storage_api::Error>;
    /// Read PoS unbond (unbonded tokens from validator self-bond or a
    /// delegation).
    fn read_unbond(
        &self,
        key: &BondId,
    ) -> Result<Option<Unbonds>, storage_api::Error>;
    /// Read PoS validator set (active and inactive).
    fn read_validator_set(&self) -> Result<ValidatorSets, storage_api::Error>;
    /// Read PoS total deltas for all validators (active and inactive)
    fn read_total_deltas(&self) -> Result<TotalDeltas, storage_api::Error>;

    /// Check if the given address is a validator by checking that it has some
    /// state.
    fn is_validator(
        &self,
        address: &Address,
    ) -> Result<bool, storage_api::Error> {
        let state = self.read_validator_state(address)?;
        Ok(state.is_some())
    }

    /// Get the total bond amount for the given bond ID at the given epoch.
    fn bond_amount(
        &self,
        bond_id: &BondId,
        epoch: Epoch,
    ) -> Result<token::Amount, storage_api::Error> {
        // TODO new slash logic
        let slashes = self.read_validator_slashes(&bond_id.validator)?;
        // TODO apply rewards, if any
        let bonds = self.read_bond(bond_id)?;
        Ok(bonds
            .and_then(|bonds| {
                bonds.get(epoch).map(|bond| {
                    let mut total: u64 = 0;
                    // Find the sum of the bonds
                    for (start_epoch, delta) in bond.pos_deltas.into_iter() {
                        let delta: u64 = delta.into();
                        total += delta;
                        // Apply slashes if any
                        for slash in slashes.iter() {
                            if slash.epoch <= start_epoch {
                                let current_slashed =
                                    decimal_mult_u64(slash.rate, delta);
                                total -= current_slashed;
                            }
                        }
                    }
                    let neg_deltas: u64 = bond.neg_deltas.into();
                    token::Amount::from(total - neg_deltas)
                })
            })
            .unwrap_or_default())
    }

    /// Get all the validator known addresses. These validators may be in any
    /// state, e.g. active, inactive or jailed.
    fn validator_addresses(
        &self,
        epoch: Epoch,
    ) -> Result<HashSet<Address>, storage_api::Error> {
        let validator_sets = self.read_validator_set()?;
        let validator_set = validator_sets.get(epoch).unwrap();

        Ok(validator_set
            .active
            .union(&validator_set.inactive)
            .map(|validator| validator.address.clone())
            .collect())
    }

    /// Get the total stake of a validator at the given epoch or current when
    /// `None`. The total stake is a sum of validator's self-bonds and
    /// delegations to their address.
    fn validator_stake(
        &self,
        validator: &Address,
        epoch: Epoch,
    ) -> Result<token::Amount, storage_api::Error> {
        let deltas = self.read_validator_deltas(validator)?;
        let total_stake = deltas.and_then(|deltas| deltas.get(epoch)).and_then(
            |total_stake| {
                let sum: i128 = total_stake;
                let sum: u64 = sum.try_into().ok()?;
                Some(sum.into())
            },
        );
        Ok(total_stake.unwrap_or_default())
    }

    /// Get the total stake in PoS system at the given epoch or current when
    /// `None`.
    fn total_stake(
        &self,
        epoch: Epoch,
    ) -> Result<token::Amount, storage_api::Error> {
        let epoch = epoch;
        // TODO read total stake from storage once added
        self.validator_addresses(epoch)?
            .into_iter()
            .try_fold(token::Amount::default(), |acc, validator| {
                Ok(acc + self.validator_stake(&validator, epoch)?)
            })
    }
}

/// PoS system trait to be implemented in integration that can read and write
/// PoS data.
pub trait PosActions: PosReadOnly {
    /// Write PoS parameters.
    fn write_pos_params(
        &mut self,
        params: &PosParams,
    ) -> Result<(), storage_api::Error>;
    /// Write PoS validator's raw hash of its consensus key.
    fn write_validator_address_raw_hash(
        &mut self,
        address: &Address,
        consensus_key: &common::PublicKey,
    ) -> Result<(), storage_api::Error>;
    /// Write PoS validator's consensus key (used for signing block votes).
    fn write_validator_consensus_key(
        &mut self,
        key: &Address,
        value: ValidatorConsensusKeys,
    ) -> Result<(), storage_api::Error>;
    /// Write PoS validator's state.
    fn write_validator_state(
        &mut self,
        key: &Address,
        value: ValidatorStates,
    ) -> Result<(), storage_api::Error>;
    /// Write PoS validator's commission rate for delegator rewards
    fn write_validator_commission_rate(
        &mut self,
        key: &Address,
        value: CommissionRates,
    ) -> Result<(), storage_api::Error>;
    /// Write PoS validator's maximum change in the commission rate per epoch
    fn write_validator_max_commission_rate_change(
        &mut self,
        key: &Address,
        value: Decimal,
    ) -> Result<(), storage_api::Error>;
    /// Write PoS validator's total deltas of their bonds (validator self-bonds
    /// and delegations).
    fn write_validator_deltas(
        &mut self,
        key: &Address,
        value: ValidatorDeltas,
    ) -> Result<(), storage_api::Error>;

    /// Write PoS bond (validator self-bond or a delegation).
    fn write_bond(
        &mut self,
        key: &BondId,
        value: Bonds,
    ) -> Result<(), storage_api::Error>;
    /// Write PoS unbond (unbonded tokens from validator self-bond or a
    /// delegation).
    fn write_unbond(
        &mut self,
        key: &BondId,
        value: Unbonds,
    ) -> Result<(), storage_api::Error>;
    /// Write PoS validator set (active and inactive).
    fn write_validator_set(
        &mut self,
        value: ValidatorSets,
    ) -> Result<(), storage_api::Error>;
    /// Write PoS total deltas of all validators (active and inactive).
    fn write_total_deltas(
        &mut self,
        value: TotalDeltas,
    ) -> Result<(), storage_api::Error>;
    /// Delete an emptied PoS bond (validator self-bond or a delegation).
    fn delete_bond(&mut self, key: &BondId) -> Result<(), storage_api::Error>;
    /// Delete an emptied PoS unbond (unbonded tokens from validator self-bond
    /// or a delegation).
    fn delete_unbond(&mut self, key: &BondId)
    -> Result<(), storage_api::Error>;

    /// Transfer tokens from the `src` to the `dest`.
    fn transfer(
        &mut self,
        token: &Address,
        amount: token::Amount,
        src: &Address,
        dest: &Address,
    ) -> Result<(), storage_api::Error>;

    /// Attempt to update the given account to become a validator.
    fn become_validator(
        &mut self,
        address: &Address,
        consensus_key: &common::PublicKey,
        current_epoch: Epoch,
        commission_rate: Decimal,
        max_commission_rate_change: Decimal,
    ) -> Result<(), storage_api::Error> {
        let params = self.read_pos_params()?;
        let mut validator_set = self.read_validator_set()?;
        if self.is_validator(address)? {
            return Err(BecomeValidatorError::AlreadyValidator(
                address.clone(),
            )
            .into());
        }
        let consensus_key_clone = consensus_key.clone();
        let BecomeValidatorData {
            consensus_key,
            state,
            deltas,
            commission_rate,
            max_commission_rate_change,
        } = become_validator(
            &params,
            address,
            consensus_key,
            &mut validator_set,
            current_epoch,
            commission_rate,
            max_commission_rate_change,
        );
        self.write_validator_consensus_key(address, consensus_key)?;
        self.write_validator_state(address, state)?;
        self.write_validator_set(validator_set)?;
        self.write_validator_address_raw_hash(address, &consensus_key_clone)?;
        self.write_validator_deltas(address, deltas)?;
        self.write_validator_max_commission_rate_change(
            address,
            max_commission_rate_change,
        )?;

        let commission_rates =
            Epoched::init(commission_rate, current_epoch, &params);
        self.write_validator_commission_rate(address, commission_rates)?;

        // Do we need to write the total deltas of all validators?
        Ok(())
    }

    /// Self-bond tokens to a validator when `source` is `None` or equal to
    /// the `validator` address, or delegate tokens from the `source` to the
    /// `validator`.
    fn bond_tokens(
        &mut self,
        source: Option<&Address>,
        validator: &Address,
        amount: token::Amount,
        current_epoch: Epoch,
    ) -> Result<(), storage_api::Error> {
        if let Some(source) = source {
            if source != validator && self.is_validator(source)? {
                return Err(BondError::SourceMustNotBeAValidator(
                    source.clone(),
                )
                .into());
            }
        }
        let params = self.read_pos_params()?;
        let validator_state = self.read_validator_state(validator)?;
        let source = source.unwrap_or(validator);
        let bond_id = BondId {
            source: source.clone(),
            validator: validator.clone(),
        };
        let bond = self.read_bond(&bond_id)?;
        let validator_deltas = self.read_validator_deltas(validator)?;
        let mut total_deltas = self.read_total_deltas()?;
        let mut validator_set = self.read_validator_set()?;

        let BondData {
            bond,
            validator_deltas,
        } = bond_tokens(
            &params,
            validator_state,
            &bond_id,
            bond,
            amount,
            validator_deltas,
            &mut total_deltas,
            &mut validator_set,
            current_epoch,
        )?;
        self.write_bond(&bond_id, bond)?;
        self.write_validator_deltas(validator, validator_deltas)?;
        self.write_total_deltas(total_deltas)?;
        self.write_validator_set(validator_set)?;

        // Transfer the bonded tokens from the source to PoS
        self.transfer(
            &self.staking_token_address(),
            amount,
            source,
            &Self::POS_ADDRESS,
        )?;
        Ok(())
    }

    /// Unbond self-bonded tokens from a validator when `source` is `None` or
    /// equal to the `validator` address, or unbond delegated tokens from
    /// the `source` to the `validator`.
    fn unbond_tokens(
        &mut self,
        source: Option<&Address>,
        validator: &Address,
        amount: token::Amount,
        current_epoch: Epoch,
    ) -> Result<(), storage_api::Error> {
        let params = self.read_pos_params()?;
        let source = source.unwrap_or(validator);
        let bond_id = BondId {
            source: source.clone(),
            validator: validator.clone(),
        };
        let mut bond = match self.read_bond(&bond_id)? {
            Some(val) => val,
            None => return Err(UnbondError::NoBondFound.into()),
        };
        let unbond = self.read_unbond(&bond_id)?;
        let mut validator_deltas =
            self.read_validator_deltas(validator)?.ok_or_else(|| {
                UnbondError::ValidatorHasNoBonds(validator.clone())
            })?;
        let slashes = self.read_validator_slashes(validator)?;
        let mut total_deltas = self.read_total_deltas()?;
        let mut validator_set = self.read_validator_set()?;

        let UnbondData { unbond } = unbond_tokens(
            &params,
            &bond_id,
            &mut bond,
            unbond,
            amount,
            slashes,
            &mut validator_deltas,
            &mut total_deltas,
            &mut validator_set,
            current_epoch,
        )?;

        let total_bonds = bond.get_at_offset(
            current_epoch,
            DynEpochOffset::PipelineLen,
            &params,
        );
        match total_bonds {
            Some(total_bonds) if total_bonds.sum() != 0.into() => {
                self.write_bond(&bond_id, bond)?;
            }
            _ => {
                // If the bond is left empty, delete it
                self.delete_bond(&bond_id)?
            }
        }
        self.write_unbond(&bond_id, unbond)?;
        self.write_validator_deltas(validator, validator_deltas)?;
        self.write_total_deltas(total_deltas)?;
        self.write_validator_set(validator_set)?;

        Ok(())
    }

    /// Withdraw unbonded tokens from a self-bond to a validator when `source`
    /// is `None` or equal to the `validator` address, or withdraw unbonded
    /// tokens delegated to the `validator` to the `source`.
    fn withdraw_tokens(
        &mut self,
        source: Option<&Address>,
        validator: &Address,
        current_epoch: Epoch,
    ) -> Result<token::Amount, storage_api::Error> {
        let params = self.read_pos_params()?;
        let source = source.unwrap_or(validator);
        let bond_id = BondId {
            source: source.clone(),
            validator: validator.clone(),
        };

        let unbond = self.read_unbond(&bond_id)?;
        let slashes = self.read_validator_slashes(&bond_id.validator)?;

        let WithdrawData {
            unbond,
            withdrawn,
            slashed,
        } = withdraw_unbonds(
            &params,
            &bond_id,
            unbond,
            slashes,
            current_epoch,
        )?;

        let total_unbonds = unbond.get_at_offset(
            current_epoch,
            DynEpochOffset::UnbondingLen,
            &params,
        );
        match total_unbonds {
            Some(total_unbonds) if total_unbonds.sum() != 0.into() => {
                self.write_unbond(&bond_id, unbond)?;
            }
            _ => {
                // If the unbond is left empty, delete it
                self.delete_unbond(&bond_id)?
            }
        }

        // Transfer the tokens from PoS back to the source
        self.transfer(
            &self.staking_token_address(),
            withdrawn,
            &Self::POS_ADDRESS,
            source,
        )?;

        Ok(slashed)
    }

    /// Change the commission rate of a validator
    fn change_validator_commission_rate(
        &mut self,
        validator: &Address,
        new_rate: Decimal,
        current_epoch: Epoch,
    ) -> Result<(), storage_api::Error> {
        if new_rate < Decimal::ZERO {
            return Err(CommissionRateChangeError::NegativeRate(
                new_rate,
                validator.clone(),
            )
            .into());
        }

        let max_change = self
            .read_validator_max_commission_rate_change(validator)
            .map_err(|_| {
                CommissionRateChangeError::NoMaxSetInStorage(validator.clone())
            })?
            .ok_or_else(|| {
                CommissionRateChangeError::CannotRead(validator.clone())
            })?;
        let mut commission_rates =
            match self.read_validator_commission_rate(validator) {
                Ok(Some(rates)) => rates,
                _ => {
                    return Err(CommissionRateChangeError::CannotRead(
                        validator.clone(),
                    )
                    .into());
                }
            };
        let params = self.read_pos_params()?;
        let rate_at_pipeline = *commission_rates
            .get_at_offset(current_epoch, DynEpochOffset::PipelineLen, &params)
            .expect("Could not find a rate in given epoch");

        // Return early with no further changes if there is no rate change
        // instead of returning an error
        if new_rate == rate_at_pipeline {
            return Ok(());
        }

        let rate_before_pipeline = *commission_rates
            .get_at_offset(
                current_epoch,
                DynEpochOffset::PipelineLenMinusOne,
                &params,
            )
            .expect("Could not find a rate in given epoch");
        let change_from_prev = new_rate - rate_before_pipeline;
        if change_from_prev.abs() > max_change {
            return Err(CommissionRateChangeError::RateChangeTooLarge(
                change_from_prev,
                validator.clone(),
            )
            .into());
        }
        commission_rates.update_from_offset(
            |val, _epoch| {
                *val = new_rate;
            },
            current_epoch,
            DynEpochOffset::PipelineLen,
            &params,
        );
        self.write_validator_commission_rate(validator, commission_rates)
            .map_err(|_| {
                CommissionRateChangeError::CannotWrite(validator.clone())
            })?;

        Ok(())
    }
}

/// PoS system base trait for system initialization on genesis block, updating
/// the validator on a new epoch and applying slashes.
pub trait PosBase {
    /// Address of the PoS account
    const POS_ADDRESS: Address;
    /// Address of the staking token
    fn staking_token_address(&self) -> Address;
    /// Address of the slash pool, into which slashed tokens are transferred.
    const POS_SLASH_POOL_ADDRESS: Address;

    /// Read PoS parameters.
    fn read_pos_params(&self) -> PosParams;
    /// Read PoS raw hash of validator's consensus key.
    fn read_validator_address_raw_hash(
        &self,
        raw_hash: impl AsRef<str>,
    ) -> Option<Address>;
    /// Read PoS validator's consensus key (used for signing block votes).
    fn read_validator_consensus_key(
        &self,
        key: &Address,
    ) -> Option<ValidatorConsensusKeys>;
    /// Read PoS validator's state.
    fn read_validator_state(&self, key: &Address) -> Option<ValidatorStates>;
    /// Read PoS validator's deltas (validator self-bonds
    /// and delegations).
    fn read_validator_deltas(&self, key: &Address) -> Option<ValidatorDeltas>;
    /// Read PoS slashes applied to a validator.
    fn read_validator_slashes(&self, key: &Address) -> Slashes;
    /// Read PoS validator's commission rate
    fn read_validator_commission_rate(&self, key: &Address) -> CommissionRates;
    /// Read PoS validator's maximum commission rate change per epoch
    fn read_validator_max_commission_rate_change(
        &self,
        key: &Address,
    ) -> Decimal;
    /// Read PoS validator's reward products
    fn read_validator_rewards_products(&self, key: &Address)
    -> RewardsProducts;
    /// Read PoS validator's delegation reward products
    fn read_validator_delegation_rewards_products(
        &self,
        key: &Address,
    ) -> RewardsProducts;
    /// Read PoS validator's last known epoch with rewards products
    fn read_validator_last_known_product_epoch(&self, key: &Address) -> Epoch;
    /// Read PoS consensus validator's rewards accumulator
    fn read_consensus_validator_rewards_accumulator(
        &self,
    ) -> Option<std::collections::HashMap<Address, Decimal>>;
    /// Read PoS validator set (active and inactive).
    fn read_validator_set(&self) -> ValidatorSets;
    /// Read PoS total deltas of all validators (active and inactive).
    fn read_total_deltas(&self) -> TotalDeltas;

    /// Write PoS parameters.
    fn write_pos_params(&mut self, params: &PosParams);
    /// Write PoS validator's raw hash of its consensus key.
    fn write_validator_address_raw_hash(
        &mut self,
        address: &Address,
        consensus_key: &common::PublicKey,
    );
    /// Write PoS validator's consensus key (used for signing block votes).
    fn write_validator_consensus_key(
        &mut self,
        key: &Address,
        value: &ValidatorConsensusKeys,
    );
    /// Write PoS validator's state.
    fn write_validator_state(&mut self, key: &Address, value: &ValidatorStates);
    /// Write PoS validator's total deltas of their bonds (validator self-bonds
    /// and delegations).
    fn write_validator_deltas(
        &mut self,
        key: &Address,
        value: &ValidatorDeltas,
    );
    /// Write PoS validator's commission rate.
    fn write_validator_commission_rate(
        &mut self,
        key: &Address,
        value: &CommissionRates,
    );
    /// Write PoS validator's maximum change in the commission rate.
    fn write_validator_max_commission_rate_change(
        &mut self,
        key: &Address,
        value: &Decimal,
    );
    // TODO: should the rewards products be written entirely or appended?

    /// Write PoS validator's rewards products.
    fn write_validator_rewards_products(
        &mut self,
        key: &Address,
        value: &RewardsProducts,
    );
    /// Write PoS validator's delegation rewards products.
    fn write_validator_delegation_rewards_products(
        &mut self,
        key: &Address,
        value: &RewardsProducts,
    );
    /// Write PoS validator's last known epoch with rewards products
    fn write_validator_last_known_product_epoch(
        &mut self,
        key: &Address,
        value: &Epoch,
    );
    /// Write PoS validator's delegation rewards products.
    fn write_consensus_validator_rewards_accumulator(
        &mut self,
        value: &std::collections::HashMap<Address, Decimal>,
    );
    /// Write (append) PoS slash applied to a validator.
    fn write_validator_slash(&mut self, validator: &Address, value: Slash);
    /// Write PoS bond (validator self-bond or a delegation).
    fn write_bond(&mut self, key: &BondId, value: &Bonds);
    /// Write PoS validator set (active and inactive).
    fn write_validator_set(&mut self, value: &ValidatorSets);
    /// Write total deltas in PoS for all validators (active and inactive)
    fn write_total_deltas(&mut self, value: &TotalDeltas);
    /// Credit tokens to the `target` account. This should only be used at
    /// genesis.
    fn credit_tokens(
        &mut self,
        token: &Address,
        target: &Address,
        amount: token::Amount,
    );
    /// Transfer tokens from the `src` to the `dest`.
    fn transfer(
        &mut self,
        token: &Address,
        amount: token::Amount,
        src: &Address,
        dest: &Address,
    );

    /// Initialize the PoS system storage data in the genesis block for the
    /// given PoS parameters and initial validator set. The validators'
    /// tokens will be put into self-bonds. The given PoS parameters are written
    /// with the [`PosBase::write_pos_params`] method.
    fn init_genesis<'a>(
        &mut self,
        params: &'a PosParams,
        validators: impl Iterator<Item = &'a GenesisValidator> + Clone + 'a,
        current_epoch: Epoch,
    ) -> Result<(), GenesisError> {
        self.write_pos_params(params);

        let GenesisData {
            validators,
            validator_set,
            total_deltas,
            total_bonded_balance,
        } = init_genesis(params, validators, current_epoch)?;

        for res in validators {
            let GenesisValidatorData {
                ref address,
                consensus_key,
                commission_rate,
                max_commission_rate_change,
                state,
                deltas,
                bond: (bond_id, bond),
            } = res?;
            self.write_validator_address_raw_hash(
                address,
                consensus_key
                    .get(current_epoch)
                    .expect("Consensus key must be set"),
            );
            self.write_validator_consensus_key(address, &consensus_key);
            self.write_validator_state(address, &state);
            self.write_validator_deltas(address, &deltas);
            self.write_bond(&bond_id, &bond);
            self.write_validator_commission_rate(address, &commission_rate);
            self.write_validator_max_commission_rate_change(
                address,
                &max_commission_rate_change,
            );
        }
        self.write_validator_set(&validator_set);
        self.write_total_deltas(&total_deltas);

        // TODO: write total_staked_tokens (Amount) to storage?

        // Credit the bonded tokens to the PoS account
        self.credit_tokens(
            &self.staking_token_address(),
            &Self::POS_ADDRESS,
            total_bonded_balance,
        );
        Ok(())
    }

    /// Calls a closure on each validator update element.
    fn validator_set_update(
        &self,
        current_epoch: Epoch,
        f: impl FnMut(ValidatorSetUpdate),
    ) {
        let current_epoch: Epoch = current_epoch;
        let current_epoch_u64: u64 = current_epoch.into();
        // INVARIANT: We can only access the previous epochs data, because
        // this function is called on a beginning of a new block, before
        // anything else could be updated (in epoched data updates, the old
        // epochs data are merged with the current one).
        let previous_epoch: Option<Epoch> = if current_epoch_u64 == 0 {
            None
        } else {
            Some(Epoch::from(current_epoch_u64 - 1))
        };
        let validators = self.read_validator_set();
        let cur_validators = validators.get(current_epoch).unwrap();
        let prev_validators =
            previous_epoch.and_then(|epoch| validators.get(epoch));

        // If the validator has never been active before and it doesn't have
        // more than 0 voting power, we should not tell Tendermint to
        // update it until it does. Tendermint uses 0 voting power as a
        // way to signal that a validator has been removed from the
        // validator set, but fails if we attempt to give it a new
        // validator with 0 voting power.
        // For active validators, this would only ever happen until all the
        // validator slots are filled with non-0 voting power validators, but we
        // still need to guard against it.
        let active_validators = cur_validators.active.iter().filter_map(
            |validator: &WeightedValidator| {
                // If the validators set from previous epoch contains the same
                // validator, it means its voting power hasn't changed and hence
                // doesn't need to updated.
                if let (Some(prev_epoch), Some(prev_validators)) =
                    (previous_epoch, prev_validators)
                {
                    if prev_validators.active.contains(validator) {
                        println!(
                            "skipping validator update, still the same {}",
                            validator.address
                        );
                        return None;
                    }
                    if validator.bonded_stake == 0 {
                        // If the validator was `Pending` in the previous epoch,
                        // it means that it just was just added to validator
                        // set. We have to skip it, because it's 0.
                        if let Some(state) =
                            self.read_validator_state(&validator.address)
                        {
                            if let Some(ValidatorState::Pending) =
                                state.get(prev_epoch)
                            {
                                println!(
                                    "skipping validator update, it's new {}",
                                    validator.address
                                );
                                return None;
                            }
                        }
                    }
                }
                let consensus_key = self
                    .read_validator_consensus_key(&validator.address)
                    .unwrap()
                    .get(current_epoch)
                    .unwrap()
                    .clone();
                Some(ValidatorSetUpdate::Active(ActiveValidator {
                    consensus_key,
                    bonded_stake: validator.bonded_stake,
                }))
            },
        );
        let inactive_validators = cur_validators.inactive.iter().filter_map(
            |validator: &WeightedValidator| {
                // If the validators set from previous epoch contains the same
                // validator, it means its voting power hasn't changed and hence
                // doesn't need to updated.
                if let (Some(prev_epoch), Some(prev_validators)) =
                    (previous_epoch, prev_validators)
                {
                    if prev_validators.inactive.contains(validator) {
                        return None;
                    }
                    if validator.bonded_stake == 0 {
                        // If the validator was `Pending` in the previous epoch,
                        // it means that it just was just added to validator
                        // set. We have to skip it, because it's 0.
                        if let Some(state) =
                            self.read_validator_state(&validator.address)
                        {
                            if let Some(ValidatorState::Pending) =
                                state.get(prev_epoch)
                            {
                                return None;
                            }
                        }
                    }
                }
                let consensus_key = self
                    .read_validator_consensus_key(&validator.address)
                    .unwrap()
                    .get(current_epoch)
                    .unwrap()
                    .clone();
                Some(ValidatorSetUpdate::Deactivated(consensus_key))
            },
        );
        active_validators.chain(inactive_validators).for_each(f)
    }

    /// Distribute the PoS inflation rewards by updating the validator rewards
    /// products.
    fn log_block_rewards(
        &mut self,
        current_epoch: impl Into<Epoch>,
        proposer_address: &Address,
        votes: &Vec<VoteInfo>,
    ) -> Result<(), Error> {
        let current_epoch: Epoch = current_epoch.into();
        let validator_set = self.read_validator_set();
        let validators = validator_set.get(current_epoch).unwrap();
        let pos_params = self.read_pos_params();

        // Get total stake of the consensus validator set
        let total_active_stake = validators.active.iter().fold(
            0_u64,
            |sum,
             WeightedValidator {
                 voting_power,
                 address: _,
             }| { sum + u64::from(*voting_power) },
        );

        let mut signer_set: HashSet<Address> = HashSet::new();
        let mut total_signing_stake: u64 = 0;

        // Get set of signing validator addresses and the combined stake of
        // these signers
        for vote in votes.iter() {
            if !vote.signed_last_block {
                continue;
            }
            let tm_raw_hash_string =
                hex::encode_upper(vote.validator_address.clone());
            let native_address = self
                .read_validator_address_raw_hash(tm_raw_hash_string)
                .expect(
                    "Unable to read native address of validator from \
                     tendermint raw hash",
                );
            signer_set.insert(native_address);
            total_signing_stake += vote.validator_vp;
        }

        let active_val_stake: Decimal = total_active_stake.into();
        let signing_stake: Decimal = total_signing_stake.into();

        let mut rewards_calculator = PosRewardsCalculator::new(
            pos_params.block_proposer_reward,
            pos_params.block_vote_reward,
            total_signing_stake,
            total_active_stake,
        );

        rewards_calculator.set_reward_coeffs().unwrap();

        // Iterate over validators, calculating their fraction of the block
        // rewards accounting for possible block proposal and signing
        // (voting)
        let mut validator_accumulators = self
            .read_consensus_validator_rewards_accumulator()
            .unwrap_or_else(|| HashMap::<Address, Decimal>::new());
        for validator in validators.active.iter() {
            let mut rewards_frac: Decimal = Decimal::default();
            let stake: Decimal = validator.bonded_stake.into();

            // Proposer reward
            if validator.address == *proposer_address {
                let coeff = rewards_calculator.get_proposer_coeff().unwrap();
                rewards_frac += coeff;
            }

            // Signer reward
            if signer_set.contains(&validator.address) {
                let coeff = rewards_calculator.get_signer_coeff().unwrap();
                let signing_frac = stake / signing_stake;
                rewards_frac += coeff * signing_frac;
            }

            // Active validator reward
            let active_val_coeff =
                rewards_calculator.get_active_val_coeff().unwrap();
            let active_val_frac = stake / active_val_stake;
            rewards_frac += active_val_coeff * active_val_frac;

            let prev_val = *validator_accumulators
                .get(&validator.address)
                .unwrap_or(&Decimal::ZERO);
            validator_accumulators
                .insert(validator.address.clone(), prev_val + rewards_frac);
        }

        // Write the updated map fo reward accumulators back to storage
        self.write_consensus_validator_rewards_accumulator(
            &validator_accumulators,
        );
        Ok(())
    }

    /// Apply a slash to a byzantine validator for the given evidence.
    fn slash(
        &mut self,
        params: &PosParams,
        current_epoch: Epoch,
        evidence_epoch: Epoch,
        evidence_block_height: impl Into<u64>,
        slash_type: SlashType,
        validator: &Address,
    ) -> Result<(), SlashError> {
        let evidence_epoch = evidence_epoch;
        let rate = slash_type.get_slash_rate(params);
        let validator_slash = Slash {
            epoch: evidence_epoch,
            r#type: slash_type,
            rate,
            block_height: evidence_block_height.into(),
        };

        let mut deltas =
            self.read_validator_deltas(validator).ok_or_else(|| {
                SlashError::ValidatorHasNoTotalDeltas(validator.clone())
            })?;
        let mut validator_set = self.read_validator_set();
        let mut total_deltas = self.read_total_deltas();

        let slashed_change = slash(
            params,
            current_epoch,
            validator,
            &validator_slash,
            &mut deltas,
            &mut validator_set,
            &mut total_deltas,
        )?;
        let slashed_change: i128 = slashed_change;
        let slashed_amount = u64::try_from(slashed_change)
            .map_err(|_err| SlashError::InvalidSlashChange(slashed_change))?;
        let slashed_amount = token::Amount::from(slashed_amount);

        self.write_validator_deltas(validator, &deltas);
        self.write_validator_slash(validator, validator_slash);
        self.write_validator_set(&validator_set);
        self.write_total_deltas(&total_deltas);

        // TODO: write total staked tokens (Amount) to storage?

        // Transfer the slashed tokens to the PoS slash pool
        self.transfer(
            &self.staking_token_address(),
            slashed_amount,
            &Self::POS_ADDRESS,
            &Self::POS_SLASH_POOL_ADDRESS,
        );
        Ok(())
    }
}

#[allow(missing_docs)]
#[derive(Error, Debug)]
pub enum GenesisError {
    #[error("Voting power overflow: {0}")]
    VotingPowerOverflow(TryFromIntError),
}

#[allow(missing_docs)]
#[derive(Error, Debug)]
pub enum BecomeValidatorError {
    #[error("The given address {0} is already a validator")]
    AlreadyValidator(Address),
}

#[allow(missing_docs)]
#[derive(Error, Debug)]
pub enum BondError {
    #[error("The given address {0} is not a validator address")]
    NotAValidator(Address),
    #[error(
        "The given source address {0} is a validator address. Validators may \
         not delegate."
    )]
    SourceMustNotBeAValidator(Address),
    #[error("The given validator address {0} is inactive")]
    InactiveValidator(Address),
    #[error("Voting power overflow: {0}")]
    VotingPowerOverflow(TryFromIntError),
}

#[allow(missing_docs)]
#[derive(Error, Debug)]
pub enum UnbondError {
    #[error("No bond could be found")]
    NoBondFound,
    #[error(
        "Trying to withdraw more tokens ({0}) than the amount bonded ({0})"
    )]
    UnbondAmountGreaterThanBond(token::Amount, token::Amount),
    #[error("No bonds found for the validator {0}")]
    ValidatorHasNoBonds(Address),
    #[error("Voting power not found for the validator {0}")]
    ValidatorHasNoVotingPower(Address),
    #[error("Voting power overflow: {0}")]
    VotingPowerOverflow(TryFromIntError),
}

#[allow(missing_docs)]
#[derive(Error, Debug)]
pub enum WithdrawError {
    #[error("No unbond could be found for {0}")]
    NoUnbondFound(BondId),
    #[error("No unbond may be withdrawn yet for {0}")]
    NoWithdrawableUnbond(BondId),
}

#[allow(missing_docs)]
#[derive(Error, Debug)]
pub enum SlashError {
    #[error("The validator {0} has no total deltas value")]
    ValidatorHasNoTotalDeltas(Address),
    #[error("The validator {0} has no voting power")]
    ValidatorHasNoVotingPower(Address),
    #[error("Unexpected slash token change")]
    InvalidSlashChange(i128),
    #[error("Voting power overflow: {0}")]
    VotingPowerOverflow(TryFromIntError),
    #[error("Unexpected negative stake {0} for validator {1}")]
    NegativeStake(i128, Address),
}

#[allow(missing_docs)]
#[derive(Error, Debug)]
pub enum CommissionRateChangeError {
    #[error("Unexpected negative commission rate {0} for validator {1}")]
    NegativeRate(Decimal, Address),
    #[error("Rate change of {0} is too large for validator {1}")]
    RateChangeTooLarge(Decimal, Address),
    #[error(
        "There is no maximum rate change written in storage for validator {0}"
    )]
    NoMaxSetInStorage(Address),
    #[error("Cannot write to storage for validator {0}")]
    CannotWrite(Address),
    #[error("Cannot read storage for validator {0}")]
    CannotRead(Address),
}

struct GenesisData<Validators>
where
    Validators: Iterator<Item = Result<GenesisValidatorData, GenesisError>>,
{
    validators: Validators,
    /// Active and inactive validator sets
    validator_set: ValidatorSets,
    /// The sum of all active and inactive validators' bonded deltas
    total_deltas: TotalDeltas,
    /// The sum of all active and inactive validators' bonded tokens
    total_bonded_balance: token::Amount,
}
struct GenesisValidatorData {
    address: Address,
    consensus_key: ValidatorConsensusKeys,
    commission_rate: CommissionRates,
    max_commission_rate_change: Decimal,
    state: ValidatorStates,
    deltas: ValidatorDeltas,
    bond: (BondId, Bonds),
}

/// A function that returns genesis data created from the initial validator set.
fn init_genesis<'a>(
    params: &'a PosParams,
    validators: impl Iterator<Item = &'a GenesisValidator> + Clone + 'a,
    current_epoch: Epoch,
) -> Result<
    GenesisData<
        impl Iterator<Item = Result<GenesisValidatorData, GenesisError>> + 'a,
    >,
    GenesisError,
> {
    // Accumulate the validator set and total bonded token balance
    let mut active: BTreeSet<WeightedValidator> = BTreeSet::default();
    let mut total_bonded_delta = token::Change::default();
    let mut total_bonded_balance = token::Amount::default();
    let mut total_balance = token::Amount::default();
    for GenesisValidator {
        address, tokens, ..
    } in validators.clone()
    {
        total_bonded_balance += *tokens;
        // is some extra error handling needed here for casting the delta as
        // i64? (token::Change)
        let delta = token::Change::from(*tokens);
        total_bonded_delta += delta;
        active.insert(WeightedValidator {
            bonded_stake: (*tokens).into(),
            address: address.clone(),
        });
    }
    total_balance += total_bonded_balance;
    // Pop the smallest validators from the active set until its size is under
    // the limit and insert them into the inactive set
    let mut inactive: BTreeSet<WeightedValidator> = BTreeSet::default();
    while active.len() > params.max_validator_slots as usize {
        match active.pop_first_shim() {
            Some(first) => {
                inactive.insert(first);
            }
            None => break,
        }
    }
    let validator_set = ValidatorSet { active, inactive };
    let validator_set = Epoched::init_at_genesis(validator_set, current_epoch);
    let total_bonded_delta =
        EpochedDelta::init_at_genesis(total_bonded_delta, current_epoch);

    // Adapt the genesis validators data to PoS data
    let validators = validators.map(
        move |GenesisValidator {
                  address,
                  tokens,
                  consensus_key,
                  commission_rate,
                  max_commission_rate_change,
              }| {
            let consensus_key =
                Epoched::init_at_genesis(consensus_key.clone(), current_epoch);
            let commission_rate =
                Epoched::init_at_genesis(*commission_rate, current_epoch);
            let state = Epoched::init_at_genesis(
                ValidatorState::Candidate,
                current_epoch,
            );
            let token_delta = token::Change::from(*tokens);
            let deltas =
                EpochedDelta::init_at_genesis(token_delta, current_epoch);
            let bond_id = BondId {
                source: address.clone(),
                validator: address.clone(),
            };
            let mut pos_deltas = HashMap::default();
            pos_deltas.insert(current_epoch, *tokens);
            let bond = EpochedDelta::init_at_genesis(
                Bond {
                    pos_deltas,
                    neg_deltas: Default::default(),
                },
                current_epoch,
            );
            Ok(GenesisValidatorData {
                address: address.clone(),
                consensus_key,
                commission_rate,
                max_commission_rate_change: *max_commission_rate_change,
                state,
                deltas,
                bond: (bond_id, bond),
            })
        },
    );

    // TODO: include total_tokens here, think abt where to write to storage
    Ok(GenesisData {
        validators,
        validator_set,
        total_deltas: total_bonded_delta,
        total_bonded_balance,
    })
}

/// A function to apply a slash to byzantine validator.
#[allow(clippy::too_many_arguments)]
fn slash(
    params: &PosParams,
    current_epoch: Epoch,
    validator: &Address,
    slash: &Slash,
    validator_deltas: &mut ValidatorDeltas,
    validator_set: &mut ValidatorSets,
    total_deltas: &mut TotalDeltas,
) -> Result<token::Change, SlashError> {
    let current_stake: token::Change =
        validator_deltas.get(current_epoch).unwrap_or_default();
    if current_stake < token::Change::default() {
        return Err(SlashError::NegativeStake(
            current_stake,
            validator.clone(),
        ));
    }
    let raw_current_stake: i128 = current_stake;
    let slashed_amount: token::Change =
        decimal_mult_i128(slash.rate, raw_current_stake);
    let token_change = -slashed_amount;

    // Apply slash at pipeline offset
    let update_offset = DynEpochOffset::PipelineLen;

    // Update validator set. This has to be done before we update the
    // `validator_deltas`, because we need to look-up the validator with
    // its voting power before the change.
    update_validator_set(
        params,
        validator,
        token_change,
        update_offset,
        validator_set,
        Some(validator_deltas),
        current_epoch,
    );

    // Update validator's deltas
    validator_deltas.add_at_offset(
        token_change,
        current_epoch,
        update_offset,
        params,
    );

    // Update total deltas of all validators
    total_deltas.add_at_offset(
        token_change,
        current_epoch,
        update_offset,
        params,
    );

    Ok(slashed_amount)
}

struct BecomeValidatorData {
    consensus_key: ValidatorConsensusKeys,
    state: ValidatorStates,
    deltas: ValidatorDeltas,
    commission_rate: Decimal,
    max_commission_rate_change: Decimal,
}

/// A function that initialized data for a new validator.
fn become_validator(
    params: &PosParams,
    address: &Address,
    consensus_key: &common::PublicKey,
    validator_set: &mut ValidatorSets,
    current_epoch: Epoch,
    commission_rate: Decimal,
    max_commission_rate_change: Decimal,
) -> BecomeValidatorData {
    let consensus_key =
        Epoched::init(consensus_key.clone(), current_epoch, params);

    let mut state =
        Epoched::init_at_genesis(ValidatorState::Pending, current_epoch);
    state.set(ValidatorState::Candidate, current_epoch, params);

    let deltas = EpochedDelta::init_at_offset(
        Default::default(),
        current_epoch,
        DynEpochOffset::PipelineLen,
        params,
    );

    validator_set.update_from_offset(
        |validator_set, _epoch| {
            let validator = WeightedValidator {
                bonded_stake: 0,
                address: address.clone(),
            };
            if validator_set.active.len() < params.max_validator_slots as usize
            {
                validator_set.active.insert(validator);
            } else {
                validator_set.inactive.insert(validator);
            }
        },
        current_epoch,
        DynEpochOffset::PipelineLen,
        params,
    );

    BecomeValidatorData {
        consensus_key,
        state,
        deltas,
        commission_rate,
        max_commission_rate_change,
    }
}

struct BondData {
    pub bond: Bonds,
    pub validator_deltas: ValidatorDeltas,
}

/// Bond tokens to a validator (self-bond or delegation).
#[allow(clippy::too_many_arguments)]
fn bond_tokens(
    params: &PosParams,
    validator_state: Option<ValidatorStates>,
    bond_id: &BondId,
    current_bond: Option<Bonds>,
    amount: token::Amount,
    validator_deltas: Option<ValidatorDeltas>,
    total_deltas: &mut TotalDeltas,
    validator_set: &mut ValidatorSets,
    current_epoch: Epoch,
) -> Result<BondData, BondError> {
    // Check the validator state
    match validator_state {
        None => {
            return Err(BondError::NotAValidator(bond_id.validator.clone()));
        }
        Some(validator_state) => {
            // Check that it's not inactive anywhere from the current epoch
            // to the pipeline offset
            for epoch in
                current_epoch.iter_range(OffsetPipelineLen::value(params))
            {
                if let Some(ValidatorState::Inactive) =
                    validator_state.get(epoch)
                {
                    return Err(BondError::InactiveValidator(
                        bond_id.validator.clone(),
                    ));
                }
            }
        }
    }

    // Update or create the bond
    //
    let mut value = Bond {
        pos_deltas: HashMap::default(),
        neg_deltas: token::Amount::default(),
    };
    // Initialize the bond at the pipeline offset
    let update_offset = DynEpochOffset::PipelineLen;
    value
        .pos_deltas
        .insert(current_epoch + update_offset.value(params), amount);
    let bond = match current_bond {
        None => EpochedDelta::init_at_offset(
            value,
            current_epoch,
            update_offset,
            params,
        ),
        Some(mut bond) => {
            bond.add_at_offset(value, current_epoch, update_offset, params);
            bond
        }
    };

    // Update validator set. This has to be done before we update the
    // `validator_deltas`, because we need to look-up the validator with
    // its voting power before the change.
    let token_change = token::Change::from(amount);
    update_validator_set(
        params,
        &bond_id.validator,
        token_change,
        update_offset,
        validator_set,
        validator_deltas.as_ref(),
        current_epoch,
    );

    // Update validator's total deltas and total staked token deltas
    let delta = token::Change::from(amount);
    let validator_deltas = match validator_deltas {
        Some(mut validator_deltas) => {
            validator_deltas.add_at_offset(
                delta,
                current_epoch,
                update_offset,
                params,
            );
            validator_deltas
        }
        None => EpochedDelta::init_at_offset(
            delta,
            current_epoch,
            update_offset,
            params,
        ),
    };

    total_deltas.add_at_offset(delta, current_epoch, update_offset, params);

    Ok(BondData {
        bond,
        validator_deltas,
    })
}

struct UnbondData {
    pub unbond: Unbonds,
}

/// Unbond tokens from a validator's bond (self-bond or delegation).
#[allow(clippy::too_many_arguments)]
fn unbond_tokens(
    params: &PosParams,
    bond_id: &BondId,
    bond: &mut Bonds,
    unbond: Option<Unbonds>,
    amount: token::Amount,
    slashes: Slashes,
    validator_deltas: &mut ValidatorDeltas,
    total_deltas: &mut TotalDeltas,
    validator_set: &mut ValidatorSets,
    current_epoch: Epoch,
) -> Result<UnbondData, UnbondError> {
    // We can unbond tokens that are bonded for a future epoch (not yet
    // active), hence we check the total at the pipeline offset
    let unbondable_amount = bond
        .get_at_offset(current_epoch, DynEpochOffset::PipelineLen, params)
        .unwrap_or_default()
        .sum();
    if amount > unbondable_amount {
        return Err(UnbondError::UnbondAmountGreaterThanBond(
            amount,
            unbondable_amount,
        ));
    }

    let mut unbond = match unbond {
        Some(unbond) => unbond,
        None => EpochedDelta::init(Unbond::default(), current_epoch, params),
    };

    let update_offset = DynEpochOffset::UnbondingLen;
    let mut to_unbond = amount;
    let to_unbond = &mut to_unbond;
    let mut slashed_amount = token::Amount::default();
    // Decrement the bond deltas starting from the rightmost value (a bond in a
    // future-most epoch) until whole amount is decremented
    bond.rev_while(
        |bonds, _epoch| {
            for (epoch_start, bond_delta) in bonds.pos_deltas.iter() {
                if *to_unbond == 0.into() {
                    return true;
                }
                let mut unbonded = HashMap::default();
                let unbond_end =
                    current_epoch + update_offset.value(params) - 1;
                // We need to accumulate the slashed delta for multiple
                // slashes applicable to a bond, where
                // each slash should be calculated from
                // the delta reduced by the previous slash.
                let applied_delta = if *to_unbond > *bond_delta {
                    unbonded.insert((*epoch_start, unbond_end), *bond_delta);
                    *to_unbond -= *bond_delta;
                    *bond_delta
                } else {
                    unbonded.insert((*epoch_start, unbond_end), *to_unbond);
                    let applied_delta = *to_unbond;
                    *to_unbond = 0.into();
                    applied_delta
                };
                // Calculate how much the bond delta would be after slashing
                let mut slashed_bond_delta = applied_delta;
                for slash in &slashes {
                    if slash.epoch >= *epoch_start {
                        let raw_delta: u64 = slashed_bond_delta.into();
                        let raw_slashed_delta =
                            decimal_mult_u64(slash.rate, raw_delta);
                        let slashed_delta =
                            token::Amount::from(raw_slashed_delta);
                        slashed_bond_delta -= slashed_delta;
                    }
                }
                slashed_amount += slashed_bond_delta;

                // For each decremented bond value write a new unbond
                unbond.add(Unbond { deltas: unbonded }, current_epoch, params);
            }
            // Stop the update once all the tokens are unbonded
            *to_unbond != 0.into()
        },
        current_epoch,
        params,
    );

    bond.add_at_offset(
        Bond {
            pos_deltas: Default::default(),
            neg_deltas: amount,
        },
        current_epoch,
        update_offset,
        params,
    );

    // Update validator set. This has to be done before we update the
    // `validator_deltas`, because we need to look-up the validator with
    // its voting power before the change.
    let token_change = -token::Change::from(slashed_amount);
    update_validator_set(
        params,
        &bond_id.validator,
        token_change,
        update_offset,
        validator_set,
        Some(validator_deltas),
        current_epoch,
    );

    // Update validator's deltas
    validator_deltas.add(token_change, current_epoch, params);

    // Update the total deltas of all validators.
    // TODO: provide some error handling that was maybe here before?
    total_deltas.add(token_change, current_epoch, params);

    Ok(UnbondData { unbond })
}

/// Update validator set when a validator's receives a new bond and when its
/// bond is unbonded (self-bond or delegation).
fn update_validator_set(
    params: &PosParams,
    validator: &Address,
    token_change: token::Change,
    change_offset: DynEpochOffset,
    validator_set: &mut ValidatorSets,
    validator_deltas: Option<&ValidatorDeltas>,
    current_epoch: Epoch,
) {
    validator_set.update_from_offset(
        |validator_set, epoch| {
            // Find the validator's bonded stake at the epoch that's being
            // updated from its total deltas
            let tokens_pre = validator_deltas
                .and_then(|d| d.get(epoch))
                .unwrap_or_default();
            let tokens_post = tokens_pre + token_change;
            let tokens_pre: i128 = tokens_pre;
            let tokens_post: i128 = tokens_post;
            let tokens_pre: u64 = TryFrom::try_from(tokens_pre).unwrap();
            let tokens_post: u64 = TryFrom::try_from(tokens_post).unwrap();

            if tokens_pre != tokens_post {
                let validator_pre = WeightedValidator {
                    bonded_stake: tokens_pre,
                    address: validator.clone(),
                };
                let validator_post = WeightedValidator {
                    bonded_stake: tokens_post,
                    address: validator.clone(),
                };

                if validator_set.inactive.contains(&validator_pre) {
                    let min_active_validator =
                        validator_set.active.first_shim();
                    let min_bonded_stake = min_active_validator
                        .map(|v| v.bonded_stake)
                        .unwrap_or_default();
                    if tokens_post > min_bonded_stake {
                        let deactivate_min =
                            validator_set.active.pop_first_shim();
                        let popped =
                            validator_set.inactive.remove(&validator_pre);
                        debug_assert!(popped);
                        validator_set.active.insert(validator_post);
                        if let Some(deactivate_min) = deactivate_min {
                            validator_set.inactive.insert(deactivate_min);
                        }
                    } else {
                        validator_set.inactive.remove(&validator_pre);
                        validator_set.inactive.insert(validator_post);
                    }
                } else {
                    debug_assert!(
                        validator_set.active.contains(&validator_pre)
                    );
                    let max_inactive_validator =
                        validator_set.inactive.last_shim();
                    let max_bonded_stake = max_inactive_validator
                        .map(|v| v.bonded_stake)
                        .unwrap_or_default();
                    if tokens_post < max_bonded_stake {
                        let activate_max =
                            validator_set.inactive.pop_last_shim();
                        let popped =
                            validator_set.active.remove(&validator_pre);
                        debug_assert!(popped);
                        validator_set.inactive.insert(validator_post);
                        if let Some(activate_max) = activate_max {
                            validator_set.active.insert(activate_max);
                        }
                    } else {
                        validator_set.active.remove(&validator_pre);
                        validator_set.active.insert(validator_post);
                    }
                }
            }
        },
        current_epoch,
        change_offset,
        params,
    )
}

struct WithdrawData {
    pub unbond: Unbonds,
    pub withdrawn: token::Amount,
    pub slashed: token::Amount,
}

/// Withdraw tokens from unbonds of self-bonds or delegations.
fn withdraw_unbonds(
    params: &PosParams,
    bond_id: &BondId,
    unbond: Option<Unbonds>,
    slashes: Vec<Slash>,
    current_epoch: Epoch,
) -> Result<WithdrawData, WithdrawError> {
    let mut unbond =
        unbond.ok_or_else(|| WithdrawError::NoUnbondFound(bond_id.clone()))?;
    let withdrawable_unbond = unbond
        .get(current_epoch)
        .ok_or_else(|| WithdrawError::NoWithdrawableUnbond(bond_id.clone()))?;
    let mut slashed = token::Amount::default();
    let withdrawn_amount = withdrawable_unbond.deltas.iter().fold(
        token::Amount::default(),
        |sum, ((epoch_start, epoch_end), delta)| {
            let mut delta = *delta;
            // Check and apply slashes, if any
            for slash in &slashes {
                if slash.epoch >= *epoch_start && slash.epoch <= *epoch_end {
                    let raw_delta: u64 = delta.into();
                    let current_slashed = token::Amount::from(
                        decimal_mult_u64(slash.rate, raw_delta),
                    );
                    slashed += current_slashed;
                    delta -= current_slashed;
                }
            }
            sum + delta
        },
    );
    unbond.delete_current(current_epoch, params);
    Ok(WithdrawData {
        unbond,
        withdrawn: withdrawn_amount,
        slashed,
    })
}

impl From<BecomeValidatorError> for storage_api::Error {
    fn from(err: BecomeValidatorError) -> Self {
        Self::new(err)
    }
}

impl From<BondError> for storage_api::Error {
    fn from(err: BondError) -> Self {
        Self::new(err)
    }
}

impl From<UnbondError> for storage_api::Error {
    fn from(err: UnbondError) -> Self {
        Self::new(err)
    }
}

impl From<WithdrawError> for storage_api::Error {
    fn from(err: WithdrawError) -> Self {
        Self::new(err)
    }
}

impl From<CommissionRateChangeError> for storage_api::Error {
    fn from(err: CommissionRateChangeError) -> Self {
        Self::new(err)
    }
}
