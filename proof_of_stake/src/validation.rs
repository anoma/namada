//! Validation of updated PoS data

use std::borrow::Cow;
use std::collections::HashMap;
use std::convert::TryFrom;
use std::fmt::Debug;
use std::marker::PhantomData;

use namada_core::types::address::Address;
use namada_core::types::key::{common, PublicKeyTmRawHash};
use namada_core::types::storage::Epoch;
use namada_core::types::token;
use rust_decimal::Decimal;
use thiserror::Error;

use crate::btree_set::BTreeSetShims;
use crate::epoched::DynEpochOffset;
use crate::parameters::PosParams;
use crate::types::{
    decimal_mult_i128, decimal_mult_u64, BondId, Bonds, CommissionRates, Slash,
    Slashes, TotalDeltas, Unbonds, ValidatorConsensusKeys, ValidatorDeltas,
    ValidatorSets, ValidatorState, ValidatorStates, WeightedValidator,
};

#[allow(missing_docs)]
#[derive(Error, Debug)]
pub enum Error {
    #[error("Unexpectedly missing state value for validator {0}")]
    ValidatorStateIsRequired(Address),
    #[error("Invalid new validator state in epoch {0}")]
    InvalidNewValidatorState(u64),
    #[error("Invalid validator state update in epoch {0}")]
    InvalidValidatorStateUpdate(u64),
    #[error("Unexpectedly missing consensus key value for validator {0}")]
    ValidatorConsensusKeyIsRequired(Address),
    #[error("Missing new validator consensus key in epoch {0}")]
    MissingNewValidatorConsensusKey(u64),
    #[error("Invalid validator consensus key update in epoch {0}")]
    InvalidValidatorConsensusKeyUpdate(u64),
    #[error("Unexpectedly missing commission rate value for validator {0}")]
    ValidatorCommissionRateIsRequired(Address),
    #[error("Missing new validator commission rate in epoch {0}")]
    MissingNewValidatorCommissionRate(u64),
    #[error("Invalid validator commission rate update in epoch {0}")]
    InvalidValidatorCommissionRateUpdate(u64),
    #[error("Unexpectedly missing deltas value for validator {0}")]
    MissingValidatorDeltas(Address),
    #[error("The sum of deltas for validator {0} is negative")]
    NegativeValidatorDeltasSum(Address),
    #[error("Unexpectedly missing balance value")]
    MissingBalance,
    #[error("Last update should be equal to the current epoch")]
    InvalidLastUpdate,
    #[error(
        "Invalid staking token balances. Balance Δ {balance_delta}, bonds Δ \
         {bond_delta}, unbonds Δ {unbond_delta}"
    )]
    InvalidBalances {
        balance_delta: token::Change,
        bond_delta: token::Change,
        unbond_delta: token::Change,
    },
    #[error(
        "Data must be set or updated in the correct epoch. Got epoch {got}, \
         expected one of {expected:?}"
    )]
    EpochedDataWrongEpoch { got: u64, expected: Vec<u64> },
    #[error("Empty bond {0} must be deleted")]
    EmptyBond(BondId),
    #[error(
        "Bond ID {id} must start at the correct epoch. Got epoch {got}, \
         expected {expected}"
    )]
    InvalidBondStartEpoch { id: BondId, got: u64, expected: u64 },
    #[error(
        "Bond ID {id} must be added at the correct epoch. Got epoch {got}, \
         expected {expected}"
    )]
    InvalidNewBondEpoch { id: BondId, got: u64, expected: u64 },

    #[error(
        "Bond ID {id} must be subtracted at the correct epoch. Got epoch \
         {got}, expected {expected}"
    )]
    InvalidNegDeltaEpoch { id: BondId, got: u64, expected: u64 },

    #[error(
        "Invalid validator {address} sum of total deltas. Total Δ \
         {total_delta}, bonds Δ {bond_delta}"
    )]
    InvalidValidatorTotalDeltasSum {
        address: Address,
        total_delta: token::Change,
        bond_delta: token::Change,
    },
    #[error("Unexpectedly missing validator set value")]
    MissingValidatorSet,
    #[error("Validator {0} not found in the validator set in epoch {1}")]
    WeightedValidatorNotFound(WeightedValidator, u64),
    #[error("Duplicate validator {0} in the validator set in epoch {1}")]
    ValidatorSetDuplicate(WeightedValidator, u64),
    #[error("Validator {0} has an invalid total deltas value {1}")]
    InvalidValidatorTotalDeltas(Address, i128),
    #[error("There are too many active validators in the validator set")]
    TooManyActiveValidators,
    #[error(
        "An inactive validator {0} has voting power greater than an active \
         validator {1}"
    )]
    ValidatorSetOutOfOrder(WeightedValidator, WeightedValidator),
    #[error("Invalid active validator {0}")]
    InvalidActiveValidator(WeightedValidator),
    #[error("Invalid inactive validator {0}")]
    InvalidInactiveValidator(WeightedValidator),
    #[error("Unexpectedly missing voting power value for validator {0}")]
    MissingValidatorVotingPower(Address),
    #[error("Validator {0} has an invalid voting power value {1}")]
    InvalidValidatorVotingPower(Address, i64),
    #[error("Validator set should be updated when voting powers change")]
    ValidatorSetNotUpdated,
    #[error("Invalid voting power changes")]
    InvalidVotingPowerChanges,
    #[error("Unexpectedly missing total voting power")]
    MissingTotalVotingPower,
    #[error("Total voting power should be updated when voting powers change")]
    TotalVotingPowerNotUpdated,
    #[error("Invalid address raw hash, got {0}, expected {1}")]
    InvalidAddressRawHash(String, String),
    #[error("Invalid address raw hash update")]
    InvalidRawHashUpdate,
    #[error("Invalid new validator {0}, some fields are missing: {1:?}.")]
    InvalidNewValidator(Address, NewValidator),
    #[error("New validator {0} has not been added to the validator set.")]
    NewValidatorMissingInValidatorSet(Address),
    #[error("Validator set has not been updated for new validators.")]
    MissingValidatorSetUpdate,
    #[error(
        "Changing the maximum commission rate change per epoch for validator \
         {0} is forbidden."
    )]
    ValidatorMaxCommissionRateChangeForbidden(Address),
    #[error(
        "Invalid value of maximum commission rate change per epoch for \
         validator {0}, got {1}."
    )]
    InvalidMaxCommissionRateChange(Address, Decimal),
}

/// An update of PoS data.
#[derive(Clone, Debug)]
pub enum DataUpdate {
    /// PoS account's balance update
    Balance(Data<token::Amount>),
    /// Bond update
    Bond {
        /// Bond ID
        id: BondId,
        /// Bond prior and posterior state
        data: Data<Bonds>,
        /// List of slashes applied to the bond's validator
        slashes: Slashes,
    },
    /// Unbond update
    Unbond {
        /// Unbond ID
        id: BondId,
        /// Unbond prior and posterior state
        data: Data<Unbonds>,
        /// List of slashes applied to the bond's validator
        slashes: Slashes,
    },
    /// A validator update
    Validator {
        /// Validator's address
        address: Address,
        /// Validator's data update
        update: ValidatorUpdate,
    },
    /// Validator set update
    ValidatorSet(Data<ValidatorSets>),
    /// Total deltas update
    TotalDeltas(Data<TotalDeltas>),
    /// Validator's address raw hash
    ValidatorAddressRawHash {
        /// Raw hash value
        raw_hash: String,
        /// The validator's address
        data: Data<Address>,
    },
}

/// An update of a validator's data.
#[derive(Clone, Debug)]
pub enum ValidatorUpdate {
    /// Validator's state update
    State(Data<ValidatorStates>),
    /// Consensus key update
    ConsensusKey(Data<ValidatorConsensusKeys>),
    /// Validator deltas update
    ValidatorDeltas(Data<ValidatorDeltas>),
    /// Commission rate update
    CommissionRate(Data<CommissionRates>, Option<Decimal>),
    /// Maximum commission rate change update
    MaxCommissionRateChange(Data<Decimal>),
}

/// Data update with prior and posterior state.
#[derive(Clone, Debug)]
pub struct Data<T>
where
    T: Clone + Debug,
{
    /// State before the update
    pub pre: Option<T>,
    /// State after the update
    pub post: Option<T>,
}

/// A new validator account initialized in a transaction, which is used to check
/// that all the validator's required fields have been written.
#[derive(Clone, Debug, Default)]
pub struct NewValidator {
    has_state: bool,
    has_consensus_key: Option<common::PublicKey>,
    has_total_deltas: bool,
    has_address_raw_hash: Option<String>,
    bonded_stake: u64,
    has_commission_rate: bool,
    has_max_commission_rate_change: bool,
}

/// Validation constants
#[derive(Clone, Debug)]
struct Constants {
    current_epoch: Epoch,
    pipeline_epoch: Epoch,
    unbonding_epoch: Epoch,
    pipeline_offset: u64,
    unbonding_offset: u64,
}

/// Validate the given list of PoS data `changes`. Returns empty list, if all
/// the changes are valid.
#[must_use]
pub fn validate(
    params: &PosParams,
    changes: Vec<DataUpdate>,
    current_epoch: Epoch,
) -> Vec<Error> {
    let pipeline_offset = DynEpochOffset::PipelineLen.value(params);
    let unbonding_offset = DynEpochOffset::UnbondingLen.value(params);
    let pipeline_epoch = current_epoch + pipeline_offset;
    let unbonding_epoch = current_epoch + unbonding_offset;
    let constants = Constants {
        current_epoch,
        pipeline_epoch,
        unbonding_epoch,
        pipeline_offset,
        unbonding_offset,
    };

    let mut errors = vec![];

    let Accumulator {
        balance_delta,
        bond_delta,
        unbond_delta,
        total_deltas,
        total_stake_by_epoch,
        validator_set_pre,
        validator_set_post,
        total_deltas_by_epoch: _,
        bonded_stake_by_epoch,
        new_validators,
    } = Validate::accumulate_changes(changes, params, &constants, &mut errors);

    // Check total deltas against bonds
    for (validator, total_delta) in total_deltas.iter() {
        let bond_delta = bond_delta.get(validator).copied().unwrap_or_default();
        let total_delta = *total_delta;
        if total_delta != bond_delta {
            errors.push(Error::InvalidValidatorTotalDeltasSum {
                address: validator.clone(),
                total_delta,
                bond_delta,
            })
        }
    }
    // Check that all bonds also have a total deltas update
    for validator in bond_delta.keys() {
        if !total_deltas.contains_key(validator) {
            errors.push(Error::MissingValidatorDeltas(validator.clone()))
        }
    }
    // Check that all positive unbond deltas also have a total deltas update.
    // Negative unbond delta is from withdrawing, which removes tokens from
    // unbond, but doesn't affect total deltas.
    for (validator, delta) in &unbond_delta {
        if *delta > token::Change::default()
            && !total_deltas.contains_key(validator)
        {
            errors.push(Error::MissingValidatorDeltas(validator.clone()));
        }
    }

    // Check validator sets against validator total stakes.
    // Iter from the first epoch to the last epoch of `validator_set_post`
    if let Some(post) = &validator_set_post {
        for epoch in Epoch::iter_range(current_epoch, unbonding_offset + 1) {
            if let Some(post) = post.get_at_epoch(epoch) {
                // Check that active validators length is not over the limit
                if post.active.len() > params.max_validator_slots as usize {
                    errors.push(Error::TooManyActiveValidators)
                }
                // Check that all active have voting power >= any inactive
                if let (
                    Some(max_inactive_validator),
                    Some(min_active_validator),
                ) = (post.inactive.last_shim(), post.active.first_shim())
                {
                    if max_inactive_validator.bonded_stake
                        > min_active_validator.bonded_stake
                    {
                        errors.push(Error::ValidatorSetOutOfOrder(
                            max_inactive_validator.clone(),
                            min_active_validator.clone(),
                        ));
                    }
                }

                match validator_set_pre.as_ref().and_then(|pre| pre.get(epoch))
                {
                    Some(pre) => {
                        let total_stakes = total_stake_by_epoch
                            .get(&epoch)
                            .map(Cow::Borrowed)
                            .unwrap_or_else(|| Cow::Owned(HashMap::default()));
                        // Check active validators
                        for validator in &post.active {
                            match total_stakes.get(&validator.address) {
                                Some((_stake_pre, stake_post)) => {
                                    // Any validator who's total deltas changed,
                                    // should
                                    // be up-to-date
                                    if validator.bonded_stake
                                        != Into::<u64>::into(*stake_post)
                                    {
                                        errors.push(
                                            Error::InvalidActiveValidator(
                                                validator.clone(),
                                            ),
                                        )
                                    }
                                }
                                None => {
                                    // Others must be have the same voting power
                                    // as in pre (active or inactive), or be a
                                    // newly added validator
                                    if !pre.active.contains(validator)
                                        && !pre.inactive.contains(validator)
                                        && !new_validators
                                            .contains_key(&validator.address)
                                    {
                                        let mut is_valid = false;

                                        // It's also possible that for this
                                        // validator there has been no change in
                                        // this epoch, but in an earlier epoch.
                                        // We attempt to search for it below and
                                        // if the voting power matches the
                                        // stake, this is valid.
                                        let mut search_epoch =
                                            u64::from(epoch) - 1;
                                        while search_epoch
                                            >= current_epoch.into()
                                        {
                                            if let Some((
                                                _take_pre,
                                                last_total_stake,
                                            )) = total_stake_by_epoch
                                                .get(&search_epoch.into())
                                                .and_then(|stakes| {
                                                    stakes
                                                        .get(&validator.address)
                                                })
                                            {
                                                is_valid = validator
                                                    .bonded_stake
                                                    == Into::<u64>::into(
                                                        *last_total_stake,
                                                    );
                                                break;
                                            } else {
                                                search_epoch -= 1;
                                            }
                                        }
                                        if !is_valid {
                                            errors.push(
                                                Error::InvalidActiveValidator(
                                                    validator.clone(),
                                                ),
                                            )
                                        }
                                    }
                                }
                            }
                        }
                        // Check inactive validators
                        for validator in &post.inactive {
                            // Any validator who's total deltas changed, should
                            // be up-to-date
                            match total_stakes.get(&validator.address) {
                                Some((_stake_pre, stake_post)) => {
                                    if validator.bonded_stake
                                        != Into::<u64>::into(*stake_post)
                                    {
                                        errors.push(
                                            Error::InvalidInactiveValidator(
                                                validator.clone(),
                                            ),
                                        )
                                    }
                                }
                                None => {
                                    // Others must be have the same voting power
                                    // as in pre (active or inactive), or be a
                                    // newly added validator
                                    if !pre.active.contains(validator)
                                        && !pre.inactive.contains(validator)
                                        && !new_validators
                                            .contains_key(&validator.address)
                                    {
                                        let mut is_valid = false;

                                        // It's also possible that for this
                                        // validator there has been no change in
                                        // this epoch, but in an earlier epoch.
                                        // We attempt to search for it below and
                                        // if the voting power matches the
                                        // stake, this is valid.
                                        let mut search_epoch =
                                            u64::from(epoch) - 1;
                                        while search_epoch
                                            >= current_epoch.into()
                                        {
                                            if let Some((
                                                _take_pre,
                                                last_total_stake,
                                            )) = total_stake_by_epoch
                                                .get(&search_epoch.into())
                                                .and_then(|stakes| {
                                                    stakes
                                                        .get(&validator.address)
                                                })
                                            {
                                                is_valid = validator
                                                    .bonded_stake
                                                    == Into::<u64>::into(
                                                        *last_total_stake,
                                                    );
                                                break;
                                            } else {
                                                search_epoch -= 1;
                                            }
                                        }

                                        if !is_valid {
                                            errors.push(
                                                Error::InvalidInactiveValidator(
                                                    validator.clone(),
                                                ),
                                            )
                                        }
                                    }
                                }
                            }
                        }
                    }
                    None => errors.push(Error::MissingValidatorSet),
                }
            } else if let Some(total_stake) = total_stake_by_epoch.get(&epoch) {
                // When there's some total delta change for this epoch,
                // check that it wouldn't have affected the validator set
                // (i.e. the validator's voting power is unchanged).
                match post.get(epoch) {
                    Some(post) => {
                        for (validator, (_stake_pre, tokens_at_epoch)) in
                            total_stake
                        {
                            let weighted_validator = WeightedValidator {
                                bonded_stake: (*tokens_at_epoch).into(),
                                address: validator.clone(),
                            };
                            if !post.active.contains(&weighted_validator) {
                                if !post.inactive.contains(&weighted_validator)
                                {
                                    errors.push(
                                        Error::WeightedValidatorNotFound(
                                            weighted_validator,
                                            epoch.into(),
                                        ),
                                    );
                                }
                            } else if post
                                .inactive
                                .contains(&weighted_validator)
                            {
                                // Validator cannot be both active and inactive
                                errors.push(Error::ValidatorSetDuplicate(
                                    weighted_validator,
                                    epoch.into(),
                                ))
                            }
                        }
                    }
                    None => errors.push(Error::MissingValidatorSet),
                }
            }
        }
    } else if !bonded_stake_by_epoch.is_empty() {
        errors.push(Error::ValidatorSetNotUpdated)
    }

    // Check new validators are initialized with all the required fields
    if !new_validators.is_empty() {
        match &validator_set_post {
            None => errors.push(Error::MissingValidatorSetUpdate),
            Some(sets) => {
                let validator_sets = sets.get(pipeline_epoch);
                for (address, new_validator) in new_validators {
                    let NewValidator {
                        has_state,
                        has_consensus_key,
                        has_total_deltas,
                        has_address_raw_hash,
                        bonded_stake,
                        has_commission_rate,
                        has_max_commission_rate_change,
                    } = &new_validator;
                    // The new validator must have set all the required fields
                    if !(*has_state
                        && *has_total_deltas
                        && *has_commission_rate
                        && *has_max_commission_rate_change)
                    {
                        errors.push(Error::InvalidNewValidator(
                            address.clone(),
                            new_validator.clone(),
                        ))
                    }
                    match (has_address_raw_hash, has_consensus_key) {
                        (Some(raw_hash), Some(consensus_key)) => {
                            let expected_raw_hash = consensus_key.tm_raw_hash();
                            if raw_hash != &expected_raw_hash {
                                errors.push(Error::InvalidAddressRawHash(
                                    raw_hash.clone(),
                                    expected_raw_hash,
                                ))
                            }
                        }
                        _ => errors.push(Error::InvalidNewValidator(
                            address.clone(),
                            new_validator.clone(),
                        )),
                    }
                    let weighted_validator = WeightedValidator {
                        bonded_stake: *bonded_stake,
                        address: address.clone(),
                    };
                    match validator_sets {
                        Some(set)
                            if set.active.contains(&weighted_validator)
                                || set
                                    .inactive
                                    .contains(&weighted_validator) =>
                        {
                            continue;
                        }
                        _ => errors.push(
                            Error::NewValidatorMissingInValidatorSet(address),
                        ),
                    }
                }
            }
        }
    }

    // Sum the bond totals
    let bond_delta = bond_delta
        .values()
        .into_iter()
        .fold(token::Change::default(), |acc, delta| acc + (*delta));
    // Sum the unbond totals
    let unbond_delta = unbond_delta
        .values()
        .into_iter()
        .fold(token::Change::default(), |acc, delta| acc + (*delta));

    if balance_delta != bond_delta + unbond_delta {
        errors.push(Error::InvalidBalances {
            balance_delta,
            bond_delta,
            unbond_delta,
        })
    }

    errors
}

#[derive(Clone, Debug, Default)]
struct Accumulator {
    balance_delta: token::Change,
    /// Changes of validators' bonds
    bond_delta: HashMap<Address, token::Change>,
    /// Changes of validators' unbonds
    unbond_delta: HashMap<Address, token::Change>,

    /// Changes of all validator total deltas (up to `unbonding_epoch`)
    total_deltas: HashMap<Address, token::Change>,
    /// Stake calculated from validator total deltas for each epoch
    /// in which it has changed (the tuple of values are in pre and post state)
    total_stake_by_epoch:
        HashMap<Epoch, HashMap<Address, (token::Amount, token::Amount)>>,
    /// Total voting power delta calculated from validators' total deltas
    total_deltas_by_epoch: HashMap<Epoch, token::Change>,
    bonded_stake_by_epoch: HashMap<Epoch, HashMap<Address, token::Change>>,
    validator_set_pre: Option<ValidatorSets>,
    validator_set_post: Option<ValidatorSets>,
    new_validators: HashMap<Address, NewValidator>,
}

/// An empty local type to re-use trait bounds for the functions associated with
/// `Validate` in the `impl` below
struct Validate {
    address: PhantomData<Address>,
    token_amount: PhantomData<token::Amount>,
    token_change: PhantomData<token::Change>,
    public_key: PhantomData<common::PublicKey>,
}

impl Validate {
    fn accumulate_changes(
        changes: Vec<DataUpdate>,
        _params: &PosParams,
        constants: &Constants,
        errors: &mut Vec<Error>,
    ) -> Accumulator {
        use DataUpdate::*;
        use ValidatorUpdate::*;

        let mut accumulator = Accumulator::default();
        let Accumulator {
            balance_delta,
            bond_delta,
            unbond_delta,
            total_deltas,
            total_stake_by_epoch,
            total_deltas_by_epoch,
            bonded_stake_by_epoch: _,
            validator_set_pre,
            validator_set_post,
            new_validators,
        } = &mut accumulator;

        for change in changes {
            match change {
                Validator { address, update } => match update {
                    State(data) => Self::validator_state(
                        constants,
                        errors,
                        new_validators,
                        address,
                        data,
                    ),
                    ConsensusKey(data) => Self::validator_consensus_key(
                        constants,
                        errors,
                        new_validators,
                        address,
                        data,
                    ),
                    ValidatorDeltas(data) => Self::validator_deltas(
                        constants,
                        errors,
                        total_deltas,
                        total_stake_by_epoch,
                        new_validators,
                        address,
                        data,
                    ),
                    CommissionRate(data, max_change) => {
                        Self::validator_commission_rate(
                            constants,
                            errors,
                            new_validators,
                            address,
                            data,
                            max_change,
                        )
                    }
                    MaxCommissionRateChange(data) => {
                        Self::validator_max_commission_rate_change(
                            errors,
                            new_validators,
                            address,
                            data,
                        )
                    }
                },
                Balance(data) => Self::balance(errors, balance_delta, data),
                Bond { id, data, slashes } => {
                    Self::bond(constants, errors, bond_delta, id, data, slashes)
                }
                Unbond { id, data, slashes } => Self::unbond(
                    constants,
                    errors,
                    unbond_delta,
                    id,
                    data,
                    slashes,
                ),
                ValidatorSet(data) => Self::validator_set(
                    constants,
                    errors,
                    validator_set_pre,
                    validator_set_post,
                    data,
                ),
                TotalDeltas(data) => Self::total_deltas(
                    constants,
                    errors,
                    total_deltas_by_epoch,
                    data,
                ),
                ValidatorAddressRawHash { raw_hash, data } => {
                    Self::validator_address_raw_hash(
                        errors,
                        new_validators,
                        raw_hash,
                        data,
                    )
                }
            }
        }

        accumulator
    }

    fn validator_state(
        constants: &Constants,
        errors: &mut Vec<Error>,
        new_validators: &mut HashMap<Address, NewValidator>,
        address: Address,
        data: Data<ValidatorStates>,
    ) {
        match (data.pre, data.post) {
            (None, Some(post)) => {
                if post.last_update() != constants.current_epoch {
                    errors.push(Error::InvalidLastUpdate)
                }
                // Before pipeline epoch, the state must be `Pending`
                for epoch in Epoch::iter_range(
                    constants.current_epoch,
                    constants.pipeline_offset,
                ) {
                    match post.get(epoch) {
                        Some(ValidatorState::Pending) => {}
                        _ => errors.push(Error::InvalidNewValidatorState(
                            epoch.into(),
                        )),
                    }
                }
                // At pipeline epoch, the state must be `Candidate`
                match post.get(constants.pipeline_epoch) {
                    Some(ValidatorState::Candidate) => {}
                    _ => errors.push(Error::InvalidNewValidatorState(
                        constants.pipeline_epoch.into(),
                    )),
                }
                // Add the validator to the accumulator
                let validator = new_validators.entry(address).or_default();
                validator.has_state = true;
            }
            (Some(pre), Some(post)) => {
                if post.last_update() != constants.current_epoch {
                    errors.push(Error::InvalidLastUpdate)
                }
                use ValidatorState::*;
                // Before pipeline epoch, the only allowed state change
                // is from `Inactive` to `Pending`
                for epoch in Epoch::iter_range(
                    constants.current_epoch,
                    constants.pipeline_offset,
                ) {
                    match (pre.get(epoch), post.get(epoch)) {
                        (Some(Inactive), Some(Pending)) => {}
                        (Some(state_pre), Some(state_post))
                            if state_pre == state_post => {}
                        _ => errors.push(Error::InvalidValidatorStateUpdate(
                            epoch.into(),
                        )),
                    }
                }
                // Check allowed state changes at pipeline epoch
                match (
                    pre.get(constants.pipeline_epoch),
                    post.get(constants.pipeline_epoch),
                ) {
                    (Some(Pending), Some(Candidate) | Some(Inactive))
                    | (Some(Candidate), Some(Inactive))
                    | (Some(Inactive), Some(Candidate) | Some(Pending)) => {}
                    _ => errors.push(Error::InvalidNewValidatorState(
                        constants.pipeline_epoch.into(),
                    )),
                }
            }
            (Some(_), None) => {
                errors.push(Error::ValidatorStateIsRequired(address))
            }
            (None, None) => {}
        }
    }

    fn validator_consensus_key(
        constants: &Constants,
        errors: &mut Vec<Error>,
        new_validators: &mut HashMap<Address, NewValidator>,
        address: Address,
        data: Data<ValidatorConsensusKeys>,
    ) {
        match (data.pre, data.post) {
            (None, Some(post)) => {
                if post.last_update() != constants.current_epoch {
                    errors.push(Error::InvalidLastUpdate)
                }
                // The value must be known at pipeline epoch
                match post.get(constants.pipeline_epoch) {
                    Some(consensus_key) => {
                        let validator =
                            new_validators.entry(address).or_default();
                        validator.has_consensus_key =
                            Some(consensus_key.clone());
                    }
                    _ => errors.push(Error::MissingNewValidatorConsensusKey(
                        constants.pipeline_epoch.into(),
                    )),
                }
            }
            (Some(pre), Some(post)) => {
                if post.last_update() != constants.current_epoch {
                    errors.push(Error::InvalidLastUpdate)
                }
                // Before pipeline epoch, the key must not change
                for epoch in Epoch::iter_range(
                    constants.current_epoch,
                    constants.pipeline_offset,
                ) {
                    match (pre.get(epoch), post.get(epoch)) {
                        (Some(key_pre), Some(key_post))
                            if key_pre == key_post =>
                        {
                            continue;
                        }
                        _ => errors.push(
                            Error::InvalidValidatorConsensusKeyUpdate(
                                epoch.into(),
                            ),
                        ),
                    }
                }
            }
            (Some(_), None) => {
                errors.push(Error::ValidatorConsensusKeyIsRequired(address))
            }
            (None, None) => {}
        }
    }

    fn validator_deltas(
        constants: &Constants,
        errors: &mut Vec<Error>,
        total_deltas: &mut HashMap<Address, token::Change>,
        total_stake_by_epoch: &mut HashMap<
            Epoch,
            HashMap<Address, (token::Amount, token::Amount)>,
        >,
        new_validators: &mut HashMap<Address, NewValidator>,
        address: Address,
        data: Data<ValidatorDeltas>,
    ) {
        match (data.pre, data.post) {
            (Some(pre), Some(post)) => {
                if post.last_update() != constants.current_epoch {
                    errors.push(Error::InvalidLastUpdate)
                }
                // Changes of all total deltas (up to `unbonding_epoch`)
                let mut deltas = token::Change::default();
                // Sum of pre total deltas
                let mut pre_deltas_sum = token::Change::default();
                // Sum of post total deltas
                let mut post_deltas_sum = token::Change::default();
                // Iter from the first epoch to the last epoch of `post`
                for epoch in Epoch::iter_range(
                    constants.current_epoch,
                    constants.unbonding_offset + 1,
                ) {
                    // Changes of all total deltas (up to
                    // `unbonding_epoch`)
                    let mut delta = token::Change::default();
                    // Find the delta in `pre`
                    if let Some(change) = {
                        if epoch == constants.current_epoch {
                            // On the first epoch, we have to get the
                            // sum of all deltas at and before that
                            // epoch as the `pre` could have been set in
                            // an older epoch
                            pre.get(epoch)
                        } else {
                            pre.get_delta_at_epoch(epoch).copied()
                        }
                    } {
                        delta -= change;
                        pre_deltas_sum += change;
                    }
                    // Find the delta in `post`
                    if let Some(change) = post.get_delta_at_epoch(epoch) {
                        delta += *change;
                        post_deltas_sum += *change;
                        let stake_pre: i128 = Into::into(pre_deltas_sum);
                        let stake_post: i128 = Into::into(post_deltas_sum);
                        match (
                            u64::try_from(stake_pre),
                            u64::try_from(stake_post),
                        ) {
                            (Ok(stake_pre), Ok(stake_post)) => {
                                let stake_pre = token::Amount::from(stake_pre);
                                let stake_post =
                                    token::Amount::from(stake_post);
                                total_stake_by_epoch
                                    .entry(epoch)
                                    .or_insert_with(HashMap::default)
                                    .insert(
                                        address.clone(),
                                        (stake_pre, stake_post),
                                    );
                            }
                            _ => {
                                errors.push(Error::InvalidValidatorTotalDeltas(
                                    address.clone(),
                                    stake_post,
                                ))
                            }
                        }
                    }
                    deltas += delta;
                    // A total delta can only be increased at
                    // `pipeline_offset` from bonds and decreased at
                    // `unbonding_offset` from unbonding
                    if delta > token::Change::default()
                        && epoch != constants.pipeline_epoch
                    {
                        errors.push(Error::EpochedDataWrongEpoch {
                            got: epoch.into(),
                            expected: vec![constants.pipeline_epoch.into()],
                        })
                    }
                    if delta < token::Change::default()
                        && epoch != constants.unbonding_epoch
                    {
                        errors.push(Error::EpochedDataWrongEpoch {
                            got: epoch.into(),
                            expected: vec![constants.unbonding_epoch.into()],
                        })
                    }
                }
                if post_deltas_sum < token::Change::default() {
                    errors.push(Error::NegativeValidatorDeltasSum(
                        address.clone(),
                    ))
                }
                if deltas != token::Change::default() {
                    let deltas_entry = total_deltas.entry(address).or_default();
                    *deltas_entry += deltas;
                }
            }
            (None, Some(post)) => {
                if post.last_update() != constants.current_epoch {
                    errors.push(Error::InvalidLastUpdate)
                }
                // Changes of all total deltas (up to `unbonding_epoch`)
                let mut deltas = token::Change::default();
                for epoch in Epoch::iter_range(
                    constants.current_epoch,
                    constants.unbonding_offset + 1,
                ) {
                    if let Some(change) = post.get_delta_at_epoch(epoch) {
                        // A new total delta can only be initialized
                        // at `pipeline_offset` (from bonds) and updated
                        // at `unbonding_offset` (from unbonding)
                        if epoch != constants.pipeline_epoch
                            && epoch != constants.unbonding_epoch
                        {
                            errors.push(Error::EpochedDataWrongEpoch {
                                got: epoch.into(),
                                expected: vec![constants.pipeline_epoch.into()],
                            })
                        }
                        deltas += *change;
                        let stake: i128 = Into::into(deltas);
                        match u64::try_from(stake) {
                            Ok(stake) => {
                                let stake = token::Amount::from(stake);
                                total_stake_by_epoch
                                    .entry(epoch)
                                    .or_insert_with(HashMap::default)
                                    .insert(address.clone(), (0.into(), stake));
                            }
                            Err(_) => {
                                errors.push(Error::InvalidValidatorTotalDeltas(
                                    address.clone(),
                                    stake,
                                ))
                            }
                        }
                    }
                }
                if deltas < token::Change::default() {
                    errors.push(Error::NegativeValidatorDeltasSum(
                        address.clone(),
                    ))
                }
                if deltas != token::Change::default() {
                    let deltas_entry =
                        total_deltas.entry(address.clone()).or_default();
                    *deltas_entry += deltas;
                }
                let validator = new_validators.entry(address).or_default();
                validator.has_total_deltas = true;
                validator.bonded_stake =
                    u64::try_from(Into::<i128>::into(deltas))
                        .unwrap_or_default();
            }
            (Some(_), None) => {
                errors.push(Error::MissingValidatorDeltas(address))
            }
            (None, None) => {}
        }
    }

    fn validator_commission_rate(
        constants: &Constants,
        errors: &mut Vec<Error>,
        new_validators: &mut HashMap<Address, NewValidator>,
        address: Address,
        data: Data<CommissionRates>,
        max_change: Option<Decimal>,
    ) {
        match (data.pre, data.post) {
            (None, Some(post)) => {
                if post.last_update() != constants.current_epoch {
                    errors.push(Error::InvalidLastUpdate)
                }
                // The value must be known at the pipeline epoch
                match post.get(constants.pipeline_epoch) {
                    Some(_) => {
                        let validator =
                            new_validators.entry(address).or_default();
                        validator.has_commission_rate = true;
                    }
                    _ => errors.push(Error::MissingNewValidatorCommissionRate(
                        constants.pipeline_epoch.into(),
                    )),
                }
            }
            (Some(pre), Some(post)) => {
                if post.last_update() != constants.current_epoch {
                    errors.push(Error::InvalidLastUpdate)
                }
                if max_change.is_none() {
                    errors.push(Error::InvalidLastUpdate)
                }
                // Before the pipeline epoch, the commission rate must not
                // change
                for epoch in Epoch::iter_range(
                    constants.current_epoch,
                    constants.pipeline_offset,
                ) {
                    match (pre.get(epoch), post.get(epoch)) {
                        (Some(rate_pre), Some(rate_post))
                            if rate_pre == rate_post =>
                        {
                            continue;
                        }
                        _ => errors.push(
                            Error::InvalidValidatorCommissionRateUpdate(
                                epoch.into(),
                            ),
                        ),
                    }
                }
                // At the pipeline epoch, the rate must change by no larger than
                // `max_change` relative to the previous epoch
                match (
                    pre.get(constants.pipeline_epoch - 1),
                    post.get(constants.pipeline_epoch),
                ) {
                    (Some(prev_rate), Some(new_rate)) => {
                        if (new_rate - prev_rate).abs()
                            > max_change.unwrap_or_default()
                        {
                            errors.push(
                                Error::InvalidValidatorCommissionRateUpdate(
                                    constants.pipeline_epoch.into(),
                                ),
                            )
                        }
                    }
                    _ => errors.push(Error::ValidatorCommissionRateIsRequired(
                        address,
                    )),
                }
            }
            (Some(_), None) => {
                errors.push(Error::ValidatorCommissionRateIsRequired(address))
            }
            (None, None) => {}
        }
    }

    fn validator_max_commission_rate_change(
        errors: &mut Vec<Error>,
        new_validators: &mut HashMap<Address, NewValidator>,
        address: Address,
        data: Data<Decimal>,
    ) {
        match (data.pre, data.post) {
            (None, Some(post)) => {
                if post < Decimal::ZERO || post > Decimal::ONE {
                    errors.push(Error::InvalidMaxCommissionRateChange(
                        address.clone(),
                        post,
                    ))
                }

                let validator = new_validators.entry(address).or_default();
                validator.has_max_commission_rate_change = true;
            }
            _ => errors.push(Error::ValidatorMaxCommissionRateChangeForbidden(
                address,
            )),
        }
    }

    fn balance(
        errors: &mut Vec<Error>,
        balance_delta: &mut token::Change,
        data: Data<token::Amount>,
    ) {
        match (data.pre, data.post) {
            (None, Some(post)) => *balance_delta += token::Change::from(post),
            (Some(pre), Some(post)) => {
                *balance_delta +=
                    token::Change::from(post) - token::Change::from(pre);
            }
            (Some(_), None) => errors.push(Error::MissingBalance),
            (None, None) => {}
        }
    }

    fn bond(
        constants: &Constants,
        errors: &mut Vec<Error>,
        bond_delta: &mut HashMap<Address, token::Change>,
        id: BondId,
        data: Data<Bonds>,
        slashes: Vec<Slash>,
    ) {
        match (data.pre, data.post) {
            // Bond may be updated from newly bonded tokens and unbonding
            (Some(pre), Some(post)) => {
                if post.last_update() != constants.current_epoch {
                    errors.push(Error::InvalidLastUpdate)
                }
                let pre_offset: u64 = match constants
                    .current_epoch
                    .checked_sub(pre.last_update())
                {
                    Some(offset) => offset.into(),
                    None => {
                        // If the last_update > current_epoch, the check
                        // above must have failed with
                        // `Error::InvalidLastUpdate`
                        return;
                    }
                };

                // Pre-bonds keyed by their `start_epoch`
                let mut pre_bonds: HashMap<Epoch, token::Change> =
                    HashMap::default();
                // We have to slash only the difference between post and
                // pre, not both pre and post to avoid rounding errors
                let mut slashed_deltas: HashMap<Epoch, token::Change> =
                    HashMap::default();
                let mut neg_deltas: HashMap<Epoch, token::Change> =
                    Default::default();
                // Iter from the first epoch of `pre` to the last epoch of
                // `post`
                for epoch in Epoch::iter_range(
                    pre.last_update(),
                    pre_offset + constants.unbonding_offset + 1,
                ) {
                    if let Some(bond) = pre.get_delta_at_epoch(epoch) {
                        for (start_epoch, delta) in bond.pos_deltas.iter() {
                            let delta = token::Change::from(*delta);
                            slashed_deltas.insert(*start_epoch, -delta);
                            pre_bonds.insert(*start_epoch, delta);
                        }
                        let ins_epoch = if epoch <= constants.current_epoch {
                            constants.current_epoch
                        } else {
                            epoch
                        };
                        let entry = neg_deltas.entry(ins_epoch).or_default();
                        *entry -= token::Change::from(bond.neg_deltas);
                    }
                    if let Some(bond) = post.get_delta_at_epoch(epoch) {
                        for (start_epoch, delta) in bond.pos_deltas.iter() {
                            // An empty bond must be deleted
                            if *delta == token::Amount::default() {
                                errors.push(Error::EmptyBond(id.clone()))
                            }
                            // On the current epoch, all bond's
                            // `start_epoch`s must be equal or lower than
                            // `current_epoch`. For all others, the
                            // `start_epoch` must be equal
                            // to the `epoch` at which it's set.
                            if (epoch == constants.current_epoch
                                && *start_epoch > constants.current_epoch)
                                || (epoch != constants.current_epoch
                                    && *start_epoch != epoch)
                            {
                                errors.push(Error::InvalidBondStartEpoch {
                                    id: id.clone(),
                                    got: (*start_epoch).into(),
                                    expected: epoch.into(),
                                })
                            }
                            let delta = token::Change::from(*delta);
                            match slashed_deltas.get_mut(start_epoch) {
                                Some(pre_delta) => {
                                    if *pre_delta + delta == 0_i128 {
                                        slashed_deltas.remove(start_epoch);
                                    } else {
                                        *pre_delta += delta;
                                    }
                                }
                                None => {
                                    slashed_deltas.insert(*start_epoch, delta);
                                }
                            }

                            // Anywhere other than at `pipeline_offset`
                            // where new bonds are added, check against the
                            // data in `pre_bonds` to ensure that no new
                            // bond has been added and that the deltas are
                            // equal or lower to `pre_bonds` deltas.
                            // Note that any bonds from any epoch can be
                            // unbonded, even if they are not yet active.
                            if epoch != constants.pipeline_epoch {
                                match pre_bonds.get(start_epoch) {
                                    Some(pre_delta) => {
                                        if &delta != pre_delta {
                                            errors.push(
                                                Error::InvalidNewBondEpoch {
                                                    id: id.clone(),
                                                    got: epoch.into(),
                                                    expected: constants
                                                        .pipeline_epoch
                                                        .into(),
                                                },
                                            );
                                        }
                                    }
                                    None => {
                                        errors.push(
                                            Error::InvalidNewBondEpoch {
                                                id: id.clone(),
                                                got: epoch.into(),
                                                expected: (constants
                                                    .current_epoch
                                                    + constants
                                                        .pipeline_offset)
                                                    .into(),
                                            },
                                        );
                                    }
                                }
                            }
                        }
                        if epoch != constants.unbonding_epoch {
                            match neg_deltas.get(&epoch) {
                                Some(deltas) => {
                                    if -*deltas
                                        != token::Change::from(bond.neg_deltas)
                                    {
                                        errors.push(
                                            Error::InvalidNegDeltaEpoch {
                                                id: id.clone(),
                                                got: epoch.into(),
                                                expected: constants
                                                    .unbonding_epoch
                                                    .into(),
                                            },
                                        )
                                    }
                                }
                                None => {
                                    if bond.neg_deltas != 0.into() {
                                        errors.push(
                                            Error::InvalidNegDeltaEpoch {
                                                id: id.clone(),
                                                got: epoch.into(),
                                                expected: constants
                                                    .unbonding_epoch
                                                    .into(),
                                            },
                                        )
                                    }
                                }
                            }
                        }
                        let entry = neg_deltas.entry(epoch).or_default();
                        *entry += token::Change::from(bond.neg_deltas);
                    }
                }
                // Check slashes
                for (start_epoch, delta) in slashed_deltas.iter_mut() {
                    for slash in &slashes {
                        if slash.epoch >= *start_epoch {
                            let raw_delta: i128 = *delta;
                            let current_slashed =
                                decimal_mult_i128(slash.rate, raw_delta);
                            *delta -= current_slashed;
                        }
                    }
                }
                let total = slashed_deltas
                    .values()
                    .fold(token::Change::default(), |acc, delta| acc + *delta)
                    - neg_deltas
                        .values()
                        .fold(token::Change::default(), |acc, delta| {
                            acc + *delta
                        });

                if total != token::Change::default() {
                    let bond_entry =
                        bond_delta.entry(id.validator).or_default();
                    *bond_entry += total;
                }
            }
            // Bond may be created from newly bonded tokens only
            (None, Some(post)) => {
                if post.last_update() != constants.current_epoch {
                    errors.push(Error::InvalidLastUpdate)
                }
                let mut total_delta = token::Change::default();
                for epoch in Epoch::iter_range(
                    constants.current_epoch,
                    constants.unbonding_offset + 1,
                ) {
                    if let Some(bond) = post.get_delta_at_epoch(epoch) {
                        // A new bond must be initialized at
                        // `pipeline_offset`
                        if epoch != constants.pipeline_epoch
                            && !bond.pos_deltas.is_empty()
                        {
                            dbg!(&bond.pos_deltas);
                            errors.push(Error::EpochedDataWrongEpoch {
                                got: epoch.into(),
                                expected: vec![constants.pipeline_epoch.into()],
                            })
                        }
                        if epoch != constants.unbonding_epoch
                            && bond.neg_deltas != 0.into()
                        {
                            errors.push(Error::InvalidNegDeltaEpoch {
                                id: id.clone(),
                                got: epoch.into(),
                                expected: constants.unbonding_epoch.into(),
                            })
                        }
                        for (start_epoch, delta) in bond.pos_deltas.iter() {
                            if *start_epoch != epoch {
                                errors.push(Error::InvalidBondStartEpoch {
                                    id: id.clone(),
                                    got: (*start_epoch).into(),
                                    expected: epoch.into(),
                                })
                            }
                            let mut delta = *delta;
                            // Check slashes
                            for slash in &slashes {
                                if slash.epoch >= *start_epoch {
                                    let raw_delta: u64 = delta.into();
                                    let current_slashed = token::Amount::from(
                                        decimal_mult_u64(slash.rate, raw_delta),
                                    );
                                    delta -= current_slashed;
                                }
                            }
                            let delta = token::Change::from(delta);
                            total_delta += delta
                        }
                        total_delta -= token::Change::from(bond.neg_deltas)
                    }
                }
                // An empty bond must be deleted
                if total_delta == token::Change::default() {
                    errors.push(Error::EmptyBond(id.clone()))
                }
                let bond_entry = bond_delta.entry(id.validator).or_default();
                *bond_entry += total_delta;
            }
            // Bond may be deleted when all the tokens are unbonded
            (Some(pre), None) => {
                let mut total_delta = token::Change::default();
                for index in 0..constants.pipeline_offset + 1 {
                    let index = index as usize;
                    let epoch = pre.last_update() + index;
                    if let Some(bond) = pre.get_delta_at_epoch(epoch) {
                        for (start_epoch, delta) in &bond.pos_deltas {
                            let mut delta = *delta;
                            // Check slashes
                            for slash in &slashes {
                                if slash.epoch >= *start_epoch {
                                    let raw_delta: u64 = delta.into();
                                    let current_slashed = token::Amount::from(
                                        decimal_mult_u64(slash.rate, raw_delta),
                                    );
                                    delta -= current_slashed;
                                }
                            }
                            let delta = token::Change::from(delta);
                            total_delta -= delta
                        }
                        total_delta += token::Change::from(bond.neg_deltas)
                    }
                }
                let bond_entry = bond_delta.entry(id.validator).or_default();
                *bond_entry += total_delta;
            }
            (None, None) => {}
        }
    }

    fn unbond(
        constants: &Constants,
        errors: &mut Vec<Error>,
        unbond_delta: &mut HashMap<Address, token::Change>,
        id: BondId,
        data: Data<Unbonds>,
        slashes: Vec<Slash>,
    ) {
        match (data.pre, data.post) {
            // Unbond may be updated from newly unbonded tokens
            (Some(pre), Some(post)) => {
                if post.last_update() != constants.current_epoch {
                    errors.push(Error::InvalidLastUpdate)
                }
                let pre_offset: u64 = match constants
                    .current_epoch
                    .checked_sub(pre.last_update())
                {
                    Some(offset) => offset.into(),
                    None => {
                        // If the last_update > current_epoch, the check
                        // above must have failed with
                        // `Error::InvalidLastUpdate`
                        return;
                    }
                };

                // We have to slash only the difference between post and
                // pre, not both pre and post to avoid rounding errors
                let mut slashed_deltas: HashMap<(Epoch, Epoch), token::Change> =
                    HashMap::default();
                // Iter from the first epoch of `pre` to the last epoch of
                // `post`
                for epoch in Epoch::iter_range(
                    pre.last_update(),
                    pre_offset + constants.unbonding_offset + 1,
                ) {
                    if let Some(unbond) = pre.get_delta_at_epoch(epoch) {
                        for ((start_epoch, end_epoch), delta) in
                            unbond.deltas.iter()
                        {
                            let delta = token::Change::from(*delta);
                            slashed_deltas
                                .insert((*start_epoch, *end_epoch), -delta);
                        }
                    }
                    if let Some(unbond) = post.get_delta_at_epoch(epoch) {
                        for ((start_epoch, end_epoch), delta) in
                            unbond.deltas.iter()
                        {
                            let delta = token::Change::from(*delta);
                            let key = (*start_epoch, *end_epoch);
                            match slashed_deltas.get_mut(&key) {
                                Some(pre_delta) => {
                                    if *pre_delta + delta == 0_i128 {
                                        slashed_deltas.remove(&key);
                                    } else {
                                        *pre_delta += delta;
                                    }
                                }
                                None => {
                                    slashed_deltas.insert(key, delta);
                                }
                            }
                        }
                    }
                }
                // Check slashes
                for ((start_epoch, end_epoch), delta) in
                    slashed_deltas.iter_mut()
                {
                    for slash in &slashes {
                        if slash.epoch >= *start_epoch
                            && slash.epoch <= *end_epoch
                        {
                            let raw_delta: i128 = *delta;
                            let current_slashed =
                                decimal_mult_i128(slash.rate, raw_delta);
                            *delta -= current_slashed;
                        }
                    }
                }
                let total = slashed_deltas
                    .values()
                    .fold(token::Change::default(), |acc, delta| acc + *delta);
                if total != token::Change::default() {
                    let unbond_entry =
                        unbond_delta.entry(id.validator).or_default();
                    *unbond_entry += total;
                }
            }
            // Unbond may be created from a bond
            (None, Some(post)) => {
                if post.last_update() != constants.current_epoch {
                    errors.push(Error::InvalidLastUpdate)
                }
                let mut total_delta = token::Change::default();
                for epoch in Epoch::iter_range(
                    post.last_update(),
                    constants.unbonding_offset + 1,
                ) {
                    if let Some(unbond) = post.get_delta_at_epoch(epoch) {
                        for ((start_epoch, end_epoch), delta) in
                            unbond.deltas.iter()
                        {
                            let mut delta = *delta;
                            // Check and apply slashes, if any
                            for slash in &slashes {
                                if slash.epoch >= *start_epoch
                                    && slash.epoch <= *end_epoch
                                {
                                    let raw_delta: u64 = delta.into();
                                    let current_slashed = token::Amount::from(
                                        decimal_mult_u64(slash.rate, raw_delta),
                                    );
                                    delta -= current_slashed;
                                }
                            }
                            let delta = token::Change::from(delta);
                            total_delta += delta;
                        }
                    }
                }
                let unbond_entry =
                    unbond_delta.entry(id.validator).or_default();
                *unbond_entry += total_delta;
            }
            // Unbond may be deleted when all the tokens are withdrawn
            (Some(pre), None) => {
                let mut total_delta = token::Change::default();
                for epoch in Epoch::iter_range(
                    pre.last_update(),
                    constants.unbonding_offset + 1,
                ) {
                    if let Some(unbond) = pre.get_delta_at_epoch(epoch) {
                        for ((start_epoch, end_epoch), delta) in
                            unbond.deltas.iter()
                        {
                            let mut delta = *delta;
                            // Check and apply slashes, if any
                            for slash in &slashes {
                                if slash.epoch >= *start_epoch
                                    && slash.epoch <= *end_epoch
                                {
                                    let raw_delta: u64 = delta.into();
                                    let current_slashed = token::Amount::from(
                                        decimal_mult_u64(slash.rate, raw_delta),
                                    );
                                    delta -= current_slashed;
                                }
                            }
                            let delta = token::Change::from(delta);
                            total_delta -= delta;
                        }
                    }
                }
                let unbond_entry =
                    unbond_delta.entry(id.validator).or_default();
                *unbond_entry += total_delta;
            }
            (None, None) => {}
        }
    }

    fn validator_set(
        constants: &Constants,
        errors: &mut Vec<Error>,
        validator_set_pre: &mut Option<ValidatorSets>,
        validator_set_post: &mut Option<ValidatorSets>,
        data: Data<ValidatorSets>,
    ) {
        match (data.pre, data.post) {
            (Some(pre), Some(post)) => {
                if post.last_update() != constants.current_epoch {
                    errors.push(Error::InvalidLastUpdate)
                }
                *validator_set_pre = Some(pre);
                *validator_set_post = Some(post);
            }
            _ => errors.push(Error::MissingValidatorSet),
        }
    }

    fn total_deltas(
        constants: &Constants,
        errors: &mut Vec<Error>,
        total_delta_by_epoch: &mut HashMap<Epoch, token::Change>,
        data: Data<TotalDeltas>,
    ) {
        match (data.pre, data.post) {
            (Some(pre), Some(post)) => {
                if post.last_update() != constants.current_epoch {
                    errors.push(Error::InvalidLastUpdate)
                }
                // Iter from the first epoch to the last epoch of `post`
                for epoch in Epoch::iter_range(
                    post.last_update(),
                    constants.unbonding_offset + 1,
                ) {
                    // Find the delta in `pre`
                    let delta_pre = (if epoch == post.last_update() {
                        // On the first epoch, we have to get the
                        // sum of all deltas at and before that
                        // epoch as the `pre` could have been set in
                        // an older epoch
                        pre.get(epoch)
                    } else {
                        pre.get_delta_at_epoch(epoch).copied()
                    })
                    .unwrap_or_default();
                    // Find the delta in `post`
                    let delta_post = post
                        .get_delta_at_epoch(epoch)
                        .copied()
                        .unwrap_or_default();
                    if delta_pre != delta_post {
                        total_delta_by_epoch
                            .insert(epoch, delta_post - delta_pre);
                    }
                }
            }
            _ => errors.push(Error::MissingTotalVotingPower),
        }
    }

    fn validator_address_raw_hash(
        errors: &mut Vec<Error>,
        new_validators: &mut HashMap<Address, NewValidator>,
        raw_hash: String,
        data: Data<Address>,
    ) {
        match (data.pre, data.post) {
            (None, Some(address)) => {
                let validator = new_validators.entry(address).or_default();
                validator.has_address_raw_hash = Some(raw_hash);
            }
            (pre, post) if pre != post => {
                errors.push(Error::InvalidRawHashUpdate)
            }
            _ => {}
        }
    }
}
