//! Validation of updated PoS data

use std::borrow::Cow;
use std::collections::HashMap;
use std::convert::TryFrom;
use std::fmt::{Debug, Display};
use std::hash::Hash;
use std::marker::PhantomData;
use std::ops::{Add, AddAssign, Neg, Sub, SubAssign};

use borsh::{BorshDeserialize, BorshSchema, BorshSerialize};
use derivative::Derivative;
use thiserror::Error;

use crate::btree_set::BTreeSetShims;
use crate::epoched::DynEpochOffset;
use crate::parameters::PosParams;
use crate::types::{
    decimal_mult_i128, decimal_mult_u64, BondId, Bonds, Epoch,
    PublicKeyTmRawHash, Slash, Slashes, Unbonds,
    ValidatorConsensusKeys, ValidatorSets, ValidatorState, ValidatorStates,
    ValidatorTotalDeltas,
    WeightedValidator, TotalDeltas,
};

#[allow(missing_docs)]
#[derive(Error, Debug)]
pub enum Error<Address, TokenChange, PublicKey>
where
    Address: Display
        + Debug
        + Clone
        + PartialEq
        + Eq
        + PartialOrd
        + Ord
        + Hash
        + BorshSerialize
        + BorshSchema
        + BorshDeserialize,
    TokenChange: Debug + Display,
    PublicKey: Debug,
{
    #[error("Unexpectedly missing state value for validator {0}")]
    ValidatorStateIsRequired(Address),
    #[error("Invalid new validator state in epoch {0}")]
    InvalidNewValidatorState(u64),
    #[error("Invalid validator state update in epoch {0}")]
    InvalidValidatorStateUpdate(u64),
    #[error("Missing new validator consensus key in epoch {0}")]
    MissingNewValidatorConsensusKey(u64),
    #[error("Invalid validator consensus key update in epoch {0}")]
    InvalidValidatorConsensusKeyUpdate(u64),
    #[error("Validator staking reward address is required for validator {0}")]
    StakingRewardAddressIsRequired(Address),
    #[error(
        "Staking reward address must be different from the validator's \
         address {0}"
    )]
    StakingRewardAddressEqValidator(Address),
    #[error("Unexpectedly missing total deltas value for validator {0}")]
    MissingValidatorTotalDeltas(Address),
    #[error("The sum of total deltas for validator {0} are negative")]
    NegativeValidatorTotalDeltasSum(Address),
    #[error("Unexpectedly missing balance value")]
    MissingBalance,
    #[error("Last update should be equal to the current epoch")]
    InvalidLastUpdate,
    #[error(
        "Invalid staking token balances. Balance Δ {balance_delta}, bonds Δ \
         {bond_delta}, unbonds Δ {unbond_delta}"
    )]
    InvalidBalances {
        balance_delta: TokenChange,
        bond_delta: TokenChange,
        unbond_delta: TokenChange,
    },
    #[error(
        "Data must be set or updated in the correct epoch. Got epoch {got}, \
         expected one of {expected:?}"
    )]
    EpochedDataWrongEpoch { got: u64, expected: Vec<u64> },
    #[error("Empty bond {0} must be deleted")]
    EmptyBond(BondId<Address>),
    #[error(
        "Bond ID {id} must start at the correct epoch. Got epoch {got}, \
         expected {expected}"
    )]
    InvalidBondStartEpoch {
        id: BondId<Address>,
        got: u64,
        expected: u64,
    },
    #[error(
        "Bond ID {id} must be added at the correct epoch. Got epoch {got}, \
         expected {expected}"
    )]
    InvalidNewBondEpoch {
        id: BondId<Address>,
        got: u64,
        expected: u64,
    },

    #[error(
        "Bond ID {id} must be subtracted at the correct epoch. Got epoch \
         {got}, expected {expected}"
    )]
    InvalidNegDeltaEpoch {
        id: BondId<Address>,
        got: u64,
        expected: u64,
    },

    #[error(
        "Invalid validator {address} sum of total deltas. Total Δ \
         {total_delta}, bonds Δ {bond_delta}"
    )]
    InvalidValidatorTotalDeltasSum {
        address: Address,
        total_delta: TokenChange,
        bond_delta: TokenChange,
    },
    #[error("Unexpectedly missing validator set value")]
    MissingValidatorSet,
    #[error("Validator {0} not found in the validator set in epoch {1}")]
    WeightedValidatorNotFound(WeightedValidator<Address>, u64),
    #[error("Duplicate validator {0} in the validator set in epoch {1}")]
    ValidatorSetDuplicate(WeightedValidator<Address>, u64),
    #[error("Validator {0} has an invalid total deltas value {1}")]
    InvalidValidatorTotalDeltas(Address, i128),
    #[error("There are too many active validators in the validator set")]
    TooManyActiveValidators,
    #[error(
        "An inactive validator {0} has voting power greater than an active \
         validator {1}"
    )]
    ValidatorSetOutOfOrder(
        WeightedValidator<Address>,
        WeightedValidator<Address>,
    ),
    #[error("Invalid active validator {0}")]
    InvalidActiveValidator(WeightedValidator<Address>),
    #[error("Invalid inactive validator {0}")]
    InvalidInactiveValidator(WeightedValidator<Address>),
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
    InvalidNewValidator(Address, NewValidator<PublicKey>),
    #[error("New validator {0} has not been added to the validator set.")]
    NewValidatorMissingInValidatorSet(Address),
    #[error("Validator set has not been updated for new validators.")]
    MissingValidatorSetUpdate,
}

/// An update of PoS data.
#[derive(Clone, Debug)]
pub enum DataUpdate<Address, TokenAmount, TokenChange, PublicKey>
where
    Address: Display
        + Debug
        + Clone
        + PartialEq
        + Eq
        + PartialOrd
        + Ord
        + Hash
        + BorshDeserialize
        + BorshSerialize
        + BorshSchema,
    TokenAmount: Clone
        + Debug
        + Default
        + Eq
        + Sub
        + Add<Output = TokenAmount>
        + AddAssign
        + BorshDeserialize
        + BorshSerialize
        + BorshSchema,
    TokenChange: Display
        + Debug
        + Default
        + Clone
        + Copy
        + Add<Output = TokenChange>
        + Sub<Output = TokenChange>
        + From<TokenAmount>
        + Into<i128>
        + PartialEq
        + Eq
        + BorshDeserialize
        + BorshSerialize
        + BorshSchema,
    PublicKey: Debug + Clone + BorshDeserialize + BorshSerialize + BorshSchema,
{
    /// PoS account's balance update
    Balance(Data<TokenAmount>),
    /// Bond update
    Bond {
        /// Bond ID
        id: BondId<Address>,
        /// Bond prior and posterior state
        data: Data<Bonds<TokenAmount>>,
        /// List of slashes applied to the bond's validator
        slashes: Slashes,
    },
    /// Unbond update
    Unbond {
        /// Unbond ID
        id: BondId<Address>,
        /// Unbond prior and posterior state
        data: Data<Unbonds<TokenAmount>>,
        /// List of slashes applied to the bond's validator
        slashes: Slashes,
    },
    /// A validator update
    Validator {
        /// Validator's address
        address: Address,
        /// Validator's data update
        update: ValidatorUpdate<Address, TokenChange, PublicKey>,
    },
    /// Validator set update
    ValidatorSet(Data<ValidatorSets<Address>>),
    /// Total deltas update
    TotalDeltas(Data<TotalDeltas<TokenChange>>),
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
pub enum ValidatorUpdate<Address, TokenChange, PublicKey>
where
    Address: Clone + Debug,
    TokenChange: Display
        + Debug
        + Default
        + Clone
        + Copy
        + Add<Output = TokenChange>
        + Sub<Output = TokenChange>
        + PartialEq
        + Eq
        + BorshDeserialize
        + BorshSerialize
        + BorshSchema,
    PublicKey: Debug + Clone + BorshDeserialize + BorshSerialize + BorshSchema,
{
    /// Validator's state update
    State(Data<ValidatorStates>),
    /// Consensus key update
    ConsensusKey(Data<ValidatorConsensusKeys<PublicKey>>),
    /// Staking reward address update
    StakingRewardAddress(Data<Address>),
    /// Validator deltas update
    ValidatorDeltas(Data<ValidatorTotalDeltas<TokenChange>>),
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
#[derive(Clone, Debug, Derivative)]
// https://mcarton.github.io/rust-derivative/latest/Default.html#custom-bound
#[derivative(Default(bound = ""))]
pub struct NewValidator<PublicKey> {
    has_state: bool,
    has_consensus_key: Option<PublicKey>,
    has_total_deltas: bool,
    has_bonded_stake: bool,
    has_staking_reward_address: bool,
    has_address_raw_hash: Option<String>,
    bonded_stake: u64,
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
pub fn validate<Address, TokenAmount, TokenChange, PublicKey>(
    params: &PosParams,
    changes: Vec<DataUpdate<Address, TokenAmount, TokenChange, PublicKey>>,
    current_epoch: impl Into<Epoch>,
) -> Vec<Error<Address, TokenChange, PublicKey>>
where
    Address: Display
        + Debug
        + Clone
        + PartialEq
        + Eq
        + PartialOrd
        + Ord
        + Hash
        + BorshDeserialize
        + BorshSerialize
        + BorshSchema,
    TokenAmount: Display
        + Clone
        + Copy
        + Debug
        + Default
        + Eq
        + Add<Output = TokenAmount>
        + Sub<Output = TokenAmount>
        + AddAssign
        + SubAssign
        + Into<u64>
        + From<u64>
        + BorshDeserialize
        + BorshSerialize
        + BorshSchema,
    TokenChange: Display
        + Debug
        + Default
        + Clone
        + Copy
        + Add<Output = TokenChange>
        + Sub<Output = TokenChange>
        + Neg<Output = TokenChange>
        + SubAssign
        + AddAssign
        + From<TokenAmount>
        + Into<i128>
        + From<i128>
        + PartialEq
        + Eq
        + PartialOrd
        + Ord
        + BorshDeserialize
        + BorshSerialize
        + BorshSchema,
    PublicKey: Debug
        + Clone
        + BorshDeserialize
        + BorshSerialize
        + BorshSchema
        + PartialEq
        + PublicKeyTmRawHash,
{
    let current_epoch: Epoch = current_epoch.into();
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
            total_deltas_by_epoch,
            bonded_stake_by_epoch,
            new_validators,
        } = Validate::<Address, TokenAmount, TokenChange, PublicKey>::accumulate_changes(
            changes, params, &constants, &mut errors
        );

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
            errors.push(Error::MissingValidatorTotalDeltas(validator.clone()))
        }
    }
    // Check that all positive unbond deltas also have a total deltas update.
    // Negative unbond delta is from withdrawing, which removes tokens from
    // unbond, but doesn't affect total deltas.
    for (validator, delta) in &unbond_delta {
        if *delta > TokenChange::default()
            && !total_deltas.contains_key(validator)
        {
            errors.push(Error::MissingValidatorTotalDeltas(validator.clone()));
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
                                    if validator.bonded_stake != Into::<u64>::into(*stake_post) {
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
                                                    == Into::<u64>::into(*last_total_stake);
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
                                    if validator.bonded_stake != Into::<u64>::into(*stake_post) {
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
                                                    == Into::<u64>::into(*last_total_stake);
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
                        has_bonded_stake,
                        has_staking_reward_address,
                        has_address_raw_hash,
                        bonded_stake,
                    } = &new_validator;
                    // The new validator must have set all the required fields
                    if !(*has_state
                        && *has_total_deltas
                        && *has_bonded_stake
                        && *has_staking_reward_address)
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
        .fold(TokenChange::default(), |acc, delta| acc + (*delta));
    // Sum the unbond totals
    let unbond_delta = unbond_delta
        .values()
        .into_iter()
        .fold(TokenChange::default(), |acc, delta| acc + (*delta));

    if balance_delta != bond_delta + unbond_delta {
        errors.push(Error::InvalidBalances {
            balance_delta,
            bond_delta,
            unbond_delta,
        })
    }

    errors
}

#[derive(Clone, Debug)]
struct Accumulator<Address, TokenAmount, TokenChange, PublicKey>
where
    Address: Display
        + Debug
        + Clone
        + PartialEq
        + Eq
        + PartialOrd
        + Ord
        + Hash
        + BorshDeserialize
        + BorshSerialize
        + BorshSchema,
    TokenAmount: Display
        + Clone
        + Copy
        + Debug
        + Default
        + Eq
        + Add<Output = TokenAmount>
        + Sub<Output = TokenAmount>
        + AddAssign
        + SubAssign
        + Into<u64>
        + From<u64>
        + BorshDeserialize
        + BorshSerialize
        + BorshSchema,
    TokenChange: Display
        + Debug
        + Default
        + Clone
        + Copy
        + Add<Output = TokenChange>
        + Sub<Output = TokenChange>
        + Neg<Output = TokenChange>
        + SubAssign
        + AddAssign
        + From<TokenAmount>
        + Into<i128>
        + From<i128>
        + PartialEq
        + Eq
        + PartialOrd
        + Ord
        + BorshDeserialize
        + BorshSerialize
        + BorshSchema,
    PublicKey: Debug,
{
    balance_delta: TokenChange,
    /// Changes of validators' bonds
    bond_delta: HashMap<Address, TokenChange>,
    /// Changes of validators' unbonds
    unbond_delta: HashMap<Address, TokenChange>,

    /// Changes of all validator total deltas (up to `unbonding_epoch`)
    total_deltas: HashMap<Address, TokenChange>,
    /// Stake calculated from validator total deltas for each epoch
    /// in which it has changed (the tuple of values are in pre and post state)
    total_stake_by_epoch:
        HashMap<Epoch, HashMap<Address, (TokenAmount, TokenAmount)>>,
    /// Total voting power delta calculated from validators' total deltas
    total_deltas_by_epoch: HashMap<Epoch, TokenChange>,
    bonded_stake_by_epoch: HashMap<Epoch, HashMap<Address, TokenChange>>,
    validator_set_pre: Option<ValidatorSets<Address>>,
    validator_set_post: Option<ValidatorSets<Address>>,
    new_validators: HashMap<Address, NewValidator<PublicKey>>,
}

/// Accumulator of storage changes
impl<Address, TokenAmount, TokenChange, PublicKey> Default
    for Accumulator<Address, TokenAmount, TokenChange, PublicKey>
where
    Address: Display
        + Debug
        + Clone
        + PartialEq
        + Eq
        + PartialOrd
        + Ord
        + Hash
        + BorshDeserialize
        + BorshSerialize
        + BorshSchema,
    TokenAmount: Display
        + Clone
        + Copy
        + Debug
        + Default
        + Eq
        + Add<Output = TokenAmount>
        + Sub<Output = TokenAmount>
        + AddAssign
        + SubAssign
        + Into<u64>
        + From<u64>
        + BorshDeserialize
        + BorshSerialize
        + BorshSchema,
    TokenChange: Display
        + Debug
        + Default
        + Clone
        + Copy
        + Add<Output = TokenChange>
        + Sub<Output = TokenChange>
        + Neg<Output = TokenChange>
        + SubAssign
        + AddAssign
        + From<TokenAmount>
        + Into<i128>
        + From<i128>
        + PartialEq
        + Eq
        + PartialOrd
        + Ord
        + BorshDeserialize
        + BorshSerialize
        + BorshSchema,
    PublicKey: Debug,
{
    fn default() -> Self {
        Self {
            balance_delta: Default::default(),
            bond_delta: Default::default(),
            unbond_delta: Default::default(),
            total_deltas: Default::default(),
            total_stake_by_epoch: Default::default(),
            total_deltas_by_epoch: Default::default(),
            bonded_stake_by_epoch: Default::default(),
            validator_set_pre: Default::default(),
            validator_set_post: Default::default(),
            new_validators: Default::default(),
        }
    }
}

/// An empty local type to re-use trait bounds for the functions associated with
/// `Validate` in the `impl` below
struct Validate<Address, TokenAmount, TokenChange, PublicKey> {
    address: PhantomData<Address>,
    token_amount: PhantomData<TokenAmount>,
    token_change: PhantomData<TokenChange>,
    public_key: PhantomData<PublicKey>,
}

impl<Address, TokenAmount, TokenChange, PublicKey>
    Validate<Address, TokenAmount, TokenChange, PublicKey>
where
    Address: Display
        + Debug
        + Clone
        + PartialEq
        + Eq
        + PartialOrd
        + Ord
        + Hash
        + BorshDeserialize
        + BorshSerialize
        + BorshSchema,
    TokenAmount: Display
        + Clone
        + Copy
        + Debug
        + Default
        + Eq
        + Add<Output = TokenAmount>
        + Sub<Output = TokenAmount>
        + AddAssign
        + SubAssign
        + Into<u64>
        + From<u64>
        + BorshDeserialize
        + BorshSerialize
        + BorshSchema,
    TokenChange: Display
        + Debug
        + Default
        + Clone
        + Copy
        + Add<Output = TokenChange>
        + Sub<Output = TokenChange>
        + Neg<Output = TokenChange>
        + SubAssign
        + AddAssign
        + From<TokenAmount>
        + Into<i128>
        + From<i128>
        + PartialEq
        + Eq
        + PartialOrd
        + Ord
        + BorshDeserialize
        + BorshSerialize
        + BorshSchema,
    PublicKey: Debug
        + Clone
        + BorshDeserialize
        + BorshSerialize
        + BorshSchema
        + PartialEq,
{
    fn accumulate_changes(
        changes: Vec<DataUpdate<Address, TokenAmount, TokenChange, PublicKey>>,
        params: &PosParams,
        constants: &Constants,
        errors: &mut Vec<Error<Address, TokenChange, PublicKey>>,
    ) -> Accumulator<Address, TokenAmount, TokenChange, PublicKey> {
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
            bonded_stake_by_epoch,
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
                    StakingRewardAddress(data) => {
                        Self::validator_staking_reward_address(
                            errors,
                            new_validators,
                            address,
                            data,
                        )
                    }
                    ValidatorDeltas(data) => Self::validator_total_deltas(
                        constants,
                        errors,
                        total_deltas,
                        total_stake_by_epoch,
                        new_validators,
                        address,
                        data,
                    ),
 
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
        errors: &mut Vec<Error<Address, TokenChange, PublicKey>>,
        new_validators: &mut HashMap<Address, NewValidator<PublicKey>>,
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
        errors: &mut Vec<Error<Address, TokenChange, PublicKey>>,
        new_validators: &mut HashMap<Address, NewValidator<PublicKey>>,
        address: Address,
        data: Data<ValidatorConsensusKeys<PublicKey>>,
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
                errors.push(Error::ValidatorStateIsRequired(address))
            }
            (None, None) => {}
        }
    }

    fn validator_staking_reward_address(
        errors: &mut Vec<Error<Address, TokenChange, PublicKey>>,
        new_validators: &mut HashMap<Address, NewValidator<PublicKey>>,
        address: Address,
        data: Data<Address>,
    ) {
        match (data.pre, data.post) {
            (Some(_), Some(post)) => {
                if post == address {
                    errors
                        .push(Error::StakingRewardAddressEqValidator(address));
                }
            }
            (None, Some(post)) => {
                if post == address {
                    errors.push(Error::StakingRewardAddressEqValidator(
                        address.clone(),
                    ));
                }
                let validator = new_validators.entry(address).or_default();
                validator.has_staking_reward_address = true;
            }
            _ => errors.push(Error::StakingRewardAddressIsRequired(address)),
        }
    }

    fn validator_total_deltas(
        constants: &Constants,
        errors: &mut Vec<Error<Address, TokenChange, PublicKey>>,
        total_deltas: &mut HashMap<Address, TokenChange>,
        total_stake_by_epoch: &mut HashMap<
            Epoch,
            HashMap<Address, (TokenAmount, TokenAmount)>,
        >,
        new_validators: &mut HashMap<Address, NewValidator<PublicKey>>,
        address: Address,
        data: Data<ValidatorTotalDeltas<TokenChange>>,
    ) {
        match (data.pre, data.post) {
            (Some(pre), Some(post)) => {
                if post.last_update() != constants.current_epoch {
                    errors.push(Error::InvalidLastUpdate)
                }
                // Changes of all total deltas (up to `unbonding_epoch`)
                let mut deltas = TokenChange::default();
                // Sum of pre total deltas
                let mut pre_deltas_sum = TokenChange::default();
                // Sum of post total deltas
                let mut post_deltas_sum = TokenChange::default();
                // Iter from the first epoch to the last epoch of `post`
                for epoch in Epoch::iter_range(
                    constants.current_epoch,
                    constants.unbonding_offset + 1,
                ) {
                    // Changes of all total deltas (up to
                    // `unbonding_epoch`)
                    let mut delta = TokenChange::default();
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
                                let stake_pre = TokenAmount::from(stake_pre);
                                let stake_post = TokenAmount::from(stake_post);
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
                    if delta > TokenChange::default()
                        && epoch != constants.pipeline_epoch
                    {
                        errors.push(Error::EpochedDataWrongEpoch {
                            got: epoch.into(),
                            expected: vec![constants.pipeline_epoch.into()],
                        })
                    }
                    if delta < TokenChange::default()
                        && epoch != constants.unbonding_epoch
                    {
                        errors.push(Error::EpochedDataWrongEpoch {
                            got: epoch.into(),
                            expected: vec![constants.unbonding_epoch.into()],
                        })
                    }
                }
                if post_deltas_sum < TokenChange::default() {
                    errors.push(Error::NegativeValidatorTotalDeltasSum(
                        address.clone(),
                    ))
                }
                if deltas != TokenChange::default() {
                    let deltas_entry = total_deltas.entry(address).or_default();
                    *deltas_entry += deltas;
                }
            }
            (None, Some(post)) => {
                if post.last_update() != constants.current_epoch {
                    errors.push(Error::InvalidLastUpdate)
                }
                // Changes of all total deltas (up to `unbonding_epoch`)
                let mut deltas = TokenChange::default();
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
                                let stake = TokenAmount::from(stake);
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
                if deltas < TokenChange::default() {
                    errors.push(Error::NegativeValidatorTotalDeltasSum(
                        address.clone(),
                    ))
                }
                if deltas != TokenChange::default() {
                    let deltas_entry =
                        total_deltas.entry(address.clone()).or_default();
                    *deltas_entry += deltas;
                }
                let validator = new_validators.entry(address).or_default();
                validator.has_total_deltas = true;
            }
            (Some(_), None) => {
                errors.push(Error::MissingValidatorTotalDeltas(address))
            }
            (None, None) => {}
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn validator_voting_power(
        params: &PosParams,
        constants: &Constants,
        errors: &mut Vec<Error<Address, TokenChange, PublicKey>>,
        bonded_tokens_by_epoch: &mut HashMap<
            Epoch,
            HashMap<Address, TokenAmount>,
        >,
        expected_total_delta_by_epoch: &mut HashMap<
            Epoch,
            TokenChange,
        >,
        new_validators: &mut HashMap<Address, NewValidator<PublicKey>>,
        address: Address,
        data: Data<ValidatorTotalDeltas<TokenChange>>,
    ) {
        match (&data.pre, data.post) {
            (Some(_), Some(post)) | (None, Some(post)) => {
                if post.last_update() != constants.current_epoch {
                    errors.push(Error::InvalidLastUpdate)
                }
                let mut token_change = TokenChange::default();
                // Iter from the current epoch to the last epoch of
                // `post`
                for epoch in Epoch::iter_range(
                    constants.current_epoch,
                    constants.unbonding_offset + 1,
                ) {
                    if let Some(delta_post) = post.get_delta_at_epoch(epoch) {
                        token_change += *delta_post;

                        // If the delta is not the same as in pre-state,
                        // accumulate the expected total voting power
                        // change
                        let delta_pre = data
                            .pre
                            .as_ref()
                            .and_then(|data| {
                                if epoch == constants.current_epoch {
                                    // On the first epoch, we have to
                                    // get the sum of all deltas at and
                                    // before that epoch as the `pre`
                                    // could have been set in an older
                                    // epoch
                                    data.get(epoch)
                                } else {
                                    data.get_delta_at_epoch(epoch).copied()
                                }
                            })
                            .unwrap_or_default();
                        if delta_pre != *delta_post {
                            let current_delta =
                                expected_total_delta_by_epoch
                                    .entry(epoch)
                                    .or_insert_with(Default::default);
                            *current_delta += *delta_post - delta_pre;
                        }

                        let vp: i128 = token_change.into();
                        match u64::try_from(vp) {
                            Ok(vp) => {
                                bonded_tokens_by_epoch
                                    .entry(epoch)
                                    .or_insert_with(HashMap::default)
                                    .insert(address.clone(), TokenAmount::from(vp));
                            }
                            Err(_) => {
                                // TODO: may need better error handling here
                                errors.push(Error::InvalidValidatorVotingPower(
                                    address.clone(),
                                    i64::try_from(vp).unwrap(),
                                ))
                            }
                        }
                    }
                }
                if data.pre.is_none() {
                    let validator = new_validators.entry(address).or_default();
                    validator.has_bonded_stake = true;
                    let stake: i128 = post
                        .get_at_offset(
                            constants.current_epoch,
                            DynEpochOffset::PipelineLen,
                            params,
                        )
                        .unwrap_or_default()
                        .into();
                    validator.bonded_stake = u64::try_from(stake).unwrap_or_default();
                }
            }
            (Some(_), None) => {
                errors.push(Error::MissingValidatorVotingPower(address))
            }
            (None, None) => {}
        }
    }

    fn balance(
        errors: &mut Vec<Error<Address, TokenChange, PublicKey>>,
        balance_delta: &mut TokenChange,
        data: Data<TokenAmount>,
    ) {
        match (data.pre, data.post) {
            (None, Some(post)) => *balance_delta += TokenChange::from(post),
            (Some(pre), Some(post)) => {
                *balance_delta +=
                    TokenChange::from(post) - TokenChange::from(pre);
            }
            (Some(_), None) => errors.push(Error::MissingBalance),
            (None, None) => {}
        }
    }

    fn bond(
        constants: &Constants,
        errors: &mut Vec<Error<Address, TokenChange, PublicKey>>,
        bond_delta: &mut HashMap<Address, TokenChange>,
        id: BondId<Address>,
        data: Data<Bonds<TokenAmount>>,
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
                let mut pre_bonds: HashMap<Epoch, TokenChange> =
                    HashMap::default();
                // We have to slash only the difference between post and
                // pre, not both pre and post to avoid rounding errors
                let mut slashed_deltas: HashMap<Epoch, TokenChange> =
                    HashMap::default();
                let mut neg_deltas: HashMap<Epoch, TokenChange> =
                    Default::default();
                // Iter from the first epoch of `pre` to the last epoch of
                // `post`
                for epoch in Epoch::iter_range(
                    pre.last_update(),
                    pre_offset + constants.unbonding_offset + 1,
                ) {
                    if let Some(bond) = pre.get_delta_at_epoch(epoch) {
                        for (start_epoch, delta) in bond.pos_deltas.iter() {
                            let delta = TokenChange::from(*delta);
                            slashed_deltas.insert(*start_epoch, -delta);
                            pre_bonds.insert(*start_epoch, delta);
                        }
                        let ins_epoch = if epoch <= constants.current_epoch {
                            constants.current_epoch
                        } else {
                            epoch
                        };
                        let entry = neg_deltas.entry(ins_epoch).or_default();
                        *entry -= TokenChange::from(bond.neg_deltas);
                    }
                    if let Some(bond) = post.get_delta_at_epoch(epoch) {
                        for (start_epoch, delta) in bond.pos_deltas.iter() {
                            // An empty bond must be deleted
                            if *delta == TokenAmount::default() {
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
                            let delta = TokenChange::from(*delta);
                            match slashed_deltas.get_mut(start_epoch) {
                                Some(pre_delta) => {
                                    if *pre_delta + delta == 0_i128.into() {
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
                                        != TokenChange::from(bond.neg_deltas)
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
                        *entry += TokenChange::from(bond.neg_deltas);
                    }
                }
                // Check slashes
                for (start_epoch, delta) in slashed_deltas.iter_mut() {
                    for slash in &slashes {
                        if slash.epoch >= *start_epoch {
                            let raw_delta: i128 = (*delta).into();
                            let current_slashed = TokenChange::from(
                                decimal_mult_i128(slash.rate, raw_delta),
                            );
                            *delta -= current_slashed;
                        }
                    }
                }
                let total = slashed_deltas
                    .values()
                    .fold(TokenChange::default(), |acc, delta| acc + *delta)
                    - neg_deltas
                        .values()
                        .fold(TokenChange::default(), |acc, delta| {
                            acc + *delta
                        });

                if total != TokenChange::default() {
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
                let mut total_delta = TokenChange::default();
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
                                    let current_slashed = TokenAmount::from(
                                        decimal_mult_u64(slash.rate, raw_delta),
                                    );
                                    delta -= current_slashed;
                                }
                            }
                            let delta = TokenChange::from(delta);
                            total_delta += delta
                        }
                        total_delta -= TokenChange::from(bond.neg_deltas)
                    }
                }
                // An empty bond must be deleted
                if total_delta == TokenChange::default() {
                    errors.push(Error::EmptyBond(id.clone()))
                }
                let bond_entry = bond_delta.entry(id.validator).or_default();
                *bond_entry += total_delta;
            }
            // Bond may be deleted when all the tokens are unbonded
            (Some(pre), None) => {
                let mut total_delta = TokenChange::default();
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
                                    let current_slashed = TokenAmount::from(
                                        decimal_mult_u64(slash.rate, raw_delta),
                                    );
                                    delta -= current_slashed;
                                }
                            }
                            let delta = TokenChange::from(delta);
                            total_delta -= delta
                        }
                        total_delta += TokenChange::from(bond.neg_deltas)
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
        errors: &mut Vec<Error<Address, TokenChange, PublicKey>>,
        unbond_delta: &mut HashMap<Address, TokenChange>,
        id: BondId<Address>,
        data: Data<Unbonds<TokenAmount>>,
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
                let mut slashed_deltas: HashMap<(Epoch, Epoch), TokenChange> =
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
                            let delta = TokenChange::from(*delta);
                            slashed_deltas
                                .insert((*start_epoch, *end_epoch), -delta);
                        }
                    }
                    if let Some(unbond) = post.get_delta_at_epoch(epoch) {
                        for ((start_epoch, end_epoch), delta) in
                            unbond.deltas.iter()
                        {
                            let delta = TokenChange::from(*delta);
                            let key = (*start_epoch, *end_epoch);
                            match slashed_deltas.get_mut(&key) {
                                Some(pre_delta) => {
                                    if *pre_delta + delta == 0_i128.into() {
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
                            let raw_delta: i128 = (*delta).into();
                            let current_slashed = TokenChange::from(
                                decimal_mult_i128(slash.rate, raw_delta),
                            );
                            *delta -= current_slashed;
                        }
                    }
                }
                let total = slashed_deltas
                    .values()
                    .fold(TokenChange::default(), |acc, delta| acc + *delta);
                if total != TokenChange::default() {
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
                let mut total_delta = TokenChange::default();
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
                                    let current_slashed = TokenAmount::from(
                                        decimal_mult_u64(slash.rate, raw_delta),
                                    );
                                    delta -= current_slashed;
                                }
                            }
                            let delta = TokenChange::from(delta);
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
                let mut total_delta = TokenChange::default();
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
                                    let current_slashed = TokenAmount::from(
                                        decimal_mult_u64(slash.rate, raw_delta),
                                    );
                                    delta -= current_slashed;
                                }
                            }
                            let delta = TokenChange::from(delta);
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
        errors: &mut Vec<Error<Address, TokenChange, PublicKey>>,
        validator_set_pre: &mut Option<ValidatorSets<Address>>,
        validator_set_post: &mut Option<ValidatorSets<Address>>,
        data: Data<ValidatorSets<Address>>,
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
        errors: &mut Vec<Error<Address, TokenChange, PublicKey>>,
        total_delta_by_epoch: &mut HashMap<
            Epoch,
            TokenChange,
        >,
        data: Data<TotalDeltas<TokenChange>>,
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
        errors: &mut Vec<Error<Address, TokenChange, PublicKey>>,
        new_validators: &mut HashMap<Address, NewValidator<PublicKey>>,
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
