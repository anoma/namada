//! Proof of Stake data types

use core::fmt::Debug;
use std::collections::{BTreeSet, HashMap, VecDeque};
use std::convert::TryFrom;
use std::fmt::Display;
use std::hash::Hash;
use std::ops::Add;

use borsh::{BorshDeserialize, BorshSchema, BorshSerialize};
use namada_core::types::address::Address;
use namada_core::types::key::common;
use namada_core::types::storage::Epoch;
use namada_core::types::token;
use rust_decimal::prelude::{Decimal, ToPrimitive};

use crate::epoched::{
    Epoched, EpochedDelta, OffsetPipelineLen, OffsetUnbondingLen,
};
use crate::parameters::PosParams;

/// Epoched validator's consensus key.
pub type ValidatorConsensusKeys = Epoched<common::PublicKey, OffsetPipelineLen>;
/// Epoched validator's state.
pub type ValidatorStates = Epoched<ValidatorState, OffsetPipelineLen>;
/// Epoched validator's total deltas.
pub type ValidatorDeltas = EpochedDelta<token::Change, OffsetUnbondingLen>;

/// Epoched bond.
pub type Bonds = EpochedDelta<Bond, OffsetUnbondingLen>;
/// Epoched unbond.
pub type Unbonds = EpochedDelta<Unbond, OffsetUnbondingLen>;
/// Epoched validator set.
pub type ValidatorSets = Epoched<ValidatorSet, OffsetUnbondingLen>;
/// Epoched total deltas.
pub type TotalDeltas = EpochedDelta<token::Change, OffsetUnbondingLen>;
/// Epoched validator commission rate
pub type CommissionRates = Epoched<Decimal, OffsetPipelineLen>;

/// A genesis validator definition.
#[derive(
    Debug,
    Clone,
    BorshSerialize,
    BorshSchema,
    BorshDeserialize,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
)]
pub struct GenesisValidator {
    /// Validator's address
    pub address: Address,
    /// Staked tokens are put into a self-bond
    pub tokens: token::Amount,
    /// A public key used for signing validator's consensus actions
    pub consensus_key: common::PublicKey,
    /// Commission rate charged on rewards for delegators (bounded inside 0-1)
    pub commission_rate: Decimal,
    /// Maximum change in commission rate permitted per epoch
    pub max_commission_rate_change: Decimal,
}

/// An update of the active and inactive validator set.
#[derive(Debug, Clone)]
pub enum ValidatorSetUpdate {
    /// A validator is active
    Active(ActiveValidator),
    /// A validator who was active in the last update and is now inactive
    Deactivated(common::PublicKey),
}

/// Active validator's consensus key and its bonded stake.
#[derive(Debug, Clone)]
pub struct ActiveValidator {
    /// A public key used for signing validator's consensus actions
    pub consensus_key: common::PublicKey,
    /// Total bonded stake of the validator
    pub bonded_stake: u64,
}

/// ID of a bond and/or an unbond.
#[derive(
    Debug,
    Clone,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
    BorshDeserialize,
    BorshSerialize,
    BorshSchema,
)]
pub struct BondId {
    /// (Un)bond's source address is the owner of the bonded tokens.
    pub source: Address,
    /// (Un)bond's validator address.
    pub validator: Address,
}

/// Validator's address with its voting power.
#[derive(
    Debug,
    Clone,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    BorshDeserialize,
    BorshSerialize,
    BorshSchema,
)]
pub struct WeightedValidator {
    /// The `total_stake` field must be on top, because lexicographic ordering
    /// is based on the top-to-bottom declaration order and in the
    /// `ValidatorSet` the `WeightedValidator`s these need to be sorted by
    /// the `total_stake`.
    pub bonded_stake: u64,
    /// Validator's address
    pub address: Address,
}

impl Display for WeightedValidator {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{} with bonded stake {}",
            self.address, self.bonded_stake
        )
    }
}

/// Active and inactive validator sets.
#[derive(
    Debug,
    Clone,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    BorshDeserialize,
    BorshSerialize,
    BorshSchema,
)]
pub struct ValidatorSet {
    /// Active validator set with maximum size equal to `max_validator_slots`
    /// in [`PosParams`].
    pub active: BTreeSet<WeightedValidator>,
    /// All the other validators that are not active
    pub inactive: BTreeSet<WeightedValidator>,
}

/// Validator's state.
#[derive(
    Debug,
    Clone,
    Copy,
    BorshDeserialize,
    BorshSerialize,
    BorshSchema,
    PartialEq,
    Eq,
)]
pub enum ValidatorState {
    /// Inactive validator may not participate in the consensus.
    Inactive,
    /// A `Pending` validator will become `Candidate` in a future epoch.
    Pending,
    /// A `Candidate` validator may participate in the consensus. It is either
    /// in the active or inactive validator set.
    Candidate,
    // TODO consider adding `Jailed`
}

/// A bond is either a validator's self-bond or a delegation from a regular
/// account to a validator.
#[derive(
    Debug, Clone, Default, BorshDeserialize, BorshSerialize, BorshSchema,
)]
pub struct Bond {
    /// Bonded positive deltas. A key is the epoch set for the bond. This is
    /// used in unbonding, where it's needed for slash epoch range check.
    ///
    /// TODO: For Bonds, there's unnecessary redundancy with this hash map.
    /// We only need to keep the start `Epoch` for the Epoched head element
    /// (i.e. the current epoch data), the rest of the array can be calculated
    /// from the offset from the head
    pub pos_deltas: HashMap<Epoch, token::Amount>,
    /// Unbonded negative deltas. The values are recorded as positive, but
    /// should be subtracted when we're finding the total for some given
    /// epoch.
    pub neg_deltas: token::Amount,
}

/// An unbond contains unbonded tokens from a validator's self-bond or a
/// delegation from a regular account to a validator.
#[derive(
    Debug, Clone, Default, BorshDeserialize, BorshSerialize, BorshSchema,
)]
pub struct Unbond {
    /// A key is a pair of the epoch of the bond from which a unbond was
    /// created the epoch of unbonding. This is needed for slash epoch range
    /// check.
    pub deltas: HashMap<(Epoch, Epoch), token::Amount>,
}

/// A slash applied to validator, to punish byzantine behavior by removing
/// their staked tokens at and before the epoch of the slash.
#[derive(Debug, Clone, BorshDeserialize, BorshSerialize, BorshSchema)]
pub struct Slash {
    /// Epoch at which the slashable event occurred.
    pub epoch: Epoch,
    /// Block height at which the slashable event occurred.
    pub block_height: u64,
    /// A type of slashsable event.
    pub r#type: SlashType,
    /// A rate is the portion of staked tokens that are slashed.
    pub rate: Decimal,
}

/// Slashes applied to validator, to punish byzantine behavior by removing
/// their staked tokens at and before the epoch of the slash.
pub type Slashes = Vec<Slash>;

/// A type of slashsable event.
#[derive(Debug, Clone, BorshDeserialize, BorshSerialize, BorshSchema)]
pub enum SlashType {
    /// Duplicate block vote.
    DuplicateVote,
    /// Light client attack.
    LightClientAttack,
}

/// VoteInfo inspired from tendermint
#[derive(Debug, Clone, BorshDeserialize, BorshSerialize)]
pub struct VoteInfo {
    /// the first 20 bytes of the validator public key hash (SHA-256) taken
    /// from tendermint
    pub validator_address: Vec<u8>,
    /// validator voting power
    pub validator_vp: u64,
    /// whether the validator signature was included in the last block
    /// was the validator signature was included in the last block?
    pub signed_last_block: bool,
}

/// Validator voting record
#[derive(Debug, Default, Clone, BorshDeserialize, BorshSerialize)]
pub struct ValidatorVotingRecord {
    /// The vector of votes
    pub votes: VecDeque<bool>,
    /// The height to remove the data, if so
    pub epoch_to_clear: Option<u64>,
}

impl Display for BondId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{{source: {}, validator: {}}}",
            self.source, self.validator
        )
    }
}

impl Bond {
    /// Find the sum of all the bonds amounts.
    pub fn sum(&self) -> token::Amount {
        let pos_deltas_sum: token::Amount = self
            .pos_deltas
            .iter()
            .fold(Default::default(), |acc, (_epoch, amount)| acc + *amount);
        pos_deltas_sum - self.neg_deltas
    }
}

impl Add for Bond {
    type Output = Self;

    fn add(mut self, rhs: Self) -> Self::Output {
        // This is almost the same as `self.pos_deltas.extend(rhs.pos_deltas);`,
        // except that we add values where a key is present on both
        // sides.
        let iter = rhs.pos_deltas.into_iter();
        let reserve = if self.pos_deltas.is_empty() {
            iter.size_hint().0
        } else {
            (iter.size_hint().0 + 1) / 2
        };
        self.pos_deltas.reserve(reserve);
        iter.for_each(|(k, v)| {
            // Add or insert
            match self.pos_deltas.get_mut(&k) {
                Some(value) => *value += v,
                None => {
                    self.pos_deltas.insert(k, v);
                }
            }
        });
        self.neg_deltas += rhs.neg_deltas;
        self
    }
}

impl Unbond {
    /// Find the sum of all the unbonds amounts.
    pub fn sum(&self) -> token::Amount {
        self.deltas
            .iter()
            .fold(Default::default(), |acc, (_epoch, amount)| acc + *amount)
    }
}

impl Add for Unbond {
    type Output = Self;

    fn add(mut self, rhs: Self) -> Self::Output {
        // This is almost the same as `self.deltas.extend(rhs.deltas);`, except
        // that we add values where a key is present on both sides.
        let iter = rhs.deltas.into_iter();
        let reserve = if self.deltas.is_empty() {
            iter.size_hint().0
        } else {
            (iter.size_hint().0 + 1) / 2
        };
        self.deltas.reserve(reserve);
        iter.for_each(|(k, v)| {
            // Add or insert
            match self.deltas.get_mut(&k) {
                Some(value) => *value += v,
                None => {
                    self.deltas.insert(k, v);
                }
            }
        });
        self
    }
}

impl SlashType {
    /// Get the slash rate applicable to the given slash type from the PoS
    /// parameters.
    pub fn get_slash_rate(&self, params: &PosParams) -> Decimal {
        match self {
            SlashType::DuplicateVote => params.duplicate_vote_min_slash_rate,
            SlashType::LightClientAttack => {
                params.light_client_attack_min_slash_rate
            }
        }
    }
}

impl Display for SlashType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SlashType::DuplicateVote => write!(f, "Duplicate vote"),
            SlashType::LightClientAttack => write!(f, "Light client attack"),
        }
    }
}

/// Multiply a value of type Decimal with one of type u64 and then return the
/// truncated u64
pub fn decimal_mult_u64(dec: Decimal, int: u64) -> u64 {
    let prod = dec * Decimal::from(int);
    // truncate the number to the floor
    prod.to_u64().expect("Product is out of bounds")
}

/// Multiply a value of type Decimal with one of type i128 and then return the
/// truncated i128
pub fn decimal_mult_i128(dec: Decimal, int: i128) -> i128 {
    let prod = dec * Decimal::from(int);
    // truncate the number to the floor
    prod.to_i128().expect("Product is out of bounds")
}

/// Calculate voting power in the tendermint context (which is stored as i64)
/// from the number of tokens
pub fn into_tm_voting_power(
    votes_per_token: Decimal,
    tokens: impl Into<u64>,
) -> i64 {
    let prod = decimal_mult_u64(votes_per_token, tokens.into());
    i64::try_from(prod).expect("Invalid voting power")
}

#[cfg(test)]
pub mod tests {

    use std::ops::Range;

    use proptest::prelude::*;

    use super::*;

    /// Generate arbitrary epoch in given range
    pub fn arb_epoch(range: Range<u64>) -> impl Strategy<Value = Epoch> {
        range.prop_map(Epoch)
    }
}
