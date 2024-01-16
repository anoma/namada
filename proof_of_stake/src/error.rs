/// Custom error types
use std::num::TryFromIntError;

use namada_core::types::address::Address;
use namada_core::types::dec::Dec;
use namada_core::types::storage::Epoch;
use thiserror::Error;

use crate::rewards;
use crate::types::{BondId, ValidatorState};

#[allow(missing_docs)]
#[derive(Error, Debug)]
pub enum GenesisError {
    #[error("Voting power overflow: {0}")]
    VotingPowerOverflow(TryFromIntError),
}

#[allow(missing_docs)]
#[derive(Error, Debug)]
pub enum InflationError {
    #[error("Error in calculating rewards: {0}")]
    Rewards(rewards::RewardsError),
    #[error("Expected validator {0} to be in consensus set but got: {1:?}")]
    ExpectedValidatorInConsensus(Address, Option<ValidatorState>),
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
    UnbondAmountGreaterThanBond(String, String),
    #[error("No bonds found for the validator {0}")]
    ValidatorHasNoBonds(Address),
    #[error("Voting power not found for the validator {0}")]
    ValidatorHasNoVotingPower(Address),
    #[error("Voting power overflow: {0}")]
    VotingPowerOverflow(TryFromIntError),
    #[error("Trying to unbond from a frozen validator: {0}")]
    ValidatorIsFrozen(Address),
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
    NegativeRate(Dec, Address),
    #[error(
        "Unexpected commission rate {0} larger than 1.0 for validator {1}"
    )]
    LargerThanOne(Dec, Address),
    #[error("Rate change of {0} is too large for validator {1}")]
    RateChangeTooLarge(Dec, Address),
    #[error(
        "There is no maximum rate change written in storage for validator {0}"
    )]
    NoMaxSetInStorage(Address),
    #[error("Cannot write to storage for validator {0}")]
    CannotWrite(Address),
    #[error("Cannot read storage for validator {0}")]
    CannotRead(Address),
}

#[allow(missing_docs)]
#[derive(Error, Debug)]
pub enum UnjailValidatorError {
    #[error("The given address {0} is not a validator address")]
    NotAValidator(Address),
    #[error("The given address {0} is not jailed in epoch {1}")]
    NotJailed(Address, Epoch),
    #[error(
        "The given address {0} is not eligible for unnjailing until epoch \
         {1}: current epoch is {2}"
    )]
    NotEligible(Address, Epoch, Epoch),
}

#[allow(missing_docs)]
#[derive(Error, Debug)]
pub enum RedelegationError {
    #[error("The redelegation is chained")]
    IsChainedRedelegation,
    #[error("The source and destination validator must be different")]
    RedelegationSrcEqDest,
    #[error("The delegator must not be a validator")]
    DelegatorIsValidator,
    #[error("The address {0} must be a validator")]
    NotAValidator(Address),
}

#[allow(missing_docs)]
#[derive(Error, Debug)]
pub enum DeactivationError {
    #[error("The validator {0} is already inactive at the pipeline epoch {1}")]
    AlreadyInactive(Address, Epoch),
    #[error("The given address {0} is not a validator address")]
    NotAValidator(Address),
    #[error(
        "The given address {0} is jailed at the pipeline epoch {1} and is \
         forbidden from being deactivated"
    )]
    ValidatorIsJailed(Address, Epoch),
}

#[allow(missing_docs)]
#[derive(Error, Debug)]
pub enum ReactivationError {
    #[error("The validator {0} is not inactive at the epoch {1}")]
    NotInactive(Address, Epoch),
    #[error("No state found for validator {0} in epoch {1}")]
    NoStateFound(Address, Epoch),
}

#[allow(missing_docs)]
#[derive(Error, Debug)]
pub enum MetadataError {
    #[error("The validator email cannot be removed")]
    CannotRemoveEmail,
}

#[allow(missing_docs)]
#[derive(Error, Debug)]
pub enum ConsensusKeyChangeError {
    #[error("The consensus key is required to be an Ed25519 key")]
    MustBeEd25519,
}

impl From<BecomeValidatorError> for namada_storage::Error {
    fn from(err: BecomeValidatorError) -> Self {
        Self::new(err)
    }
}

impl From<BondError> for namada_storage::Error {
    fn from(err: BondError) -> Self {
        Self::new(err)
    }
}

impl From<UnbondError> for namada_storage::Error {
    fn from(err: UnbondError) -> Self {
        Self::new(err)
    }
}

impl From<WithdrawError> for namada_storage::Error {
    fn from(err: WithdrawError) -> Self {
        Self::new(err)
    }
}

impl From<CommissionRateChangeError> for namada_storage::Error {
    fn from(err: CommissionRateChangeError) -> Self {
        Self::new(err)
    }
}

impl From<InflationError> for namada_storage::Error {
    fn from(err: InflationError) -> Self {
        Self::new(err)
    }
}

impl From<UnjailValidatorError> for namada_storage::Error {
    fn from(err: UnjailValidatorError) -> Self {
        Self::new(err)
    }
}

impl From<RedelegationError> for namada_storage::Error {
    fn from(err: RedelegationError) -> Self {
        Self::new(err)
    }
}

impl From<DeactivationError> for namada_storage::Error {
    fn from(err: DeactivationError) -> Self {
        Self::new(err)
    }
}

impl From<ReactivationError> for namada_storage::Error {
    fn from(err: ReactivationError) -> Self {
        Self::new(err)
    }
}

impl From<MetadataError> for namada_storage::Error {
    fn from(err: MetadataError) -> Self {
        Self::new(err)
    }
}

impl From<ConsensusKeyChangeError> for namada_storage::Error {
    fn from(err: ConsensusKeyChangeError) -> Self {
        Self::new(err)
    }
}
