//! Generic Error Type for all of the Shared Crate

use namada_core::proto::Tx;
use namada_core::types::address::Address;
use namada_core::types::dec::Dec;
use namada_core::types::storage;
use namada_core::types::storage::Epoch;
use prost::EncodeError;
use tendermint_rpc::Error as RpcError;
use thiserror::Error;

use crate::sdk::error::Error::Pinned;
use crate::vm::WasmValidationError;

/// The standard Result type that most code ought to return
pub type Result<T> = std::result::Result<T, Error>;

/// General error interface for anything that may go wrong in the shared SDK.
///
/// The general mentality should be that this error type should cover all
/// possible errors that one may face.
#[derive(Clone, Error, Debug)]
pub enum Error {
    /// Errors that are caused by trying to retrieve a pinned transaction
    #[error("Error in retrieving pinned balance: {0}")]
    Pinned(#[from] PinnedBalanceError),
    /// Key Retrival Errors
    #[error("Key Error: {0}")]
    KeyRetrival(#[from] storage::Error),
    /// Transaction Errors
    #[error("{0}")]
    Tx(#[from] TxError),
    /// Event Errors
    #[error("{0}")]
    Event(#[from] EventError),
    /// Errors That deal with encoding or decoding data
    #[error("{0}")]
    Encode(#[from] EncodingError),
    /// Errors that handle querying from storage
    #[error("Querying error: {0}")]
    Query(#[from] QueryError),
    /// Any Other errors that are uncategorized
    #[error("{0}")]
    Other(String),
}

/// Errors that can occur when trying to retrieve pinned transaction
#[derive(PartialEq, Eq, Copy, Clone, Debug, Error)]
pub enum PinnedBalanceError {
    /// No transaction has yet been pinned to the given payment address
    #[error("No transaction has yet been pinned to the given payment address")]
    NoTransactionPinned,
    /// The supplied viewing key does not recognize payments to given address
    #[error(
        "The supplied viewing key does not recognize payments to given address"
    )]
    InvalidViewingKey,
}

/// Errors to do with emitting events.
#[derive(Error, Debug, Clone)]
pub enum EventError {
    /// Error when parsing an event type
    #[error("Invalid event type")]
    InvalidEventType,
    /// Error when parsing attributes from an event JSON.
    #[error("Json missing `attributes` field")]
    MissingAttributes,
    /// Missing key in attributes.
    #[error("Attributes missing key: {0}")]
    MissingKey(String),
    /// Missing value in attributes.
    #[error("Attributes missing value: {0}")]
    MissingValue(String),
}

/// Errors that deal with querying some kind of data
#[derive(Error, Debug, Clone)]
pub enum QueryError {
    /// Error that occurs when no such key exists
    #[error("Unable to find key: {0}")]
    NoSuchKey(String),
    /// Error that corresponds to not receiving any response
    #[error("No response given in the query: {0}")]
    NoResponse(String),
    /// Error that corresponds to a general error
    #[error("Error in the query: {0}")]
    General(String),
    /// Wasm querying failure
    #[error("Wasm code path {0} does not exist on chain")]
    Wasm(String),
}

/// Errors that deal with Decoding, Encoding, or Conversions
#[derive(Error, Debug, Clone)]
pub enum EncodingError {
    /// Error that deals with Serde encoding failures
    #[error("Serede Error: {0}")]
    Serde(String),
    /// Error that occurs when trying to decode a value
    #[error("Error decoding the value: {0}")]
    Decoding(String),
    /// Error that occurs when trying to encode a value
    #[error("Error encoding the value: {0}")]
    Encode(String),
    /// Error that occurs due to a conversion error
    #[error("{0}")]
    Conversion(String),
}

/// Errors to do with transaction events.
#[derive(Error, Debug, Clone)]
pub enum TxError {
    /// Accepted tx timeout
    #[error("Timed out waiting for tx to be accepted")]
    AcceptTimeout,
    /// Applied tx timeout
    #[error("Timed out waiting for tx to be applied")]
    AppliedTimeout,
    /// Expect a dry running transaction
    #[error(
        "Expected a dry-run transaction, received a wrapper transaction \
         instead: {0:?}"
    )]
    ExpectDryRun(Tx),
    /// Expect a wrapped encrypted running transaction
    #[error("Cannot broadcast a dry-run transaction")]
    ExpectWrappedRun(Tx),
    /// Expect a live running transaction
    #[error("Cannot broadcast a dry-run transaction")]
    ExpectLiveRun(Tx),
    /// Error during broadcasting a transaction
    #[error("Encountered error while broadcasting transaction: {0}")]
    TxBroadcast(RpcError),
    /// Invalid comission rate set
    #[error("Invalid new commission rate, received {0}")]
    InvalidCommissionRate(Dec),
    /// Invalid validator address
    #[error("The address {0} doesn't belong to any known validator account.")]
    InvalidValidatorAddress(Address),
    /// Not jailed at pipeline epoch
    #[error(
        "The validator address {0} is not jailed at epoch when it would be \
         restored."
    )]
    ValidatorNotCurrentlyJailed(Address),
    /// Validator still frozen and ineligible to be unjailed
    #[error(
        "The validator address {0} is currently frozen and ineligible to be \
         unjailed."
    )]
    ValidatorFrozenFromUnjailing(Address),
    /// The commission for the steward are not valid
    #[error("Invalid steward commission: {0}.")]
    InvalidStewardCommission(String),
    /// The address is not a valid steward
    #[error("The address {0} is not a valid steward.")]
    InvalidSteward(Address),
    /// Rate of epoch change too large for current epoch
    #[error(
        "New rate, {0}, is too large of a change with respect to the \
         predecessor epoch in which the rate will take effect."
    )]
    TooLargeOfChange(Dec),
    /// Error retrieving from storage
    #[error("Error retrieving from storage")]
    Retrieval,
    /// No unbonded bonds ready to withdraw in the current epoch
    #[error(
        "There are no unbonded bonds ready to withdraw in the current epoch \
         {0}."
    )]
    NoUnbondReady(Epoch),
    /// No unbonded bonds found
    #[error("No unbonded bonds found")]
    NoUnbondFound,
    /// No bonds found
    #[error("No bonds found")]
    NoBondFound,
    /// Lower bond amount than the unbond
    #[error(
        "The total bonds of the source {0} is lower than the amount to be \
         unbonded. Amount to unbond is {1} and the total bonds is {2}."
    )]
    LowerBondThanUnbond(Address, String, String),
    /// Balance is too low
    #[error(
        "The balance of the source {0} of token {1} is lower than the amount \
         to be transferred. Amount to transfer is {2} and the balance is {3}."
    )]
    BalanceTooLow(Address, Address, String, String),
    /// Balance is too low for fee payment
    #[error(
        "The balance of the source {0} of token {1} is lower than the amount \
         required for fees. Amount of the fees is {2} and the balance is {3}."
    )]
    BalanceTooLowForFees(Address, Address, String, String),
    /// Token Address does not exist on chain
    #[error("The token address {0} doesn't exist on chain.")]
    TokenDoesNotExist(Address),
    /// Source address does not exist on chain
    #[error("The address {0} doesn't exist on chain.")]
    LocationDoesNotExist(Address),
    /// Target Address does not exist on chain
    #[error("The source address {0} doesn't exist on chain.")]
    SourceDoesNotExist(Address),
    /// Source Address does not exist on chain
    #[error("The target address {0} doesn't exist on chain.")]
    TargetLocationDoesNotExist(Address),
    /// No Balance found for token
    #[error("No balance found for the source {0} of token {1}")]
    NoBalanceForToken(Address, Address),
    /// Negative balance after transfer
    #[error(
        "The balance of the source {0} is lower than the amount to be \
         transferred. Amount to transfer is {1} {2}"
    )]
    NegativeBalanceAfterTransfer(Box<Address>, String, Box<Address>),
    /// No Balance found for token
    #[error("{0}")]
    MaspError(String),
    /// Error in the fee unshielding transaction
    #[error("Error in fee unshielding: {0}")]
    FeeUnshieldingError(String),
    /// Wasm validation failed
    #[error("Validity predicate code validation failed with {0}")]
    WasmValidationFailure(WasmValidationError),
    /// Encoding transaction failure
    #[error("Encoding tx data, {0}, shouldn't fail")]
    EncodeTxFailure(String),
    /// Like EncodeTxFailure but for the encode error type
    #[error("Encoding tx data, {0}, shouldn't fail")]
    EncodeFailure(EncodeError),
    /// Failed to deserialize the proposal data from json
    #[error("Failed to deserialize the proposal data: {0}")]
    FailedGovernaneProposalDeserialize(String),
    /// The proposal data are invalid
    #[error("Proposal data are invalid: {0}")]
    InvalidProposal(String),
    /// The proposal vote is not valid
    #[error("Proposal vote is invalid")]
    InvalidProposalVote,
    /// The proposal can't be voted
    #[error("Proposal {0} can't be voted")]
    InvalidProposalVotingPeriod(u64),
    /// The proposal can't be found
    #[error("Proposal {0} can't be found")]
    ProposalDoesNotExist(u64),
    /// Updating an VP of an implicit account
    #[error(
        "A validity predicate of an implicit address cannot be directly \
         updated. You can use an established address for this purpose."
    )]
    ImplicitUpdate,
    // This should be removed? or rather refactored as it communicates
    // the same information as the ImplicitUpdate
    /// Updating a VP of an internal implicit address
    #[error(
        "A validity predicate of an internal address cannot be directly \
         updated."
    )]
    ImplicitInternalError,
    /// Unexpected Error
    #[error("Unexpected behavior reading the unbonds data has occurred")]
    UnboundError,
    /// Epoch not in storage
    #[error("Proposal end epoch is not in the storage.")]
    EpochNotInStorage,
    /// Couldn't understand who the fee payer is
    #[error("Either --signing-keys or --gas-payer must be available.")]
    InvalidFeePayer,
    /// Account threshold is not set
    #[error("Account threshold must be set.")]
    MissingAccountThreshold,
    /// Not enough signature
    #[error("Account threshold is {0} but the valid signatures are {1}.")]
    MissingSigningKeys(u8, u8),
    /// Invalid owner account
    #[error("The source account {0} is not valid or doesn't exist.")]
    InvalidAccount(String),
    /// Other Errors that may show up when using the interface
    #[error("{0}")]
    Other(String),
}

/// Checks if the given error is an invalid viewing key
pub fn is_pinned_error<T>(err: &Result<T>) -> bool {
    matches!(err, Err(Pinned(PinnedBalanceError::InvalidViewingKey)))
}
