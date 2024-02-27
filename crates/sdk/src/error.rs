//! Generic Error Type for all of the Shared Crate

use namada_core::address::Address;
use namada_core::dec::Dec;
use namada_core::ethereum_events::EthAddress;
use namada_core::event::EventError;
use namada_core::storage;
use namada_core::storage::Epoch;
use namada_tx::Tx;
use prost::EncodeError;
use tendermint_rpc::Error as RpcError;
use thiserror::Error;

use crate::error::Error::Pinned;

/// The standard Result type that most code ought to return
pub type Result<T> = std::result::Result<T, Error>;

/// General error interface for anything that may go wrong in the shared SDK.
///
/// The general mentality should be that this error type should cover all
/// possible errors that one may face.
#[derive(Error, Debug)]
pub enum Error {
    /// Errors that are caused by trying to retrieve a pinned transaction
    #[error("Error in retrieving pinned balance: {0}")]
    Pinned(#[from] PinnedBalanceError),
    /// Key Retrieval Errors
    #[error("Key Error: {0}")]
    KeyRetrival(#[from] storage::Error),
    /// Transaction Errors
    #[error("{0}")]
    Tx(#[from] TxSubmitError),
    /// Event Errors
    #[error("{0}")]
    Event(#[from] EventError),
    /// Errors That deal with encoding or decoding data
    #[error("{0}")]
    Encode(#[from] EncodingError),
    /// Errors that handle querying from storage
    #[error("Querying error: {0}")]
    Query(#[from] QueryError),
    /// Ethereum bridge related errors
    #[error("{0}")]
    EthereumBridge(#[from] EthereumBridgeError),
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
    /// The queried node is outdated, and is in the process of
    /// synchronizing with the network.
    #[error("Node is still catching up with the network")]
    CatchingUp,
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
pub enum TxSubmitError {
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
    /// Invalid commission rate set
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
    /// Already inactive at pipeline epoch
    #[error(
        "The validator address {0} is inactive at the pipeline epoch {1}."
    )]
    ValidatorInactive(Address, Epoch),
    /// Validator not inactive
    #[error(
        "The validator address {0} is not inactive at epoch {1} and so cannot \
         be reactivated."
    )]
    ValidatorNotInactive(Address, Epoch),
    /// Validator is frozen and ineligible to be unjailed or have bonds
    /// unbonded
    #[error("The validator address {0} is currently frozen.")]
    ValidatorFrozen(Address),
    /// The commission for the steward are not valid
    #[error("Invalid steward commission: {0}.")]
    InvalidStewardCommission(String),
    /// The address is not a valid steward
    #[error("The address {0} is not a valid steward.")]
    InvalidSteward(Address),
    /// Invalid bond pair
    #[error("Invalid bond pair: source {0} cannot bond to validator {1}.")]
    InvalidBondPair(Address, Address),
    /// Rate of epoch change too large for current epoch
    #[error(
        "New rate, {0}, is too large of a change with respect to the \
         predecessor epoch in which the rate will take effect."
    )]
    TooLargeOfChange(Dec),
    /// Error retrieving from storage
    #[error("Error retrieving from storage")]
    Retrieval,
    /// Bond amount is zero
    #[error("The requested bond amount is 0.")]
    BondIsZero,
    /// Unond amount is zero
    #[error("The requested unbond amount is 0.")]
    UnbondIsZero,
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
    UnbondError,
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
    /// The redelegation amount is larger than the remaining bond amount
    #[error(
        "The redelegation amount is larger than the remaining bond amount. \
         Amount to redelegate is {0} and the remaining bond amount is {1}."
    )]
    RedelegationAmountTooLarge(String, String),
    /// The redelegation amount is 0
    #[error("The amount requested to redelegate is 0 tokens")]
    RedelegationIsZero,
    /// The src and dest validators are the same
    #[error("The source and destination validators are the same")]
    RedelegationSrcEqDest,
    /// The redelegation owner is a validator
    #[error("The redelegation owner {0} is a validator")]
    RedelegatorIsValidator(Address),
    /// There is an incoming redelegation that is still subject to possible
    /// slashing
    #[error(
        "An incoming redelegation from delegator {0} to validator {1} is \
         still subject to possible slashing"
    )]
    IncomingRedelIsStillSlashable(Address, Address),
    /// An empty string was provided as a new email
    #[error("An empty string cannot be provided as a new email")]
    InvalidEmail,
    /// The consensus key is not Ed25519
    #[error("The consensus key must be an ed25519 key")]
    ConsensusKeyNotEd25519,
    /// The consensus key is not unique
    #[error("The consensus key has already been registered and is not unique")]
    ConsensusKeyNotUnique,
    /// Other Errors that may show up when using the interface
    #[error("{0}")]
    Other(String),
}

/// Ethereum bridge related errors.
#[derive(Error, Debug, Clone)]
pub enum EthereumBridgeError {
    /// Error invoking smart contract function.
    #[error("Smart contract call failed: {0}")]
    ContractCall(String),
    /// Ethereum RPC error.
    #[error("RPC error: {0}")]
    Rpc(String),
    /// Error reading the signed Bridge pool.
    #[error("Failed to read signed Bridge pool: {0}")]
    ReadSignedBridgePool(String),
    /// Error reading the Bridge pool.
    #[error("Failed to read Bridge pool: {0}")]
    ReadBridgePool(String),
    /// Error querying transfer to Ethereum progress.
    #[error("Failed to query transfer to Ethereum progress: {0}")]
    TransferToEthProgress(String),
    /// Error querying Ethereum voting powers.
    #[error("Failed to query Ethereum voting powers: {0}")]
    QueryVotingPowers(String),
    /// Ethereum node timeout error.
    #[error(
        "Timed out while attempting to communicate with the Ethereum node"
    )]
    NodeTimeout,
    /// Error generating Bridge pool proof.
    #[error("Failed to generate Bridge pool proof: {0}")]
    GenBridgePoolProof(String),
    /// Error retrieving contract address.
    #[error("Failed to retrieve contract address: {0}")]
    RetrieveContract(String),
    /// Error calculating relay cost.
    #[error("Failed to calculate relay cost: {0}")]
    RelayCost(String),
    /// Invalid Bridge pool nonce error.
    #[error("The Bridge pool nonce is invalid")]
    InvalidBpNonce,
    /// Invalid fee token error.
    #[error("An invalid fee token was provided: {0}")]
    InvalidFeeToken(Address),
    /// Not whitelisted error.
    #[error("ERC20 is not whitelisted: {0}")]
    Erc20NotWhitelisted(EthAddress),
    /// Exceeded token caps error.
    #[error("ERC20 token caps exceeded: {0}")]
    Erc20TokenCapsExceeded(EthAddress),
    /// Transfer already in pool error.
    #[error("An identical transfer is already present in the Bridge pool")]
    TransferAlreadyInPool,
}

/// Checks if the given error is an invalid viewing key
pub fn is_pinned_error<T>(err: &Result<T>) -> bool {
    matches!(err, Err(Pinned(PinnedBalanceError::InvalidViewingKey)))
}
