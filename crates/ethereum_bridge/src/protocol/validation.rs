//! Validation logic for Ethereum bridge protocol actions.

pub mod bridge_pool_roots;
pub mod ethereum_events;
pub mod validator_set_update;

use thiserror::Error;

/// The error yielded from validating faulty vote extensions.
#[derive(Error, Debug)]
pub enum VoteExtensionError {
    #[error(
        "A validator set update proof is already available in storage for the \
         given epoch"
    )]
    ValsetUpdProofAvailable,
    #[error("The nonce in the Ethereum event is invalid")]
    InvalidEthEventNonce,
    #[error("The vote extension was issued for an unexpected block height")]
    UnexpectedBlockHeight,
    #[error("The vote extension was issued for an unexpected epoch")]
    UnexpectedEpoch,
    #[error(
        "The vote extension contains duplicate or non-sorted Ethereum events"
    )]
    HaveDupesOrNonSorted,
    #[error(
        "The public key of the vote extension's associated validator could \
         not be found in storage"
    )]
    PubKeyNotInStorage,
    #[error("The vote extension's signature is invalid")]
    VerifySigFailed,
    #[error(
        "Validator is missing from an expected field in the vote extension"
    )]
    ValidatorMissingFromExtension,
    #[error(
        "Vote extension provides a superset of the available validators in \
         storage"
    )]
    ExtraValidatorsInExtension,
    #[error(
        "Found value for a field in the vote extension diverging from the \
         equivalent field in storage"
    )]
    DivergesFromStorage,
    #[error("The signature of the Bridge pool root is invalid")]
    InvalidBPRootSig,
    #[error(
        "Received a vote extension for the Ethereum bridge which is currently \
         not active"
    )]
    EthereumBridgeInactive,
}
