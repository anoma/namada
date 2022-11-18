//! API for querying the blockchain state.

use std::collections::BTreeSet;

use ferveo_common::TendermintValidator;
use thiserror::Error;

use crate::ledger::parameters::EpochDuration;
use crate::ledger::pos::namada_proof_of_stake::types::VotingPower;
use crate::ledger::pos::types::WeightedValidator;
use crate::ledger::pos::PosParams;
use crate::tendermint_proto::types::EvidenceParams;
use crate::types::address::Address;
use crate::types::ethereum_events::EthAddress;
use crate::types::key;
use crate::types::storage::{BlockHeight, Epoch};
use crate::types::token::Amount;
use crate::types::transaction::EllipticCurve;
use crate::types::vote_extensions::validator_set_update::EthAddrBook;

/// Errors returned by [`QueriesExt`] operations.
#[derive(Error, Debug)]
pub enum Error {
    /// The given address is not among the set of active validators for
    /// the corresponding epoch.
    #[error(
        "The address '{:?}' is not among the active validator set for epoch \
         {1}"
    )]
    NotValidatorAddress(Address, Epoch),
    /// The given public key does not correspond to any active validator's
    /// key at the provided epoch.
    #[error(
        "The public key '{0}' is not among the active validator set for epoch \
         {1}"
    )]
    NotValidatorKey(String, Epoch),
    /// The given public key hash does not correspond to any active validator's
    /// key at the provided epoch.
    #[error(
        "The public key hash '{0}' is not among the active validator set for \
         epoch {1}"
    )]
    NotValidatorKeyHash(String, Epoch),
    /// An invalid Tendermint validator address was detected.
    #[error("Invalid validator tendermint address")]
    InvalidTMAddress,
}

/// Result type returned by [`QueriesExt`] operations.
pub type Result<T> = ::std::result::Result<T, Error>;

/// This enum is used as a parameter to
/// [`QueriesExt::can_send_validator_set_update`].
pub enum SendValsetUpd {
    /// Check if it is possible to send a validator set update
    /// vote extension at the current block height.
    Now,
    /// Check if it is possible to send a validator set update
    /// vote extension at the previous block height.
    AtPrevHeight,
}

/// Methods used to query blockchain state, such as the currently
/// active set of validators.
pub trait QueriesExt {
    // TODO: when Rust 1.65 becomes available in Namada, we should return this
    // iterator type from [`QueriesExt::get_active_eth_addresses`], to
    // avoid a heap allocation; `F` will be the closure used to process the
    // iterator we currently return in the `Storage` impl
    // ```ignore
    // type ActiveEthAddressesIter<'db, F>: Iterator<(EthAddrBook, Address, VotingPower)>;
    // ```
    // a similar strategy can be used for [`QueriesExt::get_active_validators`]:
    // ```ignore
    // type ActiveValidatorsIter<'db, F>: Iterator<WeightedValidator<Address>>;
    // ```

    /// Get the set of active validators for a given epoch (defaulting to the
    /// epoch of the current yet-to-be-committed block).
    fn get_active_validators(
        &self,
        epoch: Option<Epoch>,
    ) -> BTreeSet<WeightedValidator<Address>>;

    /// Lookup the total voting power for an epoch (defaulting to the
    /// epoch of the current yet-to-be-committed block).
    fn get_total_voting_power(&self, epoch: Option<Epoch>) -> VotingPower;

    /// Simple helper function for the ledger to get balances
    /// of the specified token at the specified address.
    fn get_balance(&self, token: &Address, owner: &Address) -> Amount;

    /// Return evidence parameters.
    // TODO: impove this docstring
    fn get_evidence_params(
        &self,
        epoch_duration: &EpochDuration,
        pos_params: &PosParams,
    ) -> EvidenceParams;

    /// Lookup data about a validator from their protocol signing key.
    fn get_validator_from_protocol_pk(
        &self,
        pk: &key::common::PublicKey,
        epoch: Option<Epoch>,
    ) -> Result<TendermintValidator<EllipticCurve>>;

    /// Lookup data about a validator from their address.
    fn get_validator_from_address(
        &self,
        address: &Address,
        epoch: Option<Epoch>,
    ) -> Result<(VotingPower, key::common::PublicKey)>;

    /// Given a tendermint validator, the address is the hash
    /// of the validators public key. We look up the native
    /// address from storage using this hash.
    // TODO: We may change how this lookup is done, see
    // https://github.com/anoma/namada/issues/200
    fn get_validator_from_tm_address(
        &self,
        tm_address: &[u8],
        epoch: Option<Epoch>,
    ) -> Result<Address>;

    /// Determines if it is possible to send a validator set update vote
    /// extension at the provided [`BlockHeight`] in [`SendValsetUpd`].
    fn can_send_validator_set_update(&self, can_send: SendValsetUpd) -> bool;

    /// Check if we are at a given [`BlockHeight`] offset, `height_off`, within
    /// the current [`Epoch`].
    fn is_deciding_offset_within_epoch(&self, height_off: u64) -> bool;

    /// Given some [`BlockHeight`], return the corresponding [`Epoch`].
    fn get_epoch(&self, height: BlockHeight) -> Option<Epoch>;

    /// Retrieves the [`BlockHeight`] that is currently being decided.
    fn get_current_decision_height(&self) -> BlockHeight;

    /// For a given Namada validator, return its corresponding Ethereum bridge
    /// address.
    fn get_ethbridge_from_namada_addr(
        &self,
        validator: &Address,
        epoch: Option<Epoch>,
    ) -> Option<EthAddress>;

    /// For a given Namada validator, return its corresponding Ethereum
    /// governance address.
    fn get_ethgov_from_namada_addr(
        &self,
        validator: &Address,
        epoch: Option<Epoch>,
    ) -> Option<EthAddress>;

    /// Extension of [`Self::get_active_validators`], which additionally returns
    /// all Ethereum addresses of some validator.
    fn get_active_eth_addresses<'db>(
        &'db self,
        epoch: Option<Epoch>,
    ) -> Box<dyn Iterator<Item = (EthAddrBook, Address, VotingPower)> + 'db>;
}
