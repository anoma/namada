//! Storage API for querying data about Proof-of-stake related
//! data. This includes validator and epoch related data.
use std::collections::BTreeSet;

use borsh::BorshDeserialize;
use namada_core::ledger::parameters::storage::get_max_proposal_bytes_key;
use namada_core::ledger::parameters::EpochDuration;
use namada_core::ledger::storage::types::decode;
use namada_core::ledger::storage::Storage;
use namada_core::ledger::{storage, storage_api};
use namada_core::tendermint_proto::google::protobuf;
use namada_core::tendermint_proto::types::EvidenceParams;
use namada_core::types::address::Address;
use namada_core::types::chain::ProposalBytes;
use namada_core::types::storage::{BlockHeight, Epoch};
use namada_core::types::{key, token};
use thiserror::Error;

use crate::types::WeightedValidator;
use crate::{PosBase, PosParams};

/// Errors returned by [`PosQueries`] operations.
#[derive(Error, Debug)]
pub enum Error {
    /// The given address is not among the set of active validators for
    /// the corresponding epoch.
    #[error(
        "The address '{0:?}' is not among the active validator set for epoch \
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

/// Result type returned by [`PosQueries`] operations.
pub type Result<T> = ::std::result::Result<T, Error>;

/// Methods used to query blockchain proof-of-stake related state,
/// such as the currently active set of validators.
pub trait PosQueries {
    /// Get the set of active validators for a given epoch (defaulting to the
    /// epoch of the current yet-to-be-committed block).
    fn get_active_validators(
        &self,
        epoch: Option<Epoch>,
    ) -> BTreeSet<WeightedValidator>;

    /// Lookup the total voting power for an epoch (defaulting to the
    /// epoch of the current yet-to-be-committed block).
    fn get_total_voting_power(&self, epoch: Option<Epoch>) -> token::Amount;

    /// Simple helper function for the ledger to get balances
    /// of the specified token at the specified address.
    fn get_balance(&self, token: &Address, owner: &Address) -> token::Amount;

    /// Return evidence parameters.
    // TODO: impove this docstring
    fn get_evidence_params(
        &self,
        epoch_duration: &EpochDuration,
        pos_params: &PosParams,
    ) -> EvidenceParams;

    /// Lookup data about a validator from their address.
    fn get_validator_from_address(
        &self,
        address: &Address,
        epoch: Option<Epoch>,
    ) -> Result<(token::Amount, key::common::PublicKey)>;

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

    /// Check if we are at a given [`BlockHeight`] offset, `height_offset`,
    /// within the current [`Epoch`].
    fn is_deciding_offset_within_epoch(&self, height_offset: u64) -> bool;

    /// Given some [`BlockHeight`], return the corresponding [`Epoch`].
    fn get_epoch(&self, height: BlockHeight) -> Option<Epoch>;

    /// Retrieves the [`BlockHeight`] that is currently being decided.
    fn get_current_decision_height(&self) -> BlockHeight;

    /// Retrieve the `max_proposal_bytes` consensus parameter from storage.
    fn get_max_proposal_bytes(&self) -> ProposalBytes;
}

impl<D, H> PosQueries for Storage<D, H>
where
    D: storage::DB + for<'iter> storage::DBIter<'iter>,
    H: storage::StorageHasher,
{
    fn get_active_validators(
        &self,
        epoch: Option<Epoch>,
    ) -> BTreeSet<WeightedValidator> {
        let epoch = epoch.unwrap_or_else(|| self.get_current_epoch().0);
        let validator_set = self.read_validator_set();
        validator_set
            .get(epoch)
            .expect("Validators for an epoch should be known")
            .active
            .clone()
    }

    fn get_total_voting_power(&self, epoch: Option<Epoch>) -> token::Amount {
        self.get_active_validators(epoch)
            .iter()
            .map(|validator| validator.bonded_stake)
            .sum::<u64>()
            .into()
    }

    fn get_balance(&self, token: &Address, owner: &Address) -> token::Amount {
        let balance = storage_api::StorageRead::read(
            self,
            &token::balance_key(token, owner),
        );
        // Storage read must not fail, but there might be no value, in which
        // case default (0) is returned
        balance
            .expect("Storage read in the protocol must not fail")
            .unwrap_or_default()
    }

    fn get_evidence_params(
        &self,
        epoch_duration: &EpochDuration,
        pos_params: &PosParams,
    ) -> EvidenceParams {
        // Minimum number of epochs before tokens are unbonded and can be
        // withdrawn
        let len_before_unbonded =
            std::cmp::max(pos_params.unbonding_len as i64 - 1, 0);
        let max_age_num_blocks: i64 =
            epoch_duration.min_num_of_blocks as i64 * len_before_unbonded;
        let min_duration_secs = epoch_duration.min_duration.0 as i64;
        let max_age_duration = Some(protobuf::Duration {
            seconds: min_duration_secs * len_before_unbonded,
            nanos: 0,
        });
        EvidenceParams {
            max_age_num_blocks,
            max_age_duration,
            ..EvidenceParams::default()
        }
    }

    fn get_validator_from_address(
        &self,
        address: &Address,
        epoch: Option<Epoch>,
    ) -> Result<(token::Amount, key::common::PublicKey)> {
        let epoch = epoch.unwrap_or_else(|| self.get_current_epoch().0);
        self.get_active_validators(Some(epoch))
            .into_iter()
            .find(|validator| address == &validator.address)
            .map(|validator| {
                let protocol_pk_key = key::protocol_pk_key(&validator.address);
                let bytes = self
                    .read(&protocol_pk_key)
                    .expect("Validator should have public protocol key")
                    .0
                    .expect("Validator should have public protocol key");
                let protocol_pk: key::common::PublicKey =
                    BorshDeserialize::deserialize(&mut bytes.as_ref()).expect(
                        "Protocol public key in storage should be \
                         deserializable",
                    );
                (validator.bonded_stake.into(), protocol_pk)
            })
            .ok_or_else(|| Error::NotValidatorAddress(address.clone(), epoch))
    }

    fn get_validator_from_tm_address(
        &self,
        tm_address: &[u8],
        epoch: Option<Epoch>,
    ) -> Result<Address> {
        let epoch = epoch.unwrap_or_else(|| self.get_current_epoch().0);
        let validator_raw_hash = core::str::from_utf8(tm_address)
            .map_err(|_| Error::InvalidTMAddress)?;
        self.read_validator_address_raw_hash(validator_raw_hash)
            .ok_or_else(|| {
                Error::NotValidatorKeyHash(
                    validator_raw_hash.to_string(),
                    epoch,
                )
            })
    }

    fn is_deciding_offset_within_epoch(&self, height_offset: u64) -> bool {
        let current_decision_height = self.get_current_decision_height();

        // NOTE: the first stored height in `fst_block_heights_of_each_epoch`
        // is 0, because of a bug (should be 1), so this code needs to
        // handle that case
        //
        // we can remove this check once that's fixed
        if self.get_current_epoch().0 == Epoch(0) {
            let height_offset_within_epoch = BlockHeight(1 + height_offset);
            return current_decision_height == height_offset_within_epoch;
        }

        let fst_heights_of_each_epoch =
            self.block.pred_epochs.first_block_heights();

        fst_heights_of_each_epoch
            .last()
            .map(|&h| {
                let height_offset_within_epoch = h + height_offset;
                current_decision_height == height_offset_within_epoch
            })
            .unwrap_or(false)
    }

    #[inline]
    fn get_epoch(&self, height: BlockHeight) -> Option<Epoch> {
        self.block.pred_epochs.get_epoch(height)
    }

    #[inline]
    fn get_current_decision_height(&self) -> BlockHeight {
        self.last_height + 1
    }

    fn get_max_proposal_bytes(&self) -> ProposalBytes {
        let key = get_max_proposal_bytes_key();
        let (maybe_value, _gas) = self
            .read(&key)
            .expect("Must be able to read ProposalBytes from storage");
        let value =
            maybe_value.expect("ProposalBytes must be present in storage");
        decode(value).expect("Must be able to decode ProposalBytes in storage")
    }
}
