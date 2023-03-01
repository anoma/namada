//! Storage API for querying data about Proof-of-stake related
//! data. This includes validator and epoch related data.

use borsh::{BorshDeserialize, BorshSerialize};
use namada_core::ferveo_common::TendermintValidator;
use namada_core::ledger::parameters::storage::get_max_proposal_bytes_key;
use namada_core::ledger::parameters::EpochDuration;
use namada_core::ledger::storage::WlStorage;
use namada_core::ledger::storage_api::collections::lazy_map::NestedSubKey;
use namada_core::ledger::{storage, storage_api};
use namada_core::tendermint_proto::google::protobuf;
use namada_core::tendermint_proto::types::EvidenceParams;
use namada_core::types::address::Address;
use namada_core::types::chain::ProposalBytes;
use namada_core::types::key::dkg_session_keys::DkgPublicKey;
use namada_core::types::storage::{BlockHeight, Epoch};
use namada_core::types::transaction::EllipticCurve;
use namada_core::types::{key, token};
use thiserror::Error;

use crate::types::WeightedValidator;
use crate::{
    consensus_validator_set_handle, read_pos_params, ConsensusValidatorSet,
    PosParams,
};

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
    /// The underlying storage type.
    type Storage;

    /// Return a handle to [`PosQueries`].
    fn pos_queries(&self) -> PosQueriesHook<'_, Self::Storage>;
}

impl<D, H> PosQueries for WlStorage<D, H>
where
    D: storage::DB + for<'iter> storage::DBIter<'iter>,
    H: storage::StorageHasher,
{
    type Storage = Self;

    #[inline]
    fn pos_queries(&self) -> PosQueriesHook<'_, Self> {
        PosQueriesHook { wl_storage: self }
    }
}

/// A handle to [`PosQueries`].
///
/// This type is a wrapper around a pointer to a
/// [`WlStorage`].
#[derive(Debug)]
#[repr(transparent)]
pub struct PosQueriesHook<'db, DB> {
    wl_storage: &'db DB,
}

impl<'db, DB> Clone for PosQueriesHook<'db, DB> {
    fn clone(&self) -> Self {
        Self {
            wl_storage: self.wl_storage,
        }
    }
}

impl<'db, DB> Copy for PosQueriesHook<'db, DB> {}

impl<'db, D, H> PosQueriesHook<'db, WlStorage<D, H>>
where
    D: storage::DB + for<'iter> storage::DBIter<'iter>,
    H: storage::StorageHasher,
{
    /// Return a handle to the inner [`WlStorage`].
    #[inline]
    pub fn storage(self) -> &'db WlStorage<D, H> {
        self.wl_storage
    }

    /// Read the proof-of-stake parameters from storage.
    pub fn get_pos_params(self) -> PosParams {
        read_pos_params(self.wl_storage)
            .expect("Should be able to read PosParams from storage")
    }

    /// Get the set of active validators for a given epoch (defaulting to the
    /// epoch of the current yet-to-be-committed block).
    pub fn get_active_validators(
        self,
        epoch: Option<Epoch>,
    ) -> ActiveValidators<'db, D, H> {
        let epoch = epoch
            .unwrap_or_else(|| self.wl_storage.storage.get_current_epoch().0);
        ActiveValidators {
            wl_storage: self.wl_storage,
            validator_set: consensus_validator_set_handle().at(&epoch),
        }
    }

    /// Lookup the total voting power for an epoch (defaulting to the
    /// epoch of the current yet-to-be-committed block).
    pub fn get_total_voting_power(
        &self,
        epoch: Option<Epoch>,
    ) -> token::Amount {
        self.get_active_validators(epoch)
            .iter()
            .map(|validator| u64::from(validator.bonded_stake))
            .sum::<u64>()
            .into()
    }

    /// Simple helper function for the ledger to get balances
    /// of the specified token at the specified address.
    pub fn get_balance(
        &self,
        token: &Address,
        owner: &Address,
    ) -> token::Amount {
        let balance = storage_api::StorageRead::read(
            self.wl_storage,
            &token::balance_key(token, owner),
        );
        // Storage read must not fail, but there might be no value, in which
        // case default (0) is returned
        balance
            .expect("Storage read in the protocol must not fail")
            .unwrap_or_default()
    }

    /// Return evidence parameters.
    // TODO: impove this docstring
    pub fn get_evidence_params(
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

    /// Lookup data about a validator from their protocol signing key.
    pub fn get_validator_from_protocol_pk(
        &self,
        pk: &key::common::PublicKey,
        epoch: Option<Epoch>,
    ) -> Result<TendermintValidator<EllipticCurve>> {
        let pk_bytes = pk
            .try_to_vec()
            .expect("Serializing public key should not fail");
        let epoch = epoch
            .unwrap_or_else(|| self.wl_storage.storage.get_current_epoch().0);
        self.get_active_validators(Some(epoch))
            .iter()
            .find(|validator| {
                let pk_key = key::protocol_pk_key(&validator.address);
                match self.wl_storage.storage.read(&pk_key) {
                    Ok((Some(bytes), _)) => bytes == pk_bytes,
                    _ => false,
                }
            })
            .map(|validator| {
                let dkg_key =
                    key::dkg_session_keys::dkg_pk_key(&validator.address);
                let bytes = self
                    .wl_storage
                    .storage
                    .read(&dkg_key)
                    .expect("Validator should have public dkg key")
                    .0
                    .expect("Validator should have public dkg key");
                let dkg_publickey =
                    &<DkgPublicKey as BorshDeserialize>::deserialize(
                        &mut bytes.as_ref(),
                    )
                    .expect(
                        "DKG public key in storage should be deserializable",
                    );
                TendermintValidator {
                    power: validator.bonded_stake.into(),
                    address: validator.address.to_string(),
                    public_key: dkg_publickey.into(),
                }
            })
            .ok_or_else(|| Error::NotValidatorKey(pk.to_string(), epoch))
    }

    /// Lookup data about a validator from their address.
    pub fn get_validator_from_address(
        self,
        address: &Address,
        epoch: Option<Epoch>,
    ) -> Result<(token::Amount, key::common::PublicKey)> {
        let epoch = epoch
            .unwrap_or_else(|| self.wl_storage.storage.get_current_epoch().0);
        self.get_active_validators(Some(epoch))
            .iter()
            .find(|validator| address == &validator.address)
            .map(|validator| {
                let protocol_pk_key = key::protocol_pk_key(&validator.address);
                // TODO: rewrite this, to use `StorageRead::read`
                let bytes = self
                    .wl_storage
                    .storage
                    .read(&protocol_pk_key)
                    .expect("Validator should have public protocol key")
                    .0
                    .expect("Validator should have public protocol key");
                let protocol_pk: key::common::PublicKey =
                    BorshDeserialize::deserialize(&mut bytes.as_ref()).expect(
                        "Protocol public key in storage should be \
                         deserializable",
                    );
                (validator.bonded_stake, protocol_pk)
            })
            .ok_or_else(|| Error::NotValidatorAddress(address.clone(), epoch))
    }

    /// Given a tendermint validator, the address is the hash
    /// of the validators public key. We look up the native
    /// address from storage using this hash.
    // TODO: We may change how this lookup is done, see
    // https://github.com/anoma/namada/issues/200
    pub fn get_validator_from_tm_address(
        self,
        _tm_address: &[u8],
        _epoch: Option<Epoch>,
    ) -> Result<Address> {
        // let epoch = epoch.unwrap_or_else(|| self.get_current_epoch().0);
        // let validator_raw_hash = core::str::from_utf8(tm_address)
        //     .map_err(|_| Error::InvalidTMAddress)?;
        // self.read_validator_address_raw_hash(validator_raw_hash)
        //     .ok_or_else(|| {
        //         Error::NotValidatorKeyHash(
        //             validator_raw_hash.to_string(),
        //             epoch,
        //         )
        //     })
        todo!()
    }

    /// Check if we are at a given [`BlockHeight`] offset, `height_offset`,
    /// within the current [`Epoch`].
    pub fn is_deciding_offset_within_epoch(&self, height_offset: u64) -> bool {
        let current_decision_height = self.get_current_decision_height();

        // NOTE: the first stored height in `fst_block_heights_of_each_epoch`
        // is 0, because of a bug (should be 1), so this code needs to
        // handle that case
        //
        // we can remove this check once that's fixed
        if self.wl_storage.storage.get_current_epoch().0 == Epoch(0) {
            let height_offset_within_epoch = BlockHeight(1 + height_offset);
            return current_decision_height == height_offset_within_epoch;
        }

        let fst_heights_of_each_epoch = self
            .wl_storage
            .storage
            .block
            .pred_epochs
            .first_block_heights();

        fst_heights_of_each_epoch
            .last()
            .map(|&h| {
                let height_offset_within_epoch = h + height_offset;
                current_decision_height == height_offset_within_epoch
            })
            .unwrap_or(false)
    }

    /// Given some [`BlockHeight`], return the corresponding [`Epoch`].
    #[inline]
    pub fn get_epoch(self, height: BlockHeight) -> Option<Epoch> {
        self.wl_storage.storage.block.pred_epochs.get_epoch(height)
    }

    /// Retrieves the [`BlockHeight`] that is currently being decided.
    #[inline]
    pub fn get_current_decision_height(&self) -> BlockHeight {
        self.wl_storage.storage.last_height + 1
    }

    /// Retrieve the `max_proposal_bytes` consensus parameter from storage.
    pub fn get_max_proposal_bytes(self) -> ProposalBytes {
        storage_api::StorageRead::read(
            self.wl_storage,
            &get_max_proposal_bytes_key(),
        )
        .expect("Must be able to read ProposalBytes from storage")
        .expect("ProposalBytes must be present in storage")
    }

    /// Fetch the first [`BlockHeight`] of the last [`Epoch`]
    /// committed to storage.
    #[inline]
    pub fn get_epoch_start_height(self) -> BlockHeight {
        // NOTE: the first stored height in `fst_block_heights_of_each_epoch`
        // is 0, because of a bug (should be 1), so this code needs to
        // handle that case
        //
        // we can remove this check once that's fixed
        if self.wl_storage.storage.last_epoch.0 == 0 {
            return BlockHeight(1);
        }
        self.wl_storage
            .storage
            .block
            .pred_epochs
            .first_block_heights()
            .last()
            .copied()
            .expect("The block height of the current epoch should be known")
    }
}

/// A handle to the set of active validators in Namada,
/// at some given epoch.
pub struct ActiveValidators<'db, D, H>
where
    D: storage::DB + for<'iter> storage::DBIter<'iter>,
    H: storage::StorageHasher,
{
    wl_storage: &'db WlStorage<D, H>,
    validator_set: ConsensusValidatorSet,
}

impl<'db, D, H> ActiveValidators<'db, D, H>
where
    D: storage::DB + for<'iter> storage::DBIter<'iter>,
    H: storage::StorageHasher,
{
    /// Iterate over the set of active validators in Namada, at some given
    /// epoch.
    pub fn iter<'this: 'db>(
        &'this self,
    ) -> impl Iterator<Item = WeightedValidator> + 'db {
        self.validator_set
            .iter(self.wl_storage)
            .expect("Must be able to iterate over active validators")
            .map(|res| {
                let (
                    NestedSubKey::Data {
                        key: bonded_stake, ..
                    },
                    address,
                ) = res.expect(
                    "We should be able to decode validators in storage",
                );
                WeightedValidator {
                    address,
                    bonded_stake,
                }
            })
    }
}
