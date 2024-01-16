//! Storage API for querying data about Proof-of-stake related
//! data. This includes validator and epoch related data.

use namada_core::types::address::Address;
use namada_core::types::chain::ProposalBytes;
use namada_core::types::storage::{BlockHeight, Epoch};
use namada_core::types::{key, token};
use namada_parameters::storage::get_max_proposal_bytes_key;
use namada_storage::collections::lazy_map::NestedSubKey;
use namada_storage::StorageRead;
use thiserror::Error;

use crate::storage::find_validator_by_raw_hash;
use crate::types::WeightedValidator;
use crate::{
    consensus_validator_set_handle, get_total_consensus_stake, read_pos_params,
    validator_eth_cold_key_handle, validator_eth_hot_key_handle,
    ConsensusValidatorSet, PosParams,
};

/// Errors returned by [`PosQueries`] operations.
#[derive(Error, Debug)]
pub enum Error {
    /// A storage error occurred.
    #[error("Storage error: {0}")]
    Storage(#[from] namada_storage::Error),
    /// The given address is not among the set of consensus validators for
    /// the corresponding epoch.
    #[error(
        "The address '{0:?}' is not among the consensus validator set for \
         epoch {1}"
    )]
    NotValidatorAddress(Address, Epoch),
    /// The given public key does not correspond to any consensus validator's
    /// key at the provided epoch.
    #[error(
        "The public key '{0}' is not among the consensus validator set for \
         epoch {1}"
    )]
    NotValidatorKey(String, Epoch),
    /// The given public key hash does not correspond to any consensus
    /// validator's key at the provided epoch.
    #[error(
        "The public key hash '{0}' does not belong to a validator in storage"
    )]
    NotValidatorKeyHash(String),
}

/// Result type returned by [`PosQueries`] operations.
pub type Result<T> = ::std::result::Result<T, Error>;

/// Methods used to query blockchain proof-of-stake related state,
/// such as the current set of consensus validators.
pub trait PosQueries {
    /// The underlying storage type.
    type Storage;

    /// Return a handle to [`PosQueries`].
    fn pos_queries(&self) -> PosQueriesHook<'_, Self::Storage>;
}

impl<S> PosQueries for S
where
    S: StorageRead,
{
    type Storage = Self;

    #[inline]
    fn pos_queries(&self) -> PosQueriesHook<'_, Self> {
        PosQueriesHook { storage: self }
    }
}

/// A handle to [`PosQueries`].
///
/// This type is a wrapper around a pointer to a [`impl ReadStorage`].
#[derive(Debug)]
#[repr(transparent)]
pub struct PosQueriesHook<'db, S> {
    storage: &'db S,
}

impl<'db, S> Clone for PosQueriesHook<'db, S> {
    fn clone(&self) -> Self {
        Self {
            storage: self.storage,
        }
    }
}

impl<'db, S> Copy for PosQueriesHook<'db, S> {}

impl<'db, S> PosQueriesHook<'db, S>
where
    S: StorageRead,
{
    /// Return a handle to the inner storage.
    #[inline]
    pub fn storage(self) -> &'db S {
        self.storage
    }

    /// Read the proof-of-stake parameters from storage.
    pub fn get_pos_params(self) -> PosParams {
        read_pos_params(self.storage)
            .expect("Should be able to read PosParams from storage")
    }

    /// Get the set of consensus validators for a given epoch (defaulting to the
    /// epoch of the current yet-to-be-committed block).
    #[inline]
    pub fn get_consensus_validators(
        self,
        epoch: Option<Epoch>,
    ) -> ConsensusValidators<'db, S> {
        let epoch =
            epoch.unwrap_or_else(|| self.storage.get_block_epoch().unwrap());
        ConsensusValidators {
            wl_storage: self.storage,
            validator_set: consensus_validator_set_handle().at(&epoch),
        }
    }

    /// Lookup the total voting power for an epoch (defaulting to the
    /// epoch of the current yet-to-be-committed block).
    pub fn get_total_voting_power(self, epoch: Option<Epoch>) -> token::Amount {
        let epoch =
            epoch.unwrap_or_else(|| self.storage.get_block_epoch().unwrap());
        let pos_params = self.get_pos_params();
        get_total_consensus_stake(self.storage, epoch, &pos_params)
            // NB: the only reason this call should fail is if we request
            // an epoch that hasn't been reached yet. let's "fail" by
            // returning a total stake of 0 NAM
            .unwrap_or_default()
    }

    /// Lookup data about a validator from their protocol signing key.
    pub fn get_validator_from_protocol_pk(
        self,
        pk: &key::common::PublicKey,
        epoch: Option<Epoch>,
    ) -> Result<WeightedValidator> {
        let params = crate::read_pos_params(self.storage)
            .expect("Failed to fetch Pos params");
        let epoch = epoch
            .map(Ok)
            .unwrap_or_else(|| self.storage.get_block_epoch())?;
        self.get_consensus_validators(Some(epoch))
            .iter()
            .find(|validator| {
                let protocol_keys =
                    crate::validator_protocol_key_handle(&validator.address);
                match protocol_keys.get(self.storage, epoch, &params) {
                    Ok(Some(key)) => key == *pk,
                    _ => false,
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
        let params = crate::read_pos_params(self.storage)
            .expect("Failed to fetch Pos params");
        let epoch = epoch
            .map(Ok)
            .unwrap_or_else(|| self.storage.get_block_epoch())?;
        self.get_consensus_validators(Some(epoch))
            .iter()
            .find(|validator| address == &validator.address)
            .map(|validator| {
                let protocol_keys =
                    crate::validator_protocol_key_handle(&validator.address);
                let protocol_pk = protocol_keys
                    .get(self.storage, epoch, &params)
                    .unwrap()
                    .expect(
                        "Protocol public key should be set in storage after \
                         genesis.",
                    );

                (validator.bonded_stake, protocol_pk)
            })
            .ok_or_else(|| Error::NotValidatorAddress(address.clone(), epoch))
    }

    /// Given a tendermint validator, the address is the hash
    /// of the validators public key. We look up the native
    /// address from storage using this hash.
    pub fn get_validator_from_tm_address(
        self,
        tm_address: impl AsRef<str>,
    ) -> Result<Address> {
        let addr_hash = tm_address.as_ref();
        let validator = find_validator_by_raw_hash(self.storage, addr_hash)
            .map_err(Error::Storage)?;
        validator.ok_or_else(|| Error::NotValidatorKeyHash(addr_hash.into()))
    }

    /// Given some [`BlockHeight`], return the corresponding [`Epoch`].
    ///
    /// This method may return [`None`] if the corresponding data has
    /// been purged from Namada, or if it is not available yet.
    #[inline]
    pub fn get_epoch(self, height: BlockHeight) -> Option<Epoch> {
        self.storage.get_epoch_at_height(height).unwrap()
    }

    /// Retrieve the `max_proposal_bytes` consensus parameter from storage.
    pub fn get_max_proposal_bytes(self) -> ProposalBytes {
        namada_storage::StorageRead::read(
            self.storage,
            &get_max_proposal_bytes_key(),
        )
        .expect("Must be able to read ProposalBytes from storage")
        .expect("ProposalBytes must be present in storage")
    }

    /// Get a validator's Ethereum hot key from storage, at the given epoch, or
    /// the last one, if none is provided.
    pub fn read_validator_eth_hot_key(
        self,
        validator: &Address,
        epoch: Option<Epoch>,
    ) -> Option<key::common::PublicKey> {
        let epoch =
            epoch.unwrap_or_else(|| self.storage.get_block_epoch().unwrap());
        let params = self.get_pos_params();
        validator_eth_hot_key_handle(validator)
            .get(self.storage, epoch, &params)
            .ok()
            .flatten()
    }

    /// Get a validator's Ethereum cold key from storage, at the given epoch, or
    /// the last one, if none is provided.
    pub fn read_validator_eth_cold_key(
        self,
        validator: &Address,
        epoch: Option<Epoch>,
    ) -> Option<key::common::PublicKey> {
        let epoch =
            epoch.unwrap_or_else(|| self.storage.get_block_epoch().unwrap());
        let params = self.get_pos_params();
        validator_eth_cold_key_handle(validator)
            .get(self.storage, epoch, &params)
            .ok()
            .flatten()
    }
}

/// A handle to the set of consensus validators in Namada,
/// at some given epoch.
pub struct ConsensusValidators<'db, S>
where
    S: StorageRead,
{
    wl_storage: &'db S,
    validator_set: ConsensusValidatorSet,
}

impl<'db, S> ConsensusValidators<'db, S>
where
    S: StorageRead,
{
    /// Iterate over the set of consensus validators in Namada, at some given
    /// epoch.
    pub fn iter<'this: 'db>(
        &'this self,
    ) -> impl Iterator<Item = WeightedValidator> + 'db {
        self.validator_set
            .iter(self.wl_storage)
            .expect("Must be able to iterate over consensus validators")
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
