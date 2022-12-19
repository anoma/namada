//! Storage API for querying data about Proof-of-stake related
//! data. This includes validator and epoch related data.
use std::collections::BTreeSet;

use borsh::{BorshDeserialize, BorshSerialize};
use ferveo_common::TendermintValidator;
use namada_core::ledger::parameters::EpochDuration;
use namada_core::ledger::storage::Storage;
use namada_core::ledger::{storage, storage_api};
use namada_core::types::address::Address;
use namada_core::types::ethereum_events::EthAddress;
use namada_core::types::key::dkg_session_keys::DkgPublicKey;
use namada_core::types::storage::{BlockHeight, Epoch};
use namada_core::types::transaction::EllipticCurve;
use namada_core::types::vote_extensions::validator_set_update::EthAddrBook;
use namada_core::types::{key, token};
use thiserror::Error;

use crate::tendermint_proto::google::protobuf;
use crate::tendermint_proto::types::EvidenceParams;
use crate::types::WeightedValidator;
use crate::{PosBase, PosParams};

/// Errors returned by [`QueriesExt`] operations.
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

    /// Determines if it is possible to send a validator set update vote
    /// extension at the provided [`BlockHeight`] in [`SendValsetUpd`].
    ///
    /// This is done by checking if we are at the second block of a new epoch.
    fn can_send_validator_set_update(&self, can_send: SendValsetUpd) -> bool;

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
    ) -> Box<dyn Iterator<Item = (EthAddrBook, Address, token::Amount)> + 'db>;
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

    fn get_validator_from_protocol_pk(
        &self,
        pk: &key::common::PublicKey,
        epoch: Option<Epoch>,
    ) -> Result<TendermintValidator<EllipticCurve>> {
        let pk_bytes = pk
            .try_to_vec()
            .expect("Serializing public key should not fail");
        let epoch = epoch.unwrap_or_else(|| self.get_current_epoch().0);
        self.get_active_validators(Some(epoch))
            .into_iter()
            .find(|validator| {
                let pk_key = key::protocol_pk_key(&validator.address);
                match self.read(&pk_key) {
                    Ok((Some(bytes), _)) => bytes == pk_bytes,
                    _ => false,
                }
            })
            .map(|validator| {
                let dkg_key =
                    key::dkg_session_keys::dkg_pk_key(&validator.address);
                let bytes = self
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
                    power: validator.bonded_stake,
                    address: validator.address.to_string(),
                    public_key: dkg_publickey.into(),
                }
            })
            .ok_or_else(|| Error::NotValidatorKey(pk.to_string(), epoch))
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

    #[cfg(feature = "abcipp")]
    fn can_send_validator_set_update(&self, _can_send: SendValsetUpd) -> bool {
        // TODO: implement this method for ABCI++; should only be able to send
        // a validator set update at the second block of an epoch
        false
    }

    #[cfg(not(feature = "abcipp"))]
    fn can_send_validator_set_update(&self, can_send: SendValsetUpd) -> bool {
        // when checking vote extensions in Prepare
        // and ProcessProposal, we simply return true
        if matches!(can_send, SendValsetUpd::AtPrevHeight) {
            return true;
        }

        let current_decision_height = self.get_current_decision_height();

        // NOTE: the first stored height in `fst_block_heights_of_each_epoch`
        // is 0, because of a bug (should be 1), so this code needs to
        // handle that case
        //
        // we can remove this check once that's fixed
        match current_decision_height {
            BlockHeight(1) => return false,
            BlockHeight(2) => return true,
            _ => (),
        }

        let fst_heights_of_each_epoch =
            self.block.pred_epochs.first_block_heights();

        fst_heights_of_each_epoch
            .last()
            .map(|&h| {
                let second_height_of_epoch = h + 1;
                current_decision_height == second_height_of_epoch
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

    #[inline]
    fn get_ethbridge_from_namada_addr(
        &self,
        validator: &Address,
        epoch: Option<Epoch>,
    ) -> Option<EthAddress> {
        let epoch = epoch.unwrap_or_else(|| self.get_current_epoch().0);
        self.read_validator_eth_hot_key(validator)
            .as_ref()
            .and_then(|epk| epk.get(epoch).and_then(|pk| pk.try_into().ok()))
    }

    #[inline]
    fn get_ethgov_from_namada_addr(
        &self,
        validator: &Address,
        epoch: Option<Epoch>,
    ) -> Option<EthAddress> {
        let epoch = epoch.unwrap_or_else(|| self.get_current_epoch().0);
        self.read_validator_eth_cold_key(validator)
            .as_ref()
            .and_then(|epk| epk.get(epoch).and_then(|pk| pk.try_into().ok()))
    }

    #[inline]
    fn get_active_eth_addresses<'db>(
        &'db self,
        epoch: Option<Epoch>,
    ) -> Box<dyn Iterator<Item = (EthAddrBook, Address, token::Amount)> + 'db>
    {
        let epoch = epoch.unwrap_or_else(|| self.get_current_epoch().0);
        Box::new(self.get_active_validators(Some(epoch)).into_iter().map(
            move |validator| {
                let hot_key_addr = self
                    .get_ethbridge_from_namada_addr(
                        &validator.address,
                        Some(epoch),
                    )
                    .expect(
                        "All Namada validators should have an Ethereum bridge \
                         key",
                    );
                let cold_key_addr = self
                    .get_ethgov_from_namada_addr(
                        &validator.address,
                        Some(epoch),
                    )
                    .expect(
                        "All Namada validators should have an Ethereum \
                         governance key",
                    );
                let eth_addr_book = EthAddrBook {
                    hot_key_addr,
                    cold_key_addr,
                };
                (
                    eth_addr_book,
                    validator.address,
                    validator.bonded_stake.into(),
                )
            },
        ))
    }
}
