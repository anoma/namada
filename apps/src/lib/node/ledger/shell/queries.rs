//! Shell methods for querying state
use std::cmp::max;

use borsh::{BorshDeserialize, BorshSerialize};
use ferveo_common::TendermintValidator;
use namada::ledger::parameters::EpochDuration;
use namada::ledger::pos::namada_proof_of_stake::types::VotingPower;
use namada::ledger::pos::types::WeightedValidator;
use namada::ledger::pos::PosParams;
use namada::types::address::Address;
use namada::types::key;
use namada::types::key::dkg_session_keys::DkgPublicKey;
use namada::types::storage::{Epoch, Key, PrefixValue};
use namada::types::token::{self, Amount};

use super::*;
use crate::node::ledger::response;
use crate::facade::tendermint_proto::google::protobuf;
use crate::facade::tendermint_proto::types::EvidenceParams;
use crate::facade::tendermint_proto::crypto::{ProofOp, ProofOps};

#[derive(Error, Debug)]
pub enum Error {
    #[error(
        "The address '{:?}' is not among the active validator set for epoch \
         {1}"
    )]
    NotValidatorAddress(Address, Epoch),
    #[error(
        "The public key '{0}' is not among the active validator set for epoch \
         {1}"
    )]
    #[allow(dead_code)]
    NotValidatorKey(String, Epoch),
    #[error(
        "The public key hash '{0}' is not among the active validator set for \
         epoch {1}"
    )]
    NotValidatorKeyHash(String, Epoch),
    #[error("Invalid validator tendermint address")]
    InvalidTMAddress,
}

impl<D, H> Shell<D, H>
where
    D: DB + for<'iter> DBIter<'iter> + Sync + 'static,
    H: StorageHasher + Sync + 'static,
{
    /// Uses `path` in the query to forward the request to the
    /// right query method and returns the result (which may be
    /// the default if `path` is not a supported string.
    /// INVARIANT: This method must be stateless.
    pub fn query(&self, query: request::Query) -> response::Query {
        use rpc::Path;
        let height = match query.height {
            0 => self.storage.get_block_height().0,
            1.. => BlockHeight(query.height as u64),
            _ => {
                return response::Query {
                    code: 1,
                    info: format!(
                        "The query height is invalid: {}",
                        query.height
                    ),
                    ..Default::default()
                };
            }
        };
        match Path::from_str(&query.path) {
            Ok(path) => match path {
                Path::DryRunTx => self.dry_run_tx(&query.data),
                Path::Epoch => {
                    let (epoch, _gas) = self.storage.get_last_epoch();
                    let value = namada::ledger::storage::types::encode(&epoch);
                    response::Query {
                        value,
                        ..Default::default()
                    }
                }
                Path::Value(storage_key) => {
                    self.read_storage_value(&storage_key, height, query.prove)
                }
                Path::Prefix(storage_key) => {
                    self.read_storage_prefix(&storage_key, height, query.prove)
                }
                Path::HasKey(storage_key) => self.has_storage_key(&storage_key),
            },
            Err(err) => response::Query {
                code: 1,
                info: format!("RPC error: {}", err),
                ..Default::default()
            },
        }
    }

    /// Query to check if a storage key exists.
    fn has_storage_key(&self, key: &Key) -> response::Query {
        match self.storage.has_key(key) {
            Ok((has_key, _gas)) => response::Query {
                value: has_key.try_to_vec().unwrap(),
                ..Default::default()
            },
            Err(err) => response::Query {
                code: 2,
                info: format!("Storage error: {}", err),
                ..Default::default()
            },
        }
    }

    /// Query to read a range of values from storage with a matching prefix. The
    /// value in successful response is a [`Vec<PrefixValue>`] encoded with
    /// [`BorshSerialize`].
    fn read_storage_prefix(
        &self,
        key: &Key,
        height: BlockHeight,
        is_proven: bool,
    ) -> response::Query {
        if height != self.storage.get_block_height().0 {
            return response::Query {
                code: 2,
                info: format!(
                    "Prefix read works with only the latest height: height {}",
                    height
                ),
                ..Default::default()
            };
        }
        let (iter, _gas) = self.storage.iter_prefix(key);
        let mut iter = iter.peekable();
        if iter.peek().is_none() {
            response::Query {
                code: 1,
                info: format!("No value found for key: {}", key),
                ..Default::default()
            }
        } else {
            let values: std::result::Result<
                Vec<PrefixValue>,
                namada::types::storage::Error,
            > = iter
                .map(|(key, value, _gas)| {
                    let key = Key::parse(key)?;
                    Ok(PrefixValue { key, value })
                })
                .collect();
            match values {
                Ok(values) => {
                    let proof_ops = if is_proven {
                        let mut ops = vec![];
                        for PrefixValue { key, value } in &values {
                            match self.storage.get_existence_proof(
                                key,
                                value.clone(),
                                height,
                            ) {
                                Ok(p) => {
                                    let mut cur_ops: Vec<ProofOp> = p
                                        .ops
                                        .into_iter()
                                        .map(|op| op.into())
                                        .collect();
                                    ops.append(&mut cur_ops);
                                }
                                Err(err) => {
                                    return response::Query {
                                        code: 2,
                                        info: format!("Storage error: {}", err),
                                        ..Default::default()
                                    };
                                }
                            }
                        }
                        // ops is not empty in this case
                        Some(ProofOps { ops })
                    } else {
                        None
                    };
                    let value = values.try_to_vec().unwrap();
                    response::Query {
                        value,
                        proof_ops,
                        ..Default::default()
                    }
                }
                Err(err) => response::Query {
                    code: 1,
                    info: format!(
                        "Error parsing a storage key {}: {}",
                        key, err
                    ),
                    ..Default::default()
                },
            }
        }
    }

    /// Query to read a value from storage
    fn read_storage_value(
        &self,
        key: &Key,
        height: BlockHeight,
        is_proven: bool,
    ) -> response::Query {
        match self.storage.read_with_height(key, height) {
            Ok((Some(value), _gas)) => {
                let proof_ops = if is_proven {
                    match self.storage.get_existence_proof(
                        key,
                        value.clone(),
                        height,
                    ) {
                        Ok(proof) => Some(proof.into()),
                        Err(err) => {
                            return response::Query {
                                code: 2,
                                info: format!("Storage error: {}", err),
                                ..Default::default()
                            };
                        }
                    }
                } else {
                    None
                };
                response::Query {
                    value,
                    proof_ops,
                    ..Default::default()
                }
            }
            Ok((None, _gas)) => {
                let proof_ops = if is_proven {
                    match self.storage.get_non_existence_proof(key, height) {
                        Ok(proof) => Some(proof.into()),
                        Err(err) => {
                            return response::Query {
                                code: 2,
                                info: format!("Storage error: {}", err),
                                ..Default::default()
                            };
                        }
                    }
                } else {
                    None
                };
                response::Query {
                    code: 1,
                    info: format!("No value found for key: {}", key),
                    proof_ops,
                    ..Default::default()
                }
            }
            Err(err) => response::Query {
                code: 2,
                info: format!("Storage error: {}", err),
                ..Default::default()
            },
        }
    }
}

/// API for querying the blockchain state.
pub(crate) trait QueriesExt {
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
    /// of the specified token at the specified address
    fn get_balance(
        &self,
        token: &Address,
        owner: &Address,
    ) -> std::result::Result<Amount, String>;

    fn get_evidence_params(
        &self,
        epoch_duration: &EpochDuration,
        pos_params: &PosParams,
    ) -> EvidenceParams;

    /// Lookup data about a validator from their protocol signing key
    fn get_validator_from_protocol_pk(
        &self,
        pk: &key::common::PublicKey,
        epoch: Option<Epoch>,
    ) -> std::result::Result<TendermintValidator<EllipticCurve>, Error>;

    /// Lookup data about a validator from their address
    fn get_validator_from_address(
        &self,
        address: &Address,
        epoch: Option<Epoch>,
    ) -> std::result::Result<(VotingPower, common::PublicKey), Error>;

    /// Given a tendermint validator, the address is the hash
    /// of the validators public key. We look up the native
    /// address from storage using this hash.
    // TODO: We may change how this lookup is done, see
    // https://github.com/anoma/namada/issues/200
    fn get_validator_from_tm_address(
        &self,
        tm_address: &[u8],
        epoch: Option<Epoch>,
    ) -> std::result::Result<Address, Error>;
}

impl<D, H> QueriesExt for Storage<D, H>
where
    D: DB + for<'iter> DBIter<'iter>,
    H: StorageHasher,
{
    fn get_active_validators(
        &self,
        epoch: Option<Epoch>,
    ) -> BTreeSet<WeightedValidator<Address>> {
        let epoch = epoch.unwrap_or_else(|| self.get_current_epoch().0);
        let validator_set = self.read_validator_set();
        validator_set
            .get(epoch)
            .expect("Validators for an epoch should be known")
            .active
            .clone()
    }

    #[cfg(not(feature = "ABCI"))]
    fn get_total_voting_power(&self, epoch: Option<Epoch>) -> VotingPower {
        self.get_active_validators(epoch)
            .iter()
            .map(|validator| u64::from(validator.voting_power))
            .sum::<u64>()
            .into()
    }

    fn get_balance(
        &self,
        token: &Address,
        owner: &Address,
    ) -> std::result::Result<Amount, String> {
        let height = self.get_block_height().0;
        let (balance, _) = self
            .read_with_height(&token::balance_key(token, owner), height)
            .map_err(|err| {
                format!(
                    "Unable to read token {} balance of the given address {}: \
                     {:?}",
                    token, owner, err
                )
            })?;
        let balance = match balance {
            Some(balance) => balance,
            None => {
                return Err(format!(
                    "Unable to read token {} balance of the given address {}",
                    token, owner
                ));
            }
        };
        BorshDeserialize::try_from_slice(&balance[..]).map_err(|err| {
            format!(
                "Unable to deserialize the balance of the given address: {:?}",
                err
            )
        })
    }

    fn get_evidence_params(
        &self,
        epoch_duration: &EpochDuration,
        pos_params: &PosParams,
    ) -> EvidenceParams {
        // Minimum number of epochs before tokens are unbonded and can be
        // withdrawn
        let len_before_unbonded = max(pos_params.unbonding_len as i64 - 1, 0);
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

    #[allow(dead_code)]
    fn get_validator_from_protocol_pk(
        &self,
        pk: &key::common::PublicKey,
        epoch: Option<Epoch>,
    ) -> std::result::Result<TendermintValidator<EllipticCurve>, Error> {
        let pk_bytes = pk
            .try_to_vec()
            .expect("Serializing public key should not fail");
        let epoch = epoch.unwrap_or_else(|| self.get_current_epoch().0);
        self.get_active_validators(Some(epoch))
            .iter()
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
                    power: validator.voting_power.into(),
                    address: validator.address.to_string(),
                    public_key: dkg_publickey.into(),
                }
            })
            .ok_or_else(|| Error::NotValidatorKey(pk.to_string(), epoch))
    }

    #[cfg(not(feature = "ABCI"))]
    fn get_validator_from_address(
        &self,
        address: &Address,
        epoch: Option<Epoch>,
    ) -> std::result::Result<(VotingPower, common::PublicKey), Error> {
        let epoch = epoch.unwrap_or_else(|| self.get_current_epoch().0);
        self.get_active_validators(Some(epoch))
            .iter()
            .find(|validator| address == &validator.address)
            .map(|validator| {
                let protocol_pk_key = key::protocol_pk_key(&validator.address);
                let bytes = self
                    .read(&protocol_pk_key)
                    .expect("Validator should have public protocol key")
                    .0
                    .expect("Validator should have public protocol key");
                let protocol_pk: common::PublicKey =
                    BorshDeserialize::deserialize(&mut bytes.as_ref()).expect(
                        "Protocol public key in storage should be \
                         deserializable",
                    );
                (validator.voting_power, protocol_pk)
            })
            .ok_or_else(|| Error::NotValidatorAddress(address.clone(), epoch))
    }

    #[allow(dead_code)]
    fn get_validator_from_tm_address(
        &self,
        tm_address: &[u8],
        epoch: Option<Epoch>,
    ) -> std::result::Result<Address, Error> {
        let epoch = epoch.unwrap_or_else(|| self.get_current_epoch().0);
        let validator_raw_hash = core::str::from_utf8(tm_address)
            .map_err(|_| Error::InvalidTMAddress)?;
        self.read_validator_address_raw_hash(&validator_raw_hash)
            .ok_or_else(|| {
                Error::NotValidatorKeyHash(
                    validator_raw_hash.to_string(),
                    epoch,
                )
            })
    }
}
