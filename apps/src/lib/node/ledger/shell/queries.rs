//! Shell methods for querying state

use std::cmp::max;

use borsh::{BorshDeserialize, BorshSerialize};
use ferveo_common::TendermintValidator;
use namada::ledger::parameters::EpochDuration;
use namada::ledger::pos::namada_proof_of_stake::types::VotingPower;
use namada::ledger::pos::types::WeightedValidator;
use namada::ledger::pos::PosParams;
use namada::types::address::Address;
use namada::types::ethereum_events::EthAddress;
use namada::types::key;
use namada::types::key::dkg_session_keys::DkgPublicKey;
use namada::types::storage::{Epoch, Key, PrefixValue};
use namada::types::token::{self, Amount};
use namada::types::vote_extensions::validator_set_update::EthAddrBook;

use super::*;
use crate::facade::tendermint_proto::crypto::{ProofOp, ProofOps};
use crate::facade::tendermint_proto::google::protobuf;
use crate::facade::tendermint_proto::types::EvidenceParams;
use crate::node::ledger::events::log::dumb_queries;
use crate::node::ledger::response;

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
                Path::Accepted { tx_hash } => {
                    let matcher = dumb_queries::QueryMatcher::accepted(tx_hash);
                    self.query_event_log(matcher)
                }
                Path::Applied { tx_hash } => {
                    let matcher = dumb_queries::QueryMatcher::applied(tx_hash);
                    self.query_event_log(matcher)
                }
            },
            Err(err) => response::Query {
                code: 1,
                info: format!("RPC error: {}", err),
                ..Default::default()
            },
        }
    }

    /// Query events in the event log matching the given query.
    fn query_event_log(
        &self,
        matcher: dumb_queries::QueryMatcher,
    ) -> response::Query {
        let value = self
            .event_log()
            .iter_with_matcher(matcher)
            .cloned()
            .collect::<Vec<_>>()
            .try_to_vec()
            .unwrap();

        response::Query {
            value,
            ..Default::default()
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
                                value.clone().into(),
                                height,
                            ) {
                                Ok(p) => {
                                    let mut cur_ops: Vec<ProofOp> = p
                                        .ops
                                        .into_iter()
                                        .map(|op| {
                                            #[cfg(feature = "abcipp")]
                                            {
                                                ProofOp {
                                                    r#type: op.field_type,
                                                    key: op.key,
                                                    data: op.data,
                                                }
                                            }
                                            #[cfg(not(feature = "abcipp"))]
                                            {
                                                op.into()
                                            }
                                        })
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
                        value.clone().into(),
                        height,
                    ) {
                        Ok(proof) => Some({
                            #[cfg(feature = "abcipp")]
                            {
                                let ops = proof
                                    .ops
                                    .into_iter()
                                    .map(|op| ProofOp {
                                        r#type: op.field_type,
                                        key: op.key,
                                        data: op.data,
                                    })
                                    .collect();
                                ProofOps { ops }
                            }
                            #[cfg(not(feature = "abcipp"))]
                            {
                                proof.into()
                            }
                        }),
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
                        Ok(proof) => Some({
                            #[cfg(feature = "abcipp")]
                            {
                                let ops = proof
                                    .ops
                                    .into_iter()
                                    .map(|op| ProofOp {
                                        r#type: op.field_type,
                                        key: op.key,
                                        data: op.data,
                                    })
                                    .collect();
                                ProofOps { ops }
                            }
                            #[cfg(not(feature = "abcipp"))]
                            {
                                proof.into()
                            }
                        }),
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
    ) -> Box<dyn Iterator<Item = (EthAddrBook, Address, VotingPower)> + 'db>;
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

    #[cfg(feature = "abcipp")]
    fn can_send_validator_set_update(&self, _can_send: SendValsetUpd) -> bool {
        // TODO: implement this method for ABCI++; should only be able to send
        // a validator set update at the second block of an epoch
        true
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
    ) -> Box<dyn Iterator<Item = (EthAddrBook, Address, VotingPower)> + 'db>
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
                (eth_addr_book, validator.address, validator.voting_power)
            },
        ))
    }
}

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

#[cfg(test)]
mod test_queries {
    use super::*;
    use crate::node::ledger::shell::test_utils;
    use crate::node::ledger::shims::abcipp_shim_types::shim::request::FinalizeBlock;

    macro_rules! test_can_send_validator_set_update {
        (epoch_assertions: $epoch_assertions:expr $(,)?) => {
            /// Test if [`QueriesExt::can_send_validator_set_update`] behaves as
            /// expected.
            #[test]
            // TODO: we should fix this test to cope with epoch changes only
            // happening at the first block of a new epoch. an erroneous change
            // was introduced to the ledger, that updated the epoch correctly
            // at the first block of the new epoch, but recorded `height + 1`
            // instead of the actual height of the epoch change. since this
            // test depended on that erroneous logic to pass, it's busted.
            //
            // linked issues:
            // - <https://github.com/anoma/namada/issues/599>
            // - <https://github.com/anoma/namada/issues/600>
            fn test_can_send_validator_set_update() {
                let (mut shell, _recv, _) = test_utils::setup_at_height(0u64);

                let epoch_assertions = $epoch_assertions;

                // test `SendValsetUpd::Now`  and `SendValsetUpd::AtPrevHeight`
                for (curr_epoch, curr_block_height, can_send) in
                    epoch_assertions
                {
                    shell.storage.last_height =
                        BlockHeight(curr_block_height - 1);
                    assert_eq!(
                        curr_block_height,
                        shell.storage.get_current_decision_height().0
                    );
                    assert_eq!(
                        shell.storage.get_epoch(curr_block_height.into()),
                        Some(Epoch(curr_epoch))
                    );
                    assert_eq!(
                        shell
                            .storage
                            .can_send_validator_set_update(SendValsetUpd::Now),
                        can_send,
                    );
                    // TODO(feature = "abcipp"): test
                    // `SendValsetUpd::AtPrevHeight`; `idx` is the value
                    // of the current index being iterated over
                    // the array `epoch_assertions`
                    //
                    // ```ignore
                    // if let Some((epoch, height, can_send)) =
                    //     epoch_assertions.get(_idx.wrapping_sub(1)).copied()
                    // {
                    //     assert_eq!(
                    //         shell.storage.get_epoch(height.into()),
                    //         Some(Epoch(epoch))
                    //     );
                    //     assert_eq!(
                    //         shell.storage.can_send_validator_set_update(
                    //             SendValsetUpd::AtPrevHeight
                    //         ),
                    //         can_send,
                    //     );
                    // }
                    // ```
                    let time = namada::types::time::DateTimeUtc::now();
                    let mut req = FinalizeBlock::default();
                    req.header.time = time;
                    shell.finalize_block(req).expect("Test failed");
                    shell.commit();
                    shell.storage.next_epoch_min_start_time = time;
                }
            }
        };
    }

    #[cfg(feature = "abcipp")]
    test_can_send_validator_set_update! {
        // TODO(feature = "abcipp"): add some epoch assertions
        epoch_assertions: []
    }

    #[cfg(not(feature = "abcipp"))]
    test_can_send_validator_set_update! {
        epoch_assertions: [
            // (current epoch, current block height, can send valset upd)
            (0, 1, false),
            (0, 2, true),
            (0, 3, false),
            (0, 4, false),
            (0, 5, false),
            (0, 6, false),
            (0, 7, false),
            (0, 8, false),
            (0, 9, false),
            // we will change epoch here
            (0, 10, false),
            (1, 11, true),
            (1, 12, false),
            (1, 13, false),
            (1, 14, false),
            (1, 15, false),
            (1, 16, false),
            (1, 17, false),
            (1, 18, false),
            (1, 19, false),
            // we will change epoch here
            (1, 20, false),
            (2, 21, true),
            (2, 22, false),
            (2, 23, false),
            (2, 24, false),
            (2, 25, false),
            (2, 26, false),
            (2, 27, false),
            (2, 28, false),
        ],
    }
}
