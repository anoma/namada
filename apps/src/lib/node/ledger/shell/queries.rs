//! Shell methods for querying state
use std::cmp::max;
use std::default::Default;

use borsh::{BorshDeserialize, BorshSerialize};
use ferveo_common::TendermintValidator;
use namada::ledger::eth_bridge::storage::bridge_pool::{
    get_key_from_hash, get_pending_key, get_signed_root_key,
};
use namada::ledger::parameters::EpochDuration;
use namada::ledger::pos::namada_proof_of_stake::types::VotingPower;
use namada::ledger::pos::types::WeightedValidator;
use namada::ledger::pos::PosParams;
use namada::ledger::queries::{RequestCtx, ResponseQuery};
use namada::ledger::storage::{MerkleTree, StoreRef, StoreType};
use namada::ledger::storage_api;
use namada::types::address::Address;
use namada::types::eth_bridge_pool::{
    MultiSignedMerkleRoot, PendingTransfer, RelayProof,
};
use namada::types::ethereum_events::EthAddress;
use namada::types::keccak::encode::Encode;
use namada::types::key;
use namada::types::key::dkg_session_keys::DkgPublicKey;
use namada::types::storage::MembershipProof::BridgePool;
use namada::types::storage::{Epoch, MerkleValue};
use namada::types::token::{self, Amount};
use namada::types::vote_extensions::validator_set_update::EthAddrBook;

use super::*;
use crate::facade::tendermint_proto::google::protobuf;
use crate::facade::tendermint_proto::types::EvidenceParams;
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
        let ctx = RequestCtx {
            storage: &self.storage,
            event_log: self.event_log(),
            vp_wasm_cache: self.vp_wasm_cache.read_only(),
            tx_wasm_cache: self.tx_wasm_cache.read_only(),
            storage_read_past_height_limit: self.storage_read_past_height_limit,
        };

        // Convert request to domain-type
        let request = match namada::ledger::queries::RequestQuery::try_from_tm(
            &self.storage,
            query,
        ) {
            Ok(request) => request,
            Err(err) => {
                return response::Query {
                    code: 1,
                    info: format!("Unexpected query: {}", err),
                    ..Default::default()
                };
            }
        };

        // Invoke the root RPC handler - returns borsh-encoded data on success
        let result = namada::ledger::queries::handle_path(ctx, &request);
        match result {
            Ok(ResponseQuery {
                data,
                info,
                proof_ops,
            }) => response::Query {
                value: data,
                info,
                proof_ops,
                ..Default::default()
            },
            Err(err) => response::Query {
                code: 1,
                info: format!("RPC error: {}", err),
                ..Default::default()
            },
        }
    }

    /// Query events in the event log matching the given query.
    pub fn query_event_log(
        &self,
        token: &Address,
        owner: &Address,
    ) -> token::Amount {
        let balance = storage_api::StorageRead::read(
            &self.storage,
            &token::balance_key(token, owner),
        );
        // Storage read must not fail, but there might be no value, in which
        // case default (0) is returned
        balance
            .expect("Storage read in the protocol must not fail")
            .unwrap_or_default()
    }

    /// Read the current contents of the Ethereum bridge
    /// pool.
    fn read_ethereum_bridge_pool(&self) -> response::Query {
        let stores = self
            .storage
            .db
            .read_merkle_tree_stores(self.storage.last_height)
            .expect("We should always be able to read the database")
            .expect(
                "Every signed root should correspond to an existing block \
                 height",
            );
        let store = match stores.get_store(StoreType::BridgePool) {
            StoreRef::BridgePool(store) => store,
            _ => unreachable!(),
        };

        let transfers: Vec<PendingTransfer> = store
            .iter()
            .map(|hash| {
                let res = self
                    .storage
                    .read(&get_key_from_hash(hash))
                    .unwrap()
                    .0
                    .unwrap();
                BorshDeserialize::try_from_slice(res.as_slice()).unwrap()
            })
            .collect();
        response::Query {
            code: 0,
            value: transfers.try_to_vec().unwrap(),
            ..Default::default()
        }
    }

    /// Generate a merkle proof for the inclusion of the
    /// requested transfers in the Ethereum bridge pool.
    fn generate_bridge_pool_proof(
        &self,
        request_bytes: Vec<u8>,
    ) -> response::Query {
        if let Ok(transfers) =
            <Vec<PendingTransfer>>::try_from_slice(request_bytes.as_slice())
        {
            // get the latest signed merkle root of the Ethereum bridge pool
            let signed_root: MultiSignedMerkleRoot = match self
                .storage
                .read(&get_signed_root_key())
                .expect("Reading the database should not faile")
            {
                (Some(bytes), _) => {
                    BorshDeserialize::try_from_slice(bytes.as_slice()).unwrap()
                }
                _ => {
                    return response::Query {
                        code: 1,
                        log: "No signed root for the Ethereum bridge pool \
                              exists in storage."
                            .into(),
                        info: "No signed root for the Ethereum bridge pool \
                               exists in storage."
                            .into(),
                        ..Default::default()
                    };
                }
            };

            // get the merkle tree corresponding to the above root.
            let tree = MerkleTree::<H>::new(
                self.storage
                    .db
                    .read_merkle_tree_stores(signed_root.height)
                    .expect("We should always be able to read the database")
                    .expect(
                        "Every signed root should correspond to an existing \
                         block height",
                    ),
            );

            // get the membership proof
            let keys: Vec<_> = transfers.iter().map(get_pending_key).collect();
            match tree.get_sub_tree_existence_proof(
                &keys,
                transfers.into_iter().map(MerkleValue::from).collect(),
            ) {
                Ok(BridgePool(proof)) => response::Query {
                    code: 0,
                    value: RelayProof {
                        // TODO: use actual validators
                        validator_args: Default::default(),
                        root: signed_root,
                        proof,
                        // TODO: Use real nonce
                        nonce: 0.into(),
                    }
                    .encode(),
                    ..Default::default()
                },
                Err(e) => response::Query {
                    code: 1,
                    log: e.to_string(),
                    info: e.to_string(),
                    ..Default::default()
                },
                _ => unreachable!(),
            }
        } else {
            response::Query {
                code: 1,
                log: "Could not deserialize transfers".into(),
                info: "Could not deserialize transfers".into(),
                ..Default::default()
            }
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
    /// extension at the provided [`BlockHeight`].
    ///
    /// This is done by checking if we are at the first block of a new epoch,
    /// or if we are at block height 1 of the first epoch.
    ///
    /// The genesis block will not have vote extensions,
    /// therefore it is a special case, which we account for
    /// by checking if the block height is 1. Otherwise,
    /// validator set update votes will always extend
    /// Tendermint's PreCommit phase of the first block of
    /// an epoch.
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
    fn can_send_validator_set_update(&self, can_send: SendValsetUpd) -> bool {
        let (check_prev_heights, height) = match can_send {
            SendValsetUpd::Now => (false, self.get_current_decision_height()),
            SendValsetUpd::AtPrevHeight => (false, self.last_height),
            SendValsetUpd::AtFixedHeight(h) => (true, h),
        };

        // handle genesis block corner case
        if height == BlockHeight(1) {
            return true;
        }

        let fst_heights_of_each_epoch =
            self.block.pred_epochs.first_block_heights();

        // tentatively check if the last stored height
        // is the one we are looking for
        if fst_heights_of_each_epoch
            .last()
            .map(|&h| h == height)
            .unwrap_or(false)
        {
            return true;
        }

        // the values in `fst_block_heights_of_each_epoch` are stored in
        // ascending order, so we can just do a binary search over them
        check_prev_heights
            && fst_heights_of_each_epoch.binary_search(&height).is_ok()
    }

    #[cfg(not(feature = "abcipp"))]
    #[inline(always)]
    fn can_send_validator_set_update(&self, _can_send: SendValsetUpd) -> bool {
        true
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
    /// Check if it is possible to send a validator set update
    /// vote extension at any given block height.
    #[allow(dead_code)]
    AtFixedHeight(BlockHeight),
}

#[cfg(test)]
mod test_queries {
    use namada::ledger::eth_bridge::storage::bridge_pool::BridgePoolTree;
    use namada::types::eth_bridge_pool::{GasFee, TransferToEthereum};
    use namada::types::ethereum_events::EthAddress;

    use super::*;
    use crate::node::ledger::shell::test_utils;
    use crate::node::ledger::shims::abcipp_shim_types::shim::request::FinalizeBlock;

    /// An established user address for testing & development
    fn bertha_address() -> Address {
        Address::decode("atest1v4ehgw36xvcyyvejgvenxs34g3zygv3jxqunjd6rxyeyys3sxy6rwvfkx4qnj33hg9qnvse4lsfctw")
            .expect("The token address decoding shouldn't fail")
    }

    macro_rules! test_can_send_validator_set_update {
        (epoch_assertions: $epoch_assertions:expr $(,)?) => {
            /// Test if [`QueriesExt::can_send_validator_set_update`] behaves as
            /// expected.
            #[test]
            #[ignore]
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

                // TODO: switch to `Result::into_ok_or_err` when it becomes
                // stable
                const fn extract(
                    can_send: ::std::result::Result<bool, bool>,
                ) -> bool {
                    match can_send {
                        Ok(x) => x,
                        Err(x) => x,
                    }
                }

                // test `SendValsetUpd::Now`  and `SendValsetUpd::AtPrevHeight`
                for (idx, (curr_epoch, curr_block_height, can_send)) in
                    epoch_assertions.iter().copied().enumerate()
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
                        extract(can_send)
                    );
                    if let Some((epoch, height, can_send)) =
                        epoch_assertions.get(idx.wrapping_sub(1)).copied()
                    {
                        assert_eq!(
                            shell.storage.get_epoch(height.into()),
                            Some(Epoch(epoch))
                        );
                        assert_eq!(
                            shell.storage.can_send_validator_set_update(
                                SendValsetUpd::AtPrevHeight
                            ),
                            extract(can_send)
                        );
                    }
                    if epoch_assertions
                        .get(idx + 1)
                        .map(|&(_, _, change_epoch)| change_epoch.is_ok())
                        .unwrap_or(false)
                    {
                        let time = namada::types::time::DateTimeUtc::now();
                        let mut req = FinalizeBlock::default();
                        req.header.time = time;
                        shell.finalize_block(req).expect("Test failed");
                        shell.commit();
                        shell.storage.next_epoch_min_start_time = time;
                    }
                }

                // test `SendValsetUpd::AtFixedHeight`
                for (curr_epoch, curr_block_height, can_send) in
                    epoch_assertions.iter().copied()
                {
                    assert_eq!(
                        shell.storage.get_epoch(curr_block_height.into()),
                        Some(Epoch(curr_epoch))
                    );
                    assert_eq!(
                        shell.storage.can_send_validator_set_update(
                            SendValsetUpd::AtFixedHeight(
                                curr_block_height.into()
                            )
                        ),
                        extract(can_send)
                    );
                }
            }
        };
    }

    #[cfg(feature = "abcipp")]
    test_can_send_validator_set_update! {
        epoch_assertions: [
            // (current epoch, current block height, can send valset upd / Ok = change epoch)
            (0, 1, Ok(true)),
            (0, 2, Err(false)),
            (0, 3, Err(false)),
            (0, 4, Err(false)),
            (0, 5, Err(false)),
            (0, 6, Err(false)),
            (0, 7, Err(false)),
            (0, 8, Err(false)),
            (0, 9, Err(false)),
            (0, 10, Err(false)),
            (0, 11, Err(false)),
            // we will change epoch here
            (1, 12, Ok(true)),
            (1, 13, Err(false)),
            (1, 14, Err(false)),
            (1, 15, Err(false)),
            (1, 16, Err(false)),
            (1, 17, Err(false)),
            (1, 18, Err(false)),
            (1, 19, Err(false)),
            (1, 20, Err(false)),
            (1, 21, Err(false)),
            (1, 22, Err(false)),
            (1, 23, Err(false)),
            (1, 24, Err(false)),
            // we will change epoch here
            (2, 25, Ok(true)),
            (2, 26, Err(false)),
            (2, 27, Err(false)),
            (2, 28, Err(false)),
        ],
    }

    #[cfg(not(feature = "abcipp"))]
    test_can_send_validator_set_update! {
        epoch_assertions: [
            // (current epoch, current block height, can send valset upd / Ok = change epoch)
            (0, 1, Ok(true)),
            (0, 2, Err(true)),
            (0, 3, Err(true)),
            (0, 4, Err(true)),
            (0, 5, Err(true)),
            (0, 6, Err(true)),
            (0, 7, Err(true)),
            (0, 8, Err(true)),
            (0, 9, Err(true)),
            (0, 10, Err(true)),
            (0, 11, Err(true)),
            // we will change epoch here
            (1, 12, Ok(true)),
            (1, 13, Err(true)),
            (1, 14, Err(true)),
            (1, 15, Err(true)),
            (1, 16, Err(true)),
            (1, 17, Err(true)),
            (1, 18, Err(true)),
            (1, 19, Err(true)),
            (1, 20, Err(true)),
            (1, 21, Err(true)),
            (1, 22, Err(true)),
            (1, 23, Err(true)),
            (1, 24, Err(true)),
            // we will change epoch here
            (2, 25, Ok(true)),
            (2, 26, Err(true)),
            (2, 27, Err(true)),
            (2, 28, Err(true)),
        ],
    }

    /// Test that reading the bridge pool works
    #[test]
    fn test_read_bridge_pool() {
        let (mut shell, _, _) = test_utils::setup();
        let transfer = PendingTransfer {
            transfer: TransferToEthereum {
                asset: EthAddress([0; 20]),
                recipient: EthAddress([0; 20]),
                sender: bertha_address(),
                amount: 0.into(),
                nonce: 0.into(),
            },
            gas_fee: GasFee {
                amount: 0.into(),
                payer: bertha_address(),
            },
        };

        // write a transfer into the bridge pool
        shell
            .storage
            .write(&get_pending_key(&transfer), transfer.clone())
            .expect("Test failed");

        // commit the changes and increase block height
        shell.storage.commit().expect("Test failed");
        shell.storage.block.height = shell.storage.block.height + 1;

        // check the response
        let resp = shell.read_ethereum_bridge_pool();
        assert_eq!(resp.code, 0);
        let pool =
            BTreeSet::<PendingTransfer>::try_from_slice(resp.value.as_slice())
                .expect("Test failed");
        assert_eq!(pool, BTreeSet::from([transfer]));
    }

    /// Test that reading the bridge pool always gets
    /// the latest pool
    #[test]
    fn test_bridge_pool_updates() {
        let (mut shell, _, _) = test_utils::setup();
        let transfer = PendingTransfer {
            transfer: TransferToEthereum {
                asset: EthAddress([0; 20]),
                recipient: EthAddress([0; 20]),
                sender: bertha_address(),
                amount: 0.into(),
                nonce: 0.into(),
            },
            gas_fee: GasFee {
                amount: 0.into(),
                payer: bertha_address(),
            },
        };

        // write a transfer into the bridge pool
        shell
            .storage
            .write(&get_pending_key(&transfer), transfer.clone())
            .expect("Test failed");

        // commit the changes and increase block height
        shell.storage.commit().expect("Test failed");
        shell.storage.block.height = shell.storage.block.height + 1;

        // update the pool
        shell
            .storage
            .delete(&get_pending_key(&transfer))
            .expect("Test failed");
        let mut transfer2 = transfer;
        transfer2.transfer.amount = 1.into();
        shell
            .storage
            .write(&get_pending_key(&transfer2), transfer2.clone())
            .expect("Test failed");

        // commit the changes and increase block height
        shell.storage.commit().expect("Test failed");
        shell.storage.block.height = shell.storage.block.height + 1;

        // check the response
        let resp = shell.read_ethereum_bridge_pool();
        assert_eq!(resp.code, 0);
        let pool =
            BTreeSet::<PendingTransfer>::try_from_slice(resp.value.as_slice())
                .expect("Test failed");
        assert_eq!(pool, BTreeSet::from([transfer2]));
    }

    /// Test that we can get a merkle proof even if the signed
    /// merkle roots is lagging behind the pool
    #[test]
    fn test_get_merkle_proof() {
        let (mut shell, _, _) = test_utils::setup();
        let transfer = PendingTransfer {
            transfer: TransferToEthereum {
                asset: EthAddress([0; 20]),
                recipient: EthAddress([0; 20]),
                sender: bertha_address(),
                amount: 0.into(),
                nonce: 0.into(),
            },
            gas_fee: GasFee {
                amount: 0.into(),
                payer: bertha_address(),
            },
        };

        // write a transfer into the bridge pool
        shell
            .storage
            .write(&get_pending_key(&transfer), transfer.clone())
            .expect("Test failed");

        // create a signed Merkle root for this pool
        let signed_root = MultiSignedMerkleRoot {
            sigs: Default::default(),
            root: transfer.keccak256(),
            height: Default::default(),
        };

        // commit the changes and increase block height
        shell.storage.commit().expect("Test failed");
        shell.storage.block.height = shell.storage.block.height + 1;

        // update the pool
        let mut transfer2 = transfer.clone();
        transfer2.transfer.amount = 1.into();
        shell
            .storage
            .write(&get_pending_key(&transfer2), transfer2.clone())
            .expect("Test failed");

        // add the signature for the pool at the previous block height
        shell
            .storage
            .write(&get_signed_root_key(), signed_root.try_to_vec().unwrap())
            .expect("Test failed");

        // commit the changes and increase block height
        shell.storage.commit().expect("Test failed");
        shell.storage.block.height = shell.storage.block.height + 1;

        let resp = shell.generate_bridge_pool_proof(
            vec![transfer.clone()].try_to_vec().expect("Test failed"),
        );
        assert_eq!(resp.code, 0);

        let tree = BridgePoolTree::new(
            transfer.keccak256(),
            BTreeSet::from([transfer.keccak256()]),
        );
        let proof = tree
            .get_membership_proof(vec![transfer])
            .expect("Test failed");

        let proof = RelayProof {
            validator_args: Default::default(),
            root: signed_root,
            proof,
            // TODO: Use a real nonce
            nonce: 0.into(),
        }
        .encode();
        assert_eq!(proof, resp.value);
    }

    /// Test if the no merkle tree including a transfer
    /// has had its root signed, then we cannot generate
    /// a proof.
    #[test]
    fn test_cannot_get_proof() {
        let (mut shell, _, _) = test_utils::setup();
        let transfer = PendingTransfer {
            transfer: TransferToEthereum {
                asset: EthAddress([0; 20]),
                recipient: EthAddress([0; 20]),
                sender: bertha_address(),
                amount: 0.into(),
                nonce: 0.into(),
            },
            gas_fee: GasFee {
                amount: 0.into(),
                payer: bertha_address(),
            },
        };

        // write a transfer into the bridge pool
        shell
            .storage
            .write(&get_pending_key(&transfer), transfer.clone())
            .expect("Test failed");

        // create a signed Merkle root for this pool
        let signed_root = MultiSignedMerkleRoot {
            sigs: Default::default(),
            root: transfer.keccak256(),
            height: Default::default(),
        };

        // commit the changes and increase block height
        shell.storage.commit().expect("Test failed");
        shell.storage.block.height = shell.storage.block.height + 1;

        // update the pool
        let mut transfer2 = transfer;
        transfer2.transfer.amount = 1.into();
        shell
            .storage
            .write(&get_pending_key(&transfer2), transfer2.clone())
            .expect("Test failed");

        // add the signature for the pool at the previous block height
        shell
            .storage
            .write(&get_signed_root_key(), signed_root.try_to_vec().unwrap())
            .expect("Test failed");

        // commit the changes and increase block height
        shell.storage.commit().expect("Test failed");
        shell.storage.block.height = shell.storage.block.height + 1;

        // this is in the pool, but its merkle root has not been signed yet
        let resp = shell.generate_bridge_pool_proof(
            vec![transfer2].try_to_vec().expect("Test failed"),
        );
        // thus proof generation should fail
        assert_eq!(resp.code, 1);
    }
}
