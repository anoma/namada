//! Implementation of the [`RequestPrepareProposal`] ABCI++ method for the Shell

use namada::core::hints;
use namada::core::ledger::gas::TxGasMeter;
#[cfg(feature = "abcipp")]
use namada::ledger::eth_bridge::{EthBridgeQueries, SendValsetUpd};
use namada::ledger::pos::PosQueries;
use namada::ledger::protocol::get_fee_unshielding_transaction;
use namada::ledger::storage::{DBIter, StorageHasher, TempWlStorage, DB};
use namada::proof_of_stake::find_validator_by_raw_hash;
use namada::proto::Tx;
use namada::types::address::Address;
use namada::types::internal::TxInQueue;
use namada::types::key::tm_raw_hash_to_string;
use namada::types::time::DateTimeUtc;
use namada::types::transaction::wrapper::wrapper_tx::PairingEngine;
use namada::types::transaction::{
    AffineCurve, DecryptedTx, EllipticCurve, TxType,
};
#[cfg(feature = "abcipp")]
use namada::types::vote_extensions::VoteExtensionDigest;
use namada::vm::wasm::{TxCache, VpCache};
use namada::vm::WasmCacheAccess;

use super::super::*;
use super::block_alloc::states::{
    BuildingDecryptedTxBatch, BuildingProtocolTxBatch,
    EncryptedTxBatchAllocator, NextState, TryAlloc,
};
use super::block_alloc::{AllocFailure, BlockAllocator, BlockResources};
#[cfg(feature = "abcipp")]
use crate::facade::tendermint_proto::abci::ExtendedCommitInfo;
use crate::facade::tendermint_proto::abci::RequestPrepareProposal;
#[cfg(feature = "abcipp")]
use crate::facade::tendermint_proto::abci::{tx_record::TxAction, TxRecord};
use crate::facade::tendermint_proto::google::protobuf::Timestamp;
#[cfg(feature = "abcipp")]
use crate::node::ledger::shell::vote_extensions::iter_protocol_txs;
use crate::node::ledger::shell::ShellMode;
use crate::node::ledger::shims::abcipp_shim_types::shim::{response, TxBytes};

impl<D, H> Shell<D, H>
where
    D: DB + for<'iter> DBIter<'iter> + Sync + 'static,
    H: StorageHasher + Sync + 'static,
{
    /// Begin a new block.
    ///
    /// Block construction is documented in `block_alloc`
    /// and `block_alloc::states` (private modules).
    ///
    /// INVARIANT: Any changes applied in this method must be reverted if
    /// the proposal is rejected (unless we can simply overwrite
    /// them in the next block).
    pub fn prepare_proposal(
        &self,
        req: RequestPrepareProposal,
    ) -> response::PrepareProposal {
        let txs = if let ShellMode::Validator { .. } = self.mode {
            // start counting allotted space for txs
            let alloc = self.get_encrypted_txs_allocator();

            // add encrypted txs
            let tm_raw_hash_string =
                tm_raw_hash_to_string(req.proposer_address);
            let block_proposer = find_validator_by_raw_hash(
                &self.wl_storage,
                tm_raw_hash_string,
            )
            .unwrap()
            .expect(
                "Unable to find native validator address of block proposer \
                 from tendermint raw hash",
            );
            let (encrypted_txs, alloc) = self.build_encrypted_txs(
                alloc,
                &req.txs,
                req.time,
                &block_proposer,
            );
            let mut txs = encrypted_txs;
            // decrypt the wrapper txs included in the previous block
            let (mut decrypted_txs, alloc) = self.build_decrypted_txs(alloc);
            txs.append(&mut decrypted_txs);

            // add vote extension protocol txs
            let mut protocol_txs = self.build_protocol_txs(
                alloc,
                #[cfg(feature = "abcipp")]
                req.local_last_commit,
                #[cfg(not(feature = "abcipp"))]
                &req.txs,
            );
            txs.append(&mut protocol_txs);

            txs
        } else {
            vec![]
        };

        tracing::info!(
            height = req.height,
            num_of_txs = txs.len(),
            "Proposing block"
        );

        response::PrepareProposal { txs }
    }

    /// Depending on the current block height offset within the epoch,
    /// transition state accordingly, return a block space allocator
    /// with or without encrypted txs.
    ///
    /// # How to determine which path to take in the states DAG
    ///
    /// If we are at the second or third block height offset within an
    /// epoch, we do not allow encrypted transactions to be included in
    /// a block, therefore we return an allocator wrapped in an
    /// [`EncryptedTxBatchAllocator::WithoutEncryptedTxs`] value.
    /// Otherwise, we return an allocator wrapped in an
    /// [`EncryptedTxBatchAllocator::WithEncryptedTxs`] value.
    #[inline]
    fn get_encrypted_txs_allocator(&self) -> EncryptedTxBatchAllocator {
        let pos_queries = self.wl_storage.pos_queries();

        let is_2nd_height_off = pos_queries.is_deciding_offset_within_epoch(1);
        let is_3rd_height_off = pos_queries.is_deciding_offset_within_epoch(2);

        if hints::unlikely(is_2nd_height_off || is_3rd_height_off) {
            tracing::warn!(
                proposal_height =
                    ?pos_queries.get_current_decision_height(),
                "No mempool txs are being included in the current proposal"
            );
            EncryptedTxBatchAllocator::WithoutEncryptedTxs(
                (&self.wl_storage).into(),
            )
        } else {
            EncryptedTxBatchAllocator::WithEncryptedTxs(
                (&self.wl_storage).into(),
            )
        }
    }

    /// Builds a batch of encrypted transactions, retrieved from
    /// Tendermint's mempool.
    fn build_encrypted_txs(
        &self,
        mut alloc: EncryptedTxBatchAllocator,
        txs: &[TxBytes],
        block_time: Option<Timestamp>,
        block_proposer: &Address,
    ) -> (Vec<TxBytes>, BlockAllocator<BuildingDecryptedTxBatch>) {
        let pos_queries = self.wl_storage.pos_queries();
        let block_time = block_time.and_then(|block_time| {
            // If error in conversion, default to last block datetime, it's
            // valid because of mempool check
            TryInto::<DateTimeUtc>::try_into(block_time).ok()
        });
        let mut temp_wl_storage = TempWlStorage::new(&self.wl_storage.storage);
        let mut vp_wasm_cache = self.vp_wasm_cache.clone();
        let mut tx_wasm_cache = self.tx_wasm_cache.clone();

        let txs = txs
            .iter()
            .filter_map(|tx_bytes| {
                match self.validate_wrapper_bytes(tx_bytes, block_time, &mut temp_wl_storage, &mut vp_wasm_cache, &mut tx_wasm_cache, block_proposer) {
                    Ok(gas) => {
                        temp_wl_storage.write_log.commit_tx();
                        Some((tx_bytes.to_owned(), gas))
                    },
                    Err(()) => {
                        temp_wl_storage.write_log.drop_tx();
                        None
                    }
                }
            })
            .take_while(|(tx_bytes, tx_gas)| {
                alloc.try_alloc(BlockResources::new(&tx_bytes[..], tx_gas.to_owned()))
                    .map_or_else(
                        |status| match status {
                            AllocFailure::Rejected { bin_resource_left} => {
                                tracing::debug!(
                                    ?tx_bytes,
                                    bin_resource_left,
                                    proposal_height =
                                        ?pos_queries.get_current_decision_height(),
                                    "Dropping encrypted tx from the current proposal",
                                );
                                false
                            }
                            AllocFailure::OverflowsBin { bin_resource} => {
                                // TODO: handle tx whose size is greater
                                // than bin size
                                tracing::warn!(
                                    ?tx_bytes,
                                    bin_resource,
                                    proposal_height =
                                        ?pos_queries.get_current_decision_height(),
                                    "Dropping large encrypted tx from the current proposal",
                                );
                                true
                            }
                        },
                        |()| true,
                    )
            })
            .map(|(tx, _)| tx)
            .collect();
        let alloc = alloc.next_state();

        (txs, alloc)
    }

    /// Validity checks on a wrapper tx
    #[allow(clippy::too_many_arguments)]
    fn validate_wrapper_bytes<CA>(
        &self,
        tx_bytes: &[u8],
        block_time: Option<DateTimeUtc>,
        temp_wl_storage: &mut TempWlStorage<D, H>,
        vp_wasm_cache: &mut VpCache<CA>,
        tx_wasm_cache: &mut TxCache<CA>,
        block_proposer: &Address,
    ) -> Result<u64, ()>
    where
        CA: 'static + WasmCacheAccess + Sync,
    {
        let tx = Tx::try_from(tx_bytes).map_err(|_| ())?;

        // If tx doesn't have an expiration it is valid. If time cannot be
        // retrieved from block default to last block datetime which has
        // already been checked by mempool_validate, so it's valid
        if let (Some(block_time), Some(exp)) =
            (block_time.as_ref(), &tx.header().expiration)
        {
            if block_time > exp {
                return Err(());
            }
        }

        tx.validate_tx().map_err(|_| ())?;
        if let TxType::Wrapper(wrapper) = tx.header().tx_type {
            // Check tx gas limit for tx size
            let mut tx_gas_meter = TxGasMeter::new(wrapper.gas_limit);
            tx_gas_meter.add_tx_size_gas(tx_bytes).map_err(|_| ())?;

            // Check replay protection
            self.replay_protection_checks(&tx, tx_bytes, temp_wl_storage)
                .map_err(|_| ())?;

            // Check fees
            match self.wrapper_fee_check(
                &wrapper,
                get_fee_unshielding_transaction(&tx, &wrapper),
                temp_wl_storage,
                vp_wasm_cache,
                tx_wasm_cache,
                Some(block_proposer),
            ) {
                Ok(()) => Ok(u64::from(wrapper.gas_limit)),
                Err(_) => Err(()),
            }
        } else {
            Err(())
        }
    }

    /// Builds a batch of DKG decrypted transactions.
    // NOTE: we won't have frontrunning protection until V2 of the
    // Anoma protocol; Namada runs V1, therefore this method is
    // essentially a NOOP
    //
    // sources:
    // - https://specs.namada.net/main/releases/v2.html
    // - https://github.com/anoma/ferveo
    fn build_decrypted_txs(
        &self,
        mut alloc: BlockAllocator<BuildingDecryptedTxBatch>,
    ) -> (Vec<TxBytes>, BlockAllocator<BuildingProtocolTxBatch>) {
        // TODO: This should not be hardcoded
        let privkey =
            <EllipticCurve as PairingEngine>::G2Affine::prime_subgroup_generator();
        let pos_queries = self.wl_storage.pos_queries();
        let txs = self
            .wl_storage
            .storage
            .tx_queue
            .iter()
            .map(
                |TxInQueue {
                     tx,
                     gas: _,
                }| {
                    let mut tx = tx.clone();
                    match tx.decrypt(privkey).ok()
                    {
                        Some(_) => {
                            tx.update_header(TxType::Decrypted(DecryptedTx::Decrypted));
                            tx
                        },
                        // An absent or undecryptable inner_tx are both
                        // treated as undecryptable
                        None => {
                            tx.update_header(TxType::Decrypted(
                                DecryptedTx::Undecryptable
                            ));
                            tx
                        },
                    }.to_bytes()
                },
            )
            // TODO: make sure all decrypted txs are accepted
            .take_while(|tx_bytes| {
                alloc.try_alloc(&tx_bytes[..]).map_or_else(
                    |status| match status {
                        AllocFailure::Rejected { bin_resource_left: bin_space_left } => {
                            tracing::warn!(
                                ?tx_bytes,
                                bin_space_left,
                                proposal_height =
                                    ?pos_queries.get_current_decision_height(),
                                "Dropping decrypted tx from the current proposal",
                            );
                            false
                        }
                        AllocFailure::OverflowsBin { bin_resource: bin_size } => {
                            tracing::warn!(
                                ?tx_bytes,
                                bin_size,
                                proposal_height =
                                    ?pos_queries.get_current_decision_height(),
                                "Dropping large decrypted tx from the current proposal",
                            );
                            true
                        }
                    },
                    |()| true,
                )
            })
            .collect();
        let alloc = alloc.next_state();

        (txs, alloc)
    }

    /// Builds a batch of protocol transactions.
    #[cfg(feature = "abcipp")]
    fn build_protocol_txs(
        &self,
        _alloc: BlockAllocator<BuildingProtocolTxBatch>,
        local_last_commit: Option<ExtendedCommitInfo>,
    ) -> Vec<TxBytes> {
        // genesis should not contain vote extensions.
        //
        // this is because we have not decided any block through
        // consensus yet (hence height 0), which in turn means we
        // have not committed any vote extensions to a block either.
        if self.wl_storage.storage.last_block.is_none() {
            return vec![];
        }

        let (eth_events, bp_roots, valset_upds) = self.split_vote_extensions(
            local_last_commit
                .expect(
                    "Honest Namada validators will always sign \
                     ethereum_events::Vext instances, even if no Ethereum \
                     events were observed at a given block height. In fact, a \
                     quorum of signed empty ethereum_events::Vext instances \
                     commits the fact no events were observed by a majority \
                     of validators. Therefore, for block heights greater than \
                     zero, we should always have vote extensions.",
                )
                .votes,
        );

        let ethereum_events = eth_events.map(|events| {
            self.compress_ethereum_events(events)
                .unwrap_or_else(|| panic!("{}", not_enough_voting_power_msg()))
        });

        let bp_roots = bp_roots.map(|bp_roots| {
            self.compress_bridge_pool_roots(bp_roots)
                .unwrap_or_else(|| panic!("{}", not_enough_voting_power_msg()))
        });

        let validator_set_update =
            if self
                .wl_storage
                .ethbridge_queries()
                .must_send_valset_upd(SendValsetUpd::AtPrevHeight)
            {
                Some(self.compress_valset_updates(valset_upds).unwrap_or_else(
                    || panic!("{}", not_enough_voting_power_msg()),
                ))
            } else {
                None
            };

        let protocol_key = self
            .mode
            .get_protocol_key()
            .expect("Validators should always have a protocol key");

        // TODO(feature = "abcipp"):
        // - alloc space for each protocol tx
        // - handle space allocation errors
        // - transition to new allocator state
        iter_protocol_txs(VoteExtensionDigest {
            ethereum_events,
            bridge_pool_roots: bp_roots,
            validator_set_update,
        })
        .map(|tx| tx.sign(protocol_key).to_bytes())
        .collect()
    }

    /// Builds a batch of protocol transactions.
    #[cfg(not(feature = "abcipp"))]
    fn build_protocol_txs(
        &self,
        mut alloc: BlockAllocator<BuildingProtocolTxBatch>,
        txs: &[TxBytes],
    ) -> Vec<TxBytes> {
        if self.wl_storage.storage.last_block.is_none() {
            // genesis should not contain vote extensions.
            //
            // this is because we have not decided any block through
            // consensus yet (hence height 0), which in turn means we
            // have not committed any vote extensions to a block either.
            return vec![];
        }

        let deserialized_iter = self.deserialize_vote_extensions(txs);
        let pos_queries = self.wl_storage.pos_queries();

        deserialized_iter.take_while(|tx_bytes|
            alloc.try_alloc(&tx_bytes[..])
                .map_or_else(
                    |status| match status {
                        AllocFailure::Rejected { bin_resource_left} => {
                            // TODO: maybe we should find a way to include
                            // validator set updates all the time. for instance,
                            // we could have recursive bins -> bin space within
                            // a bin is partitioned into yet more bins. so, we
                            // could have, say, 2/3 of the bin space available
                            // for eth events, and 1/3 available for valset
                            // upds. to be determined, as we implement CheckTx
                            // changes (issue #367)
                            tracing::debug!(
                                ?tx_bytes,
                                bin_resource_left,
                                proposal_height =
                                    ?pos_queries.get_current_decision_height(),
                                "Dropping protocol tx from the current proposal",
                            );
                            false
                        }
                        AllocFailure::OverflowsBin { bin_resource} => {
                            // TODO: handle tx whose size is greater
                            // than bin size
                            tracing::warn!(
                                ?tx_bytes,
                                bin_resource,
                                proposal_height =
                                    ?pos_queries.get_current_decision_height(),
                                "Dropping large protocol tx from the current proposal",
                            );
                            true
                        }
                    },
                    |()| true,
                )
        )
        .collect()
    }
}

/// Returns a suitable message to be displayed when Tendermint
/// somehow decides on a block containing vote extensions
/// reflecting `<= 2/3` of the total stake.
#[cfg(feature = "abcipp")]
const fn not_enough_voting_power_msg() -> &'static str {
    "A Tendermint quorum should never decide on a block including vote \
     extensions reflecting less than or equal to 2/3 of the total stake."
}

#[cfg(test)]
// TODO: write tests for validator set update vote extensions in
// prepare proposals
mod test_prepare_proposal {
    use std::collections::BTreeSet;
    #[cfg(feature = "abcipp")]
    use std::collections::{BTreeSet, HashMap};

    use borsh::BorshSerialize;
    use namada::core::ledger::storage_api::collections::lazy_map::{
        NestedSubKey, SubKey,
    };
    use namada::ledger::gas::Gas;
    use namada::ledger::pos::PosQueries;
    use namada::ledger::replay_protection;
    use namada::proof_of_stake::btree_set::BTreeSetShims;
    use namada::proof_of_stake::types::WeightedValidator;
    use namada::proof_of_stake::{
        consensus_validator_set_handle,
        read_consensus_validator_set_addresses_with_stake, Epoch,
    };
    #[cfg(feature = "abcipp")]
    use namada::proto::SignableEthMessage;
    use namada::proto::{Code, Data, Header, Section, Signature, Signed};
    use namada::types::address::{self, Address};
    use namada::types::ethereum_events::EthereumEvent;
    #[cfg(feature = "abcipp")]
    use namada::types::key::common;
    use namada::types::key::RefTo;
    use namada::types::storage::BlockHeight;
    use namada::types::token;
    use namada::types::token::Amount;
    use namada::types::transaction::protocol::EthereumTxData;
    use namada::types::transaction::{Fee, TxType, WrapperTx};
    #[cfg(feature = "abcipp")]
    use namada::types::vote_extensions::bridge_pool_roots;
    use namada::types::vote_extensions::ethereum_events;
    #[cfg(feature = "abcipp")]
    use namada::types::vote_extensions::VoteExtension;

    use super::*;
    #[cfg(feature = "abcipp")]
    use crate::facade::tendermint_proto::abci::{
        ExtendedCommitInfo, ExtendedVoteInfo,
    };
    #[cfg(feature = "abcipp")]
    use crate::node::ledger::shell::test_utils::deactivate_bridge;
    #[cfg(feature = "abcipp")]
    use crate::node::ledger::shell::test_utils::get_bp_bytes_to_sign;
    #[cfg(feature = "abcipp")]
    use crate::node::ledger::shell::test_utils::setup_at_height;
    use crate::node::ledger::shell::test_utils::{
        self, gen_keypair, get_pkh_from_address, TestShell,
    };
    use crate::node::ledger::shims::abcipp_shim_types::shim::request::FinalizeBlock;
    use crate::wallet;

    #[cfg(feature = "abcipp")]
    fn get_local_last_commit(shell: &TestShell) -> Option<ExtendedCommitInfo> {
        let validator_addr = shell
            .mode
            .get_validator_address()
            .expect("Test failed")
            .to_owned();
        let evts = {
            let prev_height = shell.wl_storage.storage.get_last_block_height();
            let ext = ethereum_events::Vext::empty(
                prev_height,
                validator_addr.clone(),
            );
            let protocol_key = match &shell.mode {
                ShellMode::Validator { data, .. } => {
                    &data.keys.protocol_keypair
                }
                _ => panic!("Test failed"),
            };
            ext.sign(protocol_key)
        };

        let bp_root = {
            let to_sign = get_bp_bytes_to_sign();
            let sig = Signed::<_, SignableEthMessage>::new(
                shell.mode.get_eth_bridge_keypair().expect("Test failed"),
                to_sign,
            )
            .sig;
            bridge_pool_roots::Vext {
                block_height: shell.wl_storage.storage.get_last_block_height(),
                validator_addr,
                sig,
            }
            .sign(shell.mode.get_protocol_key().expect("Test failed"))
        };

        let vote_extension = VoteExtension {
            ethereum_events: Some(evts),
            bridge_pool_root: Some(bp_root),
            validator_set_update: None,
        }
        .try_to_vec()
        .expect("Test failed");

        let vote = ExtendedVoteInfo {
            vote_extension,
            ..Default::default()
        };

        Some(ExtendedCommitInfo {
            votes: vec![vote],
            ..Default::default()
        })
    }

    /// Check if we are filtering out an invalid vote extension `vext`
    fn check_eth_events_filtering(
        shell: &TestShell,
        vext: Signed<ethereum_events::Vext>,
    ) {
        #[cfg(feature = "abcipp")]
        {
            let filtered_votes: Vec<_> =
                shell.filter_invalid_eth_events_vexts(vec![vext]).collect();
            assert_eq!(filtered_votes, vec![]);
        }
        #[cfg(not(feature = "abcipp"))]
        {
            let tx = EthereumTxData::EthEventsVext(vext)
                .sign(
                    shell.mode.get_protocol_key().expect("Test failed"),
                    shell.chain_id.clone(),
                )
                .to_bytes();
            let rsp = shell.mempool_validate(&tx, Default::default());
            assert!(rsp.code != 0, "{}", rsp.log);
        }
    }

    const GAS_LIMIT_MULTIPLIER: u64 = 300_000;

    /// Test that if a tx from the mempool is not a
    /// WrapperTx type, it is not included in the
    /// proposed block.
    #[test]
    fn test_prepare_proposal_rejects_non_wrapper_tx() {
        let (shell, _recv, _, _) = test_utils::setup();
        let mut tx = Tx::from_type(TxType::Decrypted(DecryptedTx::Decrypted));
        tx.header.chain_id = shell.chain_id.clone();
        let req = RequestPrepareProposal {
            txs: vec![tx.to_bytes()],
            ..Default::default()
        };
        assert!(shell.prepare_proposal(req).txs.is_empty());
    }

    /// Test that if an error is encountered while
    /// trying to process a tx from the mempool,
    /// we simply exclude it from the proposal
    #[test]
    fn test_error_in_processing_tx() {
        let (shell, _recv, _, _) = test_utils::setup();
        let keypair = gen_keypair();
        // an unsigned wrapper will cause an error in processing
        let mut wrapper =
            Tx::from_type(TxType::Wrapper(Box::new(WrapperTx::new(
                Fee {
                    amount_per_gas_unit: Default::default(),
                    token: shell.wl_storage.storage.native_token.clone(),
                },
                keypair.ref_to(),
                Epoch(0),
                Default::default(),
                None,
            ))));
        wrapper.header.chain_id = shell.chain_id.clone();
        wrapper.set_code(Code::new("wasm_code".as_bytes().to_owned()));
        wrapper.set_data(Data::new("transaction_data".as_bytes().to_owned()));
        let wrapper = wrapper.to_bytes();
        #[allow(clippy::redundant_clone)]
        let req = RequestPrepareProposal {
            txs: vec![wrapper.clone()],
            ..Default::default()
        };
        assert!(shell.prepare_proposal(req).txs.is_empty());
    }

    /// Test if we are filtering out Ethereum events with bad
    /// signatures in a prepare proposal.
    #[test]
    fn test_prepare_proposal_filter_out_bad_vext_signatures() {
        const LAST_HEIGHT: BlockHeight = BlockHeight(2);

        let (shell, _recv, _, _) = test_utils::setup_at_height(LAST_HEIGHT);

        let signed_vote_extension = {
            let (protocol_key, _, _) = wallet::defaults::validator_keys();
            let validator_addr = wallet::defaults::validator_address();

            // generate a valid signature
            let mut ext = ethereum_events::Vext {
                validator_addr,
                block_height: LAST_HEIGHT,
                ethereum_events: vec![],
            }
            .sign(&protocol_key);
            assert!(ext.verify(&protocol_key.ref_to()).is_ok());

            // modify this signature such that it becomes invalid
            ext.sig = test_utils::invalidate_signature(ext.sig);
            ext
        };

        check_eth_events_filtering(&shell, signed_vote_extension);
    }

    /// Test if we are filtering out Ethereum events seen at
    /// unexpected block heights.
    ///
    /// In case of ABCI++, we should only accept vote extensions
    /// from `last_height`, whereas with ABCI+, vote extensions
    /// before `last_height` are accepted. In either case, vote
    /// extensions after `last_height` aren't accepted.
    #[test]
    fn test_prepare_proposal_filter_out_bad_vext_bheights() {
        const LAST_HEIGHT: BlockHeight = BlockHeight(3);

        fn check_invalid(shell: &TestShell, height: BlockHeight) {
            let (protocol_key, _, _) = wallet::defaults::validator_keys();
            let validator_addr = wallet::defaults::validator_address();

            let signed_vote_extension = {
                let ext = ethereum_events::Vext {
                    validator_addr,
                    block_height: height,
                    ethereum_events: vec![],
                }
                .sign(&protocol_key);
                assert!(ext.verify(&protocol_key.ref_to()).is_ok());
                ext
            };

            check_eth_events_filtering(shell, signed_vote_extension);
        }

        let (shell, _recv, _, _) = test_utils::setup_at_height(LAST_HEIGHT);
        assert_eq!(
            shell.wl_storage.storage.get_last_block_height(),
            LAST_HEIGHT
        );

        check_invalid(&shell, LAST_HEIGHT + 2);
        check_invalid(&shell, LAST_HEIGHT + 1);
        check_invalid(&shell, 0.into());
        #[cfg(feature = "abcipp")]
        check_invalid(&shell, LAST_HEIGHT - 1);
        #[cfg(feature = "abcipp")]
        check_invalid(&shell, LAST_HEIGHT - 2);
    }

    /// Test if we are filtering out Ethereum events seen by
    /// non-validator nodes.
    #[test]
    fn test_prepare_proposal_filter_out_bad_vext_validators() {
        const LAST_HEIGHT: BlockHeight = BlockHeight(2);

        let (shell, _recv, _, _) = test_utils::setup_at_height(LAST_HEIGHT);

        let (validator_addr, protocol_key) = {
            let bertha_key = wallet::defaults::bertha_keypair();
            let bertha_addr = wallet::defaults::bertha_address();
            (bertha_addr, bertha_key)
        };

        let signed_vote_extension = {
            let ext = ethereum_events::Vext {
                validator_addr,
                block_height: LAST_HEIGHT,
                ethereum_events: vec![],
            }
            .sign(&protocol_key);
            assert!(ext.verify(&protocol_key.ref_to()).is_ok());
            ext
        };

        check_eth_events_filtering(&shell, signed_vote_extension);
    }

    /// Test if we are filtering out duped Ethereum events in
    /// prepare proposals.
    #[test]
    #[cfg(feature = "abcipp")]
    fn test_prepare_proposal_filter_duped_ethereum_events() {
        const LAST_HEIGHT: BlockHeight = BlockHeight(3);

        let (shell, _recv, _, _) = test_utils::setup_at_height(LAST_HEIGHT);

        let (protocol_key, _, _) = wallet::defaults::validator_keys();
        let validator_addr = wallet::defaults::validator_address();

        let ethereum_event = EthereumEvent::TransfersToNamada {
            nonce: 0u64.into(),
            transfers: vec![],
        };
        let signed_vote_extension = {
            let ev = ethereum_event;
            let ext = ethereum_events::Vext {
                validator_addr,
                block_height: LAST_HEIGHT,
                ethereum_events: vec![ev.clone(), ev.clone(), ev],
            }
            .sign(&protocol_key);
            assert!(ext.verify(&protocol_key.ref_to()).is_ok());
            ext
        };

        let maybe_digest =
            shell.compress_ethereum_events(vec![signed_vote_extension]);

        // we should be filtering out the vote extension with
        // duped ethereum events; therefore, no valid vote
        // extensions will remain, and we will get no
        // digest from compressing nil vote extensions
        assert!(maybe_digest.is_none());
    }

    /// Test that we do not include vote extensions voting on ethereum
    /// events or signing bridge pool roots + nonces if the bridge
    /// is inactive.
    #[test]
    #[cfg(feature = "abcipp")]
    fn test_filter_vexts_bridge_inactive() {
        let (mut shell, _, _, _) = setup_at_height(3);
        deactivate_bridge(&mut shell);
        let vext = get_local_last_commit(&shell);
        let rsp = shell.prepare_proposal(RequestPrepareProposal {
            local_last_commit: vext,
            ..Default::default()
        });
        assert!(rsp.txs.is_empty());
    }

    /// Creates an Ethereum events digest manually.
    #[cfg(feature = "abcipp")]
    fn manually_assemble_digest(
        _protocol_key: &common::SecretKey,
        ext: Signed<ethereum_events::Vext>,
        last_height: BlockHeight,
    ) -> ethereum_events::VextDigest {
        use namada::types::vote_extensions::ethereum_events::MultiSignedEthEvent;

        let events = vec![MultiSignedEthEvent {
            event: ext.data.ethereum_events[0].clone(),
            signers: {
                let mut s = BTreeSet::new();
                s.insert((ext.data.validator_addr.clone(), last_height));
                s
            },
        }];
        let signatures = {
            let mut s = HashMap::new();
            s.insert(
                (ext.data.validator_addr.clone(), last_height),
                ext.sig.clone(),
            );
            s
        };

        let vote_extension_digest =
            ethereum_events::VextDigest { events, signatures };

        assert_eq!(
            vec![ext],
            vote_extension_digest.clone().decompress(last_height)
        );

        vote_extension_digest
    }

    /// Test if Ethereum events validation and inclusion in a block
    /// behaves as expected, considering <= 2/3 voting power.
    #[test]
    #[cfg_attr(
        feature = "abcipp",
        should_panic(expected = "A Tendermint quorum should never")
    )]
    fn test_prepare_proposal_vext_insufficient_voting_power() {
        use crate::facade::tendermint_proto::abci::{Validator, VoteInfo};

        const FIRST_HEIGHT: BlockHeight = BlockHeight(1);
        const LAST_HEIGHT: BlockHeight = BlockHeight(FIRST_HEIGHT.0 + 11);

        let (mut shell, _recv, _, _oracle_control_recv) =
            test_utils::setup_with_cfg(test_utils::SetupCfg {
                last_height: FIRST_HEIGHT,
                num_validators: 2,
            });

        let params = shell.wl_storage.pos_queries().get_pos_params();

        // artificially change the voting power of the default validator to
        // one, change the block height, and commit a dummy block,
        // to move to a new epoch
        let events_epoch = shell
            .wl_storage
            .pos_queries()
            .get_epoch(FIRST_HEIGHT)
            .expect("Test failed");
        let validators_handle =
            consensus_validator_set_handle().at(&events_epoch);
        let consensus_in_mem = validators_handle
            .iter(&shell.wl_storage)
            .expect("Test failed")
            .map(|val| {
                let (
                    NestedSubKey::Data {
                        key: stake,
                        nested_sub_key: SubKey::Data(position),
                    },
                    address,
                ) = val.expect("Test failed");
                (stake, position, address)
            })
            .collect::<Vec<_>>();

        let mut consensus_set: BTreeSet<WeightedValidator> =
            read_consensus_validator_set_addresses_with_stake(
                &shell.wl_storage,
                Epoch::default(),
            )
            .unwrap()
            .into_iter()
            .collect();
        let val1 = consensus_set.pop_first_shim().unwrap();
        let val2 = consensus_set.pop_first_shim().unwrap();
        let pkh1 = get_pkh_from_address(
            &shell.wl_storage,
            &params,
            val1.address.clone(),
            Epoch::default(),
        );
        let pkh2 = get_pkh_from_address(
            &shell.wl_storage,
            &params,
            val2.address.clone(),
            Epoch::default(),
        );

        for (val_stake, val_position, address) in consensus_in_mem.into_iter() {
            if address == wallet::defaults::validator_address() {
                validators_handle
                    .at(&val_stake)
                    .remove(&mut shell.wl_storage, &val_position)
                    .expect("Test failed");
                validators_handle
                    .at(&1.into())
                    .insert(&mut shell.wl_storage, val_position, address)
                    .expect("Test failed");
            }
        }
        // Insert some stake for the second validator to prevent total stake
        // from going to 0

        let votes = vec![
            VoteInfo {
                validator: Some(Validator {
                    address: pkh1.clone(),
                    power: u128::try_from(val1.bonded_stake)
                        .expect("Test failed")
                        as i64,
                }),
                signed_last_block: true,
            },
            VoteInfo {
                validator: Some(Validator {
                    address: pkh2,
                    power: u128::try_from(val2.bonded_stake)
                        .expect("Test failed")
                        as i64,
                }),
                signed_last_block: true,
            },
        ];
        let req = FinalizeBlock {
            proposer_address: pkh1,
            votes,
            ..Default::default()
        };
        shell.start_new_epoch(Some(req));
        assert_eq!(
            shell.wl_storage.pos_queries().get_epoch(
                shell.wl_storage.pos_queries().get_current_decision_height()
            ),
            Some(Epoch(1))
        );

        // test prepare proposal
        let (protocol_key, _, _) = wallet::defaults::validator_keys();
        let validator_addr = wallet::defaults::validator_address();

        let ethereum_event = EthereumEvent::TransfersToNamada {
            nonce: 0u64.into(),
            transfers: vec![],
        };
        let signed_eth_ev_vote_extension = {
            let ext = ethereum_events::Vext {
                validator_addr,
                block_height: LAST_HEIGHT,
                ethereum_events: vec![ethereum_event],
            }
            .sign(&protocol_key);
            assert!(ext.verify(&protocol_key.ref_to()).is_ok());
            ext
        };

        #[cfg(feature = "abcipp")]
        {
            let bp_root = {
                let to_sign = get_bp_bytes_to_sign();
                let sig = Signed::<_, SignableEthMessage>::new(
                    shell.mode.get_eth_bridge_keypair().expect("Test failed"),
                    to_sign,
                )
                .sig;
                bridge_pool_roots::Vext {
                    block_height: shell
                        .wl_storage
                        .storage
                        .get_last_block_height(),
                    validator_addr: shell
                        .mode
                        .get_validator_address()
                        .unwrap()
                        .clone(),
                    sig,
                }
                .sign(shell.mode.get_protocol_key().expect("Test failed"))
            };
            let vote_extension = VoteExtension {
                ethereum_events: Some(signed_eth_ev_vote_extension),
                bridge_pool_root: Some(bp_root),
                validator_set_update: None,
            };
            let vote = ExtendedVoteInfo {
                vote_extension: vote_extension.try_to_vec().unwrap(),
                ..Default::default()
            };
            // this should panic
            shell.prepare_proposal(RequestPrepareProposal {
                local_last_commit: Some(ExtendedCommitInfo {
                    votes: vec![vote],
                    ..Default::default()
                }),
                ..Default::default()
            });
        }
        #[cfg(not(feature = "abcipp"))]
        {
            let vote = EthereumTxData::EthEventsVext(
                signed_eth_ev_vote_extension.clone(),
            )
            .sign(&protocol_key, shell.chain_id.clone())
            .to_bytes();
            let mut rsp = shell.prepare_proposal(RequestPrepareProposal {
                txs: vec![vote],
                ..Default::default()
            });
            assert_eq!(rsp.txs.len(), 1);

            let tx_bytes = rsp.txs.remove(0);
            let got = Tx::try_from(&tx_bytes[..]).unwrap();
            let eth_tx_data = (&got).try_into().expect("Test failed");
            let rsp_ext = match eth_tx_data {
                EthereumTxData::EthEventsVext(ext) => ext,
                _ => panic!("Test failed"),
            };

            assert_eq!(signed_eth_ev_vote_extension, rsp_ext);
        }
    }

    /// Test that the decrypted txs are included
    /// in the proposal in the same order as their
    /// corresponding wrappers
    #[test]
    fn test_decrypted_txs_in_correct_order() {
        let (mut shell, _recv, _, _) = test_utils::setup();
        let keypair = gen_keypair();
        let mut expected_wrapper = vec![];
        let mut expected_decrypted = vec![];

        // Load some tokens to tx signer to pay fees
        let balance_key = token::balance_key(
            &shell.wl_storage.storage.native_token,
            &Address::from(&keypair.ref_to()),
        );
        shell
            .wl_storage
            .storage
            .write(
                &balance_key,
                Amount::native_whole(1_000).try_to_vec().unwrap(),
            )
            .unwrap();

        let mut req = RequestPrepareProposal {
            txs: vec![],
            ..Default::default()
        };
        // create a request with two new wrappers from mempool and
        // two wrappers from the previous block to be decrypted
        for i in 0..2 {
            let mut tx =
                Tx::from_type(TxType::Wrapper(Box::new(WrapperTx::new(
                    Fee {
                        amount_per_gas_unit: 1.into(),
                        token: shell.wl_storage.storage.native_token.clone(),
                    },
                    keypair.ref_to(),
                    Epoch(0),
                    GAS_LIMIT_MULTIPLIER.into(),
                    None,
                ))));
            tx.header.chain_id = shell.chain_id.clone();
            tx.set_code(Code::new("wasm_code".as_bytes().to_owned()));
            tx.set_data(Data::new(
                format!("transaction data: {}", i).as_bytes().to_owned(),
            ));
            tx.add_section(Section::Signature(Signature::new(
                tx.sechashes(),
                [(0, keypair.clone())].into_iter().collect(),
                None,
            )));

            let gas = Gas::from(
                tx.header().wrapper().expect("Wrong tx type").gas_limit,
            )
            .checked_sub(Gas::from(tx.to_bytes().len() as u64))
            .unwrap();
            shell.enqueue_tx(tx.clone(), gas);
            expected_wrapper.push(tx.clone());
            req.txs.push(tx.to_bytes());
            tx.update_header(TxType::Decrypted(DecryptedTx::Decrypted));
            expected_decrypted.push(tx.clone());
        }
        // we extract the inner data from the txs for testing
        // equality since otherwise changes in timestamps would
        // fail the test
        let expected_txs: Vec<Header> = expected_wrapper
            .into_iter()
            .chain(expected_decrypted.into_iter())
            .map(|tx| tx.header)
            .collect();
        let received: Vec<Header> = shell
            .prepare_proposal(req)
            .txs
            .into_iter()
            .map(|tx_bytes| {
                Tx::try_from(tx_bytes.as_slice())
                    .expect("Test failed")
                    .header
            })
            .collect();
        // check that the order of the txs is correct
        assert_eq!(
            received
                .iter()
                .map(|x| x.try_to_vec().unwrap())
                .collect::<Vec<_>>(),
            expected_txs
                .iter()
                .map(|x| x.try_to_vec().unwrap())
                .collect::<Vec<_>>(),
        );
    }

    /// Test that if the unsigned wrapper tx hash is known (replay attack), the
    /// transaction is not included in the block
    #[test]
    fn test_wrapper_tx_hash() {
        let (mut shell, _recv, _, _) = test_utils::setup();

        let keypair = crate::wallet::defaults::daewon_keypair();
        let mut wrapper =
            Tx::from_type(TxType::Wrapper(Box::new(WrapperTx::new(
                Fee {
                    amount_per_gas_unit: 0.into(),
                    token: shell.wl_storage.storage.native_token.clone(),
                },
                keypair.ref_to(),
                Epoch(0),
                Default::default(),
                None,
            ))));
        wrapper.header.chain_id = shell.chain_id.clone();
        wrapper.set_code(Code::new("wasm_code".as_bytes().to_owned()));
        wrapper.set_data(Data::new("transaction data".as_bytes().to_owned()));
        wrapper.add_section(Section::Signature(Signature::new(
            wrapper.sechashes(),
            [(0, keypair)].into_iter().collect(),
            None,
        )));

        // Write wrapper hash to storage
        let wrapper_unsigned_hash = wrapper.header_hash();
        let hash_key = replay_protection::get_replay_protection_key(
            &wrapper_unsigned_hash,
        );
        shell
            .wl_storage
            .storage
            .write(&hash_key, vec![])
            .expect("Test failed");

        let req = RequestPrepareProposal {
            txs: vec![wrapper.to_bytes()],
            ..Default::default()
        };

        let received =
            shell.prepare_proposal(req).txs.into_iter().map(|tx_bytes| {
                Tx::try_from(tx_bytes.as_slice())
                    .expect("Test failed")
                    .data()
                    .expect("Test failed")
            });
        assert_eq!(received.len(), 0);
    }

    /// Test that if two identical wrapper txs are proposed for this block, only
    /// one gets accepted
    #[test]
    fn test_wrapper_tx_hash_same_block() {
        let (shell, _recv, _, _) = test_utils::setup();

        let keypair = crate::wallet::defaults::daewon_keypair();
        let mut wrapper =
            Tx::from_type(TxType::Wrapper(Box::new(WrapperTx::new(
                Fee {
                    amount_per_gas_unit: 1.into(),
                    token: shell.wl_storage.storage.native_token.clone(),
                },
                keypair.ref_to(),
                Epoch(0),
                GAS_LIMIT_MULTIPLIER.into(),
                None,
            ))));
        wrapper.header.chain_id = shell.chain_id.clone();
        wrapper.set_code(Code::new("wasm_code".as_bytes().to_owned()));
        wrapper.set_data(Data::new("transaction data".as_bytes().to_owned()));
        wrapper.add_section(Section::Signature(Signature::new(
            wrapper.sechashes(),
            [(0, keypair)].into_iter().collect(),
            None,
        )));

        let req = RequestPrepareProposal {
            txs: vec![wrapper.to_bytes(); 2],
            ..Default::default()
        };
        let received =
            shell.prepare_proposal(req).txs.into_iter().map(|tx_bytes| {
                Tx::try_from(tx_bytes.as_slice())
                    .expect("Test failed")
                    .data()
                    .expect("Test failed")
            });
        assert_eq!(received.len(), 1);
    }

    /// Test that if the unsigned inner tx hash is known (replay attack), the
    /// transaction is not included in the block
    #[test]
    fn test_inner_tx_hash() {
        let (mut shell, _recv, _, _) = test_utils::setup();

        let keypair = crate::wallet::defaults::daewon_keypair();
        let mut wrapper =
            Tx::from_type(TxType::Wrapper(Box::new(WrapperTx::new(
                Fee {
                    amount_per_gas_unit: Amount::zero(),
                    token: shell.wl_storage.storage.native_token.clone(),
                },
                keypair.ref_to(),
                Epoch(0),
                Default::default(),
                None,
            ))));
        wrapper.header.chain_id = shell.chain_id.clone();
        wrapper.set_code(Code::new("wasm_code".as_bytes().to_owned()));
        wrapper.set_data(Data::new("transaction data".as_bytes().to_owned()));
        wrapper.add_section(Section::Signature(Signature::new(
            wrapper.sechashes(),
            [(0, keypair)].into_iter().collect(),
            None,
        )));
        let inner_unsigned_hash =
            wrapper.clone().update_header(TxType::Raw).header_hash();

        // Write inner hash to storage
        let hash_key =
            replay_protection::get_replay_protection_key(&inner_unsigned_hash);
        shell
            .wl_storage
            .storage
            .write(&hash_key, vec![])
            .expect("Test failed");

        let req = RequestPrepareProposal {
            txs: vec![wrapper.to_bytes()],
            ..Default::default()
        };

        let received =
            shell.prepare_proposal(req).txs.into_iter().map(|tx_bytes| {
                Tx::try_from(tx_bytes.as_slice())
                    .expect("Test failed")
                    .data()
                    .expect("Test failed")
            });
        assert_eq!(received.len(), 0);
    }

    /// Test that if two identical decrypted txs are proposed for this block,
    /// only one gets accepted
    #[test]
    fn test_inner_tx_hash_same_block() {
        let (shell, _recv, _, _) = test_utils::setup();

        let keypair = crate::wallet::defaults::daewon_keypair();
        let keypair_2 = crate::wallet::defaults::daewon_keypair();
        let mut wrapper =
            Tx::from_type(TxType::Wrapper(Box::new(WrapperTx::new(
                Fee {
                    amount_per_gas_unit: 1.into(),
                    token: shell.wl_storage.storage.native_token.clone(),
                },
                keypair.ref_to(),
                Epoch(0),
                GAS_LIMIT_MULTIPLIER.into(),
                None,
            ))));
        wrapper.header.chain_id = shell.chain_id.clone();
        let tx_code = Code::new("wasm_code".as_bytes().to_owned());
        wrapper.set_code(tx_code);
        let tx_data = Data::new("transaction data".as_bytes().to_owned());
        wrapper.set_data(tx_data);
        let mut new_wrapper = wrapper.clone();
        wrapper.add_section(Section::Signature(Signature::new(
            wrapper.sechashes(),
            [(0, keypair)].into_iter().collect(),
            None,
        )));

        new_wrapper.update_header(TxType::Wrapper(Box::new(WrapperTx::new(
            Fee {
                amount_per_gas_unit: 1.into(),
                token: shell.wl_storage.storage.native_token.clone(),
            },
            keypair_2.ref_to(),
            Epoch(0),
            GAS_LIMIT_MULTIPLIER.into(),
            None,
        ))));
        new_wrapper.add_section(Section::Signature(Signature::new(
            wrapper.sechashes(),
            [(0, keypair_2)].into_iter().collect(),
            None,
        )));

        let req = RequestPrepareProposal {
            txs: vec![wrapper.to_bytes(), new_wrapper.to_bytes()],
            ..Default::default()
        };
        let received =
            shell.prepare_proposal(req).txs.into_iter().map(|tx_bytes| {
                Tx::try_from(tx_bytes.as_slice())
                    .expect("Test failed")
                    .data()
                    .expect("Test failed")
            });
        assert_eq!(received.len(), 1);
    }

    /// Test that expired wrapper transactions are not included in the block
    #[test]
    fn test_expired_wrapper_tx() {
        let (shell, _recv, _, _) = test_utils::setup();
        let keypair = gen_keypair();
        let mut wrapper_tx =
            Tx::from_type(TxType::Wrapper(Box::new(WrapperTx::new(
                Fee {
                    amount_per_gas_unit: 1.into(),
                    token: shell.wl_storage.storage.native_token.clone(),
                },
                keypair.ref_to(),
                Epoch(0),
                Default::default(),
                None,
            ))));
        wrapper_tx.header.chain_id = shell.chain_id.clone();
        wrapper_tx.header.expiration = Some(DateTimeUtc::default());
        wrapper_tx.set_code(Code::new("wasm_code".as_bytes().to_owned()));
        wrapper_tx
            .set_data(Data::new("transaction data".as_bytes().to_owned()));
        wrapper_tx.add_section(Section::Signature(Signature::new(
            wrapper_tx.sechashes(),
            [(0, keypair)].into_iter().collect(),
            None,
        )));

        let time = DateTimeUtc::now();
        let block_time =
            namada::core::tendermint_proto::google::protobuf::Timestamp {
                seconds: time.0.timestamp(),
                nanos: time.0.timestamp_subsec_nanos() as i32,
            };
        let req = RequestPrepareProposal {
            txs: vec![wrapper_tx.to_bytes()],
            max_tx_bytes: 0,
            time: Some(block_time),
            ..Default::default()
        };
        let result = shell.prepare_proposal(req);
        eprintln!("Proposal: {:?}", result.txs);
        assert_eq!(result.txs.len(), 0);
    }

    /// Check that a tx requiring more gas than the block limit is not included
    /// in the block
    #[test]
    fn test_exceeding_max_block_gas_tx() {
        let (shell, _recv, _, _) = test_utils::setup();

        let block_gas_limit =
            namada::core::ledger::gas::get_max_block_gas(&shell.wl_storage)
                .unwrap();
        let keypair = gen_keypair();

        let wrapper = WrapperTx::new(
            Fee {
                amount_per_gas_unit: 100.into(),
                token: shell.wl_storage.storage.native_token.clone(),
            },
            keypair.ref_to(),
            Epoch(0),
            (block_gas_limit + 1).into(),
            None,
        );
        let mut wrapper_tx = Tx::from_type(TxType::Wrapper(Box::new(wrapper)));
        wrapper_tx.header.chain_id = shell.chain_id.clone();
        wrapper_tx.set_code(Code::new("wasm_code".as_bytes().to_owned()));
        wrapper_tx
            .set_data(Data::new("transaction data".as_bytes().to_owned()));
        wrapper_tx.add_section(Section::Signature(Signature::new(
            wrapper_tx.sechashes(),
            [(0, keypair)].into_iter().collect(),
            None,
        )));

        let req = RequestPrepareProposal {
            txs: vec![wrapper_tx.to_bytes()],
            max_tx_bytes: 0,
            time: None,
            ..Default::default()
        };
        let result = shell.prepare_proposal(req);
        eprintln!("Proposal: {:?}", result.txs);
        assert!(result.txs.is_empty());
    }

    // Check that a wrapper requiring more gas than its limit is not included in
    // the block
    #[test]
    fn test_exceeding_gas_limit_wrapper() {
        let (shell, _recv, _, _) = test_utils::setup();
        let keypair = gen_keypair();

        let wrapper = WrapperTx::new(
            Fee {
                amount_per_gas_unit: 100.into(),
                token: shell.wl_storage.storage.native_token.clone(),
            },
            keypair.ref_to(),
            Epoch(0),
            0.into(),
            None,
        );

        let mut wrapper_tx = Tx::from_type(TxType::Wrapper(Box::new(wrapper)));
        wrapper_tx.header.chain_id = shell.chain_id.clone();
        wrapper_tx.set_code(Code::new("wasm_code".as_bytes().to_owned()));
        wrapper_tx
            .set_data(Data::new("transaction data".as_bytes().to_owned()));
        wrapper_tx.add_section(Section::Signature(Signature::new(
            wrapper_tx.sechashes(),
            [(0, keypair)].into_iter().collect(),
            None,
        )));

        let req = RequestPrepareProposal {
            txs: vec![wrapper_tx.to_bytes()],
            max_tx_bytes: 0,
            time: None,
            ..Default::default()
        };
        let result = shell.prepare_proposal(req);
        eprintln!("Proposal: {:?}", result.txs);
        assert!(result.txs.is_empty());
    }

    // Check that a wrapper using a non-whitelisted token for fee payment is not
    // included in the block
    #[test]
    fn test_fee_non_whitelisted_token() {
        let (shell, _recv, _, _) = test_utils::setup();

        let wrapper = WrapperTx::new(
            Fee {
                amount_per_gas_unit: 100.into(),
                token: address::btc(),
            },
            crate::wallet::defaults::albert_keypair().ref_to(),
            Epoch(0),
            GAS_LIMIT_MULTIPLIER.into(),
            None,
        );

        let mut wrapper_tx = Tx::from_type(TxType::Wrapper(Box::new(wrapper)));
        wrapper_tx.header.chain_id = shell.chain_id.clone();
        wrapper_tx.set_code(Code::new("wasm_code".as_bytes().to_owned()));
        wrapper_tx
            .set_data(Data::new("transaction data".as_bytes().to_owned()));
        wrapper_tx.add_section(Section::Signature(Signature::new(
            wrapper_tx.sechashes(),
            [(0, crate::wallet::defaults::albert_keypair())]
                .into_iter()
                .collect(),
            None,
        )));

        let req = RequestPrepareProposal {
            txs: vec![wrapper_tx.to_bytes()],
            max_tx_bytes: 0,
            time: None,
            ..Default::default()
        };
        let result = shell.prepare_proposal(req);
        eprintln!("Proposal: {:?}", result.txs);
        assert!(result.txs.is_empty());
    }

    // Check that a wrapper setting a fee amount lower than the minimum required
    // is not included in the block
    #[test]
    fn test_fee_wrong_minimum_amount() {
        let (shell, _recv, _, _) = test_utils::setup();

        let wrapper = WrapperTx::new(
            Fee {
                amount_per_gas_unit: 0.into(),
                token: shell.wl_storage.storage.native_token.clone(),
            },
            crate::wallet::defaults::albert_keypair().ref_to(),
            Epoch(0),
            GAS_LIMIT_MULTIPLIER.into(),
            None,
        );
        let mut wrapper_tx = Tx::from_type(TxType::Wrapper(Box::new(wrapper)));
        wrapper_tx.header.chain_id = shell.chain_id.clone();
        wrapper_tx.set_code(Code::new("wasm_code".as_bytes().to_owned()));
        wrapper_tx
            .set_data(Data::new("transaction data".as_bytes().to_owned()));
        wrapper_tx.add_section(Section::Signature(Signature::new(
            wrapper_tx.sechashes(),
            [(0, crate::wallet::defaults::albert_keypair())]
                .into_iter()
                .collect(),
            None,
        )));

        let req = RequestPrepareProposal {
            txs: vec![wrapper_tx.to_bytes()],
            max_tx_bytes: 0,
            time: None,
            ..Default::default()
        };
        let result = shell.prepare_proposal(req);
        eprintln!("Proposal: {:?}", result.txs);
        assert!(result.txs.is_empty());
    }

    // Check that a wrapper transactions whose fees cannot be paid is rejected
    #[test]
    fn test_insufficient_balance_for_fee() {
        let (shell, _recv, _, _) = test_utils::setup();

        let wrapper = WrapperTx::new(
            Fee {
                amount_per_gas_unit: 1_000_000_000.into(),
                token: shell.wl_storage.storage.native_token.clone(),
            },
            crate::wallet::defaults::albert_keypair().ref_to(),
            Epoch(0),
            GAS_LIMIT_MULTIPLIER.into(),
            None,
        );
        let mut wrapper_tx = Tx::from_type(TxType::Wrapper(Box::new(wrapper)));
        wrapper_tx.header.chain_id = shell.chain_id.clone();
        wrapper_tx.set_code(Code::new("wasm_code".as_bytes().to_owned()));
        wrapper_tx
            .set_data(Data::new("transaction data".as_bytes().to_owned()));
        wrapper_tx.add_section(Section::Signature(Signature::new(
            wrapper_tx.sechashes(),
            [(0, crate::wallet::defaults::albert_keypair())]
                .into_iter()
                .collect(),
            None,
        )));

        let req = RequestPrepareProposal {
            txs: vec![wrapper_tx.to_bytes()],
            max_tx_bytes: 0,
            time: None,
            ..Default::default()
        };
        let result = shell.prepare_proposal(req);
        eprintln!("Proposal: {:?}", result.txs);
        assert!(result.txs.is_empty());
    }

    // Check that a fee overflow in the wrapper transaction is rejected
    #[test]
    fn test_wrapper_fee_overflow() {
        let (shell, _recv, _, _) = test_utils::setup();

        let wrapper = WrapperTx::new(
            Fee {
                amount_per_gas_unit: token::Amount::max(),
                token: shell.wl_storage.storage.native_token.clone(),
            },
            crate::wallet::defaults::albert_keypair().ref_to(),
            Epoch(0),
            GAS_LIMIT_MULTIPLIER.into(),
            None,
        );
        let mut wrapper_tx = Tx::from_type(TxType::Wrapper(Box::new(wrapper)));
        wrapper_tx.header.chain_id = shell.chain_id.clone();
        wrapper_tx.set_code(Code::new("wasm_code".as_bytes().to_owned()));
        wrapper_tx
            .set_data(Data::new("transaction data".as_bytes().to_owned()));
        wrapper_tx.add_section(Section::Signature(Signature::new(
            wrapper_tx.sechashes(),
            [(0, crate::wallet::defaults::albert_keypair())]
                .into_iter()
                .collect(),
            None,
        )));

        let req = RequestPrepareProposal {
            txs: vec![wrapper_tx.to_bytes()],
            max_tx_bytes: 0,
            time: None,
            ..Default::default()
        };
        let result = shell.prepare_proposal(req);
        eprintln!("Proposal: {:?}", result.txs);
        assert!(result.txs.is_empty());
    }
}
