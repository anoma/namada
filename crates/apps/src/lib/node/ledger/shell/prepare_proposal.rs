//! Implementation of the [`RequestPrepareProposal`] ABCI++ method for the Shell

use namada::core::hints;
use namada::gas::TxGasMeter;
use namada::ledger::protocol::get_fee_unshielding_transaction;
use namada::ledger::storage::tx_queue::TxInQueue;
use namada::proof_of_stake::storage::find_validator_by_raw_hash;
use namada::state::{DBIter, StorageHasher, TempWlStorage, DB};
use namada::tx::data::{DecryptedTx, TxType};
use namada::tx::Tx;
use namada::types::address::Address;
use namada::types::key::tm_raw_hash_to_string;
use namada::types::time::DateTimeUtc;
use namada::vm::wasm::{TxCache, VpCache};
use namada::vm::WasmCacheAccess;

use super::super::*;
use super::block_alloc::states::{
    BuildingDecryptedTxBatch, BuildingProtocolTxBatch,
    EncryptedTxBatchAllocator, NextState, TryAlloc,
};
use super::block_alloc::{AllocFailure, BlockAllocator, BlockResources};
use crate::facade::tendermint_proto::google::protobuf::Timestamp;
use crate::facade::tendermint_proto::v0_37::abci::RequestPrepareProposal;
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
            let mut protocol_txs = self.build_protocol_txs(alloc, &req.txs);
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
        let is_2nd_height_off = self.is_deciding_offset_within_epoch(1);
        let is_3rd_height_off = self.is_deciding_offset_within_epoch(2);

        if hints::unlikely(is_2nd_height_off || is_3rd_height_off) {
            tracing::warn!(
                proposal_height =
                    ?self.wl_storage.storage.block.height,
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
                                        ?self.get_current_decision_height(),
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
                                        ?self.get_current_decision_height(),
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
            tx_gas_meter.add_wrapper_gas(tx_bytes).map_err(|_| ())?;

            self.replay_protection_checks(&tx, temp_wl_storage)
                .map_err(|_| ())?;

            // Check fees
            match self.wrapper_fee_check(
                &wrapper,
                get_fee_unshielding_transaction(&tx, &wrapper),
                temp_wl_storage,
                vp_wasm_cache,
                tx_wasm_cache,
                Some(block_proposer),
                true,
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
                    tx.update_header(TxType::Decrypted(DecryptedTx::Decrypted));
                    tx.to_bytes().into()
                },
            )
            // TODO: make sure all decrypted txs are accepted
            .take_while(|tx_bytes: &TxBytes| {
                alloc.try_alloc(&tx_bytes[..]).map_or_else(
                    |status| match status {
                        AllocFailure::Rejected { bin_resource_left: bin_space_left } => {
                            tracing::warn!(
                                ?tx_bytes,
                                bin_space_left,
                                proposal_height =
                                    ?self.get_current_decision_height(),
                                "Dropping decrypted tx from the current proposal",
                            );
                            false
                        }
                        AllocFailure::OverflowsBin { bin_resource: bin_size } => {
                            tracing::warn!(
                                ?tx_bytes,
                                bin_size,
                                proposal_height =
                                    ?self.get_current_decision_height(),
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
                                    ?self.get_current_decision_height(),
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
                                    ?self.get_current_decision_height(),
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

#[cfg(test)]
// TODO: write tests for validator set update vote extensions in
// prepare proposals
mod test_prepare_proposal {
    use std::collections::BTreeSet;

    use borsh_ext::BorshSerializeExt;
    use namada::ledger::gas::Gas;
    use namada::ledger::pos::PosQueries;
    use namada::ledger::replay_protection;
    use namada::proof_of_stake::storage::{
        consensus_validator_set_handle,
        read_consensus_validator_set_addresses_with_stake,
    };
    use namada::proof_of_stake::types::WeightedValidator;
    use namada::proof_of_stake::Epoch;
    use namada::state::collections::lazy_map::{NestedSubKey, SubKey};
    use namada::token;
    use namada::token::{read_denom, Amount, DenominatedAmount};
    use namada::tx::data::{Fee, TxType, WrapperTx};
    use namada::tx::{Code, Data, Header, Section, Signature, Signed};
    use namada::types::address::{self, Address};
    use namada::types::ethereum_events::EthereumEvent;
    use namada::types::key::RefTo;
    use namada::types::storage::{BlockHeight, InnerEthEventsQueue};
    use namada::vote_ext::{ethereum_events, ethereum_tx_data_variants};

    use super::*;
    use crate::config::ValidatorLocalConfig;
    use crate::node::ledger::shell::test_utils::{
        self, gen_keypair, get_pkh_from_address, TestShell,
    };
    use crate::node::ledger::shell::EthereumTxData;
    use crate::node::ledger::shims::abcipp_shim_types::shim::request::FinalizeBlock;
    use crate::wallet;

    /// Check if we are filtering out an invalid vote extension `vext`
    fn check_eth_events_filtering(
        shell: &TestShell,
        vext: Signed<ethereum_events::Vext>,
    ) {
        let tx = EthereumTxData::EthEventsVext(vext.into())
            .sign(
                shell.mode.get_protocol_key().expect("Test failed"),
                shell.chain_id.clone(),
            )
            .to_bytes();
        let rsp = shell.mempool_validate(&tx, Default::default());
        assert!(rsp.code != 0.into(), "{}", rsp.log);
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
            txs: vec![tx.to_bytes().into()],
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
                    amount_per_gas_unit: DenominatedAmount::native(
                        Default::default(),
                    ),
                    token: shell.wl_storage.storage.native_token.clone(),
                },
                keypair.ref_to(),
                Epoch(0),
                Default::default(),
                None,
            ))));
        wrapper.header.chain_id = shell.chain_id.clone();
        wrapper.set_code(Code::new("wasm_code".as_bytes().to_owned(), None));
        wrapper.set_data(Data::new("transaction_data".as_bytes().to_owned()));
        let wrapper = wrapper.to_bytes();
        #[allow(clippy::redundant_clone)]
        let req = RequestPrepareProposal {
            txs: vec![wrapper.clone().into()],
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
            let (protocol_key, _) = wallet::defaults::validator_keys();
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
            let (protocol_key, _) = wallet::defaults::validator_keys();
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

    /// Test if Ethereum events validation and inclusion in a block
    /// behaves as expected, considering <= 2/3 voting power.
    #[test]
    fn test_prepare_proposal_vext_insufficient_voting_power() {
        use namada::tendermint::abci::types::{Validator, VoteInfo};

        const FIRST_HEIGHT: BlockHeight = BlockHeight(1);
        const LAST_HEIGHT: BlockHeight = BlockHeight(FIRST_HEIGHT.0 + 11);

        let (mut shell, _recv, _, _oracle_control_recv) =
            test_utils::setup_with_cfg(test_utils::SetupCfg {
                last_height: FIRST_HEIGHT,
                num_validators: 2,
                ..Default::default()
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
        let val1 = consensus_set.pop_first().unwrap();
        let val2 = consensus_set.pop_first().unwrap();
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
                validator: Validator {
                    address: pkh1,
                    power: (u128::try_from(val1.bonded_stake).expect("Test failed") as u64).try_into().unwrap(),
                },
                sig_info: crate::facade::tendermint::abci::types::BlockSignatureInfo::LegacySigned,
            },
            VoteInfo {
                validator: Validator {
                    address: pkh2,
                    power: (u128::try_from(val2.bonded_stake).expect("Test failed") as u64).try_into().unwrap(),
                },
                sig_info: crate::facade::tendermint::abci::types::BlockSignatureInfo::LegacySigned,
            },
        ];
        let req = FinalizeBlock {
            proposer_address: pkh1.to_vec(),
            votes,
            ..Default::default()
        };
        shell.start_new_epoch(Some(req));
        assert_eq!(
            shell
                .wl_storage
                .pos_queries()
                .get_epoch(shell.get_current_decision_height()),
            Some(Epoch(1))
        );

        // test prepare proposal
        let (protocol_key, _) = wallet::defaults::validator_keys();
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

        let vote = EthereumTxData::EthEventsVext(
            signed_eth_ev_vote_extension.clone().into(),
        )
        .sign(&protocol_key, shell.chain_id.clone())
        .to_bytes();
        let mut rsp = shell.prepare_proposal(RequestPrepareProposal {
            txs: vec![vote.into()],
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

        assert_eq!(signed_eth_ev_vote_extension, rsp_ext.0);
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
        let balance_key = token::storage_key::balance_key(
            &shell.wl_storage.storage.native_token,
            &Address::from(&keypair.ref_to()),
        );
        shell
            .wl_storage
            .storage
            .write(&balance_key, Amount::native_whole(1_000).serialize_to_vec())
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
                        amount_per_gas_unit: DenominatedAmount::native(
                            1.into(),
                        ),
                        token: shell.wl_storage.storage.native_token.clone(),
                    },
                    keypair.ref_to(),
                    Epoch(0),
                    GAS_LIMIT_MULTIPLIER.into(),
                    None,
                ))));
            tx.header.chain_id = shell.chain_id.clone();
            tx.set_code(Code::new("wasm_code".as_bytes().to_owned(), None));
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
            req.txs.push(tx.to_bytes().into());
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
                Tx::try_from(tx_bytes.as_ref()).expect("Test failed").header
            })
            .collect();
        // check that the order of the txs is correct
        assert_eq!(
            received
                .iter()
                .map(|x| x.serialize_to_vec())
                .collect::<Vec<_>>(),
            expected_txs
                .iter()
                .map(|x| x.serialize_to_vec())
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
                    amount_per_gas_unit: DenominatedAmount::native(0.into()),
                    token: shell.wl_storage.storage.native_token.clone(),
                },
                keypair.ref_to(),
                Epoch(0),
                Default::default(),
                None,
            ))));
        wrapper.header.chain_id = shell.chain_id.clone();
        wrapper.set_code(Code::new("wasm_code".as_bytes().to_owned(), None));
        wrapper.set_data(Data::new("transaction data".as_bytes().to_owned()));
        wrapper.add_section(Section::Signature(Signature::new(
            wrapper.sechashes(),
            [(0, keypair)].into_iter().collect(),
            None,
        )));

        // Write wrapper hash to storage
        let wrapper_unsigned_hash = wrapper.header_hash();
        let hash_key = replay_protection::last_key(&wrapper_unsigned_hash);
        shell
            .wl_storage
            .storage
            .write(&hash_key, vec![])
            .expect("Test failed");

        let req = RequestPrepareProposal {
            txs: vec![wrapper.to_bytes().into()],
            ..Default::default()
        };

        let received_txs = shell.prepare_proposal(req).txs;
        assert_eq!(received_txs.len(), 0);
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
                    amount_per_gas_unit: DenominatedAmount::native(1.into()),
                    token: shell.wl_storage.storage.native_token.clone(),
                },
                keypair.ref_to(),
                Epoch(0),
                GAS_LIMIT_MULTIPLIER.into(),
                None,
            ))));
        wrapper.header.chain_id = shell.chain_id.clone();
        wrapper.set_code(Code::new("wasm_code".as_bytes().to_owned(), None));
        wrapper.set_data(Data::new("transaction data".as_bytes().to_owned()));
        wrapper.add_section(Section::Signature(Signature::new(
            wrapper.sechashes(),
            [(0, keypair)].into_iter().collect(),
            None,
        )));

        let req = RequestPrepareProposal {
            txs: vec![wrapper.to_bytes().into(); 2],
            ..Default::default()
        };
        let received_txs = shell.prepare_proposal(req).txs;
        assert_eq!(received_txs.len(), 1);
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
                    amount_per_gas_unit: DenominatedAmount::native(
                        Amount::zero(),
                    ),
                    token: shell.wl_storage.storage.native_token.clone(),
                },
                keypair.ref_to(),
                Epoch(0),
                Default::default(),
                None,
            ))));
        wrapper.header.chain_id = shell.chain_id.clone();
        wrapper.set_code(Code::new("wasm_code".as_bytes().to_owned(), None));
        wrapper.set_data(Data::new("transaction data".as_bytes().to_owned()));
        wrapper.add_section(Section::Signature(Signature::new(
            wrapper.sechashes(),
            [(0, keypair)].into_iter().collect(),
            None,
        )));
        let inner_unsigned_hash = wrapper.raw_header_hash();

        // Write inner hash to storage
        let hash_key = replay_protection::last_key(&inner_unsigned_hash);
        shell
            .wl_storage
            .storage
            .write(&hash_key, vec![])
            .expect("Test failed");

        let req = RequestPrepareProposal {
            txs: vec![wrapper.to_bytes().into()],
            ..Default::default()
        };

        let received_txs = shell.prepare_proposal(req).txs;
        assert_eq!(received_txs.len(), 0);
    }

    /// Test that if two identical decrypted txs are proposed for this block,
    /// both get accepted
    #[test]
    fn test_inner_tx_hash_same_block() {
        let (shell, _recv, _, _) = test_utils::setup();

        let keypair = crate::wallet::defaults::daewon_keypair();
        let keypair_2 = crate::wallet::defaults::albert_keypair();
        let mut wrapper =
            Tx::from_type(TxType::Wrapper(Box::new(WrapperTx::new(
                Fee {
                    amount_per_gas_unit: DenominatedAmount::native(1.into()),
                    token: shell.wl_storage.storage.native_token.clone(),
                },
                keypair.ref_to(),
                Epoch(0),
                GAS_LIMIT_MULTIPLIER.into(),
                None,
            ))));
        wrapper.header.chain_id = shell.chain_id.clone();
        let tx_code = Code::new("wasm_code".as_bytes().to_owned(), None);
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
                amount_per_gas_unit: DenominatedAmount::native(1.into()),
                token: shell.wl_storage.storage.native_token.clone(),
            },
            keypair_2.ref_to(),
            Epoch(0),
            GAS_LIMIT_MULTIPLIER.into(),
            None,
        ))));
        new_wrapper.add_section(Section::Signature(Signature::new(
            new_wrapper.sechashes(),
            [(0, keypair_2)].into_iter().collect(),
            None,
        )));

        let req = RequestPrepareProposal {
            txs: vec![wrapper.to_bytes().into(), new_wrapper.to_bytes().into()],
            ..Default::default()
        };
        let received_txs = shell.prepare_proposal(req).txs;
        assert_eq!(received_txs.len(), 2);
    }

    /// Test that expired wrapper transactions are not included in the block
    #[test]
    fn test_expired_wrapper_tx() {
        let (shell, _recv, _, _) = test_utils::setup();
        let keypair = gen_keypair();
        let mut wrapper_tx =
            Tx::from_type(TxType::Wrapper(Box::new(WrapperTx::new(
                Fee {
                    amount_per_gas_unit: DenominatedAmount::native(1.into()),
                    token: shell.wl_storage.storage.native_token.clone(),
                },
                keypair.ref_to(),
                Epoch(0),
                Default::default(),
                None,
            ))));
        wrapper_tx.header.chain_id = shell.chain_id.clone();
        wrapper_tx.header.expiration = Some(DateTimeUtc::default());
        wrapper_tx.set_code(Code::new("wasm_code".as_bytes().to_owned(), None));
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
            txs: vec![wrapper_tx.to_bytes().into()],
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
            namada::parameters::get_max_block_gas(&shell.wl_storage).unwrap();
        let keypair = gen_keypair();

        let wrapper = WrapperTx::new(
            Fee {
                amount_per_gas_unit: DenominatedAmount::native(100.into()),
                token: shell.wl_storage.storage.native_token.clone(),
            },
            keypair.ref_to(),
            Epoch(0),
            (block_gas_limit + 1).into(),
            None,
        );
        let mut wrapper_tx = Tx::from_type(TxType::Wrapper(Box::new(wrapper)));
        wrapper_tx.header.chain_id = shell.chain_id.clone();
        wrapper_tx.set_code(Code::new("wasm_code".as_bytes().to_owned(), None));
        wrapper_tx
            .set_data(Data::new("transaction data".as_bytes().to_owned()));
        wrapper_tx.add_section(Section::Signature(Signature::new(
            wrapper_tx.sechashes(),
            [(0, keypair)].into_iter().collect(),
            None,
        )));

        let req = RequestPrepareProposal {
            txs: vec![wrapper_tx.to_bytes().into()],
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
                amount_per_gas_unit: DenominatedAmount::native(100.into()),
                token: shell.wl_storage.storage.native_token.clone(),
            },
            keypair.ref_to(),
            Epoch(0),
            0.into(),
            None,
        );

        let mut wrapper_tx = Tx::from_type(TxType::Wrapper(Box::new(wrapper)));
        wrapper_tx.header.chain_id = shell.chain_id.clone();
        wrapper_tx.set_code(Code::new("wasm_code".as_bytes().to_owned(), None));
        wrapper_tx
            .set_data(Data::new("transaction data".as_bytes().to_owned()));
        wrapper_tx.add_section(Section::Signature(Signature::new(
            wrapper_tx.sechashes(),
            [(0, keypair)].into_iter().collect(),
            None,
        )));

        let req = RequestPrepareProposal {
            txs: vec![wrapper_tx.to_bytes().into()],
            max_tx_bytes: 0,
            time: None,
            ..Default::default()
        };
        let result = shell.prepare_proposal(req);
        eprintln!("Proposal: {:?}", result.txs);
        assert!(result.txs.is_empty());
    }

    // Check that a wrapper using a token not accepted byt the validator for fee
    // payment is not included in the block
    #[test]
    fn test_fee_non_accepted_token() {
        let (mut shell, _recv, _, _) = test_utils::setup();
        // Update local validator configuration for gas tokens
        if let ShellMode::Validator { local_config, .. } = &mut shell.mode {
            // Remove the allowed btc
            *local_config = Some(ValidatorLocalConfig {
                accepted_gas_tokens: std::collections::HashMap::from([(
                    namada::types::address::nam(),
                    Amount::from(1),
                )]),
            });
        }

        let btc_denom = read_denom(&shell.wl_storage, &address::btc())
            .expect("unable to read denomination from storage")
            .expect("unable to find denomination of btcs");

        let wrapper = WrapperTx::new(
            Fee {
                amount_per_gas_unit: DenominatedAmount::new(
                    100.into(),
                    btc_denom,
                ),
                token: address::btc(),
            },
            crate::wallet::defaults::albert_keypair().ref_to(),
            Epoch(0),
            GAS_LIMIT_MULTIPLIER.into(),
            None,
        );

        let mut wrapper_tx = Tx::from_type(TxType::Wrapper(Box::new(wrapper)));
        wrapper_tx.header.chain_id = shell.chain_id.clone();
        wrapper_tx.set_code(Code::new("wasm_code".as_bytes().to_owned(), None));
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
            txs: vec![wrapper_tx.to_bytes().into()],
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

        let apfel_denom = read_denom(&shell.wl_storage, &address::apfel())
            .expect("unable to read denomination from storage")
            .expect("unable to find denomination of apfels");

        let wrapper = WrapperTx::new(
            Fee {
                amount_per_gas_unit: DenominatedAmount::new(
                    100.into(),
                    apfel_denom,
                ),
                token: address::apfel(),
            },
            crate::wallet::defaults::albert_keypair().ref_to(),
            Epoch(0),
            GAS_LIMIT_MULTIPLIER.into(),
            None,
        );

        let mut wrapper_tx = Tx::from_type(TxType::Wrapper(Box::new(wrapper)));
        wrapper_tx.header.chain_id = shell.chain_id.clone();
        wrapper_tx.set_code(Code::new("wasm_code".as_bytes().to_owned(), None));
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
            txs: vec![wrapper_tx.to_bytes().into()],
            max_tx_bytes: 0,
            time: None,
            ..Default::default()
        };
        let result = shell.prepare_proposal(req);
        eprintln!("Proposal: {:?}", result.txs);
        assert!(result.txs.is_empty());
    }

    // Check that a wrapper setting a fee amount lower than the minimum accepted
    // by the validator is not included in the block
    #[test]
    fn test_fee_wrong_minimum_accepted_amount() {
        let (mut shell, _recv, _, _) = test_utils::setup();
        // Update local validator configuration for gas tokens
        if let ShellMode::Validator { local_config, .. } = &mut shell.mode {
            // Remove btc and increase minimum for nam
            *local_config = Some(ValidatorLocalConfig {
                accepted_gas_tokens: std::collections::HashMap::from([(
                    namada::types::address::nam(),
                    Amount::from(100),
                )]),
            });
        }

        let wrapper = WrapperTx::new(
            Fee {
                amount_per_gas_unit: DenominatedAmount::native(10.into()),
                token: shell.wl_storage.storage.native_token.clone(),
            },
            crate::wallet::defaults::albert_keypair().ref_to(),
            Epoch(0),
            GAS_LIMIT_MULTIPLIER.into(),
            None,
        );
        let mut wrapper_tx = Tx::from_type(TxType::Wrapper(Box::new(wrapper)));
        wrapper_tx.header.chain_id = shell.chain_id.clone();
        wrapper_tx.set_code(Code::new("wasm_code".as_bytes().to_owned(), None));
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
            txs: vec![wrapper_tx.to_bytes().into()],
            max_tx_bytes: 0,
            time: None,
            ..Default::default()
        };
        let result = shell.prepare_proposal(req);
        eprintln!("Proposal: {:?}", result.txs);
        assert!(result.txs.is_empty());
    }

    // Check that a wrapper setting a fee amount lower than the minimum allowed
    // is not included in the block
    #[test]
    fn test_fee_wrong_minimum_amount() {
        let (shell, _recv, _, _) = test_utils::setup();

        let wrapper = WrapperTx::new(
            Fee {
                amount_per_gas_unit: DenominatedAmount::native(0.into()),
                token: shell.wl_storage.storage.native_token.clone(),
            },
            crate::wallet::defaults::albert_keypair().ref_to(),
            Epoch(0),
            GAS_LIMIT_MULTIPLIER.into(),
            None,
        );
        let mut wrapper_tx = Tx::from_type(TxType::Wrapper(Box::new(wrapper)));
        wrapper_tx.header.chain_id = shell.chain_id.clone();
        wrapper_tx.set_code(Code::new("wasm_code".as_bytes().to_owned(), None));
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
            txs: vec![wrapper_tx.to_bytes().into()],
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
                amount_per_gas_unit: DenominatedAmount::native(
                    1_000_000_000.into(),
                ),
                token: shell.wl_storage.storage.native_token.clone(),
            },
            crate::wallet::defaults::albert_keypair().ref_to(),
            Epoch(0),
            GAS_LIMIT_MULTIPLIER.into(),
            None,
        );
        let mut wrapper_tx = Tx::from_type(TxType::Wrapper(Box::new(wrapper)));
        wrapper_tx.header.chain_id = shell.chain_id.clone();
        wrapper_tx.set_code(Code::new("wasm_code".as_bytes().to_owned(), None));
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
            txs: vec![wrapper_tx.to_bytes().into()],
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
                amount_per_gas_unit: DenominatedAmount::native(
                    token::Amount::max(),
                ),
                token: shell.wl_storage.storage.native_token.clone(),
            },
            crate::wallet::defaults::albert_keypair().ref_to(),
            Epoch(0),
            GAS_LIMIT_MULTIPLIER.into(),
            None,
        );
        let mut wrapper_tx = Tx::from_type(TxType::Wrapper(Box::new(wrapper)));
        wrapper_tx.header.chain_id = shell.chain_id.clone();
        wrapper_tx.set_code(Code::new("wasm_code".as_bytes().to_owned(), None));
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
            txs: vec![wrapper_tx.to_bytes().into()],
            max_tx_bytes: 0,
            time: None,
            ..Default::default()
        };
        let result = shell.prepare_proposal(req);
        eprintln!("Proposal: {:?}", result.txs);
        assert!(result.txs.is_empty());
    }

    /// Test that Ethereum events with outdated nonces are
    /// not proposed during `PrepareProposal`.
    #[test]
    fn test_outdated_nonce_proposal() {
        const LAST_HEIGHT: BlockHeight = BlockHeight(3);

        let (mut shell, _recv, _, _) = test_utils::setup_at_height(LAST_HEIGHT);
        shell
            .wl_storage
            .storage
            .eth_events_queue
            // sent transfers to namada nonce to 5
            .transfers_to_namada = InnerEthEventsQueue::new_at(5.into());

        let (protocol_key, _) = wallet::defaults::validator_keys();
        let validator_addr = wallet::defaults::validator_address();

        // test an extension containing solely events with
        // bad nonces
        {
            let ethereum_event = EthereumEvent::TransfersToNamada {
                // outdated nonce (3 < 5)
                nonce: 3u64.into(),
                transfers: vec![],
            };
            let ext = {
                let ext = ethereum_events::Vext {
                    validator_addr: validator_addr.clone(),
                    block_height: LAST_HEIGHT,
                    ethereum_events: vec![ethereum_event],
                }
                .sign(&protocol_key);
                assert!(ext.verify(&protocol_key.ref_to()).is_ok());
                ext
            };
            let tx = EthereumTxData::EthEventsVext(ext.into())
                .sign(&protocol_key, shell.chain_id.clone())
                .to_bytes();
            let req = RequestPrepareProposal {
                txs: vec![tx.into()],
                ..Default::default()
            };
            let proposed_txs =
                shell.prepare_proposal(req).txs.into_iter().map(|tx_bytes| {
                    Tx::try_from(tx_bytes.as_ref()).expect("Test failed")
                });
            // since no events with valid nonces are contained in the vote
            // extension, we drop it from the proposal
            for tx in proposed_txs {
                if ethereum_tx_data_variants::EthEventsVext::try_from(&tx)
                    .is_ok()
                {
                    panic!(
                        "No ethereum events should have been found in the \
                         proposal"
                    );
                }
            }
        }

        // test an extension containing at least one event
        // with a good nonce
        {
            let event1 = EthereumEvent::TransfersToNamada {
                // outdated nonce (3 < 5)
                nonce: 3u64.into(),
                transfers: vec![],
            };
            let event2 = EthereumEvent::TransfersToNamada {
                // outdated nonce (10 >= 5)
                nonce: 10u64.into(),
                transfers: vec![],
            };
            let ext = {
                let ext = ethereum_events::Vext {
                    validator_addr,
                    block_height: LAST_HEIGHT,
                    ethereum_events: vec![event1, event2.clone()],
                }
                .sign(&protocol_key);
                assert!(ext.verify(&protocol_key.ref_to()).is_ok());
                ext
            };
            let tx = EthereumTxData::EthEventsVext(ext.into())
                .sign(&protocol_key, shell.chain_id.clone())
                .to_bytes();
            let req = RequestPrepareProposal {
                txs: vec![tx.into()],
                ..Default::default()
            };
            let proposed_txs =
                shell.prepare_proposal(req).txs.into_iter().map(|tx_bytes| {
                    Tx::try_from(tx_bytes.as_ref()).expect("Test failed")
                });
            // find the event with the good nonce
            let mut ext = 'ext: {
                for tx in proposed_txs {
                    if let Ok(ext) =
                        ethereum_tx_data_variants::EthEventsVext::try_from(&tx)
                    {
                        break 'ext ext;
                    }
                }
                panic!("No ethereum events found in proposal");
            };
            assert_eq!(ext.data.ethereum_events.len(), 2);
            let found_event = ext.0.data.ethereum_events.remove(1);
            assert_eq!(found_event, event2);
        }
    }
}
