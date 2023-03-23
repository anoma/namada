//! Implementation of the [`RequestPrepareProposal`] ABCI++ method for the Shell

use namada::core::hints;
use namada::core::ledger::gas::TxGasMeter;
use namada::core::ledger::parameters;
use namada::ledger::gas::BlockGasMeter;
use namada::ledger::storage::{DBIter, StorageHasher, DB};
use namada::proof_of_stake::pos_queries::PosQueries;
use namada::ledger::storage_api::StorageRead;
use namada::proto::Tx;
use namada::types::internal::WrapperTxInQueue;
use namada::types::time::DateTimeUtc;
use namada::types::transaction::tx_types::TxType;
use namada::types::transaction::wrapper::wrapper_tx::PairingEngine;
use namada::types::transaction::{AffineCurve, DecryptedTx, EllipticCurve};

use super::super::*;
#[allow(unused_imports)]
use super::block_space_alloc;
use super::block_space_alloc::states::{
    BuildingDecryptedTxBatch, BuildingProtocolTxBatch,
    EncryptedTxBatchAllocator, NextState, TryAlloc,
};
use super::block_space_alloc::{AllocFailure, BlockSpaceAllocator};
#[cfg(feature = "abcipp")]
use crate::facade::tendermint_proto::abci::ExtendedCommitInfo;
use crate::facade::tendermint_proto::abci::RequestPrepareProposal;
use crate::facade::tendermint_proto::google::protobuf::Timestamp;
use crate::node::ledger::shell::{process_tx, ShellMode};
use crate::node::ledger::shims::abcipp_shim_types::shim::{response, TxBytes};

impl<D, H> Shell<D, H>
where
    D: DB + for<'iter> DBIter<'iter> + Sync + 'static,
    H: StorageHasher + Sync + 'static,
{
    /// Begin a new block.
    ///
    /// Block construction is documented in [`block_space_alloc`]
    /// and [`block_space_alloc::states`].
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
            let (encrypted_txs, alloc) =
                self.build_encrypted_txs(alloc, &req.txs, &req.time);
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
        block_time: &Option<Timestamp>,
    ) -> (Vec<TxBytes>, BlockSpaceAllocator<BuildingDecryptedTxBatch>) {
        let pos_queries = self.wl_storage.pos_queries();
        let block_time = block_time.clone().and_then(|block_time| {
            // If error in conversion, default to last block datetime, it's
            // valid because of mempool check
            TryInto::<DateTimeUtc>::try_into(block_time).ok()
        });
            let mut temp_block_gas_meter = BlockGasMeter::new(
                self.wl_storage
                    .read(&parameters::storage::get_max_block_gas_key())
                    .expect("Error while reading from storage")
                    .expect("Missing max_block_gas parameter in storage"),
            );

        let txs = txs
            .iter()
            .filter_map(|tx_bytes| {
                if let Ok(tx) = Tx::try_from(tx_bytes.as_slice()) {
                    // If tx doesn't have an expiration it is valid. If time cannot be
                    // retrieved from block default to last block datetime which has
                    // already been checked by mempool_validate, so it's valid
                    if let (Some(block_time), Some(exp)) = (block_time.as_ref(), &tx.expiration) {
                        if block_time > exp { return None }
                    }
                    if let Ok(TxType::Wrapper(wrapper)) = process_tx(tx) {

        // Check tx gas limit
        let mut tx_gas_meter = TxGasMeter::new(wrapper.gas_limit.into());
        if tx_gas_meter
            .add_tx_size_gas(tx_bytes.len()).is_err() {
                            return None;
                        }

                    if temp_block_gas_meter.try_finalize_transaction(tx_gas_meter).is_ok() {
                        return Some(tx_bytes.clone());
        }
                    }
                }
                None
            })
            .take_while(|tx_bytes| {
                alloc.try_alloc(&tx_bytes[..])
                    .map_or_else(
                        |status| match status {
                            AllocFailure::Rejected { bin_space_left } => {
                                tracing::debug!(
                                    tx_bytes_len = tx_bytes.len(),
                                    bin_space_left,
                                    proposal_height =
                                        ?pos_queries.get_current_decision_height(),
                                    "Dropping encrypted tx from the current proposal",
                                );
                                false
                            }
                            AllocFailure::OverflowsBin { bin_size } => {
                                // TODO: handle tx whose size is greater
                                // than bin size
                                tracing::warn!(
                                    tx_bytes_len = tx_bytes.len(),
                                    bin_size,
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
            .collect();
        let alloc = alloc.next_state();

        (txs, alloc)
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
        mut alloc: BlockSpaceAllocator<BuildingDecryptedTxBatch>,
    ) -> (Vec<TxBytes>, BlockSpaceAllocator<BuildingProtocolTxBatch>) {
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
                |WrapperTxInQueue {
                     tx,
                    gas: _, 
                     #[cfg(not(feature = "mainnet"))]
                     has_valid_pow,
                 }| {
                    Tx::from(match tx.decrypt(privkey) {
                        Ok(tx) => DecryptedTx::Decrypted {
                            tx,
                            #[cfg(not(feature = "mainnet"))]
                            has_valid_pow: *has_valid_pow,
                        },
                        _ => DecryptedTx::Undecryptable(tx.clone()),
                    })
                    .to_bytes()
                },
            )
            // TODO: make sure all decrypted txs are accepted
            .take_while(|tx_bytes| {
                alloc.try_alloc(&tx_bytes[..]).map_or_else(
                    |status| match status {
                        AllocFailure::Rejected { bin_space_left } => {
                            tracing::warn!(
                                tx_bytes_len = tx_bytes.len(),
                                bin_space_left,
                                proposal_height =
                                    ?pos_queries.get_current_decision_height(),
                                "Dropping decrypted tx from the current proposal",
                            );
                            false
                        }
                        AllocFailure::OverflowsBin { bin_size } => {
                            tracing::warn!(
                                tx_bytes_len = tx_bytes.len(),
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
    fn build_protocol_txs(
        &self,
        _alloc: BlockSpaceAllocator<BuildingProtocolTxBatch>,
        #[cfg(feature = "abcipp")] _local_last_commit: Option<
            ExtendedCommitInfo,
        >,
        #[cfg(not(feature = "abcipp"))] _txs: &[TxBytes],
    ) -> Vec<TxBytes> {
        // no protocol txs are implemented yet
        vec![]
    }
}

#[cfg(test)]
mod test_prepare_proposal {

    use borsh::BorshSerialize;
    use namada::proof_of_stake::Epoch;
    use namada::types::transaction::{Fee, WrapperTx};

    use super::*;
    use crate::node::ledger::shell::test_utils::{self, gen_keypair};

    const GAS_LIMIT_MULTIPLIER: u64 = 1;

    /// Test that if a tx from the mempool is not a
    /// WrapperTx type, it is not included in the
    /// proposed block.
    #[test]
    fn test_prepare_proposal_rejects_non_wrapper_tx() {
        let (shell, _) = test_utils::setup(1);
        let tx = Tx::new(
            "wasm_code".as_bytes().to_owned(),
            Some("transaction_data".as_bytes().to_owned()),
            shell.chain_id.clone(),
            None,
        );
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
        let (shell, _) = test_utils::setup(1);
        let keypair = gen_keypair();
        let tx = Tx::new(
            "wasm_code".as_bytes().to_owned(),
            Some("transaction_data".as_bytes().to_owned()),
            shell.chain_id.clone(),
            None,
        );
        // an unsigned wrapper will cause an error in processing
        let wrapper = Tx::new(
            "".as_bytes().to_owned(),
            Some(
                WrapperTx::new(
                    Fee {
                        amount: 0.into(),
                        token: shell.wl_storage.storage.native_token.clone(),
                    },
                    &keypair,
                    Epoch(0),
                    0.into(),
                    tx,
                    Default::default(),
                    #[cfg(not(feature = "mainnet"))]
                    None,
                )
                .try_to_vec()
                .expect("Test failed"),
            ),
            shell.chain_id.clone(),
            None,
        )
        .to_bytes();
        #[allow(clippy::redundant_clone)]
        let req = RequestPrepareProposal {
            txs: vec![wrapper.clone()],
            ..Default::default()
        };
        assert!(shell.prepare_proposal(req).txs.is_empty());
    }

    /// Test that the decrypted txs are included
    /// in the proposal in the same order as their
    /// corresponding wrappers
    #[test]
    fn test_decrypted_txs_in_correct_order() {
        let (mut shell, _) = test_utils::setup(1);
        let keypair = gen_keypair();
        let mut expected_wrapper = vec![];
        let mut expected_decrypted = vec![];

        let mut req = RequestPrepareProposal {
            txs: vec![],
            ..Default::default()
        };
        // create a request with two new wrappers from mempool and
        // two wrappers from the previous block to be decrypted
        for i in 0..2 {
            let tx = Tx::new(
                "wasm_code".as_bytes().to_owned(),
                Some(format!("transaction data: {}", i).as_bytes().to_owned()),
                shell.chain_id.clone(),
                None,
            );
            expected_decrypted.push(Tx::from(DecryptedTx::Decrypted {
                tx: tx.clone(),
                #[cfg(not(feature = "mainnet"))]
                has_valid_pow: false,
            }));
            let wrapper_tx = WrapperTx::new(
                Fee {
                    amount: 0.into(),
                    token: shell.wl_storage.storage.native_token.clone(),
                },
                &keypair,
                Epoch(0),
                GAS_LIMIT_MULTIPLIER.into(),
                tx,
                Default::default(),
                #[cfg(not(feature = "mainnet"))]
                None,
            );
            let wrapper = wrapper_tx
                .sign(&keypair, shell.chain_id.clone(), None)
                .expect("Test failed");
            shell.enqueue_tx(wrapper_tx, 0);
            expected_wrapper.push(wrapper.clone());
            req.txs.push(wrapper.to_bytes());
        }
        let expected_txs: Vec<TxBytes> = expected_wrapper
            .into_iter()
            .chain(expected_decrypted.into_iter())
            // we extract the inner data from the txs for testing
            // equality since otherwise changes in timestamps would
            // fail the test
            .map(|tx| tx.data.expect("Test failed"))
            .collect();
        let received: Vec<TxBytes> = shell
            .prepare_proposal(req)
            .txs
            .into_iter()
            .map(|tx_bytes| {
                Tx::try_from(tx_bytes.as_slice())
                    .expect("Test failed")
                    .data
                    .expect("Test failed")
            })
            .collect();
        // check that the order of the txs is correct
        assert_eq!(received, expected_txs);
    }

    /// Test that expired wrapper transactions are not included in the block
    #[test]
    fn test_expired_wrapper_tx() {
        let (shell, _) = test_utils::setup(1);
        let keypair = gen_keypair();
        let tx_time = DateTimeUtc::now();
        let tx = Tx::new(
            "wasm_code".as_bytes().to_owned(),
            Some("transaction data".as_bytes().to_owned()),
            shell.chain_id.clone(),
            None,
        );
        let wrapper_tx = WrapperTx::new(
            Fee {
                amount: 0.into(),
                token: shell.wl_storage.storage.native_token.clone(),
            },
            &keypair,
            Epoch(0),
            0.into(),
            tx,
            Default::default(),
            #[cfg(not(feature = "mainnet"))]
            None,
        );
        let wrapper = wrapper_tx
            .sign(&keypair, shell.chain_id.clone(), Some(tx_time))
            .expect("Test failed");

        let time = DateTimeUtc::now();
        let block_time =
            namada::core::tendermint_proto::google::protobuf::Timestamp {
                seconds: time.0.timestamp(),
                nanos: time.0.timestamp_subsec_nanos() as i32,
            };
        let req = RequestPrepareProposal {
            txs: vec![wrapper.to_bytes()],
            max_tx_bytes: 0,
            time: Some(block_time),
            ..Default::default()
        };
        let result = shell.prepare_proposal(req);
        eprintln!("Proposal: {:?}", result.txs);
        assert!(result.txs.is_empty());
    }

    /// Check that a tx requiring more gas than the block limit is not included in the block
    #[test]
    fn test_exceeding_max_block_gas_tx() {
        let (shell, _) = test_utils::setup(1);

        let block_gas_limit: u64 = shell
            .wl_storage
            .read(&parameters::storage::get_max_block_gas_key())
            .expect("Error while reading from storage")
            .expect("Missing max_block_gas parameter in storage");
        let keypair = gen_keypair();

        let tx = Tx::new(
            "wasm_code".as_bytes().to_owned(),
            Some("transaction data".as_bytes().to_owned()),
            shell.chain_id.clone(),
            None,
        );

        let wrapper = WrapperTx::new(
            Fee {
                amount: 100.into(),
                token: shell.wl_storage.storage.native_token.clone(),
            },
            &keypair,
            Epoch(0),
            (block_gas_limit + 1).into(),
            tx,
            Default::default(),
            #[cfg(not(feature = "mainnet"))]
            None,
        )
        .sign(&keypair, shell.chain_id.clone(), None)
        .expect("Wrapper signing failed");

        let req = RequestPrepareProposal {
            txs: vec![wrapper.to_bytes()],
            max_tx_bytes: 0,
            time: None,
            ..Default::default()
        };
        #[cfg(feature = "abcipp")]
        assert_eq!(
            shell.prepare_proposal(req).tx_records,
            vec![record::remove(wrapper.to_bytes())]
        );
        #[cfg(not(feature = "abcipp"))]
        {
            let result = shell.prepare_proposal(req);
            eprintln!("Proposal: {:?}", result.txs);
            assert!(result.txs.is_empty());
        }
    }

    // Check that a wrapper requiring more gas than its limit is not included in the block
    #[test]
    fn test_exceeding_gas_limit_wrapper() {
        let (shell, _) = test_utils::setup(1);
        let keypair = gen_keypair();

        let tx = Tx::new(
            "wasm_code".as_bytes().to_owned(),
            Some("transaction data".as_bytes().to_owned()),
            shell.chain_id.clone(),
            None,
        );

        let wrapper = WrapperTx::new(
            Fee {
                amount: 100.into(),
                token: shell.wl_storage.storage.native_token.clone(),
            },
            &keypair,
            Epoch(0),
            0.into(),
            tx,
            Default::default(),
            #[cfg(not(feature = "mainnet"))]
            None,
        )
        .sign(&keypair, shell.chain_id.clone(), None)
        .expect("Wrapper signing failed");

        let req = RequestPrepareProposal {
            txs: vec![wrapper.to_bytes()],
            max_tx_bytes: 0,
            time: None,
            ..Default::default()
        };
        #[cfg(feature = "abcipp")]
        assert_eq!(
            shell.prepare_proposal(req).tx_records,
            vec![record::remove(wrapper.to_bytes())]
        );
        #[cfg(not(feature = "abcipp"))]
        {
            let result = shell.prepare_proposal(req);
            eprintln!("Proposal: {:?}", result.txs);
            assert!(result.txs.is_empty());
        }
    }
}
