//! Implementation of the [`RequestPrepareProposal`] ABCI++ method for the Shell

use namada::core::hints;
use namada::ledger::storage::{DBIter, StorageHasher, TempWlStorage, DB};
use namada::proof_of_stake::pos_queries::PosQueries;
use namada::proto::Tx;
use namada::types::internal::TxInQueue;
use namada::types::time::DateTimeUtc;
use namada::types::transaction::wrapper::wrapper_tx::PairingEngine;
use namada::types::transaction::{
    AffineCurve, DecryptedTx, EllipticCurve, TxType,
};

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
#[cfg(feature = "abcipp")]
use crate::facade::tendermint_proto::abci::{tx_record::TxAction, TxRecord};
use crate::facade::tendermint_proto::google::protobuf::Timestamp;
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
        // start counting allotted space for txs
        let alloc = self.get_encrypted_txs_allocator();
        // add encrypted txs
        let (encrypted_txs, alloc) = self.build_encrypted_txs(
            alloc,
            TempWlStorage::new(&self.wl_storage.storage),
            &req.txs,
            &req.time,
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
        mut temp_wl_storage: TempWlStorage<D, H>,
        txs: &[TxBytes],
        block_time: &Option<Timestamp>,
    ) -> (Vec<TxBytes>, BlockSpaceAllocator<BuildingDecryptedTxBatch>) {
        let pos_queries = self.wl_storage.pos_queries();
        let block_time = block_time.clone().and_then(|block_time| {
            // If error in conversion, default to last block datetime, it's
            // valid because of mempool check
            TryInto::<DateTimeUtc>::try_into(block_time).ok()
        });
        let txs = txs
            .iter()
            .filter_map(|tx_bytes| {
                if let Ok(tx) = Tx::try_from(tx_bytes.as_slice()) {
                    // If tx doesn't have an expiration it is valid. If time cannot be
                    // retrieved from block default to last block datetime which has
                    // already been checked by mempool_validate, so it's valid
                    if let (Some(block_time), Some(exp)) = (block_time.as_ref(), &tx.header.expiration) {
                        if block_time > exp { return None }
                    }
                    if tx.validate_tx().is_ok() && tx.header().wrapper().is_some() && self.replay_protection_checks(&tx, tx_bytes.as_slice(), &mut temp_wl_storage).is_ok() {
                        return Some(tx_bytes.clone());
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
                |TxInQueue {
                     tx,
                     #[cfg(not(feature = "mainnet"))]
                     has_valid_pow,
                }| {
                    let mut tx = tx.clone();
                    match tx.decrypt(privkey).ok()
                    {
                        Some(()) => {
                            tx.update_header(TxType::Decrypted(DecryptedTx::Decrypted {
                                #[cfg(not(feature = "mainnet"))]
                                has_valid_pow: *has_valid_pow,
                            }));
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
    use namada::ledger::replay_protection;
    use namada::proof_of_stake::Epoch;
    use namada::proto::{Code, Data, Header, Section, Signature};
    use namada::types::transaction::{Fee, WrapperTx};

    use super::*;
    use crate::node::ledger::shell::test_utils::{self, gen_keypair};

    /// Test that if a tx from the mempool is not a
    /// WrapperTx type, it is not included in the
    /// proposed block.
    #[test]
    fn test_prepare_proposal_rejects_non_wrapper_tx() {
        let (shell, _) = test_utils::setup(1);
        let mut tx = Tx::new(TxType::Decrypted(DecryptedTx::Decrypted {
            has_valid_pow: true,
        }));
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
        let (shell, _) = test_utils::setup(1);
        let keypair = gen_keypair();
        // an unsigned wrapper will cause an error in processing
        let mut wrapper = Tx::new(TxType::Wrapper(Box::new(WrapperTx::new(
            Fee {
                amount: 0.into(),
                token: shell.wl_storage.storage.native_token.clone(),
            },
            &keypair,
            Epoch(0),
            Default::default(),
            #[cfg(not(feature = "mainnet"))]
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
            let mut tx = Tx::new(TxType::Wrapper(Box::new(WrapperTx::new(
                Fee {
                    amount: Default::default(),
                    token: shell.wl_storage.storage.native_token.clone(),
                },
                &keypair,
                Epoch(0),
                Default::default(),
                #[cfg(not(feature = "mainnet"))]
                None,
            ))));
            tx.header.chain_id = shell.chain_id.clone();
            tx.set_code(Code::new("wasm_code".as_bytes().to_owned()));
            tx.set_data(Data::new(
                format!("transaction data: {}", i).as_bytes().to_owned(),
            ));
            tx.add_section(Section::Signature(Signature::new(
                tx.sechashes(),
                &keypair,
            )));

            shell.enqueue_tx(tx.clone());
            expected_wrapper.push(tx.clone());
            req.txs.push(tx.to_bytes());
            tx.update_header(TxType::Decrypted(DecryptedTx::Decrypted {
                #[cfg(not(feature = "mainnet"))]
                has_valid_pow: false,
            }));
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
        let (mut shell, _) = test_utils::setup(1);

        let keypair = crate::wallet::defaults::daewon_keypair();
        let mut wrapper = Tx::new(TxType::Wrapper(Box::new(WrapperTx::new(
            Fee {
                amount: 0.into(),
                token: shell.wl_storage.storage.native_token.clone(),
            },
            &keypair,
            Epoch(0),
            Default::default(),
            #[cfg(not(feature = "mainnet"))]
            None,
        ))));
        wrapper.header.chain_id = shell.chain_id.clone();
        wrapper.set_code(Code::new("wasm_code".as_bytes().to_owned()));
        wrapper.set_data(Data::new("transaction data".as_bytes().to_owned()));
        wrapper.add_section(Section::Signature(Signature::new(
            wrapper.sechashes(),
            &keypair,
        )));

        // Write wrapper hash to storage
        let wrapper_unsigned_hash = wrapper.header_hash();
        let hash_key =
            replay_protection::get_tx_hash_key(&wrapper_unsigned_hash);
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
        let (shell, _) = test_utils::setup(1);

        let keypair = crate::wallet::defaults::daewon_keypair();
        let mut wrapper = Tx::new(TxType::Wrapper(Box::new(WrapperTx::new(
            Fee {
                amount: 0.into(),
                token: shell.wl_storage.storage.native_token.clone(),
            },
            &keypair,
            Epoch(0),
            Default::default(),
            #[cfg(not(feature = "mainnet"))]
            None,
        ))));
        wrapper.header.chain_id = shell.chain_id.clone();
        wrapper.set_code(Code::new("wasm_code".as_bytes().to_owned()));
        wrapper.set_data(Data::new("transaction data".as_bytes().to_owned()));
        wrapper.add_section(Section::Signature(Signature::new(
            wrapper.sechashes(),
            &keypair,
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
        let (mut shell, _) = test_utils::setup(1);

        let keypair = crate::wallet::defaults::daewon_keypair();
        let mut wrapper = Tx::new(TxType::Wrapper(Box::new(WrapperTx::new(
            Fee {
                amount: 0.into(),
                token: shell.wl_storage.storage.native_token.clone(),
            },
            &keypair,
            Epoch(0),
            Default::default(),
            #[cfg(not(feature = "mainnet"))]
            None,
        ))));
        wrapper.header.chain_id = shell.chain_id.clone();
        wrapper.set_code(Code::new("wasm_code".as_bytes().to_owned()));
        wrapper.set_data(Data::new("transaction data".as_bytes().to_owned()));
        wrapper.add_section(Section::Signature(Signature::new(
            wrapper.sechashes(),
            &keypair,
        )));
        let inner_unsigned_hash =
            wrapper.clone().update_header(TxType::Raw).header_hash();

        // Write inner hash to storage
        let hash_key = replay_protection::get_tx_hash_key(&inner_unsigned_hash);
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
        let (shell, _) = test_utils::setup(1);

        let keypair = crate::wallet::defaults::daewon_keypair();
        let keypair_2 = crate::wallet::defaults::daewon_keypair();
        let mut wrapper = Tx::new(TxType::Wrapper(Box::new(WrapperTx::new(
            Fee {
                amount: 0.into(),
                token: shell.wl_storage.storage.native_token.clone(),
            },
            &keypair,
            Epoch(0),
            Default::default(),
            #[cfg(not(feature = "mainnet"))]
            None,
        ))));
        wrapper.header.chain_id = shell.chain_id.clone();
        let tx_code = Code::new("wasm_code".as_bytes().to_owned());
        wrapper.set_code(tx_code.clone());
        let tx_data = Data::new("transaction data".as_bytes().to_owned());
        wrapper.set_data(tx_data.clone());
        wrapper.add_section(Section::Signature(Signature::new(
            wrapper.sechashes(),
            &keypair,
        )));

        let mut new_wrapper =
            Tx::new(TxType::Wrapper(Box::new(WrapperTx::new(
                Fee {
                    amount: 0.into(),
                    token: shell.wl_storage.storage.native_token.clone(),
                },
                &keypair_2,
                Epoch(0),
                Default::default(),
                #[cfg(not(feature = "mainnet"))]
                None,
            ))));
        new_wrapper.header.chain_id = shell.chain_id.clone();
        new_wrapper.header.timestamp = wrapper.header.timestamp;
        new_wrapper.set_code(tx_code);
        new_wrapper.set_data(tx_data);
        new_wrapper.add_section(Section::Signature(Signature::new(
            wrapper.sechashes(),
            &keypair,
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
        let (shell, _) = test_utils::setup(1);
        let keypair = gen_keypair();
        let tx_time = DateTimeUtc::now();
        let mut wrapper_tx =
            Tx::new(TxType::Wrapper(Box::new(WrapperTx::new(
                Fee {
                    amount: 0.into(),
                    token: shell.wl_storage.storage.native_token.clone(),
                },
                &keypair,
                Epoch(0),
                Default::default(),
                #[cfg(not(feature = "mainnet"))]
                None,
            ))));
        wrapper_tx.header.chain_id = shell.chain_id.clone();
        wrapper_tx.header.expiration = Some(tx_time);
        wrapper_tx.set_code(Code::new("wasm_code".as_bytes().to_owned()));
        wrapper_tx
            .set_data(Data::new("transaction data".as_bytes().to_owned()));
        wrapper_tx.add_section(Section::Signature(Signature::new(
            wrapper_tx.sechashes(),
            &keypair,
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
}
