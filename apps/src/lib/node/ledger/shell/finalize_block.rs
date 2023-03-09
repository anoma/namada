//! Implementation of the `FinalizeBlock` ABCI++ method for the Shell

use namada::ledger::pos::namada_proof_of_stake;
use namada::ledger::pos::types::into_tm_voting_power;
use namada::ledger::protocol;
use namada::ledger::storage_api::StorageRead;
use namada::types::storage::{BlockHash, BlockResults, Header};
use namada::types::token::Amount;
use namada::types::transaction::protocol::ProtocolTxType;
use namada::types::vote_extensions::ethereum_events::MultiSignedEthEvent;

use super::governance::execute_governance_proposals;
use super::*;
use crate::facade::tendermint_proto::abci::Misbehavior as Evidence;
use crate::facade::tendermint_proto::crypto::PublicKey as TendermintPublicKey;
use crate::node::ledger::shell::stats::InternalStats;

impl<D, H> Shell<D, H>
where
    D: DB + for<'iter> DBIter<'iter> + Sync + 'static,
    H: StorageHasher + Sync + 'static,
{
    /// Updates the chain with new header, height, etc. Also keeps track
    /// of epoch changes and applies associated updates to validator sets,
    /// etc. as necessary.
    ///
    /// Validate and apply decrypted transactions unless
    /// [`Shell::process_proposal`] detected that they were not submitted in
    /// correct order or more decrypted txs arrived than expected. In that
    /// case, all decrypted transactions are not applied and must be
    /// included in the next `Shell::prepare_proposal` call.
    ///
    /// Incoming wrapper txs need no further validation. They
    /// are added to the block.
    ///
    /// Error codes:
    ///   0: Ok
    ///   1: Invalid tx
    ///   2: Tx is invalidly signed
    ///   3: Wasm runtime error
    ///   4: Invalid order of decrypted txs
    ///   5. More decrypted txs than expected
    pub fn finalize_block(
        &mut self,
        req: shim::request::FinalizeBlock,
    ) -> Result<shim::response::FinalizeBlock> {
        // reset gas meter before we start
        self.gas_meter.reset();
        let mut response = shim::response::FinalizeBlock::default();
        // begin the next block and check if a new epoch began
        let (height, new_epoch) =
            self.update_state(req.header, req.hash, req.byzantine_validators);

        let current_epoch = self.wl_storage.storage.block.epoch;

        if new_epoch {
            namada::ledger::storage::update_allowed_conversions(
                &mut self.wl_storage,
            )?;

            let _proposals_result =
                execute_governance_proposals(self, &mut response)?;

            // Copy the new_epoch + pipeline_len - 1 validator set into
            // new_epoch + pipeline_len
            let pos_params =
                namada_proof_of_stake::read_pos_params(&self.wl_storage)?;
            namada_proof_of_stake::copy_validator_sets_and_positions(
                &mut self.wl_storage,
                current_epoch,
                current_epoch + pos_params.pipeline_len,
                &namada_proof_of_stake::consensus_validator_set_handle(),
                &namada_proof_of_stake::below_capacity_validator_set_handle(),
            )?;
        }

        let wrapper_fees = self.get_wrapper_tx_fees();
        let mut stats = InternalStats::default();

        // Tracks the accepted transactions
        self.wl_storage.storage.block.results = BlockResults::default();
        for (tx_index, processed_tx) in req.txs.iter().enumerate() {
            let tx = if let Ok(tx) = Tx::try_from(processed_tx.tx.as_ref()) {
                tx
            } else {
                tracing::error!(
                    "FinalizeBlock received a tx that could not be \
                     deserialized to a Tx type. This is likely a protocol \
                     transaction."
                );
                continue;
            };
            let tx_length = processed_tx.tx.len();
            // If [`process_proposal`] rejected a Tx due to invalid signature,
            // emit an event here and move on to next tx.
            if ErrorCodes::from_u32(processed_tx.result.code).unwrap()
                == ErrorCodes::InvalidSig
            {
                let mut tx_event = match process_tx(tx.clone()) {
                    Ok(tx @ TxType::Wrapper(_))
                    | Ok(tx @ TxType::Protocol(_)) => {
                        Event::new_tx_event(&tx, height.0)
                    }
                    _ => match TxType::try_from(tx) {
                        Ok(tx @ TxType::Wrapper(_))
                        | Ok(tx @ TxType::Protocol(_)) => {
                            Event::new_tx_event(&tx, height.0)
                        }
                        _ => {
                            tracing::error!(
                                "Internal logic error: FinalizeBlock received \
                                 a tx with an invalid signature error code \
                                 that could not be deserialized to a \
                                 WrapperTx / ProtocolTx type"
                            );
                            continue;
                        }
                    },
                };
                tx_event["code"] = processed_tx.result.code.to_string();
                tx_event["info"] =
                    format!("Tx rejected: {}", &processed_tx.result.info);
                tx_event["gas_used"] = "0".into();
                response.events.push(tx_event);
                continue;
            }

            let tx_type = if let Ok(tx_type) = process_tx(tx) {
                tx_type
            } else {
                tracing::error!(
                    "Internal logic error: FinalizeBlock received tx that \
                     could not be deserialized to a valid TxType"
                );
                continue;
            };
            // If [`process_proposal`] rejected a Tx, emit an event here and
            // move on to next tx
            if ErrorCodes::from_u32(processed_tx.result.code).unwrap()
                != ErrorCodes::Ok
            {
                let mut tx_event = Event::new_tx_event(&tx_type, height.0);
                tx_event["code"] = processed_tx.result.code.to_string();
                tx_event["info"] =
                    format!("Tx rejected: {}", &processed_tx.result.info);
                tx_event["gas_used"] = "0".into();
                response.events.push(tx_event);
                // if the rejected tx was decrypted, remove it
                // from the queue of txs to be processed
                if let TxType::Decrypted(_) = &tx_type {
                    self.wl_storage.storage.tx_queue.pop();
                }
                continue;
            }

            let mut tx_event = match &tx_type {
                TxType::Wrapper(wrapper) => {
                    let mut tx_event = Event::new_tx_event(&tx_type, height.0);

                    #[cfg(not(feature = "mainnet"))]
                    let has_valid_pow =
                        self.invalidate_pow_solution_if_valid(wrapper);

                    // Charge fee
                    let fee_payer =
                        if wrapper.pk != address::masp_tx_key().ref_to() {
                            wrapper.fee_payer()
                        } else {
                            address::masp()
                        };

                    let balance_key =
                        token::balance_key(&wrapper.fee.token, &fee_payer);
                    let balance: token::Amount = self
                        .wl_storage
                        .read(&balance_key)
                        .expect("must be able to read")
                        .unwrap_or_default();

                    match balance.checked_sub(wrapper_fees) {
                        Some(amount) => {
                            self.wl_storage
                                .storage
                                .write(
                                    &balance_key,
                                    amount.try_to_vec().unwrap(),
                                )
                                .unwrap();
                        }
                        None => {
                            #[cfg(not(feature = "mainnet"))]
                            let reject = !has_valid_pow;
                            #[cfg(feature = "mainnet")]
                            let reject = true;
                            if reject {
                                // Burn remaining funds
                                self.wl_storage
                                    .storage
                                    .write(
                                        &balance_key,
                                        Amount::from(0).try_to_vec().unwrap(),
                                    )
                                    .unwrap();
                                tx_event["info"] =
                                    "Insufficient balance for fee".into();
                                tx_event["code"] = ErrorCodes::InvalidTx.into();
                                tx_event["gas_used"] = "0".to_string();

                                response.events.push(tx_event);
                                continue;
                            }
                        }
                    }

                    self.wl_storage.storage.tx_queue.push(WrapperTxInQueue {
                        tx: wrapper.clone(),
                        #[cfg(not(feature = "mainnet"))]
                        has_valid_pow,
                    });
                    tx_event
                }
                TxType::Decrypted(inner) => {
                    // We remove the corresponding wrapper tx from the queue
                    self.wl_storage.storage.tx_queue.pop();
                    let mut event = Event::new_tx_event(&tx_type, height.0);

                    match inner {
                        DecryptedTx::Decrypted {
                            tx,
                            has_valid_pow: _,
                        } => {
                            stats.increment_tx_type(
                                namada::core::types::hash::Hash(tx.code_hash())
                                    .to_string(),
                            );
                        }
                        DecryptedTx::Undecryptable(_) => {
                            event["log"] =
                                "Transaction could not be decrypted.".into();
                            event["code"] = ErrorCodes::Undecryptable.into();
                        }
                    }

                    event
                }
                TxType::Raw(_) => {
                    tracing::error!(
                        "Internal logic error: FinalizeBlock received a \
                         TxType::Raw transaction"
                    );
                    continue;
                }
                TxType::Protocol(protocol_tx) => match protocol_tx.tx {
                    ProtocolTxType::EthEventsVext(ref ext) => {
                        if self
                            .mode
                            .get_validator_address()
                            .map(|validator| {
                                validator == &ext.data.validator_addr
                            })
                            .unwrap_or(false)
                        {
                            for event in ext.data.ethereum_events.iter() {
                                self.mode.dequeue_eth_event(event);
                            }
                        }
                        Event::new_tx_event(&tx_type, height.0)
                    }
                    ProtocolTxType::BridgePoolVext(_)
                    | ProtocolTxType::BridgePool(_) => {
                        Event::new_tx_event(&tx_type, height.0)
                    }
                    ProtocolTxType::ValSetUpdateVext(_)
                    | ProtocolTxType::ValidatorSetUpdate(_) => {
                        Event::new_tx_event(&tx_type, height.0)
                    }
                    ProtocolTxType::EthereumEvents(ref digest) => {
                        if let Some(address) =
                            self.mode.get_validator_address().cloned()
                        {
                            let this_signer =
                                &(address, self.wl_storage.storage.last_height);
                            for MultiSignedEthEvent { event, signers } in
                                &digest.events
                            {
                                if signers.contains(this_signer) {
                                    self.mode.dequeue_eth_event(event);
                                }
                            }
                        }
                        Event::new_tx_event(&tx_type, height.0)
                    }
                    ref protocol_tx_type => {
                        tracing::error!(
                            ?protocol_tx_type,
                            "Internal logic error: FinalizeBlock received an \
                             unsupported TxType::Protocol transaction: {:?}",
                            protocol_tx
                        );
                        continue;
                    }
                },
            };

            match protocol::dispatch_tx(
                tx_type,
                tx_length,
                TxIndex(
                    tx_index
                        .try_into()
                        .expect("transaction index out of bounds"),
                ),
                &mut self.gas_meter,
                &mut self.wl_storage,
                &mut self.vp_wasm_cache,
                &mut self.tx_wasm_cache,
            )
            .map_err(Error::TxApply)
            {
                Ok(result) => {
                    if result.is_accepted() {
                        tracing::trace!(
                            "all VPs accepted transaction {} storage \
                             modification {:#?}",
                            tx_event["hash"],
                            result
                        );
                        stats.increment_successful_txs();
                        self.wl_storage.commit_tx();
                        if !tx_event.contains_key("code") {
                            tx_event["code"] = ErrorCodes::Ok.into();
                            self.wl_storage
                                .storage
                                .block
                                .results
                                .accept(tx_index);
                        }
                        if let Some(ibc_event) = &result.ibc_event {
                            // Add the IBC event besides the tx_event
                            let event = Event::from(ibc_event.clone());
                            response.events.push(event);
                        }
                        match serde_json::to_string(
                            &result.initialized_accounts,
                        ) {
                            Ok(initialized_accounts) => {
                                tx_event["initialized_accounts"] =
                                    initialized_accounts;
                            }
                            Err(err) => {
                                tracing::error!(
                                    "Failed to serialize the initialized \
                                     accounts: {}",
                                    err
                                );
                            }
                        }
                    } else {
                        tracing::trace!(
                            "some VPs rejected transaction {} storage \
                             modification {:#?}",
                            tx_event["hash"],
                            result.vps_result.rejected_vps
                        );
                        stats.increment_rejected_txs();
                        self.wl_storage.drop_tx();
                        tx_event["code"] = ErrorCodes::InvalidTx.into();
                    }
                    tx_event["gas_used"] = result.gas_used.to_string();
                    tx_event["info"] = result.to_string();
                }
                Err(msg) => {
                    tracing::info!(
                        "Transaction {} failed with: {}",
                        tx_event["hash"],
                        msg
                    );
                    stats.increment_errored_txs();
                    self.wl_storage.drop_tx();
                    tx_event["gas_used"] = self
                        .gas_meter
                        .get_current_transaction_gas()
                        .to_string();
                    tx_event["info"] = msg.to_string();
                    tx_event["code"] = ErrorCodes::WasmRuntimeError.into();
                }
            }
            response.events.push(tx_event);
        }

        stats.set_tx_cache_size(
            self.tx_wasm_cache.get_size(),
            self.tx_wasm_cache.get_cache_size(),
        );
        stats.set_vp_cache_size(
            self.vp_wasm_cache.get_size(),
            self.vp_wasm_cache.get_cache_size(),
        );

        tracing::info!("{}", stats);
        tracing::info!("{}", stats.format_tx_executed());

        if new_epoch {
            self.update_epoch(&mut response);
        }

        let _ = self
            .gas_meter
            .finalize_transaction()
            .map_err(|_| Error::GasOverflow)?;

        self.event_log_mut().log_events(response.events.clone());
        tracing::debug!("End finalize_block {height} of epoch {current_epoch}");

        Ok(response)
    }

    /// Sets the metadata necessary for a new block, including
    /// the hash, height, validator changes, and evidence of
    /// byzantine behavior. Applies slashes if necessary.
    /// Returns a bool indicating if a new epoch began and
    /// the height of the new block.
    fn update_state(
        &mut self,
        header: Header,
        hash: BlockHash,
        byzantine_validators: Vec<Evidence>,
    ) -> (BlockHeight, bool) {
        let height = self.wl_storage.storage.last_height + 1;

        self.gas_meter.reset();

        self.wl_storage
            .storage
            .begin_block(hash, height)
            .expect("Beginning a block shouldn't fail");

        let header_time = header.time;
        self.wl_storage
            .storage
            .set_header(header)
            .expect("Setting a header shouldn't fail");

        self.byzantine_validators = byzantine_validators;

        let new_epoch = self
            .wl_storage
            .storage
            .update_epoch(height, header_time)
            .expect("Must be able to update epoch");

        self.slash();
        (height, new_epoch)
    }

    /// If a new epoch begins, we update the response to include
    /// changes to the validator sets and consensus parameters
    fn update_epoch(&self, response: &mut shim::response::FinalizeBlock) {
        // Apply validator set update
        let (current_epoch, _gas) = self.wl_storage.storage.get_current_epoch();
        let pos_params =
            namada_proof_of_stake::read_pos_params(&self.wl_storage)
                .expect("Could not find the PoS parameters");
        // TODO ABCI validator updates on block H affects the validator set
        // on block H+2, do we need to update a block earlier?
        // self.wl_storage.validator_set_update(current_epoch, |update| {
        response.validator_updates =
            namada_proof_of_stake::validator_set_update_tendermint(
                &self.wl_storage,
                &pos_params,
                current_epoch,
                |update| {
                    let (consensus_key, power) = match update {
                        ValidatorSetUpdate::Consensus(ConsensusValidator {
                            consensus_key,
                            bonded_stake,
                        }) => {
                            let power: i64 = into_tm_voting_power(
                                pos_params.tm_votes_per_token,
                                bonded_stake,
                            );
                            (consensus_key, power)
                        }
                        ValidatorSetUpdate::Deactivated(consensus_key) => {
                            // Any validators that have been dropped from the
                            // consensus set must have voting power set to 0 to
                            // remove them from the conensus set
                            let power = 0_i64;
                            (consensus_key, power)
                        }
                    };
                    let pub_key = TendermintPublicKey {
                        sum: Some(key_to_tendermint(&consensus_key).unwrap()),
                    };
                    let pub_key = Some(pub_key);
                    ValidatorUpdate { pub_key, power }
                },
            )
            .expect("Must be able to update validator sets");
    }
}

/// We test the failure cases of [`finalize_block`]. The happy flows
/// are covered by the e2e tests.
#[cfg(test)]
mod test_finalize_block {
    use std::collections::BTreeMap;
    use std::str::FromStr;

    use namada::eth_bridge::storage::bridge_pool::{
        get_key_from_hash, get_nonce_key, get_signed_root_key,
    };
    use namada::ledger::eth_bridge::EthBridgeQueries;
    use namada::ledger::parameters::EpochDuration;
    use namada::ledger::storage_api;
    use namada::types::ethereum_events::{EthAddress, Uint};
    use namada::types::governance::ProposalVote;
    use namada::types::keccak::KeccakHash;
    use namada::types::storage::Epoch;
    use namada::types::time::{DateTimeUtc, DurationSecs};
    use namada::types::transaction::governance::{
        InitProposalData, VoteProposalData,
    };
    use namada::types::transaction::{EncryptionKey, Fee, WrapperTx, MIN_FEE};
    use namada::types::vote_extensions::ethereum_events;
    use namada::types::vote_extensions::ethereum_events::MultiSignedEthEvent;

    use super::*;
    use crate::node::ledger::shell::test_utils::*;
    use crate::node::ledger::shims::abcipp_shim_types::shim::request::{
        FinalizeBlock, ProcessedTx,
    };

    /// Check that if a wrapper tx was rejected by [`process_proposal`],
    /// check that the correct event is returned. Check that it does
    /// not appear in the queue of txs to be decrypted
    #[test]
    fn test_process_proposal_rejected_wrapper_tx() {
        let (mut shell, _, _, _) = setup();
        let keypair = gen_keypair();
        let mut processed_txs = vec![];
        let mut valid_wrappers = vec![];

        // Add unshielded balance for fee paymenty
        let balance_key = token::balance_key(
            &shell.wl_storage.storage.native_token,
            &Address::from(&keypair.ref_to()),
        );
        shell
            .wl_storage
            .storage
            .write(&balance_key, Amount::whole(1000).try_to_vec().unwrap())
            .unwrap();

        // create some wrapper txs
        for i in 1u64..5 {
            let raw_tx = Tx::new(
                "wasm_code".as_bytes().to_owned(),
                Some(format!("transaction data: {}", i).as_bytes().to_owned()),
            );
            let wrapper = WrapperTx::new(
                Fee {
                    amount: MIN_FEE.into(),
                    token: shell.wl_storage.storage.native_token.clone(),
                },
                &keypair,
                Epoch(0),
                0.into(),
                raw_tx.clone(),
                Default::default(),
                #[cfg(not(feature = "mainnet"))]
                None,
            );
            let tx = wrapper.sign(&keypair).expect("Test failed");
            if i > 1 {
                processed_txs.push(ProcessedTx {
                    tx: tx.to_bytes(),
                    result: TxResult {
                        code: u32::try_from(i.rem_euclid(2))
                            .expect("Test failed"),
                        info: "".into(),
                    },
                });
            } else {
                shell.enqueue_tx(wrapper.clone());
            }

            if i != 3 {
                valid_wrappers.push(wrapper)
            }
        }

        // check that the correct events were created
        for (index, event) in shell
            .finalize_block(FinalizeBlock {
                txs: processed_txs.clone(),
                ..Default::default()
            })
            .expect("Test failed")
            .iter()
            .enumerate()
        {
            assert_eq!(event.event_type.to_string(), String::from("accepted"));
            let code = event.attributes.get("code").expect("Test failed");
            assert_eq!(code, &index.rem_euclid(2).to_string());
        }
        // verify that the queue of wrapper txs to be processed is correct
        let mut valid_tx = valid_wrappers.iter();
        let mut counter = 0;
        for wrapper in shell.iter_tx_queue() {
            // we cannot easily implement the PartialEq trait for WrapperTx
            // so we check the hashes of the inner txs for equality
            assert_eq!(
                wrapper.tx.tx_hash,
                valid_tx.next().expect("Test failed").tx_hash
            );
            counter += 1;
        }
        assert_eq!(counter, 3);
    }

    /// Check that if a decrypted tx was rejected by [`process_proposal`],
    /// check that the correct event is returned. Check that it is still
    /// removed from the queue of txs to be included in the next block
    /// proposal
    #[test]
    fn test_process_proposal_rejected_decrypted_tx() {
        let (mut shell, _, _, _) = setup();
        let keypair = gen_keypair();
        let raw_tx = Tx::new(
            "wasm_code".as_bytes().to_owned(),
            Some(String::from("transaction data").as_bytes().to_owned()),
        );
        let wrapper = WrapperTx::new(
            Fee {
                amount: 0.into(),
                token: shell.wl_storage.storage.native_token.clone(),
            },
            &keypair,
            Epoch(0),
            0.into(),
            raw_tx.clone(),
            Default::default(),
            #[cfg(not(feature = "mainnet"))]
            None,
        );

        let processed_tx = ProcessedTx {
            tx: Tx::from(TxType::Decrypted(DecryptedTx::Decrypted {
                tx: raw_tx,
                #[cfg(not(feature = "mainnet"))]
                has_valid_pow: false,
            }))
            .to_bytes(),
            result: TxResult {
                code: ErrorCodes::InvalidTx.into(),
                info: "".into(),
            },
        };
        shell.enqueue_tx(wrapper);

        // check that the decrypted tx was not applied
        for event in shell
            .finalize_block(FinalizeBlock {
                txs: vec![processed_tx],
                ..Default::default()
            })
            .expect("Test failed")
        {
            assert_eq!(event.event_type.to_string(), String::from("applied"));
            let code = event.attributes.get("code").expect("Test failed");
            assert_eq!(code, &String::from(ErrorCodes::InvalidTx));
        }
        // check that the corresponding wrapper tx was removed from the queue
        assert!(shell.wl_storage.storage.tx_queue.is_empty());
    }

    /// Test that if a tx is undecryptable, it is applied
    /// but the tx result contains the appropriate error code.
    #[test]
    fn test_undecryptable_returns_error_code() {
        let (mut shell, _, _, _) = setup();

        let keypair = crate::wallet::defaults::daewon_keypair();
        let pubkey = EncryptionKey::default();
        // not valid tx bytes
        let tx = "garbage data".as_bytes().to_owned();
        let inner_tx =
            namada::types::transaction::encrypted::EncryptedTx::encrypt(
                &tx, pubkey,
            );
        let wrapper = WrapperTx {
            fee: Fee {
                amount: 0.into(),
                token: shell.wl_storage.storage.native_token.clone(),
            },
            pk: keypair.ref_to(),
            epoch: Epoch(0),
            gas_limit: 0.into(),
            inner_tx,
            tx_hash: hash_tx(&tx),
            #[cfg(not(feature = "mainnet"))]
            pow_solution: None,
        };
        let processed_tx = ProcessedTx {
            tx: Tx::from(TxType::Decrypted(DecryptedTx::Undecryptable(
                wrapper.clone(),
            )))
            .to_bytes(),
            result: TxResult {
                code: ErrorCodes::Ok.into(),
                info: "".into(),
            },
        };

        shell.enqueue_tx(wrapper);

        // check that correct error message is returned
        for event in shell
            .finalize_block(FinalizeBlock {
                txs: vec![processed_tx],
                ..Default::default()
            })
            .expect("Test failed")
        {
            assert_eq!(event.event_type.to_string(), String::from("applied"));
            let code = event.attributes.get("code").expect("Test failed");
            assert_eq!(code, &String::from(ErrorCodes::Undecryptable));
            let log = event.attributes.get("log").expect("Test failed");
            assert!(log.contains("Transaction could not be decrypted."))
        }
        // check that the corresponding wrapper tx was removed from the queue
        assert!(shell.wl_storage.storage.tx_queue.is_empty());
    }

    /// Test that the wrapper txs are queued in the order they
    /// are received from the block. Tests that the previously
    /// decrypted txs are de-queued.
    #[test]
    fn test_mixed_txs_queued_in_correct_order() {
        let (mut shell, _, _, _) = setup();
        let keypair = gen_keypair();
        let mut processed_txs = vec![];
        let mut valid_txs = vec![];

        // Add unshielded balance for fee paymenty
        let balance_key = token::balance_key(
            &shell.wl_storage.storage.native_token,
            &Address::from(&keypair.ref_to()),
        );
        shell
            .wl_storage
            .storage
            .write(&balance_key, Amount::whole(1000).try_to_vec().unwrap())
            .unwrap();

        // create two decrypted txs
        let mut wasm_path = top_level_directory();
        wasm_path.push("wasm_for_tests/tx_no_op.wasm");
        let tx_code = std::fs::read(wasm_path)
            .expect("Expected a file at given code path");
        for i in 0..2 {
            let raw_tx = Tx::new(
                tx_code.clone(),
                Some(
                    format!("Decrypted transaction data: {}", i)
                        .as_bytes()
                        .to_owned(),
                ),
            );
            let wrapper_tx = WrapperTx::new(
                Fee {
                    amount: MIN_FEE.into(),
                    token: shell.wl_storage.storage.native_token.clone(),
                },
                &keypair,
                Epoch(0),
                0.into(),
                raw_tx.clone(),
                Default::default(),
                #[cfg(not(feature = "mainnet"))]
                None,
            );
            shell.enqueue_tx(wrapper_tx);
            processed_txs.push(ProcessedTx {
                tx: Tx::from(TxType::Decrypted(DecryptedTx::Decrypted {
                    tx: raw_tx,
                    #[cfg(not(feature = "mainnet"))]
                    has_valid_pow: false,
                }))
                .to_bytes(),
                result: TxResult {
                    code: ErrorCodes::Ok.into(),
                    info: "".into(),
                },
            });
        }
        // create two wrapper txs
        for i in 0..2 {
            let raw_tx = Tx::new(
                "wasm_code".as_bytes().to_owned(),
                Some(
                    format!("Encrypted transaction data: {}", i)
                        .as_bytes()
                        .to_owned(),
                ),
            );
            let wrapper_tx = WrapperTx::new(
                Fee {
                    amount: MIN_FEE.into(),
                    token: shell.wl_storage.storage.native_token.clone(),
                },
                &keypair,
                Epoch(0),
                0.into(),
                raw_tx.clone(),
                Default::default(),
                #[cfg(not(feature = "mainnet"))]
                None,
            );
            let wrapper = wrapper_tx.sign(&keypair).expect("Test failed");
            valid_txs.push(wrapper_tx);
            processed_txs.push(ProcessedTx {
                tx: wrapper.to_bytes(),
                result: TxResult {
                    code: ErrorCodes::Ok.into(),
                    info: "".into(),
                },
            });
        }
        // Put the wrapper txs in front of the decrypted txs
        processed_txs.rotate_left(2);
        // check that the correct events were created
        for (index, event) in shell
            .finalize_block(FinalizeBlock {
                txs: processed_txs,
                ..Default::default()
            })
            .expect("Test failed")
            .iter()
            .enumerate()
        {
            if index < 2 {
                // these should be accepted wrapper txs
                assert_eq!(
                    event.event_type.to_string(),
                    String::from("accepted")
                );
                let code =
                    event.attributes.get("code").expect("Test failed").as_str();
                assert_eq!(code, String::from(ErrorCodes::Ok).as_str());
            } else {
                // these should be accepted decrypted txs
                assert_eq!(
                    event.event_type.to_string(),
                    String::from("applied")
                );
                let code =
                    event.attributes.get("code").expect("Test failed").as_str();
                assert_eq!(code, String::from(ErrorCodes::Ok).as_str());
            }
        }

        // check that the applied decrypted txs were dequeued and the
        // accepted wrappers were enqueued in correct order
        let mut txs = valid_txs.iter();

        let mut counter = 0;
        for wrapper in shell.iter_tx_queue() {
            assert_eq!(
                wrapper.tx.tx_hash,
                txs.next().expect("Test failed").tx_hash
            );
            counter += 1;
        }
        assert_eq!(counter, 2);
    }

    /// Test if a rejected protocol tx is applied and emits
    /// the correct event
    #[test]
    fn test_rejected_protocol_tx() {
        const LAST_HEIGHT: BlockHeight = BlockHeight(3);
        let (mut shell, _, _, _) = setup_at_height(LAST_HEIGHT);
        let protocol_key =
            shell.mode.get_protocol_key().expect("Test failed").clone();

        let tx = ProtocolTxType::EthereumEvents(ethereum_events::VextDigest {
            signatures: Default::default(),
            events: vec![],
        })
        .sign(&protocol_key)
        .to_bytes();

        let req = FinalizeBlock {
            txs: vec![ProcessedTx {
                tx,
                result: TxResult {
                    code: ErrorCodes::InvalidTx.into(),
                    info: Default::default(),
                },
            }],
            ..Default::default()
        };
        let mut resp = shell.finalize_block(req).expect("Test failed");
        assert_eq!(resp.len(), 1);
        let event = resp.remove(0);
        assert_eq!(event.event_type.to_string(), String::from("applied"));
        let code = event.attributes.get("code").expect("Test failed");
        assert_eq!(code, &String::from(ErrorCodes::InvalidTx));
    }

    /// Test that once a validator's vote for an Ethereum event lands
    /// on-chain from a vote extension digest, it dequeues from the
    /// list of events to vote on.
    #[test]
    fn test_eth_events_dequeued_digest() {
        let (mut shell, _, oracle, _) = setup();
        let protocol_key =
            shell.mode.get_protocol_key().expect("Test failed").clone();
        let address = shell
            .mode
            .get_validator_address()
            .expect("Test failed")
            .clone();

        // ---- the ledger receives a new Ethereum event
        let event = EthereumEvent::NewContract {
            name: "Test".to_string(),
            address: EthAddress([0; 20]),
        };
        tokio_test::block_on(oracle.send(event.clone())).expect("Test failed");
        let [queued_event]: [EthereumEvent; 1] =
            shell.new_ethereum_events().try_into().expect("Test failed");
        assert_eq!(queued_event, event);

        // ---- The protocol tx that includes this event on-chain
        let ext = ethereum_events::Vext {
            block_height: shell.wl_storage.storage.last_height,
            ethereum_events: vec![event.clone()],
            validator_addr: address.clone(),
        }
        .sign(&protocol_key);

        let processed_tx = {
            let signed = MultiSignedEthEvent {
                event,
                signers: BTreeSet::from([(
                    address.clone(),
                    shell.wl_storage.storage.last_height,
                )]),
            };

            let digest = ethereum_events::VextDigest {
                signatures: vec![(
                    (address, shell.wl_storage.storage.last_height),
                    ext.sig,
                )]
                .into_iter()
                .collect(),
                events: vec![signed],
            };
            ProcessedTx {
                tx: ProtocolTxType::EthereumEvents(digest)
                    .sign(&protocol_key)
                    .to_bytes(),
                result: TxResult {
                    code: ErrorCodes::Ok.into(),
                    info: "".into(),
                },
            }
        };

        // ---- This protocol tx is accepted
        let [result]: [Event; 1] = shell
            .finalize_block(FinalizeBlock {
                txs: vec![processed_tx],
                ..Default::default()
            })
            .expect("Test failed")
            .try_into()
            .expect("Test failed");
        assert_eq!(result.event_type.to_string(), String::from("applied"));
        let code = result.attributes.get("code").expect("Test failed").as_str();
        assert_eq!(code, String::from(ErrorCodes::Ok).as_str());

        // --- The event is removed from the queue
        assert!(shell.new_ethereum_events().is_empty());
    }

    /// Test that once a validator's vote for an Ethereum event lands
    /// on-chain from a protocol tx, it dequeues from the
    /// list of events to vote on.
    #[test]
    fn test_eth_events_dequeued_protocol_tx() {
        let (mut shell, _, oracle, _) = setup();
        let protocol_key =
            shell.mode.get_protocol_key().expect("Test failed").clone();
        let address = shell
            .mode
            .get_validator_address()
            .expect("Test failed")
            .clone();

        // ---- the ledger receives a new Ethereum event
        let event = EthereumEvent::NewContract {
            name: "Test".to_string(),
            address: EthAddress([0; 20]),
        };
        tokio_test::block_on(oracle.send(event.clone())).expect("Test failed");
        let [queued_event]: [EthereumEvent; 1] =
            shell.new_ethereum_events().try_into().expect("Test failed");
        assert_eq!(queued_event, event);

        // ---- The protocol tx that includes this event on-chain
        let ext = ethereum_events::Vext {
            block_height: shell.wl_storage.storage.last_height,
            ethereum_events: vec![event],
            validator_addr: address,
        }
        .sign(&protocol_key);
        let processed_tx = ProcessedTx {
            tx: ProtocolTxType::EthEventsVext(ext)
                .sign(&protocol_key)
                .to_bytes(),
            result: TxResult {
                code: ErrorCodes::Ok.into(),
                info: "".into(),
            },
        };

        // ---- This protocol tx is accepted
        let [result]: [Event; 1] = shell
            .finalize_block(FinalizeBlock {
                txs: vec![processed_tx],
                ..Default::default()
            })
            .expect("Test failed")
            .try_into()
            .expect("Test failed");
        assert_eq!(result.event_type.to_string(), String::from("applied"));
        let code = result.attributes.get("code").expect("Test failed").as_str();
        assert_eq!(code, String::from(ErrorCodes::Ok).as_str());

        // --- The event is removed from the queue
        assert!(shell.new_ethereum_events().is_empty());
    }

    /// Helper function for testing the relevant protocol tx
    /// for signing bridge pool roots and nonces
    fn test_bp_roots<F>(craft_tx: F)
    where
        F: FnOnce(&TestShell) -> Tx,
    {
        let (mut shell, _, _, _) = setup_at_height(3u64);
        namada::eth_bridge::test_utils::commit_bridge_pool_root_at_height(
            &mut shell.wl_storage.storage,
            &KeccakHash([1; 32]),
            3.into(),
        );
        let value = BlockHeight(4).try_to_vec().expect("Test failed");
        shell
            .wl_storage
            .storage
            .block
            .tree
            .update(&get_key_from_hash(&KeccakHash([1; 32])), value)
            .expect("Test failed");
        shell
            .wl_storage
            .storage
            .write(
                &get_nonce_key(),
                Uint::from(1).try_to_vec().expect("Test failed"),
            )
            .expect("Test failed");
        let tx = craft_tx(&shell);
        let processed_tx = ProcessedTx {
            tx: tx.to_bytes(),
            result: TxResult {
                code: ErrorCodes::Ok.into(),
                info: "".into(),
            },
        };
        let req = FinalizeBlock {
            txs: vec![processed_tx],
            ..Default::default()
        };
        let root = shell
            .wl_storage
            .read_bytes(&get_signed_root_key())
            .expect("Reading signed Bridge pool root shouldn't fail.");
        assert!(root.is_none());
        _ = shell.finalize_block(req).expect("Test failed");
        let (root, _) = shell
            .wl_storage
            .ethbridge_queries()
            .get_signed_bridge_pool_root()
            .expect("Test failed");
        assert_eq!(root.data.0, KeccakHash([1; 32]));
        assert_eq!(root.data.1, Uint::from(1));
    }

    #[test]
    /// Test that the generated protocol tx passes Finalize Block
    /// and effects the expected storage changes.
    fn test_bp_roots_protocol_tx() {
        test_bp_roots(|shell: &TestShell| {
            let vext = shell.extend_vote_with_bp_roots().expect("Test failed");
            ProtocolTxType::BridgePoolVext(vext)
                .sign(shell.mode.get_protocol_key().expect("Test failed"))
        });
    }

    /// Test that the finalize block handler never commits changes directly to
    /// the DB.
    #[test]
    fn test_finalize_doesnt_commit_db() {
        let (mut shell, _broadcaster, _, _) = setup();

        // Update epoch duration to make sure we go through couple epochs
        let epoch_duration = EpochDuration {
            min_num_of_blocks: 5,
            min_duration: DurationSecs(0),
        };
        namada::ledger::parameters::update_epoch_parameter(
            &mut shell.wl_storage.storage,
            &epoch_duration,
        )
        .unwrap();
        shell.wl_storage.storage.next_epoch_min_start_height = BlockHeight(5);
        shell.wl_storage.storage.next_epoch_min_start_time = DateTimeUtc::now();

        // Add a proposal to be executed on next epoch change.
        let mut add_proposal = |proposal_id, vote| {
            let validator = shell.mode.get_validator_address().unwrap().clone();
            shell.proposal_data.insert(proposal_id);
            let proposal = InitProposalData {
                id: Some(proposal_id),
                content: vec![],
                author: validator.clone(),
                voting_start_epoch: Epoch::default(),
                voting_end_epoch: Epoch::default().next(),
                grace_epoch: Epoch::default().next(),
                proposal_code: None,
            };
            storage_api::governance::init_proposal(
                &mut shell.wl_storage,
                proposal,
            )
            .unwrap();
            let vote = VoteProposalData {
                id: proposal_id,
                vote,
                voter: validator,
                delegations: vec![],
            };
            // Vote to accept the proposal (there's only one validator, so its
            // vote decides)
            storage_api::governance::vote_proposal(&mut shell.wl_storage, vote)
                .unwrap();
        };
        // Add a proposal to be accepted and one to be rejected.
        add_proposal(0, ProposalVote::Yay);
        add_proposal(1, ProposalVote::Nay);

        // Commit the genesis state
        shell.wl_storage.commit_genesis().unwrap();
        shell.commit();

        // Collect all storage key-vals into a sorted map
        let store_block_state = |shell: &TestShell| -> BTreeMap<_, _> {
            let prefix: Key = FromStr::from_str("").unwrap();
            shell
                .wl_storage
                .iter_prefix(&prefix)
                .expect("Test failed")
                .map(|(key, val, _gas)| (key, val))
                .collect()
        };

        // Store the full state in sorted map
        let mut last_storage_state: std::collections::BTreeMap<
            String,
            Vec<u8>,
        > = store_block_state(&shell);

        // Keep applying finalize block
        for _ in 0..20 {
            let req = FinalizeBlock::default();
            let _events = shell.finalize_block(req).unwrap();
            let new_state = store_block_state(&shell);
            // The new state must be unchanged
            itertools::assert_equal(
                last_storage_state.iter(),
                new_state.iter(),
            );
            // Commit the block to move on to the next one
            shell.wl_storage.commit_block().unwrap();

            // Store the state after commit for the next iteration
            last_storage_state = store_block_state(&shell);
        }
    }
}
