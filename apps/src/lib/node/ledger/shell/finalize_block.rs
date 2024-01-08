//! Implementation of the `FinalizeBlock` ABCI++ method for the Shell

use data_encoding::HEXUPPER;
use masp_primitives::merkle_tree::CommitmentTree;
use masp_primitives::sapling::Node;
use masp_proofs::bls12_381;
use namada::governance::pgf::inflation as pgf_inflation;
use namada::ledger::events::EventType;
use namada::ledger::gas::{GasMetering, TxGasMeter};
use namada::ledger::pos::namada_proof_of_stake;
use namada::ledger::protocol;
use namada::proof_of_stake::storage::{
    find_validator_by_raw_hash, read_last_block_proposer_address,
    write_last_block_proposer_address,
};
use namada::state::wl_storage::WriteLogAndStorage;
use namada::state::write_log::StorageModification;
use namada::state::{
    ResultExt, StorageRead, StorageWrite, EPOCH_SWITCH_BLOCKS_DELAY,
};
use namada::token::conversion::update_allowed_conversions;
use namada::token::storage_key::{
    MASP_NOTE_COMMITMENT_ANCHOR_PREFIX, MASP_NOTE_COMMITMENT_TREE_KEY,
};
use namada::tx::data::protocol::ProtocolTxType;
use namada::types::address::MASP;
use namada::types::key::tm_raw_hash_to_string;
use namada::types::storage::{BlockHash, BlockResults, Epoch, Header, KeySeg};
use namada::vote_ext::ethereum_events::MultiSignedEthEvent;
use namada::vote_ext::ethereum_tx_data_variants;

use super::governance::execute_governance_proposals;
use super::*;
use crate::facade::tendermint::abci::types::{Misbehavior, VoteInfo};
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
        let mut response = shim::response::FinalizeBlock::default();

        // Begin the new block and check if a new epoch has begun
        let (height, new_epoch) =
            self.update_state(req.header, req.hash, req.byzantine_validators);

        let (current_epoch, _gas) = self.wl_storage.storage.get_current_epoch();
        let update_for_tendermint = matches!(
            self.wl_storage.storage.update_epoch_blocks_delay,
            Some(EPOCH_SWITCH_BLOCKS_DELAY)
        );

        tracing::info!(
            "Block height: {height}, epoch: {current_epoch}, is new epoch: \
             {new_epoch}."
        );
        tracing::debug!(
            "New epoch block delay for updating the Tendermint validator set: \
             {:?}",
            self.wl_storage.storage.update_epoch_blocks_delay
        );

        // Finalize the transactions' hashes from the previous block
        for hash in self.wl_storage.storage.iter_replay_protection() {
            self.wl_storage
                .write_log
                .finalize_tx_hash(hash)
                .expect("Failed tx hashes finalization")
        }

        let pos_params =
            namada_proof_of_stake::storage::read_pos_params(&self.wl_storage)?;

        if new_epoch {
            update_allowed_conversions(&mut self.wl_storage)?;

            execute_governance_proposals(self, &mut response)?;

            // Copy the new_epoch + pipeline_len - 1 validator set into
            // new_epoch + pipeline_len
            namada_proof_of_stake::validator_set_update::copy_validator_sets_and_positions(
                &mut self.wl_storage,
                &pos_params,
                current_epoch,
                current_epoch + pos_params.pipeline_len,
            )?;

            // Compute the total stake of the consensus validator set and record
            // it in storage
            namada_proof_of_stake::compute_and_store_total_consensus_stake(
                &mut self.wl_storage,
                current_epoch,
            )?;
        }

        // Get the actual votes from cometBFT in the preferred format
        let votes = pos_votes_from_abci(&self.wl_storage, &req.votes);

        // Invariant: Has to be applied before `record_slashes_from_evidence`
        // because it potentially needs to be able to read validator state from
        // previous epoch and jailing validator removes the historical state
        if !votes.is_empty() {
            self.log_block_rewards(
                votes.clone(),
                height,
                current_epoch,
                new_epoch,
            )?;
        }

        // Invariant: This has to be applied after
        // `copy_validator_sets_and_positions` and before `self.update_epoch`.
        self.record_slashes_from_evidence();
        // Invariant: This has to be applied after
        // `copy_validator_sets_and_positions` if we're starting a new epoch
        if new_epoch {
            // Invariant: Process slashes before inflation as they may affect
            // the rewards in the current epoch.
            self.process_slashes();
            self.apply_inflation(current_epoch)?;
        }

        // Consensus set liveness check
        if !votes.is_empty() {
            let vote_height = height.prev_height();
            let epoch_of_votes = self
                .wl_storage
                .storage
                .block
                .pred_epochs
                .get_epoch(vote_height)
                .expect(
                    "Should always find an epoch when looking up the vote \
                     height before recording liveness data.",
                );
            namada_proof_of_stake::record_liveness_data(
                &mut self.wl_storage,
                &votes,
                epoch_of_votes,
                vote_height,
                &pos_params,
            )?;
        }

        let validator_set_update_epoch =
            self.get_validator_set_update_epoch(current_epoch);

        // Jail validators for inactivity
        namada_proof_of_stake::jail_for_liveness(
            &mut self.wl_storage,
            &pos_params,
            current_epoch,
            validator_set_update_epoch,
        )?;

        if new_epoch {
            // Prune liveness data from validators that are no longer in the
            // consensus set
            namada_proof_of_stake::prune_liveness_data(
                &mut self.wl_storage,
                current_epoch,
            )?;
        }

        let mut stats = InternalStats::default();

        let native_block_proposer_address = {
            let tm_raw_hash_string =
                tm_raw_hash_to_string(req.proposer_address);
            find_validator_by_raw_hash(&self.wl_storage, tm_raw_hash_string)
                .unwrap()
                .expect(
                    "Unable to find native validator address of block \
                     proposer from tendermint raw hash",
                )
        };

        // Tracks the accepted transactions
        self.wl_storage.storage.block.results = BlockResults::default();
        let mut changed_keys = BTreeSet::new();
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
            // If [`process_proposal`] rejected a Tx due to invalid signature,
            // emit an event here and move on to next tx.
            if ResultCode::from_u32(processed_tx.result.code).unwrap()
                == ResultCode::InvalidSig
            {
                let mut tx_event = match tx.header().tx_type {
                    TxType::Wrapper(_) | TxType::Protocol(_) => {
                        Event::new_tx_event(&tx, height.0)
                    }
                    _ => {
                        tracing::error!(
                            "Internal logic error: FinalizeBlock received a \
                             tx with an invalid signature error code that \
                             could not be deserialized to a WrapperTx / \
                             ProtocolTx type"
                        );
                        continue;
                    }
                };
                tx_event["code"] = processed_tx.result.code.to_string();
                tx_event["info"] =
                    format!("Tx rejected: {}", &processed_tx.result.info);
                tx_event["gas_used"] = "0".into();
                response.events.push(tx_event);
                continue;
            }

            if tx.validate_tx().is_err() {
                tracing::error!(
                    "Internal logic error: FinalizeBlock received tx that \
                     could not be deserialized to a valid TxType"
                );
                continue;
            };
            let tx_header = tx.header();
            // If [`process_proposal`] rejected a Tx, emit an event here and
            // move on to next tx
            if ResultCode::from_u32(processed_tx.result.code).unwrap()
                != ResultCode::Ok
            {
                let mut tx_event = Event::new_tx_event(&tx, height.0);
                tx_event["code"] = processed_tx.result.code.to_string();
                tx_event["info"] =
                    format!("Tx rejected: {}", &processed_tx.result.info);
                tx_event["gas_used"] = "0".into();
                response.events.push(tx_event);
                // if the rejected tx was decrypted, remove it
                // from the queue of txs to be processed
                if let TxType::Decrypted(_) = &tx_header.tx_type {
                    self.wl_storage
                        .storage
                        .tx_queue
                        .pop()
                        .expect("Missing wrapper tx in queue");
                }

                continue;
            }

            let (mut tx_event, embedding_wrapper, mut tx_gas_meter, wrapper) =
                match &tx_header.tx_type {
                    TxType::Wrapper(wrapper) => {
                        stats.increment_wrapper_txs();
                        let tx_event = Event::new_tx_event(&tx, height.0);
                        let gas_meter = TxGasMeter::new(wrapper.gas_limit);
                        (tx_event, None, gas_meter, Some(tx.clone()))
                    }
                    TxType::Decrypted(inner) => {
                        // We remove the corresponding wrapper tx from the queue
                        let tx_in_queue = self
                            .wl_storage
                            .storage
                            .tx_queue
                            .pop()
                            .expect("Missing wrapper tx in queue");
                        let mut event = Event::new_tx_event(&tx, height.0);

                        match inner {
                            DecryptedTx::Decrypted => {
                                if let Some(code_sec) = tx
                                    .get_section(tx.code_sechash())
                                    .and_then(|x| Section::code_sec(x.as_ref()))
                                {
                                    stats.increment_tx_type(
                                        code_sec.code.hash().to_string(),
                                    );
                                }
                            }
                            DecryptedTx::Undecryptable => {
                                tracing::info!(
                                    "Tx with hash {} was un-decryptable",
                                    tx_in_queue.tx.header_hash()
                                );
                                event["info"] =
                                    "Transaction is invalid.".into();
                                event["log"] = "Transaction could not be \
                                                decrypted."
                                    .into();
                                event["code"] =
                                    ResultCode::Undecryptable.into();
                                response.events.push(event);
                                continue;
                            }
                        }

                        (
                            event,
                            Some(tx_in_queue.tx),
                            TxGasMeter::new_from_sub_limit(tx_in_queue.gas),
                            None,
                        )
                    }
                    TxType::Raw => {
                        tracing::error!(
                            "Internal logic error: FinalizeBlock received a \
                             TxType::Raw transaction"
                        );
                        continue;
                    }
                    TxType::Protocol(protocol_tx) => match protocol_tx.tx {
                        ProtocolTxType::BridgePoolVext
                        | ProtocolTxType::BridgePool
                        | ProtocolTxType::ValSetUpdateVext
                        | ProtocolTxType::ValidatorSetUpdate => (
                            Event::new_tx_event(&tx, height.0),
                            None,
                            TxGasMeter::new_from_sub_limit(0.into()),
                            None,
                        ),
                        ProtocolTxType::EthEventsVext => {
                            let ext =
                            ethereum_tx_data_variants::EthEventsVext::try_from(
                                &tx,
                            )
                            .unwrap();
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
                            (
                                Event::new_tx_event(&tx, height.0),
                                None,
                                TxGasMeter::new_from_sub_limit(0.into()),
                                None,
                            )
                        }
                        ProtocolTxType::EthereumEvents => {
                            let digest =
                            ethereum_tx_data_variants::EthereumEvents::try_from(
                                &tx,
                            ).unwrap();
                            if let Some(address) =
                                self.mode.get_validator_address().cloned()
                            {
                                let this_signer = &(
                                    address,
                                    self.wl_storage
                                        .storage
                                        .get_last_block_height(),
                                );
                                for MultiSignedEthEvent { event, signers } in
                                    &digest.events
                                {
                                    if signers.contains(this_signer) {
                                        self.mode.dequeue_eth_event(event);
                                    }
                                }
                            }
                            (
                                Event::new_tx_event(&tx, height.0),
                                None,
                                TxGasMeter::new_from_sub_limit(0.into()),
                                None,
                            )
                        }
                    },
                };

            match protocol::dispatch_tx(
                tx,
                processed_tx.tx.as_ref(),
                TxIndex(
                    tx_index
                        .try_into()
                        .expect("transaction index out of bounds"),
                ),
                &mut tx_gas_meter,
                &mut self.wl_storage,
                &mut self.vp_wasm_cache,
                &mut self.tx_wasm_cache,
                Some(&native_block_proposer_address),
            )
            .map_err(Error::TxApply)
            {
                Ok(ref mut result) => {
                    if result.is_accepted() {
                        if let EventType::Accepted = tx_event.event_type {
                            // Wrapper transaction
                            tracing::trace!(
                                "Wrapper transaction {} was accepted",
                                tx_event["hash"]
                            );
                            self.wl_storage.storage.tx_queue.push(TxInQueue {
                                tx: wrapper.expect("Missing expected wrapper"),
                                gas: tx_gas_meter.get_available_gas(),
                            });
                        } else {
                            tracing::trace!(
                                "all VPs accepted transaction {} storage \
                                 modification {:#?}",
                                tx_event["hash"],
                                result
                            );
                            changed_keys
                                .extend(result.changed_keys.iter().cloned());
                            stats.increment_successful_txs();
                            if let Some(wrapper) = embedding_wrapper {
                                self.commit_inner_tx_hash(wrapper);
                            }
                        }
                        self.wl_storage.commit_tx();
                        if !tx_event.contains_key("code") {
                            tx_event["code"] = ResultCode::Ok.into();
                            self.wl_storage
                                .storage
                                .block
                                .results
                                .accept(tx_index);
                        }
                        // events from other sources
                        response.events.extend(
                            // ibc events
                            result
                                .ibc_events
                                .iter()
                                .cloned()
                                .map(|ibc_event| {
                                    // Add the IBC event besides the tx_event
                                    let mut event = Event::from(ibc_event);
                                    // Add the height for IBC event query
                                    event["height"] = height.to_string();
                                    event
                                })
                                // eth bridge events
                                .chain(
                                    result
                                        .eth_bridge_events
                                        .iter()
                                        .map(Event::from),
                                ),
                        );
                    } else {
                        tracing::trace!(
                            "some VPs rejected transaction {} storage \
                             modification {:#?}",
                            tx_event["hash"],
                            result.vps_result.rejected_vps
                        );

                        if let Some(wrapper) = embedding_wrapper {
                            // If decrypted tx failed for any reason but invalid
                            // signature, commit its hash to storage, otherwise
                            // allow for a replay
                            if !result.vps_result.invalid_sig {
                                self.commit_inner_tx_hash(wrapper);
                            }
                        }

                        stats.increment_rejected_txs();
                        self.wl_storage.drop_tx();
                        tx_event["code"] = ResultCode::InvalidTx.into();
                    }
                    tx_event["gas_used"] = result.gas_used.to_string();
                    tx_event["info"] = "Check inner_tx for result.".to_string();
                    tx_event["inner_tx"] = result.to_string();
                }
                Err(msg) => {
                    tracing::info!(
                        "Transaction {} failed with: {}",
                        tx_event["hash"],
                        msg
                    );

                    // If transaction type is Decrypted and didn't failed
                    // because of out of gas nor invalid
                    // section commitment, commit its hash to prevent replays
                    if let Some(wrapper) = embedding_wrapper {
                        if !matches!(
                            msg,
                            Error::TxApply(protocol::Error::GasError(_))
                                | Error::TxApply(
                                    protocol::Error::MissingSection(_)
                                )
                                | Error::TxApply(
                                    protocol::Error::ReplayAttempt(_)
                                )
                        ) {
                            self.commit_inner_tx_hash(wrapper);
                        } else if let Error::TxApply(
                            protocol::Error::ReplayAttempt(_),
                        ) = msg
                        {
                            // Remove the wrapper hash but keep the inner tx
                            // hash. A replay of the wrapper is impossible since
                            // the inner tx hash is committed to storage and
                            // we validate the wrapper against that hash too
                            self.wl_storage
                                .delete_tx_hash(wrapper.header_hash())
                                .expect(
                                    "Error while deleting tx hash from storage",
                                );
                        }
                    }

                    stats.increment_errored_txs();
                    self.wl_storage.drop_tx();

                    tx_event["gas_used"] =
                        tx_gas_meter.get_tx_consumed_gas().to_string();
                    tx_event["info"] = msg.to_string();
                    if let EventType::Accepted = tx_event.event_type {
                        // If wrapper, invalid tx error code
                        tx_event["code"] = ResultCode::InvalidTx.into();
                    } else {
                        tx_event["code"] = ResultCode::WasmRuntimeError.into();
                    }
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

        // Update the MASP commitment tree anchor if the tree was updated
        let tree_key = Key::from(MASP.to_db_key())
            .push(&MASP_NOTE_COMMITMENT_TREE_KEY.to_owned())
            .expect("Cannot obtain a storage key");
        if let Some(StorageModification::Write { value }) =
            self.wl_storage.write_log.read(&tree_key).0
        {
            let updated_tree = CommitmentTree::<Node>::try_from_slice(value)
                .into_storage_result()?;
            let anchor_key = Key::from(MASP.to_db_key())
                .push(&MASP_NOTE_COMMITMENT_ANCHOR_PREFIX.to_owned())
                .expect("Cannot obtain a storage key")
                .push(&namada::types::hash::Hash(
                    bls12_381::Scalar::from(updated_tree.root()).to_bytes(),
                ))
                .expect("Cannot obtain a storage key");
            self.wl_storage.write(&anchor_key, ())?;
        }

        if update_for_tendermint {
            self.update_epoch(&mut response);
            // send the latest oracle configs. These may have changed due to
            // governance.
            self.update_eth_oracle(&changed_keys);
        }

        write_last_block_proposer_address(
            &mut self.wl_storage,
            native_block_proposer_address,
        )?;

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
        byzantine_validators: Vec<Misbehavior>,
    ) -> (BlockHeight, bool) {
        let height = self.wl_storage.storage.get_last_block_height() + 1;

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
            .update_epoch(height, header_time)
            .expect("Must be able to update epoch");
        (height, new_epoch)
    }

    /// If a new epoch begins, we update the response to include
    /// changes to the validator sets and consensus parameters
    fn update_epoch(&mut self, response: &mut shim::response::FinalizeBlock) {
        // Apply validator set update
        response.validator_updates = self
            .get_abci_validator_updates(false, |pk, power| {
                let pub_key =
                    crate::facade::tendermint_proto::v0_37::crypto::PublicKey {
                        sum: Some(key_to_tendermint(&pk).unwrap()),
                    };
                let pub_key = Some(pub_key);
                namada::tendermint_proto::v0_37::abci::ValidatorUpdate {
                    pub_key,
                    power,
                }
            })
            .expect("Must be able to update validator set");
    }

    /// Calculate the new inflation rate, mint the new tokens to the PoS
    /// account, then update the reward products of the validators. This is
    /// executed while finalizing the first block of a new epoch and is applied
    /// with respect to the previous epoch.
    fn apply_inflation(&mut self, current_epoch: Epoch) -> Result<()> {
        let last_epoch = current_epoch.prev();

        // Get the number of blocks in the last epoch
        let first_block_of_last_epoch = self
            .wl_storage
            .storage
            .block
            .pred_epochs
            .first_block_heights[last_epoch.0 as usize]
            .0;
        let num_blocks_in_last_epoch =
            self.wl_storage.storage.block.height.0 - first_block_of_last_epoch;

        // PoS inflation
        namada_proof_of_stake::rewards::apply_inflation(
            &mut self.wl_storage,
            last_epoch,
            num_blocks_in_last_epoch,
        )?;

        // Pgf inflation
        pgf_inflation::apply_inflation(&mut self.wl_storage)?;

        Ok(())
    }

    // Process the proposer and votes in the block to assign their PoS rewards.
    fn log_block_rewards(
        &mut self,
        votes: Vec<namada_proof_of_stake::types::VoteInfo>,
        height: BlockHeight,
        current_epoch: Epoch,
        new_epoch: bool,
    ) -> Result<()> {
        // Read the block proposer of the previously committed block in storage
        // (n-1 if we are in the process of finalizing n right now).
        match read_last_block_proposer_address(&self.wl_storage)? {
            Some(proposer_address) => {
                tracing::debug!(
                    "Found last block proposer: {proposer_address}"
                );
                namada_proof_of_stake::rewards::log_block_rewards(
                    &mut self.wl_storage,
                    if new_epoch {
                        current_epoch.prev()
                    } else {
                        current_epoch
                    },
                    &proposer_address,
                    votes,
                )?;
            }
            None => {
                if height > BlockHeight::default().next_height() {
                    tracing::error!(
                        "Can't find the last block proposer at height {height}"
                    );
                } else {
                    tracing::debug!(
                        "No last block proposer at height {height}"
                    );
                }
            }
        }
        Ok(())
    }

    // Write the inner tx hash to storage and remove the corresponding wrapper
    // hash since it's redundant (we check the inner tx hash too when validating
    // the wrapper). Requires the wrapper transaction as argument to recover
    // both the hashes.
    fn commit_inner_tx_hash(&mut self, wrapper_tx: Tx) {
        self.wl_storage
            .write_tx_hash(wrapper_tx.raw_header_hash())
            .expect("Error while writing tx hash to storage");

        self.wl_storage
            .delete_tx_hash(wrapper_tx.header_hash())
            .expect("Error while deleting tx hash from storage");
    }
}

/// Convert ABCI vote info to PoS vote info. Any info which fails the conversion
/// will be skipped and errors logged.
///
/// # Panics
/// Panics if a validator's address cannot be converted to native address
/// (either due to storage read error or the address not being found) or
/// if the voting power cannot be converted to u64.
fn pos_votes_from_abci(
    storage: &impl StorageRead,
    votes: &[VoteInfo],
) -> Vec<namada_proof_of_stake::types::VoteInfo> {
    votes
        .iter()
        .filter_map(
            |VoteInfo {
                 validator,
                 sig_info,
             }| {
                let crate::facade::tendermint::abci::types::Validator {
                    address,
                    power,
                } = validator;
                let tm_raw_hash_string = HEXUPPER.encode(address);
                if sig_info.is_signed() {
                    tracing::debug!(
                        "Looking up validator from Tendermint VoteInfo's raw \
                         hash {tm_raw_hash_string}"
                    );

                    // Look-up the native address
                    let validator_address = find_validator_by_raw_hash(
                        storage,
                        &tm_raw_hash_string,
                    )
                    .expect(
                        "Must be able to read from storage to find native \
                         address of validator from tendermint raw hash",
                    )
                    .expect(
                        "Must be able to find the native address of validator \
                         from tendermint raw hash",
                    );

                    // Try to convert voting power to u64
                    let validator_vp = u64::try_from(*power).expect(
                        "Must be able to convert voting power from i64 to u64",
                    );

                    Some(namada_proof_of_stake::types::VoteInfo {
                        validator_address,
                        validator_vp,
                    })
                } else {
                    tracing::debug!(
                        "Validator {tm_raw_hash_string} didn't sign last block"
                    );
                    None
                }
            },
        )
        .collect()
}

/// We test the failure cases of [`finalize_block`]. The happy flows
/// are covered by the e2e tests.
#[cfg(test)]
mod test_finalize_block {
    use std::collections::{BTreeMap, BTreeSet, HashMap};
    use std::num::NonZeroU64;
    use std::str::FromStr;

    use data_encoding::HEXUPPER;
    use namada::core::ledger::replay_protection;
    use namada::eth_bridge::storage::bridge_pool::{
        self, get_key_from_hash, get_nonce_key, get_signed_root_key,
    };
    use namada::eth_bridge::storage::min_confirmations_key;
    use namada::ethereum_bridge::storage::wrapped_erc20s;
    use namada::governance::storage::keys::get_proposal_execution_key;
    use namada::governance::storage::proposal::ProposalType;
    use namada::governance::storage::vote::{StorageProposalVote, VoteType};
    use namada::governance::{InitProposalData, VoteProposalData};
    use namada::ledger::gas::VpGasMeter;
    use namada::ledger::native_vp::parameters::ParametersVp;
    use namada::ledger::native_vp::NativeVp;
    use namada::ledger::parameters::EpochDuration;
    use namada::ledger::pos::PosQueries;
    use namada::proof_of_stake::storage::{
        enqueued_slashes_handle, get_num_consensus_validators,
        read_consensus_validator_set_addresses_with_stake, read_total_stake,
        read_validator_stake, rewards_accumulator_handle,
        validator_consensus_key_handle, validator_rewards_products_handle,
        validator_slashes_handle, validator_state_handle, write_pos_params,
    };
    use namada::proof_of_stake::storage_key::{
        is_validator_slashes_key, slashes_prefix,
    };
    use namada::proof_of_stake::types::{
        BondId, SlashType, ValidatorState, WeightedValidator,
    };
    use namada::proof_of_stake::{unjail_validator, ADDRESS as pos_address};
    use namada::state::StorageWrite;
    use namada::token::{Amount, DenominatedAmount, NATIVE_MAX_DECIMAL_PLACES};
    use namada::tx::data::{Fee, WrapperTx};
    use namada::tx::{Code, Data, Section, Signature};
    use namada::types::dec::{Dec, POS_DECIMAL_PRECISION};
    use namada::types::ethereum_events::{EthAddress, Uint as ethUint};
    use namada::types::hash::Hash;
    use namada::types::keccak::KeccakHash;
    use namada::types::key::testing::common_sk_from_simple_seed;
    use namada::types::key::tm_consensus_key_raw_hash;
    use namada::types::storage::{Epoch, KeySeg};
    use namada::types::time::{DateTimeUtc, DurationSecs};
    use namada::types::uint::Uint;
    use namada::vote_ext::{ethereum_events, EthereumTxData};
    use namada_sdk::eth_bridge::MinimumConfirmations;
    use namada_sdk::proof_of_stake::storage::{
        liveness_missed_votes_handle, liveness_sum_missed_votes_handle,
        read_consensus_validator_set_addresses,
    };
    use namada_test_utils::tx_data::TxWriteData;
    use namada_test_utils::TestWasms;
    use test_log::test;

    use super::*;
    use crate::facade::tendermint::abci::types::{
        Misbehavior, Validator, VoteInfo,
    };
    use crate::node::ledger::oracle::control::Command;
    use crate::node::ledger::shell::test_utils::*;
    use crate::node::ledger::shims::abcipp_shim_types::shim::request::{
        FinalizeBlock, ProcessedTx,
    };

    const GAS_LIMIT_MULTIPLIER: u64 = 100_000_000;

    /// Make a wrapper tx and a processed tx from the wrapped tx that can be
    /// added to `FinalizeBlock` request.
    fn mk_wrapper_tx(
        shell: &TestShell,
        keypair: &common::SecretKey,
    ) -> (Tx, ProcessedTx) {
        let mut wrapper_tx =
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
        wrapper_tx.header.chain_id = shell.chain_id.clone();
        wrapper_tx.set_code(Code::new("wasm_code".as_bytes().to_owned(), None));
        wrapper_tx.set_data(Data::new(
            "Encrypted transaction data".as_bytes().to_owned(),
        ));
        wrapper_tx.add_section(Section::Signature(Signature::new(
            wrapper_tx.sechashes(),
            [(0, keypair.clone())].into_iter().collect(),
            None,
        )));
        let tx = wrapper_tx.to_bytes();
        (
            wrapper_tx,
            ProcessedTx {
                tx: tx.into(),
                result: TxResult {
                    code: ResultCode::Ok.into(),
                    info: "".into(),
                },
            },
        )
    }

    /// Make a wrapper tx and a processed tx from the wrapped tx that can be
    /// added to `FinalizeBlock` request.
    fn mk_decrypted_tx(
        shell: &mut TestShell,
        keypair: &common::SecretKey,
    ) -> ProcessedTx {
        let tx_code = TestWasms::TxNoOp.read_bytes();
        let mut outer_tx =
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
        outer_tx.header.chain_id = shell.chain_id.clone();
        outer_tx.set_code(Code::new(tx_code, None));
        outer_tx.set_data(Data::new(
            "Decrypted transaction data".as_bytes().to_owned(),
        ));
        let gas_limit =
            Gas::from(outer_tx.header().wrapper().unwrap().gas_limit)
                .checked_sub(Gas::from(outer_tx.to_bytes().len() as u64))
                .unwrap();
        shell.enqueue_tx(outer_tx.clone(), gas_limit);
        outer_tx.update_header(TxType::Decrypted(DecryptedTx::Decrypted));
        ProcessedTx {
            tx: outer_tx.to_bytes().into(),
            result: TxResult {
                code: ResultCode::Ok.into(),
                info: "".into(),
            },
        }
    }

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
        let balance_key = token::storage_key::balance_key(
            &shell.wl_storage.storage.native_token,
            &Address::from(&keypair.ref_to()),
        );
        shell
            .wl_storage
            .storage
            .write(&balance_key, Amount::native_whole(1000).serialize_to_vec())
            .unwrap();

        // create some wrapper txs
        for i in 1u64..5 {
            let (wrapper, mut processed_tx) = mk_wrapper_tx(&shell, &keypair);
            if i > 1 {
                processed_tx.result.code =
                    u32::try_from(i.rem_euclid(2)).unwrap();
                processed_txs.push(processed_tx);
            } else {
                let wrapper_info =
                    if let TxType::Wrapper(w) = wrapper.header().tx_type {
                        w
                    } else {
                        panic!("Unexpected tx type");
                    };
                shell.enqueue_tx(
                    wrapper.clone(),
                    Gas::from(wrapper_info.gas_limit)
                        .checked_sub(Gas::from(wrapper.to_bytes().len() as u64))
                        .unwrap(),
                );
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
            let valid_tx = valid_tx.next().expect("Test failed");
            assert_eq!(wrapper.tx.header.code_hash, *valid_tx.code_sechash());
            assert_eq!(wrapper.tx.header.data_hash, *valid_tx.data_sechash());
            counter += 1;
        }
        assert_eq!(counter, 3);
    }

    /// Check that if a decrypted tx was rejected by [`process_proposal`],
    /// the correct event is returned. Check that it is still
    /// removed from the queue of txs to be included in the next block
    /// proposal
    #[test]
    fn test_process_proposal_rejected_decrypted_tx() {
        let (mut shell, _, _, _) = setup();
        let keypair = gen_keypair();
        let mut outer_tx =
            Tx::from_type(TxType::Wrapper(Box::new(WrapperTx::new(
                Fee {
                    amount_per_gas_unit: DenominatedAmount::native(
                        Default::default(),
                    ),
                    token: shell.wl_storage.storage.native_token.clone(),
                },
                keypair.ref_to(),
                Epoch(0),
                GAS_LIMIT_MULTIPLIER.into(),
                None,
            ))));
        outer_tx.header.chain_id = shell.chain_id.clone();
        outer_tx.set_code(Code::new("wasm_code".as_bytes().to_owned(), None));
        outer_tx.set_data(Data::new(
            String::from("transaction data").as_bytes().to_owned(),
        ));
        let gas_limit =
            Gas::from(outer_tx.header().wrapper().unwrap().gas_limit)
                .checked_sub(Gas::from(outer_tx.to_bytes().len() as u64))
                .unwrap();
        shell.enqueue_tx(outer_tx.clone(), gas_limit);

        outer_tx.update_header(TxType::Decrypted(DecryptedTx::Decrypted));
        let processed_tx = ProcessedTx {
            tx: outer_tx.to_bytes().into(),
            result: TxResult {
                code: ResultCode::InvalidTx.into(),
                info: "".into(),
            },
        };

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
            assert_eq!(code, &String::from(ResultCode::InvalidTx));
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
        // not valid tx bytes
        let wrapper = Tx::from_type(TxType::Wrapper(Box::new(WrapperTx::new(
            Fee {
                amount_per_gas_unit: DenominatedAmount::native(0.into()),
                token: shell.wl_storage.storage.native_token.clone(),
            },
            keypair.ref_to(),
            Epoch(0),
            GAS_LIMIT_MULTIPLIER.into(),
            None,
        ))));
        let processed_tx = ProcessedTx {
            tx: Tx::from_type(TxType::Decrypted(DecryptedTx::Undecryptable))
                .to_bytes()
                .into(),
            result: TxResult {
                code: ResultCode::Ok.into(),
                info: "".into(),
            },
        };

        let gas_limit =
            Gas::from(wrapper.header().wrapper().unwrap().gas_limit)
                .checked_sub(Gas::from(wrapper.to_bytes().len() as u64))
                .unwrap();
        shell.enqueue_tx(wrapper, gas_limit);

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
            assert_eq!(code, &String::from(ResultCode::Undecryptable));
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

        // Add unshielded balance for fee payment
        let balance_key = token::storage_key::balance_key(
            &shell.wl_storage.storage.native_token,
            &Address::from(&keypair.ref_to()),
        );
        shell
            .wl_storage
            .storage
            .write(&balance_key, Amount::native_whole(1000).serialize_to_vec())
            .unwrap();

        // create two decrypted txs
        for _ in 0..2 {
            processed_txs.push(mk_decrypted_tx(&mut shell, &keypair));
        }
        // create two wrapper txs
        for _ in 0..2 {
            let (tx, processed_tx) = mk_wrapper_tx(&shell, &keypair);
            valid_txs.push(tx.clone());
            processed_txs.push(processed_tx);
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
                assert_eq!(code, String::from(ResultCode::Ok).as_str());
            } else {
                // these should be accepted decrypted txs
                assert_eq!(
                    event.event_type.to_string(),
                    String::from("applied")
                );
                let code =
                    event.attributes.get("code").expect("Test failed").as_str();
                assert_eq!(code, String::from(ResultCode::Ok).as_str());
            }
        }

        // check that the applied decrypted txs were dequeued and the
        // accepted wrappers were enqueued in correct order
        let mut txs = valid_txs.iter();

        let mut counter = 0;
        for wrapper in shell.iter_tx_queue() {
            let next = txs.next().expect("Test failed");
            assert_eq!(wrapper.tx.header.code_hash, *next.code_sechash());
            assert_eq!(wrapper.tx.header.data_hash, *next.data_sechash());
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

        let tx = EthereumTxData::EthereumEvents(ethereum_events::VextDigest {
            signatures: Default::default(),
            events: vec![],
        })
        .sign(&protocol_key, shell.chain_id.clone())
        .to_bytes();

        let req = FinalizeBlock {
            txs: vec![ProcessedTx {
                tx: tx.into(),
                result: TxResult {
                    code: ResultCode::InvalidTx.into(),
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
        assert_eq!(code, &String::from(ResultCode::InvalidTx));
    }

    /// Test that once a validator's vote for an Ethereum event lands
    /// on-chain from a vote extension digest, it dequeues from the
    /// list of events to vote on.
    #[test]
    fn test_eth_events_dequeued_digest() {
        let (mut shell, _, oracle, _) = setup_at_height(3);
        let protocol_key =
            shell.mode.get_protocol_key().expect("Test failed").clone();
        let address = shell
            .mode
            .get_validator_address()
            .expect("Test failed")
            .clone();

        // ---- the ledger receives a new Ethereum event
        let event = EthereumEvent::TransfersToNamada {
            nonce: 0u64.into(),
            transfers: vec![],
        };
        tokio_test::block_on(oracle.send(event.clone())).expect("Test failed");
        let [queued_event]: [EthereumEvent; 1] =
            shell.new_ethereum_events().try_into().expect("Test failed");
        assert_eq!(queued_event, event);

        // ---- The protocol tx that includes this event on-chain
        let ext = ethereum_events::Vext {
            block_height: shell.wl_storage.storage.get_last_block_height(),
            ethereum_events: vec![event.clone()],
            validator_addr: address.clone(),
        }
        .sign(&protocol_key);

        let processed_tx = {
            let signed = MultiSignedEthEvent {
                event,
                signers: BTreeSet::from([(
                    address.clone(),
                    shell.wl_storage.storage.get_last_block_height(),
                )]),
            };

            let digest = ethereum_events::VextDigest {
                signatures: vec![(
                    (address, shell.wl_storage.storage.get_last_block_height()),
                    ext.sig,
                )]
                .into_iter()
                .collect(),
                events: vec![signed],
            };
            ProcessedTx {
                tx: EthereumTxData::EthereumEvents(digest)
                    .sign(&protocol_key, shell.chain_id.clone())
                    .to_bytes()
                    .into(),
                result: TxResult {
                    code: ResultCode::Ok.into(),
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
        assert_eq!(code, String::from(ResultCode::Ok).as_str());

        // --- The event is removed from the queue
        assert!(shell.new_ethereum_events().is_empty());
    }

    /// Test that once a validator's vote for an Ethereum event lands
    /// on-chain from a protocol tx, it dequeues from the
    /// list of events to vote on.
    #[test]
    fn test_eth_events_dequeued_protocol_tx() {
        let (mut shell, _, oracle, _) = setup_at_height(3);
        let protocol_key =
            shell.mode.get_protocol_key().expect("Test failed").clone();
        let address = shell
            .mode
            .get_validator_address()
            .expect("Test failed")
            .clone();

        // ---- the ledger receives a new Ethereum event
        let event = EthereumEvent::TransfersToNamada {
            nonce: 0u64.into(),
            transfers: vec![],
        };
        tokio_test::block_on(oracle.send(event.clone())).expect("Test failed");
        let [queued_event]: [EthereumEvent; 1] =
            shell.new_ethereum_events().try_into().expect("Test failed");
        assert_eq!(queued_event, event);

        // ---- The protocol tx that includes this event on-chain
        let ext = ethereum_events::Vext {
            block_height: shell.wl_storage.storage.get_last_block_height(),
            ethereum_events: vec![event],
            validator_addr: address,
        }
        .sign(&protocol_key);
        let processed_tx = ProcessedTx {
            tx: EthereumTxData::EthEventsVext(ext.into())
                .sign(&protocol_key, shell.chain_id.clone())
                .to_bytes()
                .into(),
            result: TxResult {
                code: ResultCode::Ok.into(),
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
        assert_eq!(code, String::from(ResultCode::Ok).as_str());

        // --- The event is removed from the queue
        assert!(shell.new_ethereum_events().is_empty());
    }

    /// Actions to perform in [`test_bp`].
    enum TestBpAction {
        /// The tested unit correctly signed over the bridge pool root.
        VerifySignedRoot,
        /// The tested unit correctly incremented the bridge pool's nonce.
        CheckNonceIncremented,
    }

    /// Helper function for testing the relevant protocol tx
    /// for signing bridge pool roots and nonces
    fn test_bp<F>(craft_tx: F)
    where
        F: FnOnce(&mut TestShell) -> (Tx, TestBpAction),
    {
        let (mut shell, _, _, _) = setup_at_height(1u64);
        namada::eth_bridge::test_utils::commit_bridge_pool_root_at_height(
            &mut shell.wl_storage,
            &KeccakHash([1; 32]),
            1.into(),
        );
        let value = BlockHeight(2).serialize_to_vec();
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
            .write(&get_nonce_key(), Uint::from(1).serialize_to_vec())
            .expect("Test failed");
        let (tx, action) = craft_tx(&mut shell);
        let processed_tx = ProcessedTx {
            tx: tx.to_bytes().into(),
            result: TxResult {
                code: ResultCode::Ok.into(),
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
        shell.wl_storage.commit_block().unwrap();
        match action {
            TestBpAction::VerifySignedRoot => {
                let (root, _) = shell
                    .wl_storage
                    .ethbridge_queries()
                    .get_signed_bridge_pool_root()
                    .expect("Test failed");
                assert_eq!(root.data.0, KeccakHash([1; 32]));
                assert_eq!(root.data.1, ethUint::from(1));
            }
            TestBpAction::CheckNonceIncremented => {
                let nonce = shell
                    .wl_storage
                    .ethbridge_queries()
                    .get_bridge_pool_nonce();
                assert_eq!(nonce, ethUint::from(2));
            }
        }
    }

    #[test]
    /// Test that adding a new erc20 transfer to the bridge pool
    /// increments the pool's nonce.
    fn test_bp_nonce_is_incremented() {
        test_bp(|shell: &mut TestShell| {
            let asset = EthAddress([0xff; 20]);
            let receiver = EthAddress([0xaa; 20]);
            let bertha = crate::wallet::defaults::bertha_address();
            // add bertha's escrowed `asset` to the pool
            {
                let token = wrapped_erc20s::token(&asset);
                let owner_key = token::storage_key::balance_key(
                    &token,
                    &bridge_pool::BRIDGE_POOL_ADDRESS,
                );
                let supply_key = token::storage_key::minted_balance_key(&token);
                let amt: Amount = 999_999_u64.into();
                shell
                    .wl_storage
                    .write(&owner_key, amt)
                    .expect("Test failed");
                shell
                    .wl_storage
                    .write(&supply_key, amt)
                    .expect("Test failed");
            }
            // add bertha's gas fees the pool
            {
                let amt: Amount = 999_999_u64.into();
                let pool_balance_key = token::storage_key::balance_key(
                    &shell.wl_storage.storage.native_token,
                    &bridge_pool::BRIDGE_POOL_ADDRESS,
                );
                shell
                    .wl_storage
                    .write(&pool_balance_key, amt)
                    .expect("Test failed");
            }
            // write transfer to storage
            let transfer = {
                use namada::types::eth_bridge_pool::{
                    GasFee, PendingTransfer, TransferToEthereum,
                    TransferToEthereumKind,
                };
                let pending = PendingTransfer {
                    transfer: TransferToEthereum {
                        kind: TransferToEthereumKind::Erc20,
                        amount: 10u64.into(),
                        asset,
                        recipient: receiver,
                        sender: bertha.clone(),
                    },
                    gas_fee: GasFee {
                        token: shell.wl_storage.storage.native_token.clone(),
                        amount: 10u64.into(),
                        payer: bertha.clone(),
                    },
                };
                let transfer = (&pending).into();
                shell
                    .wl_storage
                    .write(&bridge_pool::get_pending_key(&pending), pending)
                    .expect("Test failed");
                transfer
            };
            let ethereum_event = EthereumEvent::TransfersToEthereum {
                nonce: 1u64.into(),
                transfers: vec![transfer],
                relayer: bertha,
            };
            let (protocol_key, _) = crate::wallet::defaults::validator_keys();
            let validator_addr = crate::wallet::defaults::validator_address();
            let ext = {
                let ext = ethereum_events::Vext {
                    validator_addr,
                    block_height: shell
                        .wl_storage
                        .storage
                        .get_last_block_height(),
                    ethereum_events: vec![ethereum_event],
                }
                .sign(&protocol_key);
                assert!(ext.verify(&protocol_key.ref_to()).is_ok());
                ext
            };
            let tx = EthereumTxData::EthEventsVext(ext.into())
                .sign(&protocol_key, shell.chain_id.clone());
            (tx, TestBpAction::CheckNonceIncremented)
        });
    }

    #[test]
    /// Test that the generated protocol tx passes Finalize Block
    /// and effects the expected storage changes.
    fn test_bp_roots_protocol_tx() {
        test_bp(|shell: &mut TestShell| {
            let vext = shell.extend_vote_with_bp_roots().expect("Test failed");
            let tx = EthereumTxData::BridgePoolVext(vext.into()).sign(
                shell.mode.get_protocol_key().expect("Test failed"),
                shell.chain_id.clone(),
            );
            (tx, TestBpAction::VerifySignedRoot)
        });
    }

    /// Test that the finalize block handler never commits changes directly to
    /// the DB.
    #[test]
    fn test_finalize_doesnt_commit_db() {
        let (mut shell, _broadcaster, _, _eth_control) = setup();

        // Update epoch duration to make sure we go through couple epochs
        let epoch_duration = EpochDuration {
            min_num_of_blocks: 5,
            min_duration: DurationSecs(0),
        };
        namada::ledger::parameters::update_epoch_parameter(
            &mut shell.wl_storage,
            &epoch_duration,
        )
        .unwrap();
        shell.wl_storage.storage.next_epoch_min_start_height = BlockHeight(5);
        shell.wl_storage.storage.next_epoch_min_start_time = DateTimeUtc::now();

        let txs_key = gen_keypair();
        // Add unshielded balance for fee payment
        let balance_key = token::storage_key::balance_key(
            &shell.wl_storage.storage.native_token,
            &Address::from(&txs_key.ref_to()),
        );
        shell
            .wl_storage
            .storage
            .write(&balance_key, Amount::native_whole(1000).serialize_to_vec())
            .unwrap();

        // Add a proposal to be executed on next epoch change.
        let mut add_proposal = |proposal_id, vote| {
            let validator = shell.mode.get_validator_address().unwrap().clone();
            shell.proposal_data.insert(proposal_id);

            let proposal = InitProposalData {
                id: Some(proposal_id),
                content: Hash::default(),
                author: validator.clone(),
                voting_start_epoch: Epoch::default(),
                voting_end_epoch: Epoch::default().next(),
                grace_epoch: Epoch::default().next(),
                r#type: ProposalType::Default(None),
            };

            namada::governance::init_proposal(
                &mut shell.wl_storage,
                proposal,
                vec![],
                None,
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
            namada::governance::vote_proposal(&mut shell.wl_storage, vote)
                .unwrap();
        };

        // Add a proposal to be accepted and one to be rejected.
        add_proposal(0, StorageProposalVote::Yay(VoteType::Default));
        add_proposal(1, StorageProposalVote::Nay);

        // Commit the genesis state
        shell.wl_storage.commit_block().unwrap();
        shell.commit();

        // Collect all storage key-vals into a sorted map
        let store_block_state = |shell: &TestShell| -> BTreeMap<_, _> {
            shell
                .wl_storage
                .storage
                .db
                .iter_prefix(None)
                .map(|(key, val, _gas)| (key, val))
                .collect()
        };

        // Store the full state in sorted map
        let mut last_storage_state: std::collections::BTreeMap<
            String,
            Vec<u8>,
        > = store_block_state(&shell);

        // Keep applying finalize block
        let validator = shell.mode.get_validator_address().unwrap();
        let pos_params =
            namada_proof_of_stake::storage::read_pos_params(&shell.wl_storage)
                .unwrap();
        let consensus_key =
            namada_proof_of_stake::storage::validator_consensus_key_handle(
                validator,
            )
            .get(&shell.wl_storage, Epoch::default(), &pos_params)
            .unwrap()
            .unwrap();
        let proposer_address = HEXUPPER
            .decode(consensus_key.tm_raw_hash().as_bytes())
            .unwrap();
        let val_stake = read_validator_stake(
            &shell.wl_storage,
            &pos_params,
            validator,
            Epoch::default(),
        )
        .unwrap();

        let votes = vec![VoteInfo {
            validator: Validator {
                address: proposer_address.clone().try_into().unwrap(),
                power: (u128::try_from(val_stake).expect("Test failed") as u64)
                    .try_into()
                    .unwrap(),
            },
            sig_info: tendermint::abci::types::BlockSignatureInfo::LegacySigned,
        }];

        // Need to supply a proposer address and votes to flow through the
        // inflation code
        for _ in 0..20 {
            // Add some txs
            let mut txs = vec![];
            // create two decrypted txs
            for _ in 0..2 {
                txs.push(mk_decrypted_tx(&mut shell, &txs_key));
            }
            // create two wrapper txs
            for _ in 0..2 {
                let (_tx, processed_tx) = mk_wrapper_tx(&shell, &txs_key);
                txs.push(processed_tx);
            }

            let req = FinalizeBlock {
                txs,
                proposer_address: proposer_address.clone(),
                votes: votes.clone(),
                ..Default::default()
            };
            // merkle tree root before finalize_block
            let root_pre = shell.shell.wl_storage.storage.block.tree.root();

            let _events = shell.finalize_block(req).unwrap();

            // the merkle tree root should not change after finalize_block
            let root_post = shell.shell.wl_storage.storage.block.tree.root();
            assert_eq!(root_pre.0, root_post.0);
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

    /// A unit test for PoS inflationary rewards
    #[test]
    fn test_inflation_accounting() {
        // GENERAL IDEA OF THE TEST:
        // For the duration of an epoch, choose some number of times for each of
        // 4 genesis validators to propose a block and choose some arbitrary
        // voting distribution for each block. After each call of
        // finalize_block, check the validator rewards accumulators to ensure
        // that the proper inflation is being applied for each validator. Can
        // also check that the last and current block proposers are being stored
        // properly. At the end of the epoch, check that the validator rewards
        // products are appropriately updated.

        let (mut shell, _recv, _, _) = setup_with_cfg(SetupCfg {
            last_height: 0,
            num_validators: 4,
            ..Default::default()
        });

        let mut validator_set: BTreeSet<WeightedValidator> =
            read_consensus_validator_set_addresses_with_stake(
                &shell.wl_storage,
                Epoch::default(),
            )
            .unwrap()
            .into_iter()
            .collect();

        let params = read_pos_params(&shell.wl_storage).unwrap();

        let val1 = validator_set.pop_first().unwrap();
        let val2 = validator_set.pop_first().unwrap();
        let val3 = validator_set.pop_first().unwrap();
        let val4 = validator_set.pop_first().unwrap();

        let get_pkh = |address, epoch| {
            let ck = validator_consensus_key_handle(&address)
                .get(&shell.wl_storage, epoch, &params)
                .unwrap()
                .unwrap();
            let hash_string = tm_consensus_key_raw_hash(&ck);
            let vec = HEXUPPER.decode(hash_string.as_bytes()).unwrap();
            let res: [u8; 20] = TryFrom::try_from(vec).unwrap();
            res
        };

        let pkh1 = get_pkh(val1.address.clone(), Epoch::default());
        let pkh2 = get_pkh(val2.address.clone(), Epoch::default());
        let pkh3 = get_pkh(val3.address.clone(), Epoch::default());
        let pkh4 = get_pkh(val4.address.clone(), Epoch::default());

        // All validators sign blocks initially
        let votes = vec![
            VoteInfo {
                validator: Validator {
                    address: pkh1,
                    power: (u128::try_from(val1.bonded_stake)
                        .expect("Test failed")
                        as u64)
                        .try_into()
                        .unwrap(),
                },
                sig_info:
                    tendermint::abci::types::BlockSignatureInfo::LegacySigned,
            },
            VoteInfo {
                validator: Validator {
                    address: pkh2,
                    power: (u128::try_from(val2.bonded_stake)
                        .expect("Test failed")
                        as u64)
                        .try_into()
                        .unwrap(),
                },
                sig_info:
                    tendermint::abci::types::BlockSignatureInfo::LegacySigned,
            },
            VoteInfo {
                validator: Validator {
                    address: pkh3,
                    power: (u128::try_from(val3.bonded_stake)
                        .expect("Test failed")
                        as u64)
                        .try_into()
                        .unwrap(),
                },
                sig_info:
                    tendermint::abci::types::BlockSignatureInfo::LegacySigned,
            },
            VoteInfo {
                validator: Validator {
                    address: pkh4,
                    power: (u128::try_from(val4.bonded_stake)
                        .expect("Test failed")
                        as u64)
                        .try_into()
                        .unwrap(),
                },
                sig_info:
                    tendermint::abci::types::BlockSignatureInfo::LegacySigned,
            },
        ];

        let rewards_prod_1 = validator_rewards_products_handle(&val1.address);
        let rewards_prod_2 = validator_rewards_products_handle(&val2.address);
        let rewards_prod_3 = validator_rewards_products_handle(&val3.address);
        let rewards_prod_4 = validator_rewards_products_handle(&val4.address);

        let is_decimal_equal_enough = |target: Dec, to_compare: Dec| -> bool {
            // also return false if to_compare > target since this should
            // never happen for the use cases
            if to_compare < target {
                let tolerance = Dec::new(1, POS_DECIMAL_PRECISION / 2)
                    .expect("Dec creation failed");
                let res = Dec::one() - to_compare / target;
                res < tolerance
            } else {
                to_compare == target
            }
        };

        // NOTE: Want to manually set the block proposer and the vote
        // information in a FinalizeBlock object. In non-abcipp mode,
        // the block proposer is written in ProcessProposal, so need to
        // manually do it here let proposer_address = pkh1.clone();

        // FINALIZE BLOCK 1. Tell Namada that val1 is the block proposer. We
        // won't receive votes from TM since we receive votes at a 1-block
        // delay, so votes will be empty here
        next_block_for_inflation(&mut shell, pkh1.to_vec(), vec![], None);
        assert!(
            rewards_accumulator_handle()
                .is_empty(&shell.wl_storage)
                .unwrap()
        );

        // FINALIZE BLOCK 2. Tell Namada that val1 is the block proposer.
        // Include votes that correspond to block 1. Make val2 the next block's
        // proposer.
        next_block_for_inflation(
            &mut shell,
            pkh2.to_vec(),
            votes.clone(),
            None,
        );
        assert!(rewards_prod_1.is_empty(&shell.wl_storage).unwrap());
        assert!(rewards_prod_2.is_empty(&shell.wl_storage).unwrap());
        assert!(rewards_prod_3.is_empty(&shell.wl_storage).unwrap());
        assert!(rewards_prod_4.is_empty(&shell.wl_storage).unwrap());
        assert!(
            !rewards_accumulator_handle()
                .is_empty(&shell.wl_storage)
                .unwrap()
        );
        // Val1 was the proposer, so its reward should be larger than all
        // others, which should themselves all be equal
        let acc_sum = get_rewards_sum(&shell.wl_storage);
        assert!(is_decimal_equal_enough(Dec::one(), acc_sum));
        let acc = get_rewards_acc(&shell.wl_storage);
        assert_eq!(acc.get(&val2.address), acc.get(&val3.address));
        assert_eq!(acc.get(&val2.address), acc.get(&val4.address));
        assert!(
            acc.get(&val1.address).cloned().unwrap()
                > acc.get(&val2.address).cloned().unwrap()
        );

        // FINALIZE BLOCK 3, with val1 as proposer for the next block.
        next_block_for_inflation(&mut shell, pkh1.to_vec(), votes, None);
        assert!(rewards_prod_1.is_empty(&shell.wl_storage).unwrap());
        assert!(rewards_prod_2.is_empty(&shell.wl_storage).unwrap());
        assert!(rewards_prod_3.is_empty(&shell.wl_storage).unwrap());
        assert!(rewards_prod_4.is_empty(&shell.wl_storage).unwrap());
        // Val2 was the proposer for this block, so its rewards accumulator
        // should be the same as val1 now. Val3 and val4 should be equal as
        // well.
        let acc_sum = get_rewards_sum(&shell.wl_storage);
        assert!(is_decimal_equal_enough(Dec::two(), acc_sum));
        let acc = get_rewards_acc(&shell.wl_storage);
        assert_eq!(acc.get(&val1.address), acc.get(&val2.address));
        assert_eq!(acc.get(&val3.address), acc.get(&val4.address));
        assert!(
            acc.get(&val1.address).cloned().unwrap()
                > acc.get(&val3.address).cloned().unwrap()
        );

        // Now we don't receive a vote from val4.
        let votes = vec![
            VoteInfo {
                validator: Validator {
                    address: pkh1,
                    power: (u128::try_from(val1.bonded_stake)
                        .expect("Test failed")
                        as u64)
                        .try_into()
                        .unwrap(),
                },
                sig_info:
                    tendermint::abci::types::BlockSignatureInfo::LegacySigned,
            },
            VoteInfo {
                validator: Validator {
                    address: pkh2,
                    power: (u128::try_from(val2.bonded_stake)
                        .expect("Test failed")
                        as u64)
                        .try_into()
                        .unwrap(),
                },
                sig_info:
                    tendermint::abci::types::BlockSignatureInfo::LegacySigned,
            },
            VoteInfo {
                validator: Validator {
                    address: pkh3,
                    power: (u128::try_from(val3.bonded_stake)
                        .expect("Test failed")
                        as u64)
                        .try_into()
                        .unwrap(),
                },
                sig_info:
                    tendermint::abci::types::BlockSignatureInfo::LegacySigned,
            },
            VoteInfo {
                validator: Validator {
                    address: pkh4,
                    power: (u128::try_from(val4.bonded_stake)
                        .expect("Test failed")
                        as u64)
                        .try_into()
                        .unwrap(),
                },
                sig_info: tendermint::abci::types::BlockSignatureInfo::Flag(
                    tendermint::block::BlockIdFlag::Absent,
                ),
            },
        ];

        // FINALIZE BLOCK 4. The next block proposer will be val1. Only val1,
        // val2, and val3 vote on this block.
        next_block_for_inflation(
            &mut shell,
            pkh1.to_vec(),
            votes.clone(),
            None,
        );
        assert!(rewards_prod_1.is_empty(&shell.wl_storage).unwrap());
        assert!(rewards_prod_2.is_empty(&shell.wl_storage).unwrap());
        assert!(rewards_prod_3.is_empty(&shell.wl_storage).unwrap());
        assert!(rewards_prod_4.is_empty(&shell.wl_storage).unwrap());
        let acc_sum = get_rewards_sum(&shell.wl_storage);
        assert!(is_decimal_equal_enough(Dec::new(3, 0).unwrap(), acc_sum));
        let acc = get_rewards_acc(&shell.wl_storage);
        assert!(
            acc.get(&val1.address).cloned().unwrap()
                > acc.get(&val2.address).cloned().unwrap()
        );
        assert!(
            acc.get(&val2.address).cloned().unwrap()
                > acc.get(&val3.address).cloned().unwrap()
        );
        assert!(
            acc.get(&val3.address).cloned().unwrap()
                > acc.get(&val4.address).cloned().unwrap()
        );

        // Advance to the start of epoch 1. Val1 is the only block proposer for
        // the rest of the epoch. Val4 does not vote for the rest of the epoch.
        let height_of_next_epoch =
            shell.wl_storage.storage.next_epoch_min_start_height;
        let current_height = 4_u64;
        assert_eq!(current_height, shell.wl_storage.storage.block.height.0);

        for _ in current_height..height_of_next_epoch.0 + 2 {
            dbg!(
                get_rewards_acc(&shell.wl_storage),
                get_rewards_sum(&shell.wl_storage),
            );
            next_block_for_inflation(
                &mut shell,
                pkh1.to_vec(),
                votes.clone(),
                None,
            );
        }
        assert!(
            rewards_accumulator_handle()
                .is_empty(&shell.wl_storage)
                .unwrap()
        );
        let rp1 = rewards_prod_1
            .get(&shell.wl_storage, &Epoch::default())
            .unwrap()
            .unwrap();
        let rp2 = rewards_prod_2
            .get(&shell.wl_storage, &Epoch::default())
            .unwrap()
            .unwrap();
        let rp3 = rewards_prod_3
            .get(&shell.wl_storage, &Epoch::default())
            .unwrap()
            .unwrap();
        let rp4 = rewards_prod_4
            .get(&shell.wl_storage, &Epoch::default())
            .unwrap()
            .unwrap();
        assert!(rp1 > rp2);
        assert!(rp2 > rp3);
        assert!(rp3 > rp4);
    }

    /// A unit test for PoS inflationary rewards claiming and querying
    #[test]
    fn test_claim_rewards() {
        let (mut shell, _recv, _, _) = setup_with_cfg(SetupCfg {
            last_height: 0,
            num_validators: 1,
            ..Default::default()
        });

        let mut validator_set: BTreeSet<WeightedValidator> =
            read_consensus_validator_set_addresses_with_stake(
                &shell.wl_storage,
                Epoch::default(),
            )
            .unwrap()
            .into_iter()
            .collect();

        let params = read_pos_params(&shell.wl_storage).unwrap();

        let validator = validator_set.pop_first().unwrap();

        let get_pkh = |address, epoch| {
            let ck = validator_consensus_key_handle(&address)
                .get(&shell.wl_storage, epoch, &params)
                .unwrap()
                .unwrap();
            let hash_string = tm_consensus_key_raw_hash(&ck);
            let decoded = HEXUPPER.decode(hash_string.as_bytes()).unwrap();
            TryFrom::try_from(decoded).unwrap()
        };

        let pkh1 = get_pkh(validator.address.clone(), Epoch::default());
        let votes = vec![VoteInfo {
            validator: Validator {
                address: pkh1,
                power: (u128::try_from(validator.bonded_stake).unwrap() as u64)
                    .try_into()
                    .unwrap(),
            },
            sig_info: tendermint::abci::types::BlockSignatureInfo::LegacySigned,
        }];
        // let rewards_prod_1 =
        // validator_rewards_products_handle(&val1.address);

        let is_reward_equal_enough = |expected: token::Amount,
                                      actual: token::Amount,
                                      tolerance: u64|
         -> bool {
            let diff = expected - actual;
            diff <= tolerance.into()
        };

        let bond_id = BondId {
            source: validator.address.clone(),
            validator: validator.address.clone(),
        };
        let init_stake = validator.bonded_stake;

        let mut total_rewards = token::Amount::zero();
        let mut total_claimed = token::Amount::zero();

        // FINALIZE BLOCK 1. Tell Namada that val1 is the block proposer. We
        // won't receive votes from TM since we receive votes at a 1-block
        // delay, so votes will be empty here
        next_block_for_inflation(&mut shell, pkh1.to_vec(), vec![], None);
        assert!(
            rewards_accumulator_handle()
                .is_empty(&shell.wl_storage)
                .unwrap()
        );

        let (current_epoch, inflation) =
            advance_epoch(&mut shell, &pkh1, &votes, None);
        total_rewards += inflation;

        // Query the available rewards
        let query_rewards = namada_proof_of_stake::query_reward_tokens(
            &shell.wl_storage,
            None,
            &validator.address,
            current_epoch,
        )
        .unwrap();

        // Claim the rewards from the initial epoch
        let reward_1 = namada_proof_of_stake::claim_reward_tokens(
            &mut shell.wl_storage,
            None,
            &validator.address,
            current_epoch,
        )
        .unwrap();
        total_claimed += reward_1;
        assert_eq!(reward_1, query_rewards);
        assert!(is_reward_equal_enough(total_rewards, total_claimed, 1));

        // Query the available rewards again and check that it is 0 now after
        // the claim
        let query_rewards = namada_proof_of_stake::query_reward_tokens(
            &shell.wl_storage,
            None,
            &validator.address,
            current_epoch,
        )
        .unwrap();
        assert_eq!(query_rewards, token::Amount::zero());

        // Try a claim the next block and ensure we get 0 tokens back
        next_block_for_inflation(
            &mut shell,
            pkh1.to_vec(),
            votes.clone(),
            None,
        );
        let att = namada_proof_of_stake::claim_reward_tokens(
            &mut shell.wl_storage,
            None,
            &validator.address,
            current_epoch,
        )
        .unwrap();
        assert_eq!(att, token::Amount::zero());

        // Go to the next epoch
        let (current_epoch, inflation) =
            advance_epoch(&mut shell, &pkh1, &votes, None);
        total_rewards += inflation;

        // Unbond some tokens
        let unbond_amount = token::Amount::native_whole(50_000);
        let unbond_res = namada_proof_of_stake::unbond_tokens(
            &mut shell.wl_storage,
            None,
            &validator.address,
            unbond_amount,
            current_epoch,
            false,
        )
        .unwrap();
        assert_eq!(unbond_res.sum, unbond_amount);

        // Query the available rewards
        let query_rewards = namada_proof_of_stake::query_reward_tokens(
            &shell.wl_storage,
            None,
            &validator.address,
            current_epoch,
        )
        .unwrap();

        let rew = namada_proof_of_stake::claim_reward_tokens(
            &mut shell.wl_storage,
            None,
            &validator.address,
            current_epoch,
        )
        .unwrap();
        total_claimed += rew;
        assert!(is_reward_equal_enough(total_rewards, total_claimed, 3));
        assert_eq!(query_rewards, rew);

        // Check the bond amounts for rewards up thru the withdrawable epoch
        let withdraw_epoch = current_epoch + params.withdrawable_epoch_offset();
        let last_claim_epoch =
            namada_proof_of_stake::storage::get_last_reward_claim_epoch(
                &shell.wl_storage,
                &validator.address,
                &validator.address,
            )
            .unwrap();
        let bond_amounts = namada_proof_of_stake::bond_amounts_for_rewards(
            &shell.wl_storage,
            &bond_id,
            last_claim_epoch.unwrap_or_default(),
            withdraw_epoch,
        )
        .unwrap();

        // Should only have the remaining amounts in bonds themselves
        let mut exp_bond_amounts = BTreeMap::<Epoch, token::Amount>::new();
        for epoch in Epoch::iter_bounds_inclusive(
            last_claim_epoch.unwrap_or_default(),
            withdraw_epoch,
        ) {
            exp_bond_amounts
                .insert(epoch, validator.bonded_stake - unbond_amount);
        }
        assert_eq!(exp_bond_amounts, bond_amounts);

        let pipeline_epoch_from_unbond = current_epoch + params.pipeline_len;

        // Advance to the withdrawable epoch
        let mut current_epoch = current_epoch;
        let mut missed_rewards = token::Amount::zero();
        while current_epoch < withdraw_epoch {
            let votes = get_default_true_votes(
                &shell.wl_storage,
                shell.wl_storage.storage.block.epoch,
            );
            let (new_epoch, inflation) =
                advance_epoch(&mut shell, &pkh1, &votes, None);
            current_epoch = new_epoch;

            total_rewards += inflation;
            if current_epoch <= pipeline_epoch_from_unbond {
                missed_rewards += inflation;
            }
        }

        // Withdraw tokens
        let withdraw_amount = namada_proof_of_stake::withdraw_tokens(
            &mut shell.wl_storage,
            None,
            &validator.address,
            current_epoch,
        )
        .unwrap();
        assert_eq!(withdraw_amount, unbond_amount);

        // Query the available rewards
        let query_rewards = namada_proof_of_stake::query_reward_tokens(
            &shell.wl_storage,
            None,
            &validator.address,
            current_epoch,
        )
        .unwrap();

        // Claim tokens
        let reward_2 = namada_proof_of_stake::claim_reward_tokens(
            &mut shell.wl_storage,
            None,
            &validator.address,
            current_epoch,
        )
        .unwrap();
        total_claimed += reward_2;
        assert_eq!(query_rewards, reward_2);

        // The total rewards claimed should be approximately equal to the total
        // minted inflation, minus (unbond_amount / initial_stake) * rewards
        // from the unbond epoch and the following epoch (the missed_rewards)
        let ratio = Dec::from(unbond_amount) / Dec::from(init_stake);
        let lost_rewards = ratio * missed_rewards;
        let uncertainty = Dec::from_str("0.07").unwrap();
        let token_uncertainty = uncertainty * lost_rewards;
        let token_diff = total_claimed + lost_rewards - total_rewards;
        assert!(token_diff < token_uncertainty);

        // Query the available rewards to check that they are 0
        let query_rewards = namada_proof_of_stake::query_reward_tokens(
            &shell.wl_storage,
            None,
            &validator.address,
            current_epoch,
        )
        .unwrap();
        assert_eq!(query_rewards, token::Amount::zero());
    }

    /// A unit test for PoS inflationary rewards claiming
    #[test]
    fn test_claim_validator_commissions() {
        let (mut shell, _recv, _, _) = setup_with_cfg(SetupCfg {
            last_height: 0,
            num_validators: 1,
            ..Default::default()
        });

        let mut validator_set: BTreeSet<WeightedValidator> =
            read_consensus_validator_set_addresses_with_stake(
                &shell.wl_storage,
                Epoch::default(),
            )
            .unwrap()
            .into_iter()
            .collect();

        let params = read_pos_params(&shell.wl_storage).unwrap();

        let validator = validator_set.pop_first().unwrap();
        let commission_rate =
            namada_proof_of_stake::storage::validator_commission_rate_handle(
                &validator.address,
            )
            .get(&shell.wl_storage, Epoch(0), &params)
            .unwrap()
            .unwrap();

        let get_pkh = |address, epoch| {
            let ck = validator_consensus_key_handle(&address)
                .get(&shell.wl_storage, epoch, &params)
                .unwrap()
                .unwrap();
            let hash_string = tm_consensus_key_raw_hash(&ck);
            HEXUPPER.decode(hash_string.as_bytes()).unwrap()
        };

        let pkh1 = get_pkh(validator.address.clone(), Epoch::default());

        let is_reward_equal_enough = |expected: token::Amount,
                                      actual: token::Amount,
                                      tolerance: u64|
         -> bool {
            let diff = expected - actual;
            diff <= tolerance.into()
        };

        let init_stake = validator.bonded_stake;

        let mut total_rewards = token::Amount::zero();
        let mut total_claimed = token::Amount::zero();

        // FINALIZE BLOCK 1. Tell Namada that val1 is the block proposer. We
        // won't receive votes from TM since we receive votes at a 1-block
        // delay, so votes will be empty here
        next_block_for_inflation(&mut shell, pkh1.clone(), vec![], None);
        assert!(
            rewards_accumulator_handle()
                .is_empty(&shell.wl_storage)
                .unwrap()
        );

        // Make an account with balance and delegate some tokens
        let delegator = address::testing::gen_implicit_address();
        let del_amount = init_stake;
        let staking_token = shell.wl_storage.storage.native_token.clone();
        namada::token::credit_tokens(
            &mut shell.wl_storage,
            &staking_token,
            &delegator,
            2 * init_stake,
        )
        .unwrap();
        let mut current_epoch = shell.wl_storage.storage.block.epoch;
        namada_proof_of_stake::bond_tokens(
            &mut shell.wl_storage,
            Some(&delegator),
            &validator.address,
            del_amount,
            current_epoch,
            None,
        )
        .unwrap();

        // Advance to pipeline epoch
        for _ in 0..params.pipeline_len {
            let votes = get_default_true_votes(
                &shell.wl_storage,
                shell.wl_storage.storage.block.epoch,
            );
            let (new_epoch, inflation) =
                advance_epoch(&mut shell, &pkh1, &votes, None);
            current_epoch = new_epoch;
            total_rewards += inflation;
        }

        // Claim the rewards for the validator for the first two epochs
        let val_reward_1 = namada_proof_of_stake::claim_reward_tokens(
            &mut shell.wl_storage,
            None,
            &validator.address,
            current_epoch,
        )
        .unwrap();
        total_claimed += val_reward_1;
        assert!(is_reward_equal_enough(
            total_rewards,
            total_claimed,
            current_epoch.0
        ));

        // Go to the next epoch, where now the delegator's stake has been active
        // for an epoch
        let votes = get_default_true_votes(
            &shell.wl_storage,
            shell.wl_storage.storage.block.epoch,
        );
        let (new_epoch, inflation_3) =
            advance_epoch(&mut shell, &pkh1, &votes, None);
        current_epoch = new_epoch;
        total_rewards += inflation_3;

        // Claim again for the validator
        let val_reward_2 = namada_proof_of_stake::claim_reward_tokens(
            &mut shell.wl_storage,
            None,
            &validator.address,
            current_epoch,
        )
        .unwrap();

        // Claim for the delegator
        let del_reward_1 = namada_proof_of_stake::claim_reward_tokens(
            &mut shell.wl_storage,
            Some(&delegator),
            &validator.address,
            current_epoch,
        )
        .unwrap();

        // Check that both claims add up to the inflation minted in the last
        // epoch
        assert!(is_reward_equal_enough(
            inflation_3,
            val_reward_2 + del_reward_1,
            current_epoch.0
        ));

        // Check that the commission earned is expected
        let del_stake = Dec::from(del_amount);
        let tot_stake = Dec::from(init_stake + del_amount);
        let stake_ratio = del_stake / tot_stake;
        let del_rewards_no_commission = stake_ratio * inflation_3;
        let commission = commission_rate * del_rewards_no_commission;
        let exp_val_reward =
            (Dec::one() - stake_ratio) * inflation_3 + commission;
        let exp_del_reward = del_rewards_no_commission - commission;

        assert!(is_reward_equal_enough(exp_val_reward, val_reward_2, 1));
        assert!(is_reward_equal_enough(exp_del_reward, del_reward_1, 1));
    }

    /// A unit test for changing consensus keys and communicating to CometBFT
    #[test]
    fn test_change_validator_consensus_key() {
        let (mut shell, _recv, _, _) = setup_with_cfg(SetupCfg {
            last_height: 0,
            num_validators: 3,
            ..Default::default()
        });

        let mut validators: BTreeSet<WeightedValidator> =
            read_consensus_validator_set_addresses_with_stake(
                &shell.wl_storage,
                Epoch::default(),
            )
            .unwrap()
            .into_iter()
            .collect();

        let params = read_pos_params(&shell.wl_storage).unwrap();
        let mut current_epoch = shell.wl_storage.storage.block.epoch;

        let validator1 = validators.pop_first().unwrap();
        let validator2 = validators.pop_first().unwrap();
        let validator3 = validators.pop_first().unwrap();

        let init_stake = validator1.bonded_stake;

        // Give the validators some tokens for txs
        let staking_token = shell.wl_storage.storage.native_token.clone();
        namada::token::credit_tokens(
            &mut shell.wl_storage,
            &staking_token,
            &validator1.address,
            init_stake,
        )
        .unwrap();
        namada::token::credit_tokens(
            &mut shell.wl_storage,
            &staking_token,
            &validator2.address,
            init_stake,
        )
        .unwrap();
        namada::token::credit_tokens(
            &mut shell.wl_storage,
            &staking_token,
            &validator3.address,
            init_stake,
        )
        .unwrap();

        let get_pkh = |address, epoch| {
            let ck = validator_consensus_key_handle(&address)
                .get(&shell.wl_storage, epoch, &params)
                .unwrap()
                .unwrap();
            let hash_string = tm_consensus_key_raw_hash(&ck);
            HEXUPPER.decode(hash_string.as_bytes()).unwrap()
        };
        let pkh1 = get_pkh(validator1.address.clone(), Epoch::default());

        // FINALIZE BLOCK 1. Tell Namada that val1 is the block proposer. We
        // won't receive votes from TM since we receive votes at a 1-block
        // delay, so votes will be empty here
        next_block_for_inflation(&mut shell, pkh1.clone(), vec![], None);
        assert!(
            rewards_accumulator_handle()
                .is_empty(&shell.wl_storage)
                .unwrap()
        );

        // Check that there's 3 unique consensus keys
        let consensus_keys =
            namada_proof_of_stake::storage::get_consensus_key_set(
                &shell.wl_storage,
            )
            .unwrap();
        assert_eq!(consensus_keys.len(), 3);
        // let ck1 = validator_consensus_key_handle(&validator)
        //     .get(&storage, current_epoch, &params)
        //     .unwrap()
        //     .unwrap();
        // assert_eq!(ck, og_ck);

        // Let one validator update stake, one change consensus key, and then
        // one do both

        // Validator1 bonds 1 NAM
        let bond_amount = token::Amount::native_whole(1);
        namada_proof_of_stake::bond_tokens(
            &mut shell.wl_storage,
            None,
            &validator1.address,
            bond_amount,
            current_epoch,
            None,
        )
        .unwrap();

        // Validator2 changes consensus key
        let new_ck2 = common_sk_from_simple_seed(1).ref_to();
        namada_proof_of_stake::change_consensus_key(
            &mut shell.wl_storage,
            &validator2.address,
            &new_ck2,
            current_epoch,
        )
        .unwrap();

        // Validator3 bonds 1 NAM and changes consensus key
        namada_proof_of_stake::bond_tokens(
            &mut shell.wl_storage,
            None,
            &validator3.address,
            bond_amount,
            current_epoch,
            None,
        )
        .unwrap();
        let new_ck3 = common_sk_from_simple_seed(2).ref_to();
        namada_proof_of_stake::change_consensus_key(
            &mut shell.wl_storage,
            &validator3.address,
            &new_ck3,
            current_epoch,
        )
        .unwrap();

        // Check that there's 5 unique consensus keys
        let consensus_keys =
            namada_proof_of_stake::storage::get_consensus_key_set(
                &shell.wl_storage,
            )
            .unwrap();
        assert_eq!(consensus_keys.len(), 5);

        // Advance to pipeline epoch
        for _ in 0..params.pipeline_len {
            let votes = get_default_true_votes(
                &shell.wl_storage,
                shell.wl_storage.storage.block.epoch,
            );
            let (new_epoch, _inflation) =
                advance_epoch(&mut shell, &pkh1, &votes, None);
            current_epoch = new_epoch;
        }

        let consensus_vals = read_consensus_validator_set_addresses_with_stake(
            &shell.wl_storage,
            current_epoch,
        )
        .unwrap();
        let exp_vals = vec![
            WeightedValidator {
                address: validator1.address.clone(),
                bonded_stake: init_stake + bond_amount,
            },
            WeightedValidator {
                address: validator2.address.clone(),
                bonded_stake: init_stake,
            },
            WeightedValidator {
                address: validator3.address.clone(),
                bonded_stake: init_stake + bond_amount,
            },
        ]
        .into_iter()
        .collect::<BTreeSet<_>>();
        assert_eq!(consensus_vals, exp_vals);

        // Val 1 changes consensus key
        let new_ck1 = common_sk_from_simple_seed(3).ref_to();
        namada_proof_of_stake::change_consensus_key(
            &mut shell.wl_storage,
            &validator1.address,
            &new_ck1,
            current_epoch,
        )
        .unwrap();

        // Val 2 is fully unbonded
        namada_proof_of_stake::unbond_tokens(
            &mut shell.wl_storage,
            None,
            &validator2.address,
            init_stake,
            current_epoch,
            false,
        )
        .unwrap();

        // Val 3 is fully unbonded and changes consensus key
        namada_proof_of_stake::unbond_tokens(
            &mut shell.wl_storage,
            None,
            &validator3.address,
            init_stake + bond_amount,
            current_epoch,
            false,
        )
        .unwrap();
        let new2_ck3 = common_sk_from_simple_seed(4).ref_to();
        namada_proof_of_stake::change_consensus_key(
            &mut shell.wl_storage,
            &validator1.address,
            &new2_ck3,
            current_epoch,
        )
        .unwrap();

        // Check that there's 7 unique consensus keys
        let consensus_keys =
            namada_proof_of_stake::storage::get_consensus_key_set(
                &shell.wl_storage,
            )
            .unwrap();
        assert_eq!(consensus_keys.len(), 7);

        // Advance to pipeline epoch
        for _ in 0..params.pipeline_len {
            let votes = get_default_true_votes(
                &shell.wl_storage,
                shell.wl_storage.storage.block.epoch,
            );
            let (new_epoch, _inflation) =
                advance_epoch(&mut shell, &pkh1, &votes, None);
            current_epoch = new_epoch;
        }

        let consensus_vals = read_consensus_validator_set_addresses_with_stake(
            &shell.wl_storage,
            current_epoch,
        )
        .unwrap();
        let exp_vals = vec![WeightedValidator {
            address: validator1.address.clone(),
            bonded_stake: init_stake + bond_amount,
        }]
        .into_iter()
        .collect::<BTreeSet<_>>();
        assert_eq!(consensus_vals, exp_vals);

        // Now promote the below-threshold validators back into the consensus
        // set, along with consensus key changes

        // Val2 bonds 1 NAM and changes consensus key
        namada_proof_of_stake::bond_tokens(
            &mut shell.wl_storage,
            None,
            &validator2.address,
            bond_amount,
            current_epoch,
            None,
        )
        .unwrap();
        let new2_ck2 = common_sk_from_simple_seed(5).ref_to();
        namada_proof_of_stake::change_consensus_key(
            &mut shell.wl_storage,
            &validator2.address,
            &new2_ck2,
            current_epoch,
        )
        .unwrap();

        // Val3 bonds 1 NAM
        namada_proof_of_stake::bond_tokens(
            &mut shell.wl_storage,
            None,
            &validator3.address,
            bond_amount,
            current_epoch,
            None,
        )
        .unwrap();

        // Check that there's 8 unique consensus keys
        let consensus_keys =
            namada_proof_of_stake::storage::get_consensus_key_set(
                &shell.wl_storage,
            )
            .unwrap();
        assert_eq!(consensus_keys.len(), 8);

        // Advance to pipeline epoch
        for _ in 0..params.pipeline_len {
            let votes = get_default_true_votes(
                &shell.wl_storage,
                shell.wl_storage.storage.block.epoch,
            );
            let (new_epoch, _inflation) =
                advance_epoch(&mut shell, &pkh1, &votes, None);
            current_epoch = new_epoch;
        }

        let consensus_vals = read_consensus_validator_set_addresses_with_stake(
            &shell.wl_storage,
            current_epoch,
        )
        .unwrap();
        let exp_vals = vec![
            WeightedValidator {
                address: validator1.address,
                bonded_stake: init_stake + bond_amount,
            },
            WeightedValidator {
                address: validator2.address,
                bonded_stake: bond_amount,
            },
            WeightedValidator {
                address: validator3.address,
                bonded_stake: bond_amount,
            },
        ]
        .into_iter()
        .collect::<BTreeSet<_>>();
        assert_eq!(consensus_vals, exp_vals);
    }

    fn get_rewards_acc<S>(storage: &S) -> HashMap<Address, Dec>
    where
        S: StorageRead,
    {
        rewards_accumulator_handle()
            .iter(storage)
            .unwrap()
            .map(|elem| elem.unwrap())
            .collect::<HashMap<Address, Dec>>()
    }

    fn get_rewards_sum<S>(storage: &S) -> Dec
    where
        S: StorageRead,
    {
        let acc = get_rewards_acc(storage);
        if acc.is_empty() {
            Dec::zero()
        } else {
            acc.iter().fold(Dec::zero(), |sum, elm| sum + *elm.1)
        }
    }

    /// Test that replay protection keys are not added to the merkle tree
    #[test]
    fn test_replay_keys_not_merkelized() {
        let (mut shell, _, _, _) = setup();

        let (wrapper_tx, processed_tx) =
            mk_wrapper_tx(&shell, &crate::wallet::defaults::albert_keypair());

        let wrapper_hash_key =
            replay_protection::last_key(&wrapper_tx.header_hash());

        // merkle tree root before finalize_block
        let root_pre = shell.shell.wl_storage.storage.block.tree.root();

        let event = &shell
            .finalize_block(FinalizeBlock {
                txs: vec![processed_tx],
                ..Default::default()
            })
            .expect("Test failed")[0];
        assert_eq!(event.event_type.to_string(), String::from("accepted"));
        let code = event
            .attributes
            .get("code")
            .expect(
                "Test
        failed",
            )
            .as_str();
        assert_eq!(code, String::from(ResultCode::Ok).as_str());

        // the merkle tree root should not change after finalize_block
        let root_post = shell.shell.wl_storage.storage.block.tree.root();
        assert_eq!(root_pre.0, root_post.0);

        // Check transaction's hash in storage
        assert!(
            shell
                .shell
                .wl_storage
                .write_log
                .has_replay_protection_entry(&wrapper_tx.header_hash())
                .unwrap_or_default()
        );
        // Check that the hash is present in the merkle tree
        assert!(
            !shell
                .shell
                .wl_storage
                .storage
                .block
                .tree
                .has_key(&wrapper_hash_key)
                .unwrap()
        );
    }

    /// Test that a decrypted tx that has already been applied in the same block
    /// doesn't get reapplied
    #[test]
    fn test_duplicated_decrypted_tx_same_block() {
        let (mut shell, _, _, _) = setup();
        let keypair = gen_keypair();
        let keypair_2 = gen_keypair();
        let mut batch = namada::state::testing::TestStorage::batch();

        let tx_code = TestWasms::TxNoOp.read_bytes();
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
        wrapper.set_code(Code::new(tx_code, None));
        wrapper.set_data(Data::new(
            "Decrypted transaction data".as_bytes().to_owned(),
        ));

        let mut new_wrapper = wrapper.clone();
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
        wrapper.add_section(Section::Signature(Signature::new(
            wrapper.sechashes(),
            [(0, keypair)].into_iter().collect(),
            None,
        )));

        let mut inner = wrapper.clone();
        let mut new_inner = new_wrapper.clone();

        for inner in [&mut inner, &mut new_inner] {
            inner.update_header(TxType::Decrypted(DecryptedTx::Decrypted));
        }

        // Write wrapper hashes in storage
        for tx in [&wrapper, &new_wrapper] {
            let hash_subkey = replay_protection::last_key(&tx.header_hash());
            shell
                .wl_storage
                .storage
                .write_replay_protection_entry(&mut batch, &hash_subkey)
                .expect("Test failed");
        }

        let mut processed_txs: Vec<ProcessedTx> = vec![];
        for inner in [&inner, &new_inner] {
            processed_txs.push(ProcessedTx {
                tx: inner.to_bytes().into(),
                result: TxResult {
                    code: ResultCode::Ok.into(),
                    info: "".into(),
                },
            })
        }

        shell.enqueue_tx(wrapper.clone(), GAS_LIMIT_MULTIPLIER.into());
        shell.enqueue_tx(new_wrapper.clone(), GAS_LIMIT_MULTIPLIER.into());
        // merkle tree root before finalize_block
        let root_pre = shell.shell.wl_storage.storage.block.tree.root();

        let event = &shell
            .finalize_block(FinalizeBlock {
                txs: processed_txs,
                ..Default::default()
            })
            .expect("Test failed");

        // the merkle tree root should not change after finalize_block
        let root_post = shell.shell.wl_storage.storage.block.tree.root();
        assert_eq!(root_pre.0, root_post.0);

        assert_eq!(event[0].event_type.to_string(), String::from("applied"));
        let code = event[0].attributes.get("code").unwrap().as_str();
        assert_eq!(code, String::from(ResultCode::Ok).as_str());
        assert_eq!(event[1].event_type.to_string(), String::from("applied"));
        let code = event[1].attributes.get("code").unwrap().as_str();
        assert_eq!(code, String::from(ResultCode::WasmRuntimeError).as_str());

        for (inner, wrapper) in [(inner, wrapper), (new_inner, new_wrapper)] {
            assert!(
                shell
                    .wl_storage
                    .write_log
                    .has_replay_protection_entry(&inner.raw_header_hash())
                    .unwrap_or_default()
            );
            assert!(
                !shell
                    .wl_storage
                    .write_log
                    .has_replay_protection_entry(&wrapper.header_hash())
                    .unwrap_or_default()
            );
        }
    }

    /// Test that if a decrypted transaction fails because of out-of-gas,
    /// undecryptable, invalid signature or wrong section commitment, its hash
    /// is not committed to storage. Also checks that a tx failing for other
    /// reason has its hash written to storage.
    #[test]
    fn test_tx_hash_handling() {
        let (mut shell, _, _, _) = setup();
        let keypair = gen_keypair();
        let mut batch = namada::state::testing::TestStorage::batch();

        let (out_of_gas_wrapper, _) = mk_wrapper_tx(&shell, &keypair);
        let (undecryptable_wrapper, _) = mk_wrapper_tx(&shell, &keypair);
        let mut wasm_path = top_level_directory();
        // Write a key to trigger the vp to validate the signature
        wasm_path.push("wasm_for_tests/tx_write.wasm");
        let tx_code = std::fs::read(wasm_path)
            .expect("Expected a file at given code path");
        let mut unsigned_wrapper =
            Tx::from_type(TxType::Wrapper(Box::new(WrapperTx::new(
                Fee {
                    amount_per_gas_unit: DenominatedAmount::native(
                        Amount::zero(),
                    ),
                    token: shell.wl_storage.storage.native_token.clone(),
                },
                keypair.ref_to(),
                Epoch(0),
                GAS_LIMIT_MULTIPLIER.into(),
                None,
            ))));
        unsigned_wrapper.header.chain_id = shell.chain_id.clone();
        let mut failing_wrapper = unsigned_wrapper.clone();
        unsigned_wrapper.set_code(Code::new(tx_code, None));
        let addr = Address::from(&keypair.to_public());
        let key = Key::from(addr.to_db_key())
            .join(&Key::from("test".to_string().to_db_key()));
        unsigned_wrapper.set_data(Data::new(
            borsh::to_vec(&TxWriteData {
                key,
                value: "test".as_bytes().to_owned(),
            })
            .unwrap(),
        ));
        let mut wasm_path = top_level_directory();
        wasm_path.push("wasm_for_tests/tx_fail.wasm");
        let tx_code = std::fs::read(wasm_path)
            .expect("Expected a file at given code path");
        failing_wrapper.set_code(Code::new(tx_code, None));
        failing_wrapper.set_data(Data::new(
            "Encrypted transaction data".as_bytes().to_owned(),
        ));
        let mut wrong_commitment_wrapper = failing_wrapper.clone();
        wrong_commitment_wrapper.set_code_sechash(Hash::default());

        let mut out_of_gas_inner = out_of_gas_wrapper.clone();
        let mut undecryptable_inner = undecryptable_wrapper.clone();
        let mut unsigned_inner = unsigned_wrapper.clone();
        let mut wrong_commitment_inner = wrong_commitment_wrapper.clone();
        let mut failing_inner = failing_wrapper.clone();

        undecryptable_inner
            .update_header(TxType::Decrypted(DecryptedTx::Undecryptable));
        for inner in [
            &mut out_of_gas_inner,
            &mut unsigned_inner,
            &mut wrong_commitment_inner,
            &mut failing_inner,
        ] {
            inner.update_header(TxType::Decrypted(DecryptedTx::Decrypted));
        }

        // Write wrapper hashes in storage
        for wrapper in [
            &out_of_gas_wrapper,
            &undecryptable_wrapper,
            &unsigned_wrapper,
            &wrong_commitment_wrapper,
            &failing_wrapper,
        ] {
            let hash_subkey =
                replay_protection::last_key(&wrapper.header_hash());
            shell
                .wl_storage
                .storage
                .write_replay_protection_entry(&mut batch, &hash_subkey)
                .unwrap();
        }

        let mut processed_txs: Vec<ProcessedTx> = vec![];
        for inner in [
            &out_of_gas_inner,
            &undecryptable_inner,
            &unsigned_inner,
            &wrong_commitment_inner,
            &failing_inner,
        ] {
            processed_txs.push(ProcessedTx {
                tx: inner.to_bytes().into(),
                result: TxResult {
                    code: ResultCode::Ok.into(),
                    info: "".into(),
                },
            })
        }

        shell.enqueue_tx(out_of_gas_wrapper.clone(), Gas::default());
        shell.enqueue_tx(
            undecryptable_wrapper.clone(),
            GAS_LIMIT_MULTIPLIER.into(),
        );
        shell.enqueue_tx(unsigned_wrapper.clone(), u64::MAX.into()); // Prevent out of gas which would still make the test pass
        shell.enqueue_tx(
            wrong_commitment_wrapper.clone(),
            GAS_LIMIT_MULTIPLIER.into(),
        );
        shell.enqueue_tx(failing_wrapper.clone(), GAS_LIMIT_MULTIPLIER.into());
        // merkle tree root before finalize_block
        let root_pre = shell.shell.wl_storage.storage.block.tree.root();

        let event = &shell
            .finalize_block(FinalizeBlock {
                txs: processed_txs,
                ..Default::default()
            })
            .expect("Test failed");

        // the merkle tree root should not change after finalize_block
        let root_post = shell.shell.wl_storage.storage.block.tree.root();
        assert_eq!(root_pre.0, root_post.0);

        assert_eq!(event[0].event_type.to_string(), String::from("applied"));
        let code = event[0].attributes.get("code").unwrap().as_str();
        assert_eq!(code, String::from(ResultCode::WasmRuntimeError).as_str());
        assert_eq!(event[1].event_type.to_string(), String::from("applied"));
        let code = event[1].attributes.get("code").unwrap().as_str();
        assert_eq!(code, String::from(ResultCode::Undecryptable).as_str());
        assert_eq!(event[2].event_type.to_string(), String::from("applied"));
        let code = event[2].attributes.get("code").unwrap().as_str();
        assert_eq!(code, String::from(ResultCode::InvalidTx).as_str());
        assert_eq!(event[3].event_type.to_string(), String::from("applied"));
        let code = event[3].attributes.get("code").unwrap().as_str();
        assert_eq!(code, String::from(ResultCode::WasmRuntimeError).as_str());
        assert_eq!(event[4].event_type.to_string(), String::from("applied"));
        let code = event[4].attributes.get("code").unwrap().as_str();
        assert_eq!(code, String::from(ResultCode::WasmRuntimeError).as_str());

        for (invalid_inner, valid_wrapper) in [
            (out_of_gas_inner, out_of_gas_wrapper),
            (undecryptable_inner, undecryptable_wrapper),
            (unsigned_inner, unsigned_wrapper),
            (wrong_commitment_inner, wrong_commitment_wrapper),
        ] {
            assert!(
                !shell
                    .wl_storage
                    .write_log
                    .has_replay_protection_entry(
                        &invalid_inner.raw_header_hash()
                    )
                    .unwrap_or_default()
            );
            assert!(
                shell
                    .wl_storage
                    .storage
                    .has_replay_protection_entry(&valid_wrapper.header_hash())
                    .unwrap_or_default()
            );
        }
        assert!(
            shell
                .wl_storage
                .write_log
                .has_replay_protection_entry(&failing_inner.raw_header_hash())
                .expect("test failed")
        );
        assert!(
            !shell
                .wl_storage
                .write_log
                .has_replay_protection_entry(&failing_wrapper.header_hash())
                .unwrap_or_default()
        );
    }

    #[test]
    /// Test that the hash of the wrapper transaction is committed to storage
    /// even if the wrapper tx fails. The inner transaction hash must instead be
    /// removed
    fn test_commits_hash_if_wrapper_failure() {
        let (mut shell, _, _, _) = setup();
        let keypair = gen_keypair();

        let mut wrapper =
            Tx::from_type(TxType::Wrapper(Box::new(WrapperTx::new(
                Fee {
                    amount_per_gas_unit: DenominatedAmount::native(0.into()),
                    token: shell.wl_storage.storage.native_token.clone(),
                },
                keypair.ref_to(),
                Epoch(0),
                0.into(),
                None,
            ))));
        wrapper.header.chain_id = shell.chain_id.clone();
        wrapper.set_code(Code::new("wasm_code".as_bytes().to_owned(), None));
        wrapper.set_data(Data::new(
            "Encrypted transaction data".as_bytes().to_owned(),
        ));
        wrapper.add_section(Section::Signature(Signature::new(
            wrapper.sechashes(),
            [(0, keypair)].into_iter().collect(),
            None,
        )));

        let wrapper_hash = wrapper.header_hash();

        // Invalid wrapper tx that should lead to a commitment of the wrapper
        // hash and no commitment of the inner hash
        let processed_txs = vec![ProcessedTx {
            tx: wrapper.to_bytes().into(),
            result: TxResult {
                code: ResultCode::Ok.into(),
                info: "".into(),
            },
        }];
        // merkle tree root before finalize_block
        let root_pre = shell.shell.wl_storage.storage.block.tree.root();

        let event = &shell
            .finalize_block(FinalizeBlock {
                txs: processed_txs,
                ..Default::default()
            })
            .expect("Test failed");

        // the merkle tree root should not change after finalize_block
        let root_post = shell.shell.wl_storage.storage.block.tree.root();
        assert_eq!(root_pre.0, root_post.0);

        assert_eq!(event[0].event_type.to_string(), String::from("accepted"));
        let code = event[0]
            .attributes
            .get("code")
            .expect("Test failed")
            .as_str();
        assert_eq!(code, String::from(ResultCode::InvalidTx).as_str());

        assert!(
            shell
                .wl_storage
                .write_log
                .has_replay_protection_entry(&wrapper_hash)
                .unwrap_or_default()
        );
        assert!(
            !shell
                .wl_storage
                .write_log
                .has_replay_protection_entry(&wrapper.raw_header_hash())
                .unwrap_or_default()
        );
    }

    // Test that if the fee payer doesn't have enough funds for fee payment the
    // ledger drains their balance. Note that because of the checks in process
    // proposal this scenario should never happen
    #[test]
    fn test_fee_payment_if_insufficient_balance() {
        let (mut shell, _, _, _) = setup();
        let keypair = gen_keypair();

        let mut wrapper =
            Tx::from_type(TxType::Wrapper(Box::new(WrapperTx::new(
                Fee {
                    amount_per_gas_unit: DenominatedAmount::native(100.into()),
                    token: shell.wl_storage.storage.native_token.clone(),
                },
                keypair.ref_to(),
                Epoch(0),
                GAS_LIMIT_MULTIPLIER.into(),
                None,
            ))));
        wrapper.header.chain_id = shell.chain_id.clone();
        wrapper.set_code(Code::new("wasm_code".as_bytes().to_owned(), None));
        wrapper.set_data(Data::new(
            "Encrypted transaction data".as_bytes().to_owned(),
        ));
        wrapper.add_section(Section::Signature(Signature::new(
            wrapper.sechashes(),
            [(0, keypair.clone())].into_iter().collect(),
            None,
        )));

        let processed_tx = ProcessedTx {
            tx: wrapper.to_bytes().into(),
            result: TxResult {
                code: ResultCode::Ok.into(),
                info: "".into(),
            },
        };

        let event = &shell
            .finalize_block(FinalizeBlock {
                txs: vec![processed_tx],
                ..Default::default()
            })
            .expect("Test failed")[0];

        // Check balance of fee payer is 0
        assert_eq!(event.event_type.to_string(), String::from("accepted"));
        let code = event.attributes.get("code").expect("Testfailed").as_str();
        assert_eq!(code, String::from(ResultCode::InvalidTx).as_str());
        let balance_key = token::storage_key::balance_key(
            &shell.wl_storage.storage.native_token,
            &Address::from(&keypair.to_public()),
        );
        let balance: Amount = shell
            .wl_storage
            .read(&balance_key)
            .unwrap()
            .unwrap_or_default();

        assert_eq!(balance, 0.into())
    }

    // Test that the fees collected from a block are withdrew from the wrapper
    // signer and credited to the block proposer
    #[test]
    fn test_fee_payment_to_block_proposer() {
        let (mut shell, _, _, _) = setup();

        let validator = shell.mode.get_validator_address().unwrap().to_owned();
        let pos_params =
            namada_proof_of_stake::storage::read_pos_params(&shell.wl_storage)
                .unwrap();
        let consensus_key =
            namada_proof_of_stake::storage::validator_consensus_key_handle(
                &validator,
            )
            .get(&shell.wl_storage, Epoch::default(), &pos_params)
            .unwrap()
            .unwrap();
        let proposer_address = HEXUPPER
            .decode(consensus_key.tm_raw_hash().as_bytes())
            .unwrap();

        let proposer_balance = namada::token::read_balance(
            &shell.wl_storage,
            &shell.wl_storage.storage.native_token,
            &validator,
        )
        .unwrap();

        let mut wasm_path = top_level_directory();
        wasm_path.push("wasm_for_tests/tx_no_op.wasm");
        let tx_code = std::fs::read(wasm_path)
            .expect("Expected a file at given code path");
        let mut wrapper =
            Tx::from_type(TxType::Wrapper(Box::new(WrapperTx::new(
                Fee {
                    amount_per_gas_unit: DenominatedAmount::native(1.into()),
                    token: shell.wl_storage.storage.native_token.clone(),
                },
                crate::wallet::defaults::albert_keypair().ref_to(),
                Epoch(0),
                5_000_000.into(),
                None,
            ))));
        wrapper.header.chain_id = shell.chain_id.clone();
        wrapper.set_code(Code::new(tx_code, None));
        wrapper.set_data(Data::new(
            "Enxrypted transaction data".as_bytes().to_owned(),
        ));
        wrapper.add_section(Section::Signature(Signature::new(
            wrapper.sechashes(),
            [(0, crate::wallet::defaults::albert_keypair())]
                .into_iter()
                .collect(),
            None,
        )));
        let fee_amount =
            wrapper.header().wrapper().unwrap().get_tx_fee().unwrap();
        let fee_amount = namada::token::denom_to_amount(
            fee_amount,
            &wrapper.header().wrapper().unwrap().fee.token,
            &shell.wl_storage,
        )
        .unwrap();

        let signer_balance = namada::token::read_balance(
            &shell.wl_storage,
            &shell.wl_storage.storage.native_token,
            &wrapper.header().wrapper().unwrap().fee_payer(),
        )
        .unwrap();

        let processed_tx = ProcessedTx {
            tx: wrapper.to_bytes().into(),
            result: TxResult {
                code: ResultCode::Ok.into(),
                info: "".into(),
            },
        };

        let event = &shell
            .finalize_block(FinalizeBlock {
                txs: vec![processed_tx],
                proposer_address,
                ..Default::default()
            })
            .expect("Test failed")[0];

        // Check fee payment
        assert_eq!(event.event_type.to_string(), String::from("accepted"));
        let code = event.attributes.get("code").expect("Test failed").as_str();
        assert_eq!(code, String::from(ResultCode::Ok).as_str());

        let new_proposer_balance = namada::token::read_balance(
            &shell.wl_storage,
            &shell.wl_storage.storage.native_token,
            &validator,
        )
        .unwrap();
        assert_eq!(
            new_proposer_balance,
            proposer_balance.checked_add(fee_amount).unwrap()
        );

        let new_signer_balance = namada::token::read_balance(
            &shell.wl_storage,
            &shell.wl_storage.storage.native_token,
            &wrapper.header().wrapper().unwrap().fee_payer(),
        )
        .unwrap();
        assert_eq!(
            new_signer_balance,
            signer_balance.checked_sub(fee_amount).unwrap()
        )
    }

    #[test]
    fn test_ledger_slashing() -> namada::state::StorageResult<()> {
        let num_validators = 7_u64;
        let (mut shell, _recv, _, _) = setup_with_cfg(SetupCfg {
            last_height: 0,
            num_validators,
            ..Default::default()
        });
        let mut params = read_pos_params(&shell.wl_storage).unwrap();
        params.owned.unbonding_len = 4;
        write_pos_params(&mut shell.wl_storage, &params.owned)?;

        let validator_set: Vec<WeightedValidator> =
            read_consensus_validator_set_addresses_with_stake(
                &shell.wl_storage,
                Epoch::default(),
            )
            .unwrap()
            .into_iter()
            .collect();

        let val1 = validator_set[0].clone();
        let val2 = validator_set[1].clone();

        let initial_stake = val1.bonded_stake;
        let total_initial_stake = num_validators * initial_stake;

        let get_pkh = |address, epoch| {
            let ck = validator_consensus_key_handle(&address)
                .get(&shell.wl_storage, epoch, &params)
                .unwrap()
                .unwrap();
            let hash_string = tm_consensus_key_raw_hash(&ck);
            let vec = HEXUPPER.decode(hash_string.as_bytes()).unwrap();
            let res: [u8; 20] = TryFrom::try_from(vec).unwrap();
            res
        };

        let mut all_pkhs: Vec<[u8; 20]> = Vec::new();
        let mut behaving_pkhs: Vec<[u8; 20]> = Vec::new();
        for (idx, validator) in validator_set.iter().enumerate() {
            // Every validator should be in the consensus set
            assert_eq!(
                validator_state_handle(&validator.address)
                    .get(&shell.wl_storage, Epoch::default(), &params)
                    .unwrap(),
                Some(ValidatorState::Consensus)
            );
            all_pkhs.push(get_pkh(validator.address.clone(), Epoch::default()));
            if idx > 1_usize {
                behaving_pkhs
                    .push(get_pkh(validator.address.clone(), Epoch::default()));
            }
        }

        let pkh1 = all_pkhs[0];
        let pkh2 = all_pkhs[1];

        // Finalize block 1 (no votes since this is the first block)
        next_block_for_inflation(&mut shell, pkh1.to_vec(), vec![], None);

        let votes = get_default_true_votes(
            &shell.wl_storage,
            shell.wl_storage.storage.block.epoch,
        );
        assert!(!votes.is_empty());
        assert_eq!(votes.len(), 7_usize);

        // For block 2, include the evidences found for block 1.
        // NOTE: Only the type, height, and validator address fields from the
        // Misbehavior struct are used in Namada
        let byzantine_validators = vec![
            Misbehavior {
                kind: MisbehaviorKind::DuplicateVote,
                validator: Validator {
                    address: pkh1,
                    power: Default::default(),
                },
                height: 1_u32.into(),
                time: tendermint::Time::unix_epoch(),
                total_voting_power: Default::default(),
            },
            Misbehavior {
                kind: MisbehaviorKind::LightClientAttack,
                validator: Validator {
                    address: pkh2,
                    power: Default::default(),
                },
                height: 2_u32.into(),
                time: tendermint::Time::unix_epoch(),
                total_voting_power: Default::default(),
            },
        ];
        next_block_for_inflation(
            &mut shell,
            pkh1.to_vec(),
            votes,
            Some(byzantine_validators),
        );

        let processing_epoch = shell.wl_storage.storage.block.epoch
            + params.unbonding_len
            + 1_u64
            + params.cubic_slashing_window_length;

        // Check that the ValidatorState, enqueued slashes, and validator sets
        // are properly updated
        assert_eq!(
            validator_state_handle(&val1.address)
                .get(&shell.wl_storage, Epoch::default(), &params)
                .unwrap(),
            Some(ValidatorState::Consensus)
        );
        assert_eq!(
            validator_state_handle(&val2.address)
                .get(&shell.wl_storage, Epoch::default(), &params)
                .unwrap(),
            Some(ValidatorState::Consensus)
        );
        assert!(
            enqueued_slashes_handle()
                .at(&Epoch::default())
                .is_empty(&shell.wl_storage)?
        );
        assert_eq!(
            get_num_consensus_validators(&shell.wl_storage, Epoch::default())
                .unwrap(),
            7_u64
        );
        for epoch in Epoch::default().next().iter_range(params.pipeline_len) {
            assert_eq!(
                validator_state_handle(&val1.address)
                    .get(&shell.wl_storage, epoch, &params)
                    .unwrap(),
                Some(ValidatorState::Jailed)
            );
            assert_eq!(
                validator_state_handle(&val2.address)
                    .get(&shell.wl_storage, epoch, &params)
                    .unwrap(),
                Some(ValidatorState::Jailed)
            );
            assert!(
                enqueued_slashes_handle()
                    .at(&epoch)
                    .is_empty(&shell.wl_storage)?
            );
            assert_eq!(
                get_num_consensus_validators(&shell.wl_storage, epoch).unwrap(),
                5_u64
            );
        }
        assert!(
            !enqueued_slashes_handle()
                .at(&processing_epoch)
                .is_empty(&shell.wl_storage)?
        );

        // Advance to the processing epoch
        loop {
            let votes = get_default_true_votes(
                &shell.wl_storage,
                shell.wl_storage.storage.block.epoch,
            );
            next_block_for_inflation(
                &mut shell,
                pkh1.to_vec(),
                votes.clone(),
                None,
            );
            // println!(
            //     "Block {} epoch {}",
            //     shell.wl_storage.storage.block.height,
            //     shell.wl_storage.storage.block.epoch
            // );
            if shell.wl_storage.storage.block.epoch == processing_epoch {
                // println!("Reached processing epoch");
                break;
            } else {
                assert!(
                    enqueued_slashes_handle()
                        .at(&shell.wl_storage.storage.block.epoch)
                        .is_empty(&shell.wl_storage)?
                );
                let stake1 = read_validator_stake(
                    &shell.wl_storage,
                    &params,
                    &val1.address,
                    shell.wl_storage.storage.block.epoch,
                )?;
                let stake2 = read_validator_stake(
                    &shell.wl_storage,
                    &params,
                    &val2.address,
                    shell.wl_storage.storage.block.epoch,
                )?;
                let total_stake = read_total_stake(
                    &shell.wl_storage,
                    &params,
                    shell.wl_storage.storage.block.epoch,
                )?;
                assert_eq!(stake1, initial_stake);
                assert_eq!(stake2, initial_stake);
                assert_eq!(total_stake, total_initial_stake);
            }
        }

        let num_slashes = namada::state::iter_prefix_bytes(
            &shell.wl_storage,
            &slashes_prefix(),
        )?
        .filter(|kv_res| {
            let (k, _v) = kv_res.as_ref().unwrap();
            is_validator_slashes_key(k).is_some()
        })
        .count();

        assert_eq!(num_slashes, 2);
        assert_eq!(
            validator_slashes_handle(&val1.address)
                .len(&shell.wl_storage)
                .unwrap(),
            1_u64
        );
        assert_eq!(
            validator_slashes_handle(&val2.address)
                .len(&shell.wl_storage)
                .unwrap(),
            1_u64
        );

        let slash1 = validator_slashes_handle(&val1.address)
            .get(&shell.wl_storage, 0)?
            .unwrap();
        let slash2 = validator_slashes_handle(&val2.address)
            .get(&shell.wl_storage, 0)?
            .unwrap();

        assert_eq!(slash1.r#type, SlashType::DuplicateVote);
        assert_eq!(slash2.r#type, SlashType::LightClientAttack);
        assert_eq!(slash1.epoch, Epoch::default());
        assert_eq!(slash2.epoch, Epoch::default());

        // Each validator has equal weight in this test, and two have been
        // slashed
        let frac = Dec::two() / Dec::new(7, 0).unwrap();
        let cubic_rate = Dec::new(9, 0).unwrap() * frac * frac;

        assert_eq!(slash1.rate, cubic_rate);
        assert_eq!(slash2.rate, cubic_rate);

        // Check that there are still 5 consensus validators and the 2
        // misbehaving ones are still jailed
        for epoch in shell
            .wl_storage
            .storage
            .block
            .epoch
            .iter_range(params.pipeline_len + 1)
        {
            assert_eq!(
                validator_state_handle(&val1.address)
                    .get(&shell.wl_storage, epoch, &params)
                    .unwrap(),
                Some(ValidatorState::Jailed)
            );
            assert_eq!(
                validator_state_handle(&val2.address)
                    .get(&shell.wl_storage, epoch, &params)
                    .unwrap(),
                Some(ValidatorState::Jailed)
            );
            assert_eq!(
                get_num_consensus_validators(&shell.wl_storage, epoch).unwrap(),
                5_u64
            );
        }

        // Check that the deltas at the pipeline epoch are slashed
        let pipeline_epoch =
            shell.wl_storage.storage.block.epoch + params.pipeline_len;
        let stake1 = read_validator_stake(
            &shell.wl_storage,
            &params,
            &val1.address,
            pipeline_epoch,
        )?;
        let stake2 = read_validator_stake(
            &shell.wl_storage,
            &params,
            &val2.address,
            pipeline_epoch,
        )?;
        let total_stake =
            read_total_stake(&shell.wl_storage, &params, pipeline_epoch)?;

        let expected_slashed = initial_stake.mul_ceil(cubic_rate);

        println!(
            "Initial stake = {}\nCubic rate = {}\nExpected slashed = {}\n",
            initial_stake.to_string_native(),
            cubic_rate,
            expected_slashed.to_string_native()
        );

        assert!(
            (stake1.change() - (initial_stake - expected_slashed).change())
                .abs()
                <= 1.into()
        );
        assert!(
            (stake2.change() - (initial_stake - expected_slashed).change())
                .abs()
                <= 1.into()
        );
        assert_eq!(total_stake, total_initial_stake - 2u64 * expected_slashed);

        // Unjail one of the validators
        let current_epoch = shell.wl_storage.storage.block.epoch;
        unjail_validator(&mut shell.wl_storage, &val1.address, current_epoch)?;
        let pipeline_epoch = current_epoch + params.pipeline_len;

        // Check that the state is the same until the pipeline epoch, at which
        // point one validator is unjailed
        for epoch in shell
            .wl_storage
            .storage
            .block
            .epoch
            .iter_range(params.pipeline_len)
        {
            assert_eq!(
                validator_state_handle(&val1.address)
                    .get(&shell.wl_storage, epoch, &params)
                    .unwrap(),
                Some(ValidatorState::Jailed)
            );
            assert_eq!(
                validator_state_handle(&val2.address)
                    .get(&shell.wl_storage, epoch, &params)
                    .unwrap(),
                Some(ValidatorState::Jailed)
            );
            assert_eq!(
                get_num_consensus_validators(&shell.wl_storage, epoch).unwrap(),
                5_u64
            );
        }
        assert_eq!(
            validator_state_handle(&val1.address)
                .get(&shell.wl_storage, pipeline_epoch, &params)
                .unwrap(),
            Some(ValidatorState::Consensus)
        );
        assert_eq!(
            validator_state_handle(&val2.address)
                .get(&shell.wl_storage, pipeline_epoch, &params)
                .unwrap(),
            Some(ValidatorState::Jailed)
        );
        assert_eq!(
            get_num_consensus_validators(&shell.wl_storage, pipeline_epoch)
                .unwrap(),
            6_u64
        );

        Ok(())
    }

    /// NOTE: must call `get_default_true_votes` before every call to
    /// `next_block_for_inflation`
    #[test]
    fn test_multiple_misbehaviors() -> namada::state::StorageResult<()> {
        for num_validators in &[4_u64, 6_u64, 9_u64] {
            tracing::debug!("\nNUM VALIDATORS = {}", num_validators);
            test_multiple_misbehaviors_by_num_vals(*num_validators)?;
        }
        Ok(())
    }

    /// Current test procedure (prefixed by epoch in which the event occurs):
    /// 0) Validator initial stake of 00_000
    /// 1) Delegate 37_231 to validator
    /// 1) Self-unbond 84_654
    /// 2) Unbond delegation of 18_000
    /// 3) Self-bond 9_123
    /// 4) Self-unbond 15_000
    /// 5) Delegate 8_144 to validator
    /// 6) Discover misbehavior in epoch 3
    /// 7) Discover misbehavior in epoch 4
    fn test_multiple_misbehaviors_by_num_vals(
        num_validators: u64,
    ) -> namada::state::StorageResult<()> {
        // Setup the network with pipeline_len = 2, unbonding_len = 4
        // let num_validators = 8_u64;
        let (mut shell, _recv, _, _) = setup_with_cfg(SetupCfg {
            last_height: 0,
            num_validators,
            ..Default::default()
        });
        let mut params = read_pos_params(&shell.wl_storage).unwrap();
        params.owned.unbonding_len = 4;
        params.owned.max_validator_slots = 50;
        write_pos_params(&mut shell.wl_storage, &params.owned)?;

        // Slash pool balance
        let nam_address = shell.wl_storage.storage.native_token.clone();
        let slash_balance_key = token::storage_key::balance_key(
            &nam_address,
            &namada_proof_of_stake::SLASH_POOL_ADDRESS,
        );
        let slash_pool_balance_init: token::Amount = shell
            .wl_storage
            .read(&slash_balance_key)
            .expect("must be able to read")
            .unwrap_or_default();
        debug_assert_eq!(slash_pool_balance_init, token::Amount::zero());

        let consensus_set: Vec<WeightedValidator> =
            read_consensus_validator_set_addresses_with_stake(
                &shell.wl_storage,
                Epoch::default(),
            )
            .unwrap()
            .into_iter()
            .collect();

        let val1 = consensus_set[0].clone();
        let pkh1 = get_pkh_from_address(
            &shell.wl_storage,
            &params,
            val1.address.clone(),
            Epoch::default(),
        );

        let initial_stake = val1.bonded_stake;
        let total_initial_stake = num_validators * initial_stake;

        // Finalize block 1
        next_block_for_inflation(&mut shell, pkh1.to_vec(), vec![], None);

        let votes = get_default_true_votes(&shell.wl_storage, Epoch::default());
        assert!(!votes.is_empty());

        // Advance to epoch 1 and
        // 1. Delegate 67231 NAM to validator
        // 2. Validator self-unbond 154654 NAM
        let (current_epoch, _) = advance_epoch(&mut shell, &pkh1, &votes, None);
        assert_eq!(shell.wl_storage.storage.block.epoch.0, 1_u64);

        // Make an account with balance and delegate some tokens
        let delegator = address::testing::gen_implicit_address();
        let del_1_amount = token::Amount::native_whole(37_231);
        let staking_token = shell.wl_storage.storage.native_token.clone();
        namada::token::credit_tokens(
            &mut shell.wl_storage,
            &staking_token,
            &delegator,
            token::Amount::native_whole(200_000),
        )
        .unwrap();
        namada_proof_of_stake::bond_tokens(
            &mut shell.wl_storage,
            Some(&delegator),
            &val1.address,
            del_1_amount,
            current_epoch,
            None,
        )
        .unwrap();

        // Self-unbond
        let self_unbond_1_amount = token::Amount::native_whole(84_654);
        namada_proof_of_stake::unbond_tokens(
            &mut shell.wl_storage,
            None,
            &val1.address,
            self_unbond_1_amount,
            current_epoch,
            false,
        )
        .unwrap();

        let val_stake = namada_proof_of_stake::storage::read_validator_stake(
            &shell.wl_storage,
            &params,
            &val1.address,
            current_epoch + params.pipeline_len,
        )
        .unwrap();

        let total_stake = namada_proof_of_stake::storage::read_total_stake(
            &shell.wl_storage,
            &params,
            current_epoch + params.pipeline_len,
        )
        .unwrap();

        assert_eq!(
            val_stake,
            initial_stake + del_1_amount - self_unbond_1_amount
        );
        assert_eq!(
            total_stake,
            total_initial_stake + del_1_amount - self_unbond_1_amount
        );

        // Advance to epoch 2 and
        // 1. Unbond 18000 NAM from delegation
        let votes = get_default_true_votes(
            &shell.wl_storage,
            shell.wl_storage.storage.block.epoch,
        );
        let (current_epoch, _) = advance_epoch(&mut shell, &pkh1, &votes, None);
        tracing::debug!("\nUnbonding in epoch 2");
        let del_unbond_1_amount = token::Amount::native_whole(18_000);
        namada_proof_of_stake::unbond_tokens(
            &mut shell.wl_storage,
            Some(&delegator),
            &val1.address,
            del_unbond_1_amount,
            current_epoch,
            false,
        )
        .unwrap();

        let val_stake = namada_proof_of_stake::storage::read_validator_stake(
            &shell.wl_storage,
            &params,
            &val1.address,
            current_epoch + params.pipeline_len,
        )
        .unwrap();
        let total_stake = namada_proof_of_stake::storage::read_total_stake(
            &shell.wl_storage,
            &params,
            current_epoch + params.pipeline_len,
        )
        .unwrap();
        assert_eq!(
            val_stake,
            initial_stake + del_1_amount
                - self_unbond_1_amount
                - del_unbond_1_amount
        );
        assert_eq!(
            total_stake,
            total_initial_stake + del_1_amount
                - self_unbond_1_amount
                - del_unbond_1_amount
        );

        // Advance to epoch 3 and
        // 1. Validator self-bond 9123 NAM
        let votes = get_default_true_votes(
            &shell.wl_storage,
            shell.wl_storage.storage.block.epoch,
        );
        let (current_epoch, _) = advance_epoch(&mut shell, &pkh1, &votes, None);
        tracing::debug!("\nBonding in epoch 3");

        let self_bond_1_amount = token::Amount::native_whole(9_123);
        namada_proof_of_stake::bond_tokens(
            &mut shell.wl_storage,
            None,
            &val1.address,
            self_bond_1_amount,
            current_epoch,
            None,
        )
        .unwrap();

        // Advance to epoch 4
        // 1. Validator self-unbond 15000 NAM
        let votes = get_default_true_votes(
            &shell.wl_storage,
            shell.wl_storage.storage.block.epoch,
        );
        let (current_epoch, _) = advance_epoch(&mut shell, &pkh1, &votes, None);
        assert_eq!(current_epoch.0, 4_u64);

        let self_unbond_2_amount = token::Amount::native_whole(15_000);
        namada_proof_of_stake::unbond_tokens(
            &mut shell.wl_storage,
            None,
            &val1.address,
            self_unbond_2_amount,
            current_epoch,
            false,
        )
        .unwrap();

        // Advance to epoch 5 and
        // Delegate 8144 NAM to validator
        let votes = get_default_true_votes(
            &shell.wl_storage,
            shell.wl_storage.storage.block.epoch,
        );
        let (current_epoch, _) = advance_epoch(&mut shell, &pkh1, &votes, None);
        assert_eq!(current_epoch.0, 5_u64);
        tracing::debug!("Delegating in epoch 5");

        // Delegate
        let del_2_amount = token::Amount::native_whole(8_144);
        namada_proof_of_stake::bond_tokens(
            &mut shell.wl_storage,
            Some(&delegator),
            &val1.address,
            del_2_amount,
            current_epoch,
            None,
        )
        .unwrap();

        tracing::debug!("Advancing to epoch 6");

        // Advance to epoch 6
        let votes = get_default_true_votes(
            &shell.wl_storage,
            shell.wl_storage.storage.block.epoch,
        );
        let (current_epoch, _) = advance_epoch(&mut shell, &pkh1, &votes, None);
        assert_eq!(current_epoch.0, 6_u64);

        // Discover a misbehavior committed in epoch 3
        // NOTE: Only the type, height, and validator address fields from the
        // Misbehavior struct are used in Namada
        let misbehavior_epoch = Epoch(3_u64);
        let height = shell
            .wl_storage
            .storage
            .block
            .pred_epochs
            .first_block_heights[misbehavior_epoch.0 as usize];
        let misbehaviors = vec![Misbehavior {
            kind: MisbehaviorKind::DuplicateVote,
            validator: Validator {
                address: pkh1,
                power: Default::default(),
            },
            height: height.try_into().unwrap(),
            time: tendermint::Time::unix_epoch(),
            total_voting_power: Default::default(),
        }];
        let votes = get_default_true_votes(
            &shell.wl_storage,
            shell.wl_storage.storage.block.epoch,
        );
        next_block_for_inflation(
            &mut shell,
            pkh1.to_vec(),
            votes.clone(),
            Some(misbehaviors),
        );

        // Assertions
        assert_eq!(current_epoch.0, 6_u64);
        let processing_epoch = misbehavior_epoch
            + params.unbonding_len
            + 1_u64
            + params.cubic_slashing_window_length;
        let enqueued_slash = enqueued_slashes_handle()
            .at(&processing_epoch)
            .at(&val1.address)
            .front(&shell.wl_storage)
            .unwrap()
            .unwrap();
        assert_eq!(enqueued_slash.epoch, misbehavior_epoch);
        assert_eq!(enqueued_slash.r#type, SlashType::DuplicateVote);
        assert_eq!(enqueued_slash.rate, Dec::zero());
        let last_slash =
            namada_proof_of_stake::storage::read_validator_last_slash_epoch(
                &shell.wl_storage,
                &val1.address,
            )
            .unwrap();
        assert_eq!(last_slash, Some(misbehavior_epoch));
        assert!(
            namada_proof_of_stake::storage::validator_slashes_handle(
                &val1.address
            )
            .is_empty(&shell.wl_storage)
            .unwrap()
        );

        tracing::debug!("Advancing to epoch 7");

        // Advance to epoch 7
        let (current_epoch, _) = advance_epoch(&mut shell, &pkh1, &votes, None);

        // Discover two more misbehaviors, one committed in epoch 3, one in
        // epoch 4
        let height4 = shell
            .wl_storage
            .storage
            .block
            .pred_epochs
            .first_block_heights[4];
        let misbehaviors = vec![
            Misbehavior {
                kind: MisbehaviorKind::DuplicateVote,
                validator: Validator {
                    address: pkh1,
                    power: Default::default(),
                },
                height: height.try_into().unwrap(),
                time: tendermint::Time::unix_epoch(),
                total_voting_power: Default::default(),
            },
            Misbehavior {
                kind: MisbehaviorKind::DuplicateVote,
                validator: Validator {
                    address: pkh1,
                    power: Default::default(),
                },
                height: height4.try_into().unwrap(),
                time: tendermint::Time::unix_epoch(),
                total_voting_power: Default::default(),
            },
        ];
        let votes = get_default_true_votes(
            &shell.wl_storage,
            shell.wl_storage.storage.block.epoch,
        );
        next_block_for_inflation(
            &mut shell,
            pkh1.to_vec(),
            votes,
            Some(misbehaviors),
        );
        assert_eq!(current_epoch.0, 7_u64);
        let enqueued_slashes_8 = enqueued_slashes_handle()
            .at(&processing_epoch)
            .at(&val1.address);
        let enqueued_slashes_9 = enqueued_slashes_handle()
            .at(&processing_epoch.next())
            .at(&val1.address);

        assert_eq!(enqueued_slashes_8.len(&shell.wl_storage).unwrap(), 2_u64);
        assert_eq!(enqueued_slashes_9.len(&shell.wl_storage).unwrap(), 1_u64);
        let last_slash =
            namada_proof_of_stake::storage::read_validator_last_slash_epoch(
                &shell.wl_storage,
                &val1.address,
            )
            .unwrap();
        assert_eq!(last_slash, Some(Epoch(4)));
        assert!(
            namada_proof_of_stake::is_validator_frozen(
                &shell.wl_storage,
                &val1.address,
                current_epoch,
                &params
            )
            .unwrap()
        );
        assert!(
            namada_proof_of_stake::storage::validator_slashes_handle(
                &val1.address
            )
            .is_empty(&shell.wl_storage)
            .unwrap()
        );

        let pre_stake_10 =
            namada_proof_of_stake::storage::read_validator_stake(
                &shell.wl_storage,
                &params,
                &val1.address,
                Epoch(10),
            )
            .unwrap();
        assert_eq!(
            pre_stake_10,
            initial_stake + del_1_amount
                - self_unbond_1_amount
                - del_unbond_1_amount
                + self_bond_1_amount
                - self_unbond_2_amount
                + del_2_amount
        );

        tracing::debug!("\nNow processing the infractions\n");

        // Advance to epoch 9, where the infractions committed in epoch 3 will
        // be processed
        let votes = get_default_true_votes(
            &shell.wl_storage,
            shell.wl_storage.storage.block.epoch,
        );
        let _ = advance_epoch(&mut shell, &pkh1, &votes, None);
        let votes = get_default_true_votes(
            &shell.wl_storage,
            shell.wl_storage.storage.block.epoch,
        );
        let (current_epoch, _) = advance_epoch(&mut shell, &pkh1, &votes, None);
        assert_eq!(current_epoch.0, 9_u64);

        let val_stake_3 = namada_proof_of_stake::storage::read_validator_stake(
            &shell.wl_storage,
            &params,
            &val1.address,
            Epoch(3),
        )
        .unwrap();
        let val_stake_4 = namada_proof_of_stake::storage::read_validator_stake(
            &shell.wl_storage,
            &params,
            &val1.address,
            Epoch(4),
        )
        .unwrap();

        let tot_stake_3 = namada_proof_of_stake::storage::read_total_stake(
            &shell.wl_storage,
            &params,
            Epoch(3),
        )
        .unwrap();
        let tot_stake_4 = namada_proof_of_stake::storage::read_total_stake(
            &shell.wl_storage,
            &params,
            Epoch(4),
        )
        .unwrap();

        let vp_frac_3 = Dec::from(val_stake_3) / Dec::from(tot_stake_3);
        let vp_frac_4 = Dec::from(val_stake_4) / Dec::from(tot_stake_4);
        let tot_frac = Dec::two() * vp_frac_3 + vp_frac_4;
        let cubic_rate = std::cmp::min(
            Dec::one(),
            Dec::new(9, 0).unwrap() * tot_frac * tot_frac,
        );
        dbg!(&cubic_rate);

        let equal_enough = |rate1: Dec, rate2: Dec| -> bool {
            let tolerance = Dec::new(1, 9).unwrap();
            rate1.abs_diff(&rate2) < tolerance
        };

        // There should be 2 slashes processed for the validator, each with rate
        // equal to the cubic slashing rate
        let val_slashes =
            namada_proof_of_stake::storage::validator_slashes_handle(
                &val1.address,
            );
        assert_eq!(val_slashes.len(&shell.wl_storage).unwrap(), 2u64);
        let is_rate_good = val_slashes
            .iter(&shell.wl_storage)
            .unwrap()
            .all(|s| equal_enough(s.unwrap().rate, cubic_rate));
        assert!(is_rate_good);

        // Check the amount of stake deducted from the futuremost epoch while
        // processing the slashes
        let post_stake_10 = read_validator_stake(
            &shell.wl_storage,
            &params,
            &val1.address,
            Epoch(10),
        )
        .unwrap();
        // The amount unbonded after the infraction that affected the deltas
        // before processing is `del_unbond_1_amount + self_bond_1_amount -
        // self_unbond_2_amount` (since this self-bond was enacted then unbonded
        // all after the infraction). Thus, the additional deltas to be
        // deducted is the (infraction stake - this) * rate
        let slash_rate_3 = std::cmp::min(Dec::one(), Dec::two() * cubic_rate);
        let exp_slashed_during_processing_9 = (initial_stake + del_1_amount
            - self_unbond_1_amount
            - del_unbond_1_amount
            + self_bond_1_amount
            - self_unbond_2_amount)
            .mul_ceil(slash_rate_3);
        assert!(
            ((pre_stake_10 - post_stake_10).change()
                - exp_slashed_during_processing_9.change())
            .abs()
                < Uint::from(1000),
            "Expected {}, got {} (with less than 1000 err)",
            exp_slashed_during_processing_9.to_string_native(),
            (pre_stake_10 - post_stake_10).to_string_native(),
        );

        // Check that we can compute the stake at the pipeline epoch
        // NOTE: may be off. by 1 namnam due to rounding;
        let exp_pipeline_stake = (Dec::one() - slash_rate_3)
            * Dec::from(
                initial_stake + del_1_amount
                    - self_unbond_1_amount
                    - del_unbond_1_amount
                    + self_bond_1_amount
                    - self_unbond_2_amount,
            )
            + Dec::from(del_2_amount);

        assert!(
            exp_pipeline_stake.abs_diff(&Dec::from(post_stake_10))
                <= Dec::new(2, NATIVE_MAX_DECIMAL_PLACES).unwrap(),
            "Expected {}, got {} (with less than 2 err), diff {}",
            exp_pipeline_stake,
            post_stake_10.to_string_native(),
            exp_pipeline_stake.abs_diff(&Dec::from(post_stake_10)),
        );

        // Check the balance of the Slash Pool
        // TODO: finish once implemented
        // let slash_pool_balance: token::Amount = shell
        //     .wl_storage
        //     .read(&slash_balance_key)
        //     .expect("must be able to read")
        //     .unwrap_or_default();
        // let exp_slashed_3 = decimal_mult_amount(
        //     std::cmp::min(Decimal::TWO * cubic_rate, Decimal::ONE),
        //     val_stake_3 - del_unbond_1_amount + self_bond_1_amount
        //         - self_unbond_2_amount,
        // );
        // assert_eq!(slash_pool_balance, exp_slashed_3);

        // Advance to epoch 10, where the infraction committed in epoch 4 will
        // be processed
        let votes = get_default_true_votes(
            &shell.wl_storage,
            shell.wl_storage.storage.block.epoch,
        );
        let (current_epoch, _) = advance_epoch(&mut shell, &pkh1, &votes, None);
        assert_eq!(current_epoch.0, 10_u64);

        // Check the balance of the Slash Pool
        // TODO: finish once implemented
        // let slash_pool_balance: token::Amount = shell
        //     .wl_storage
        //     .read(&slash_balance_key)
        //     .expect("must be able to read")
        //     .unwrap_or_default();

        // let exp_slashed_4 = if dec!(2) * cubic_rate >= Decimal::ONE {
        //     token::Amount::zero()
        // } else if dec!(3) * cubic_rate >= Decimal::ONE {
        //     decimal_mult_amount(
        //         Decimal::ONE - dec!(2) * cubic_rate,
        //         val_stake_4 + self_bond_1_amount - self_unbond_2_amount,
        //     )
        // } else {
        //     decimal_mult_amount(
        //         std::cmp::min(cubic_rate, Decimal::ONE),
        //         val_stake_4 + self_bond_1_amount - self_unbond_2_amount,
        //     )
        // };
        // dbg!(slash_pool_balance, exp_slashed_3 + exp_slashed_4);
        // assert!(
        //     (slash_pool_balance.change()
        //         - (exp_slashed_3 + exp_slashed_4).change())
        //     .abs()
        //         <= 1
        // );

        let val_stake = read_validator_stake(
            &shell.wl_storage,
            &params,
            &val1.address,
            current_epoch + params.pipeline_len,
        )?;

        let post_stake_10 = read_validator_stake(
            &shell.wl_storage,
            &params,
            &val1.address,
            Epoch(10),
        )
        .unwrap();

        // Stake at current epoch should be equal to stake at pipeline
        assert_eq!(
            post_stake_10,
            val_stake,
            "Stake at pipeline in epoch {} ({}) expected to be equal to stake \
             in epoch 10 ({}).",
            current_epoch + params.pipeline_len,
            val_stake.to_string_native(),
            post_stake_10.to_string_native()
        );

        // dbg!(&val_stake);
        // dbg!(pre_stake_10 - post_stake_10);

        // dbg!(&exp_slashed_during_processing_9);
        // TODO: finish once implemented
        // assert!(
        //     ((pre_stake_11 - post_stake_11).change() -
        // exp_slashed_4.change())         .abs()
        //         <= 1
        // );

        // dbg!(&val_stake, &exp_stake);
        // dbg!(exp_slashed_during_processing_8 +
        // exp_slashed_during_processing_9); dbg!(
        //     val_stake_3
        //         - (exp_slashed_during_processing_8 +
        //           exp_slashed_during_processing_9)
        // );

        // let exp_stake = val_stake_3 - del_unbond_1_amount +
        // self_bond_1_amount
        //     - self_unbond_2_amount
        //     + del_2_amount
        //     - exp_slashed_3
        //     - exp_slashed_4;

        // assert!((exp_stake.change() - post_stake_11.change()).abs() <= 1);

        for _ in 0..2 {
            let votes = get_default_true_votes(
                &shell.wl_storage,
                shell.wl_storage.storage.block.epoch,
            );
            let _ = advance_epoch(&mut shell, &pkh1, &votes, None);
        }
        let current_epoch = shell.wl_storage.storage.block.epoch;
        assert_eq!(current_epoch.0, 12_u64);

        tracing::debug!("\nCHECK BOND AND UNBOND DETAILS");
        let details = namada_proof_of_stake::queries::bonds_and_unbonds(
            &shell.wl_storage,
            None,
            None,
        )
        .unwrap();

        let del_id = BondId {
            source: delegator.clone(),
            validator: val1.address.clone(),
        };
        let self_id = BondId {
            source: val1.address.clone(),
            validator: val1.address.clone(),
        };

        let del_details = details.get(&del_id).unwrap();
        let self_details = details.get(&self_id).unwrap();
        // dbg!(del_details, self_details);

        // Check slashes
        assert_eq!(del_details.slashes, self_details.slashes);
        assert_eq!(del_details.slashes.len(), 3);
        assert_eq!(del_details.slashes[0].epoch, Epoch(3));
        assert!(equal_enough(del_details.slashes[0].rate, cubic_rate));
        assert_eq!(del_details.slashes[1].epoch, Epoch(3));
        assert!(equal_enough(del_details.slashes[1].rate, cubic_rate));
        assert_eq!(del_details.slashes[2].epoch, Epoch(4));
        assert!(equal_enough(del_details.slashes[2].rate, cubic_rate));

        // Check delegations
        assert_eq!(del_details.bonds.len(), 2);
        assert_eq!(del_details.bonds[0].start, Epoch(3));
        assert_eq!(
            del_details.bonds[0].amount,
            del_1_amount - del_unbond_1_amount
        );
        assert!(
            (del_details.bonds[0].slashed_amount.unwrap().change()
                - std::cmp::min(
                    Dec::one(),
                    Dec::new(3, 0).unwrap() * cubic_rate
                ) * (del_1_amount.change() - del_unbond_1_amount.change()))
            .abs()
                <= Uint::from(2)
        );
        assert_eq!(del_details.bonds[1].start, Epoch(7));
        assert_eq!(del_details.bonds[1].amount, del_2_amount);
        assert_eq!(del_details.bonds[1].slashed_amount, None);

        // Check self-bonds
        assert_eq!(self_details.bonds.len(), 1);
        assert_eq!(self_details.bonds[0].start, Epoch(0));
        assert_eq!(
            self_details.bonds[0].amount,
            initial_stake - self_unbond_1_amount + self_bond_1_amount
                - self_unbond_2_amount
        );
        assert!(
            (self_details.bonds[0].slashed_amount.unwrap().change()
                - (std::cmp::min(
                    Dec::one(),
                    Dec::new(3, 0).unwrap() * cubic_rate
                ) * (initial_stake - self_unbond_1_amount
                    + self_bond_1_amount
                    - self_unbond_2_amount))
                    .change())
                <= Amount::from_uint(1000, NATIVE_MAX_DECIMAL_PLACES)
                    .unwrap()
                    .change()
        );

        // Check delegation unbonds
        assert_eq!(del_details.unbonds.len(), 1);
        assert_eq!(del_details.unbonds[0].start, Epoch(3));
        assert_eq!(del_details.unbonds[0].withdraw, Epoch(9));
        assert_eq!(del_details.unbonds[0].amount, del_unbond_1_amount);
        assert!(
            (del_details.unbonds[0].slashed_amount.unwrap().change()
                - (std::cmp::min(Dec::one(), Dec::two() * cubic_rate)
                    * del_unbond_1_amount)
                    .change())
            .abs()
                <= Uint::from(1)
        );

        // Check self-unbonds
        assert_eq!(self_details.unbonds.len(), 3);
        assert_eq!(self_details.unbonds[0].start, Epoch(0));
        assert_eq!(self_details.unbonds[0].withdraw, Epoch(8));
        assert_eq!(self_details.unbonds[1].start, Epoch(0));
        assert_eq!(self_details.unbonds[1].withdraw, Epoch(11));
        assert_eq!(self_details.unbonds[2].start, Epoch(5));
        assert_eq!(self_details.unbonds[2].withdraw, Epoch(11));
        assert_eq!(self_details.unbonds[0].amount, self_unbond_1_amount);
        assert_eq!(self_details.unbonds[0].slashed_amount, None);
        assert_eq!(
            self_details.unbonds[1].amount,
            self_unbond_2_amount - self_bond_1_amount
        );
        let rate =
            std::cmp::min(Dec::one(), Dec::new(3, 0).unwrap() * cubic_rate);
        assert!(
            // at most off by 1
            (self_details.unbonds[1].slashed_amount.unwrap().change()
                - (self_unbond_2_amount - self_bond_1_amount)
                    .mul_ceil(rate)
                    .change())
            .abs()
                <= Uint::from(1)
        );
        assert_eq!(self_details.unbonds[2].amount, self_bond_1_amount);
        assert_eq!(self_details.unbonds[2].slashed_amount, None);

        tracing::debug!("\nWITHDRAWING DELEGATION UNBOND");
        // let slash_pool_balance_pre_withdraw = slash_pool_balance;
        // Withdraw the delegation unbonds, which total to 18_000. This should
        // only be affected by the slashes in epoch 3
        let del_withdraw = namada_proof_of_stake::withdraw_tokens(
            &mut shell.wl_storage,
            Some(&delegator),
            &val1.address,
            current_epoch,
        )
        .unwrap();

        let exp_del_withdraw_slashed_amount =
            del_unbond_1_amount.mul_ceil(slash_rate_3);
        assert!(
            (del_withdraw
                - (del_unbond_1_amount - exp_del_withdraw_slashed_amount))
                .raw_amount()
                <= Uint::one()
        );

        // TODO: finish once implemented
        // Check the balance of the Slash Pool
        // let slash_pool_balance: token::Amount = shell
        //     .wl_storage
        //     .read(&slash_balance_key)
        //     .expect("must be able to read")
        //     .unwrap_or_default();
        // dbg!(del_withdraw, slash_pool_balance);
        // assert_eq!(
        //     slash_pool_balance - slash_pool_balance_pre_withdraw,
        //     exp_del_withdraw_slashed_amount
        // );

        // println!("\nWITHDRAWING SELF UNBOND");
        // Withdraw the self unbonds, which total 154_654 + 15_000 - 9_123. Only
        // the (15_000 - 9_123) tokens are slashable.
        // let self_withdraw = namada_proof_of_stake::withdraw_tokens(
        //     &mut shell.wl_storage,
        //     None,
        //     &val1.address,
        //     current_epoch,
        // )
        // .unwrap();

        // let exp_self_withdraw_slashed_amount = decimal_mult_amount(
        //     std::cmp::min(dec!(3) * cubic_rate, Decimal::ONE),
        //     self_unbond_2_amount - self_bond_1_amount,
        // );
        // Check the balance of the Slash Pool
        // let slash_pool_balance: token::Amount = shell
        //     .wl_storage
        //     .read(&slash_balance_key)
        //     .expect("must be able to read")
        //     .unwrap_or_default();

        // dbg!(self_withdraw, slash_pool_balance);
        // dbg!(
        //     decimal_mult_amount(dec!(2) * cubic_rate, val_stake_3)
        //         + decimal_mult_amount(cubic_rate, val_stake_4)
        // );

        // assert_eq!(
        //     exp_self_withdraw_slashed_amount,
        //     slash_pool_balance
        //         - slash_pool_balance_pre_withdraw
        //         - exp_del_withdraw_slashed_amount
        // );

        Ok(())
    }

    #[test]
    fn test_jail_validator_for_inactivity() -> namada::state::StorageResult<()>
    {
        let num_validators = 5_u64;
        let (mut shell, _recv, _, _) = setup_with_cfg(SetupCfg {
            last_height: 0,
            num_validators,
            ..Default::default()
        });
        let params = read_pos_params(&shell.wl_storage).unwrap();

        let initial_consensus_set: Vec<Address> =
            read_consensus_validator_set_addresses(
                &shell.wl_storage,
                Epoch::default(),
            )
            .unwrap()
            .into_iter()
            .collect();
        let val1 = initial_consensus_set[0].clone();
        let pkh1 = get_pkh_from_address(
            &shell.wl_storage,
            &params,
            val1.clone(),
            Epoch::default(),
        );
        let val2 = initial_consensus_set[1].clone();
        let pkh2 = get_pkh_from_address(
            &shell.wl_storage,
            &params,
            val2.clone(),
            Epoch::default(),
        );

        let validator_stake =
            namada_proof_of_stake::storage::read_validator_stake(
                &shell.wl_storage,
                &params,
                &val2,
                Epoch::default(),
            )
            .unwrap();

        let val3 = initial_consensus_set[2].clone();
        let val4 = initial_consensus_set[3].clone();
        let val5 = initial_consensus_set[4].clone();

        // Finalize block 1
        next_block_for_inflation(&mut shell, pkh1.to_vec(), vec![], None);

        // Ensure that there is no liveness data yet since there were no votes
        let missed_votes = liveness_missed_votes_handle();
        let sum_missed_votes = liveness_sum_missed_votes_handle();
        assert!(missed_votes.is_empty(&shell.wl_storage)?);
        assert!(sum_missed_votes.is_empty(&shell.wl_storage)?);

        let minimum_unsigned_blocks = ((Dec::one()
            - params.liveness_threshold)
            * params.liveness_window_check)
            .to_uint()
            .unwrap()
            .as_u64();

        // Finalize block 2 and ensure that some data has been written
        let default_all_votes = get_default_true_votes(
            &shell.wl_storage,
            shell.wl_storage.storage.block.epoch,
        );
        next_block_for_inflation(
            &mut shell,
            pkh1.to_vec(),
            default_all_votes,
            None,
        );
        assert!(missed_votes.is_empty(&shell.wl_storage)?);
        for val in &initial_consensus_set {
            let sum = sum_missed_votes.get(&shell.wl_storage, val)?;
            assert_eq!(sum, Some(0u64));
        }

        // Completely unbond one of the validator to test the pruning at the
        // pipeline epoch
        let mut current_epoch = shell.wl_storage.storage.block.epoch;
        namada_proof_of_stake::unbond_tokens(
            &mut shell.wl_storage,
            None,
            &val5,
            validator_stake,
            current_epoch,
            false,
        )?;
        let pipeline_vals = read_consensus_validator_set_addresses(
            &shell.wl_storage,
            current_epoch + params.pipeline_len,
        )?;
        assert_eq!(pipeline_vals.len(), initial_consensus_set.len() - 1);
        let val5_pipeline_state = validator_state_handle(&val5)
            .get(
                &shell.wl_storage,
                current_epoch + params.pipeline_len,
                &params,
            )?
            .unwrap();
        assert_eq!(val5_pipeline_state, ValidatorState::BelowThreshold);

        // Advance to the next epoch with no votes from validator 2
        // NOTE: assume the minimum blocks for jailing is larger than remaining
        // blocks to next epoch!
        let mut votes_no2 = get_default_true_votes(
            &shell.wl_storage,
            shell.wl_storage.storage.block.epoch,
        );
        votes_no2.retain(|vote| vote.validator.address != pkh2);

        let first_height_without_vote = 2;
        let mut val2_num_missed_blocks = 0u64;
        while current_epoch == Epoch::default() {
            next_block_for_inflation(
                &mut shell,
                pkh1.to_vec(),
                votes_no2.clone(),
                None,
            );
            current_epoch = shell.wl_storage.storage.block.epoch;
            val2_num_missed_blocks += 1;
        }

        // Checks upon the new epoch
        for val in &initial_consensus_set {
            let missed_votes = liveness_missed_votes_handle().at(val);
            let sum = sum_missed_votes.get(&shell.wl_storage, val)?;

            if val == &val2 {
                assert_eq!(sum, Some(val2_num_missed_blocks));
                for height in first_height_without_vote
                    ..first_height_without_vote + val2_num_missed_blocks
                {
                    assert!(missed_votes.contains(&shell.wl_storage, &height)?);
                    assert!(sum.unwrap() < minimum_unsigned_blocks);
                }
            } else {
                assert!(missed_votes.is_empty(&shell.wl_storage)?);
                assert_eq!(sum, Some(0u64));
            }
        }

        // Advance blocks up to just before the next epoch
        loop {
            next_block_for_inflation(
                &mut shell,
                pkh1.to_vec(),
                votes_no2.clone(),
                None,
            );
            if shell.wl_storage.storage.update_epoch_blocks_delay == Some(1) {
                break;
            }
        }
        assert_eq!(shell.wl_storage.storage.block.epoch, current_epoch);
        let pipeline_vals = read_consensus_validator_set_addresses(
            &shell.wl_storage,
            current_epoch + params.pipeline_len,
        )?;
        assert_eq!(pipeline_vals.len(), initial_consensus_set.len() - 1);
        let val2_sum_missed_votes =
            liveness_sum_missed_votes_handle().get(&shell.wl_storage, &val2)?;
        assert_eq!(
            val2_sum_missed_votes,
            Some(shell.wl_storage.storage.block.height.0 - 2)
        );
        for val in &initial_consensus_set {
            if val == &val2 {
                continue;
            }
            let sum = sum_missed_votes.get(&shell.wl_storage, val)?;
            assert_eq!(sum, Some(0u64));
        }

        // Now advance one more block to the next epoch, where validator 2 will
        // miss its 10th vote and should thus be jailed for liveness
        next_block_for_inflation(
            &mut shell,
            pkh1.to_vec(),
            votes_no2.clone(),
            None,
        );
        current_epoch = shell.wl_storage.storage.block.epoch;
        assert_eq!(current_epoch, Epoch(2));

        let val2_sum_missed_votes =
            liveness_sum_missed_votes_handle().get(&shell.wl_storage, &val2)?;
        assert_eq!(val2_sum_missed_votes, Some(minimum_unsigned_blocks));

        // Check the validator sets for all epochs up through the pipeline
        let consensus_vals = read_consensus_validator_set_addresses(
            &shell.wl_storage,
            current_epoch,
        )?;
        assert_eq!(
            consensus_vals,
            HashSet::from_iter([
                val1.clone(),
                val2.clone(),
                val3.clone(),
                val4.clone()
            ])
        );
        for offset in 1..=params.pipeline_len {
            let consensus_vals = read_consensus_validator_set_addresses(
                &shell.wl_storage,
                current_epoch + offset,
            )?;
            assert_eq!(
                consensus_vals,
                HashSet::from_iter([val1.clone(), val3.clone(), val4.clone()])
            );
            let val2_state = validator_state_handle(&val2)
                .get(&shell.wl_storage, current_epoch + offset, &params)?
                .unwrap();
            assert_eq!(val2_state, ValidatorState::Jailed);
            let val5_state = validator_state_handle(&val5)
                .get(&shell.wl_storage, current_epoch + offset, &params)?
                .unwrap();
            assert_eq!(val5_state, ValidatorState::BelowThreshold);
        }

        // Check the liveness data for validators 2 and 5 (2 should still be
        // there, 5 should be removed)
        for val in &initial_consensus_set {
            let missed_votes = liveness_missed_votes_handle().at(val);
            let sum = sum_missed_votes.get(&shell.wl_storage, val)?;

            if val == &val2 {
                assert_eq!(
                    sum,
                    Some(shell.wl_storage.storage.block.height.0 - 2)
                );
                for height in first_height_without_vote
                    ..shell.wl_storage.storage.block.height.0
                {
                    assert!(missed_votes.contains(&shell.wl_storage, &height)?);
                }
            } else if val == &val5 {
                assert!(missed_votes.is_empty(&shell.wl_storage)?);
                assert!(sum.is_none());
            } else {
                assert!(missed_votes.is_empty(&shell.wl_storage)?);
                assert_eq!(sum, Some(0u64));
            }
        }

        // Advance to the next epoch to ensure that the val2 data is removed
        // from the liveness data
        let next_epoch = current_epoch.next();
        loop {
            let votes = get_default_true_votes(
                &shell.wl_storage,
                shell.wl_storage.storage.block.epoch,
            );
            current_epoch = advance_epoch(&mut shell, &pkh1, &votes, None).0;
            if current_epoch == next_epoch {
                break;
            }
        }

        // Check that the liveness data only contains data for vals 1, 3, and 4
        for val in &initial_consensus_set {
            let missed_votes = liveness_missed_votes_handle().at(val);
            let sum = sum_missed_votes.get(&shell.wl_storage, val)?;

            assert!(missed_votes.is_empty(&shell.wl_storage)?);
            if val == &val2 || val == &val5 {
                assert!(sum.is_none());
            } else {
                assert_eq!(sum, Some(0u64));
            }
        }

        // Validator 2 unjail itself
        namada_proof_of_stake::unjail_validator(
            &mut shell.wl_storage,
            &val2,
            current_epoch,
        )?;
        let pipeline_epoch = current_epoch + params.pipeline_len;
        let val2_pipeline_state = validator_state_handle(&val2).get(
            &shell.wl_storage,
            pipeline_epoch,
            &params,
        )?;
        assert_eq!(val2_pipeline_state, Some(ValidatorState::Consensus));

        // Advance to the pipeline epoch
        loop {
            let votes = get_default_true_votes(
                &shell.wl_storage,
                shell.wl_storage.storage.block.epoch,
            );
            current_epoch = advance_epoch(&mut shell, &pkh1, &votes, None).0;
            if current_epoch == pipeline_epoch {
                break;
            }
        }
        let sum_liveness = liveness_sum_missed_votes_handle();
        assert_eq!(sum_liveness.get(&shell.wl_storage, &val1)?, Some(0u64));
        assert_eq!(sum_liveness.get(&shell.wl_storage, &val2)?, None);
        assert_eq!(sum_liveness.get(&shell.wl_storage, &val3)?, Some(0u64));
        assert_eq!(sum_liveness.get(&shell.wl_storage, &val4)?, Some(0u64));
        assert_eq!(sum_liveness.get(&shell.wl_storage, &val5)?, None);

        Ok(())
    }

    fn get_default_true_votes<S>(storage: &S, epoch: Epoch) -> Vec<VoteInfo>
    where
        S: StorageRead,
    {
        let params = read_pos_params(storage).unwrap();
        read_consensus_validator_set_addresses_with_stake(storage, epoch)
            .unwrap()
            .into_iter()
            .map(|val| {
                let pkh = get_pkh_from_address(
                    storage,
                    &params,
                    val.address.clone(),
                    epoch,
                );
                VoteInfo {
                    validator: Validator {
                        address: pkh,
                        power: (u128::try_from(val.bonded_stake).unwrap() as u64).try_into().unwrap(),
                    },
                    sig_info: tendermint::abci::types::BlockSignatureInfo::LegacySigned,
                }
            })
            .collect::<Vec<_>>()
    }

    fn advance_epoch(
        shell: &mut TestShell,
        proposer_address: &[u8],
        consensus_votes: &[VoteInfo],
        misbehaviors: Option<Vec<Misbehavior>>,
    ) -> (Epoch, token::Amount) {
        let current_epoch = shell.wl_storage.storage.block.epoch;
        let staking_token =
            namada_proof_of_stake::staking_token_address(&shell.wl_storage);

        // NOTE: assumed that the only change in pos address balance by
        // advancing to the next epoch is minted inflation - no change occurs
        // due to slashing
        let pos_balance_pre = shell
            .wl_storage
            .read::<token::Amount>(&token::storage_key::balance_key(
                &staking_token,
                &pos_address,
            ))
            .unwrap()
            .unwrap_or_default();
        loop {
            next_block_for_inflation(
                shell,
                proposer_address.to_owned(),
                consensus_votes.to_owned(),
                misbehaviors.clone(),
            );
            if shell.wl_storage.storage.block.epoch == current_epoch.next() {
                break;
            }
        }
        let pos_balance_post = shell
            .wl_storage
            .read::<token::Amount>(&token::storage_key::balance_key(
                &staking_token,
                &pos_address,
            ))
            .unwrap()
            .unwrap_or_default();

        (
            shell.wl_storage.storage.block.epoch,
            pos_balance_post - pos_balance_pre,
        )
    }

    /// Test that updating the ethereum bridge params via governance works.
    #[tokio::test]
    async fn test_eth_bridge_param_updates() {
        let (mut shell, _broadcaster, _, mut control_receiver) =
            setup_at_height(3u64);
        let proposal_execution_key = get_proposal_execution_key(0);
        shell
            .wl_storage
            .write(&proposal_execution_key, 0u64)
            .expect("Test failed.");
        let mut tx = Tx::new(shell.chain_id.clone(), None);
        tx.add_code_from_hash(Hash::default(), None).add_data(0u64);
        let new_min_confirmations = MinimumConfirmations::from(unsafe {
            NonZeroU64::new_unchecked(42)
        });
        shell
            .wl_storage
            .write(&min_confirmations_key(), new_min_confirmations)
            .expect("Test failed");
        let gas_meter = VpGasMeter::new_from_tx_meter(
            &TxGasMeter::new_from_sub_limit(u64::MAX.into()),
        );
        let keys_changed = BTreeSet::from([min_confirmations_key()]);
        let verifiers = BTreeSet::default();
        let ctx = namada::ledger::native_vp::Ctx::new(
            shell.mode.get_validator_address().expect("Test failed"),
            &shell.wl_storage.storage,
            &shell.wl_storage.write_log,
            &tx,
            &TxIndex(0),
            gas_meter,
            &keys_changed,
            &verifiers,
            shell.vp_wasm_cache.clone(),
        );
        let parameters = ParametersVp { ctx };
        let result = parameters
            .validate_tx(&tx, &keys_changed, &verifiers)
            .expect("Test failed");
        assert!(result);

        // we advance forward to the next epoch
        let mut req = FinalizeBlock::default();
        req.header.time = namada::types::time::DateTimeUtc::now();
        let current_decision_height =
            shell.wl_storage.pos_queries().get_current_decision_height();
        if let Some(b) = shell.wl_storage.storage.last_block.as_mut() {
            b.height = current_decision_height + 11;
        }
        shell.finalize_block(req).expect("Test failed");
        shell.commit();

        let consensus_set: Vec<WeightedValidator> =
            read_consensus_validator_set_addresses_with_stake(
                &shell.wl_storage,
                Epoch::default(),
            )
            .unwrap()
            .into_iter()
            .collect();

        let params = read_pos_params(&shell.wl_storage).unwrap();
        let val1 = consensus_set[0].clone();
        let pkh1 = get_pkh_from_address(
            &shell.wl_storage,
            &params,
            val1.address.clone(),
            Epoch::default(),
        );

        let _ = control_receiver.recv().await.expect("Test failed");
        // Finalize block 2
        let votes = vec![VoteInfo {
            validator: Validator {
                address: pkh1,
                power: (u128::try_from(val1.bonded_stake).expect("Test failed")
                    as u64)
                    .try_into()
                    .unwrap(),
            },
            sig_info: tendermint::abci::types::BlockSignatureInfo::LegacySigned,
        }];
        next_block_for_inflation(&mut shell, pkh1.to_vec(), votes, None);
        let Command::UpdateConfig(cmd) =
            control_receiver.recv().await.expect("Test failed");
        assert_eq!(u64::from(cmd.min_confirmations), 42);
    }
}
