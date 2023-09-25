//! Implementation of the `FinalizeBlock` ABCI++ method for the Shell

use std::collections::HashMap;

use data_encoding::HEXUPPER;
use namada::core::ledger::pgf::ADDRESS as pgf_address;
use namada::ledger::events::EventType;
use namada::ledger::gas::{GasMetering, TxGasMeter};
use namada::ledger::parameters::storage as params_storage;
use namada::ledger::pos::{namada_proof_of_stake, staking_token_address};
use namada::ledger::storage::EPOCH_SWITCH_BLOCKS_DELAY;
use namada::ledger::storage_api::token::credit_tokens;
use namada::ledger::storage_api::{pgf, StorageRead, StorageWrite};
use namada::ledger::{inflation, protocol, replay_protection};
use namada::proof_of_stake::{
    delegator_rewards_products_handle, find_validator_by_raw_hash,
    read_last_block_proposer_address, read_pos_params, read_total_stake,
    read_validator_stake, rewards_accumulator_handle,
    validator_commission_rate_handle, validator_rewards_products_handle,
    write_last_block_proposer_address,
};
use namada::types::address::Address;
use namada::types::dec::Dec;
use namada::types::key::tm_raw_hash_to_string;
use namada::types::storage::{BlockHash, BlockResults, Epoch, Header};
use namada::types::token::Amount;
use namada::types::transaction::protocol::{
    ethereum_tx_data_variants, ProtocolTxType,
};
use namada::types::vote_extensions::ethereum_events::MultiSignedEthEvent;

use super::governance::execute_governance_proposals;
use super::*;
use crate::facade::tendermint_proto::abci::{
    Misbehavior as Evidence, VoteInfo,
};
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

        if new_epoch {
            namada::ledger::storage::update_allowed_conversions(
                &mut self.wl_storage,
            )?;

            execute_governance_proposals(self, &mut response)?;

            // Copy the new_epoch + pipeline_len - 1 validator set into
            // new_epoch + pipeline_len
            let pos_params =
                namada_proof_of_stake::read_pos_params(&self.wl_storage)?;
            namada_proof_of_stake::copy_validator_sets_and_positions(
                &mut self.wl_storage,
                current_epoch,
                current_epoch + pos_params.pipeline_len,
            )?;
            namada_proof_of_stake::store_total_consensus_stake(
                &mut self.wl_storage,
                current_epoch,
            )?;
            namada_proof_of_stake::purge_validator_sets_for_old_epoch(
                &mut self.wl_storage,
                current_epoch,
            )?;
        }

        // Invariant: Has to be applied before `record_slashes_from_evidence`
        // because it potentially needs to be able to read validator state from
        // previous epoch and jailing validator removes the historical state
        self.log_block_rewards(&req.votes, height, current_epoch, new_epoch)?;
        if new_epoch {
            self.apply_inflation(current_epoch)?;
        }

        // Invariant: This has to be applied after
        // `copy_validator_sets_and_positions` and before `self.update_epoch`.
        self.record_slashes_from_evidence();
        // Invariant: This has to be applied after
        // `copy_validator_sets_and_positions` if we're starting a new epoch
        if new_epoch {
            self.process_slashes();
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
            if ErrorCodes::from_u32(processed_tx.result.code).unwrap()
                == ErrorCodes::InvalidSig
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
            if ErrorCodes::from_u32(processed_tx.result.code).unwrap()
                != ErrorCodes::Ok
            {
                let mut tx_event = Event::new_tx_event(&tx, height.0);
                tx_event["code"] = processed_tx.result.code.to_string();
                tx_event["info"] =
                    format!("Tx rejected: {}", &processed_tx.result.info);
                tx_event["gas_used"] = "0".into();
                response.events.push(tx_event);
                // if the rejected tx was decrypted, remove it
                // from the queue of txs to be processed and remove the hash
                // from storage
                if let TxType::Decrypted(_) = &tx_header.tx_type {
                    let tx_hash = self
                        .wl_storage
                        .storage
                        .tx_queue
                        .pop()
                        .expect("Missing wrapper tx in queue")
                        .tx
                        .clone()
                        .update_header(TxType::Raw)
                        .header_hash();
                    let tx_hash_key =
                        replay_protection::get_replay_protection_key(&tx_hash);
                    self.wl_storage
                        .delete(&tx_hash_key)
                        .expect("Error while deleting tx hash from storage");
                }

                #[cfg(not(any(feature = "abciplus", feature = "abcipp")))]
                if let TxType::Wrapper(wrapper) = &tx_header.tx_type {
                    // Charge fee if wrapper transaction went out of gas or
                    // failed because of fees
                    let error_code =
                        ErrorCodes::from_u32(processed_tx.result.code).unwrap();
                    if (error_code == ErrorCodes::TxGasLimit)
                        | (error_code == ErrorCodes::FeeError)
                    {
                        let masp_transaction = wrapper
                            .unshield_section_hash
                            .map(|ref hash| {
                                tx.get_section(hash)
                                    .map(|section| {
                                        if let Section::MaspTx(transaction) =
                                            section
                                        {
                                            Some(transaction.to_owned())
                                        } else {
                                            None
                                        }
                                    })
                                    .flatten()
                            })
                            .flatten();
                        if let Err(msg) = protocol::charge_fee(
                            wrapper,
                            masp_transaction,
                            ShellParams::new(
                                TxGasMeter::new_from_sub_limit(u64::MAX),
                                &mut self.wl_storage,
                                &mut self.vp_wasm_cache,
                                &mut self.tx_wasm_cache,
                            ),
                            Some(&native_block_proposer_address),
                            &mut BTreeSet::default(),
                        ) {
                            self.wl_storage.write_log.drop_tx();
                            tracing::error!(
                                "Rejected wrapper tx {} could not pay fee: {}",
                                Hash::sha256(
                                    tx::try_from(processed_tx.as_ref())
                                        .unwrap()
                                ),
                                msg
                            )
                        }
                    }
                }

                continue;
            }

            let (mut tx_event, tx_unsigned_hash, mut tx_gas_meter, wrapper) =
                match &tx_header.tx_type {
                    TxType::Wrapper(wrapper) => {
                        stats.increment_wrapper_txs();
                        let tx_event = Event::new_tx_event(&tx, height.0);
                        let gas_meter = TxGasMeter::new(wrapper.gas_limit);
                        (tx_event, None, gas_meter, Some(tx.clone()))
                    }
                    TxType::Decrypted(inner) => {
                        // We remove the corresponding wrapper tx from the queue
                        let mut tx_in_queue = self
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
                                    ErrorCodes::Undecryptable.into();
                                continue;
                            }
                        }

                        (
                            event,
                            Some(
                                tx_in_queue
                                    .tx
                                    .update_header(TxType::Raw)
                                    .header_hash(),
                            ),
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
                        ref protocol_tx_type => {
                            tracing::error!(
                                ?protocol_tx_type,
                                "Internal logic error: FinalizeBlock received \
                                 an unsupported TxType::Protocol transaction: \
                                 {:?}",
                                protocol_tx
                            );
                            continue;
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
                Ok(result) => {
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
                            stats.increment_successful_txs();
                        }
                        self.wl_storage.commit_tx();
                        if !tx_event.contains_key("code") {
                            tx_event["code"] = ErrorCodes::Ok.into();
                            self.wl_storage
                                .storage
                                .block
                                .results
                                .accept(tx_index);
                        }
                        for ibc_event in &result.ibc_events {
                            // Add the IBC event besides the tx_event
                            let mut event = Event::from(ibc_event.clone());
                            // Add the height for IBC event query
                            event["height"] = height.to_string();
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
                    // If transaction type is Decrypted and failed because of
                    // out of gas, remove its hash from storage to allow
                    // rewrapping it
                    if let Some(hash) = tx_unsigned_hash {
                        if let Error::TxApply(protocol::Error::GasError(_)) =
                            msg
                        {
                            let tx_hash_key =
                                replay_protection::get_replay_protection_key(
                                    &hash,
                                );
                            self.wl_storage.delete(&tx_hash_key).expect(
                                "Error while deleting tx hash key from storage",
                            );
                        }
                    }

                    tx_event["gas_used"] =
                        tx_gas_meter.get_tx_consumed_gas().to_string();
                    tx_event["info"] = msg.to_string();
                    if let EventType::Accepted = tx_event.event_type {
                        // If wrapper, invalid tx error code
                        tx_event["code"] = ErrorCodes::InvalidTx.into();
                    } else {
                        tx_event["code"] = ErrorCodes::WasmRuntimeError.into();
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

        if update_for_tendermint {
            self.update_epoch(&mut response);
            // send the latest oracle configs. These may have changed due to
            // governance.
            self.update_eth_oracle();
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
        byzantine_validators: Vec<Evidence>,
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
            .get_abci_validator_updates(false)
            .expect("Must be able to update validator set");
    }

    /// Calculate the new inflation rate, mint the new tokens to the PoS
    /// account, then update the reward products of the validators. This is
    /// executed while finalizing the first block of a new epoch and is applied
    /// with respect to the previous epoch.
    fn apply_inflation(&mut self, current_epoch: Epoch) -> Result<()> {
        let last_epoch = current_epoch.prev();
        // Get input values needed for the PD controller for PoS and MASP.
        // Run the PD controllers to calculate new rates.
        //
        // MASP is included below just for some completeness.

        let params = read_pos_params(&self.wl_storage)?;

        // Read from Parameters storage
        let epochs_per_year: u64 = self
            .read_storage_key(&params_storage::get_epochs_per_year_key())
            .expect("Epochs per year should exist in storage");
        let pos_p_gain_nom: Dec = self
            .read_storage_key(&params_storage::get_pos_gain_p_key())
            .expect("PoS P-gain factor should exist in storage");
        let pos_d_gain_nom: Dec = self
            .read_storage_key(&params_storage::get_pos_gain_d_key())
            .expect("PoS D-gain factor should exist in storage");

        let pos_last_staked_ratio: Dec = self
            .read_storage_key(&params_storage::get_staked_ratio_key())
            .expect("PoS staked ratio should exist in storage");
        let pos_last_inflation_amount: token::Amount = self
            .read_storage_key(&params_storage::get_pos_inflation_amount_key())
            .expect("PoS inflation amount should exist in storage");
        // Read from PoS storage
        let total_tokens = self
            .read_storage_key(&token::minted_balance_key(
                &staking_token_address(&self.wl_storage),
            ))
            .expect("Total NAM balance should exist in storage");
        let pos_locked_supply =
            read_total_stake(&self.wl_storage, &params, last_epoch)?;
        let pos_locked_ratio_target = params.target_staked_ratio;
        let pos_max_inflation_rate = params.max_inflation_rate;

        // TODO: properly fetch these values (arbitrary for now)
        let masp_locked_supply: Amount = Amount::default();
        let masp_locked_ratio_target = Dec::new(5, 1).expect("Cannot fail");
        let masp_locked_ratio_last = Dec::new(5, 1).expect("Cannot fail");
        let masp_max_inflation_rate = Dec::new(2, 1).expect("Cannot fail");
        let masp_last_inflation_rate = Dec::new(12, 2).expect("Cannot fail");
        let masp_p_gain = Dec::new(1, 1).expect("Cannot fail");
        let masp_d_gain = Dec::new(1, 1).expect("Cannot fail");

        // Run rewards PD controller
        let pos_controller = inflation::RewardsController {
            locked_tokens: pos_locked_supply,
            total_tokens,
            locked_ratio_target: pos_locked_ratio_target,
            locked_ratio_last: pos_last_staked_ratio,
            max_reward_rate: pos_max_inflation_rate,
            last_inflation_amount: pos_last_inflation_amount,
            p_gain_nom: pos_p_gain_nom,
            d_gain_nom: pos_d_gain_nom,
            epochs_per_year,
        };
        let _masp_controller = inflation::RewardsController {
            locked_tokens: masp_locked_supply,
            total_tokens,
            locked_ratio_target: masp_locked_ratio_target,
            locked_ratio_last: masp_locked_ratio_last,
            max_reward_rate: masp_max_inflation_rate,
            last_inflation_amount: token::Amount::from(
                masp_last_inflation_rate,
            ),
            p_gain_nom: masp_p_gain,
            d_gain_nom: masp_d_gain,
            epochs_per_year,
        };

        // Run the rewards controllers
        let inflation::ValsToUpdate {
            locked_ratio,
            inflation,
        } = pos_controller.run();
        // let new_masp_vals = _masp_controller.run();

        // Get the number of blocks in the last epoch
        let first_block_of_last_epoch = self
            .wl_storage
            .storage
            .block
            .pred_epochs
            .first_block_heights[last_epoch.0 as usize]
            .0;
        let num_blocks_in_last_epoch = if first_block_of_last_epoch == 0 {
            self.wl_storage.storage.block.height.0 - 1
        } else {
            self.wl_storage.storage.block.height.0 - first_block_of_last_epoch
        };

        // Read the rewards accumulator and calculate the new rewards products
        // for the previous epoch
        //
        // TODO: think about changing the reward to Decimal
        let mut reward_tokens_remaining = inflation;
        let mut new_rewards_products: HashMap<Address, (Dec, Dec)> =
            HashMap::new();
        for acc in rewards_accumulator_handle().iter(&self.wl_storage)? {
            let (address, value) = acc?;

            // Get reward token amount for this validator
            let fractional_claim = value / num_blocks_in_last_epoch;
            let reward = fractional_claim * inflation;

            // Get validator data at the last epoch
            let stake = read_validator_stake(
                &self.wl_storage,
                &params,
                &address,
                last_epoch,
            )?
            .map(Dec::from)
            .unwrap_or_default();
            let last_rewards_product =
                validator_rewards_products_handle(&address)
                    .get(&self.wl_storage, &last_epoch)?
                    .unwrap_or_else(Dec::one);
            let last_delegation_product =
                delegator_rewards_products_handle(&address)
                    .get(&self.wl_storage, &last_epoch)?
                    .unwrap_or_else(Dec::one);
            let commission_rate = validator_commission_rate_handle(&address)
                .get(&self.wl_storage, last_epoch, &params)?
                .expect("Should be able to find validator commission rate");

            let new_product =
                last_rewards_product * (Dec::one() + Dec::from(reward) / stake);
            let new_delegation_product = last_delegation_product
                * (Dec::one()
                    + (Dec::one() - commission_rate) * Dec::from(reward)
                        / stake);
            new_rewards_products
                .insert(address, (new_product, new_delegation_product));
            reward_tokens_remaining -= reward;
        }
        for (
            address,
            (new_validator_reward_product, new_delegator_reward_product),
        ) in new_rewards_products
        {
            validator_rewards_products_handle(&address).insert(
                &mut self.wl_storage,
                last_epoch,
                new_validator_reward_product,
            )?;
            delegator_rewards_products_handle(&address).insert(
                &mut self.wl_storage,
                last_epoch,
                new_delegator_reward_product,
            )?;
        }

        let staking_token = staking_token_address(&self.wl_storage);

        // Mint tokens to the PoS account for the last epoch's inflation
        let pos_reward_tokens = inflation - reward_tokens_remaining;
        tracing::info!(
            "Minting tokens for PoS rewards distribution into the PoS \
             account. Amount: {}.",
            pos_reward_tokens.to_string_native(),
        );
        credit_tokens(
            &mut self.wl_storage,
            &staking_token,
            &address::POS,
            pos_reward_tokens,
        )?;

        if reward_tokens_remaining > token::Amount::zero() {
            let amount = Amount::from_uint(reward_tokens_remaining, 0).unwrap();
            tracing::info!(
                "Minting tokens remaining from PoS rewards distribution into \
                 the Governance account. Amount: {}.",
                amount.to_string_native()
            );
            credit_tokens(
                &mut self.wl_storage,
                &staking_token,
                &address::GOV,
                amount,
            )?;
        }

        // Write new rewards parameters that will be used for the inflation of
        // the current new epoch
        self.wl_storage
            .write(&params_storage::get_pos_inflation_amount_key(), inflation)
            .expect("unable to write new reward rate");
        self.wl_storage
            .write(&params_storage::get_staked_ratio_key(), locked_ratio)
            .expect("unable to write new locked ratio");

        // Delete the accumulators from storage
        // TODO: refactor with https://github.com/anoma/namada/issues/1225
        let addresses_to_drop: HashSet<Address> = rewards_accumulator_handle()
            .iter(&self.wl_storage)?
            .map(|a| a.unwrap().0)
            .collect();
        for address in addresses_to_drop.into_iter() {
            rewards_accumulator_handle()
                .remove(&mut self.wl_storage, &address)?;
        }

        // Pgf inflation
        let pgf_parameters = pgf::get_parameters(&self.wl_storage)?;

        let pgf_pd_rate =
            pgf_parameters.pgf_inflation_rate / Dec::from(epochs_per_year);
        let pgf_inflation = Dec::from(total_tokens) * pgf_pd_rate;

        let pgf_stewards_pd_rate =
            pgf_parameters.stewards_inflation_rate / Dec::from(epochs_per_year);
        let pgf_steward_inflation =
            Dec::from(total_tokens) * pgf_stewards_pd_rate;

        let pgf_inflation_amount =
            token::Amount::from(pgf_inflation + pgf_steward_inflation);

        credit_tokens(
            &mut self.wl_storage,
            &staking_token,
            &pgf_address,
            pgf_inflation_amount,
        )?;

        tracing::info!(
            "Minting {} tokens for PGF rewards distribution into the PGF \
             account.",
            pgf_inflation_amount.to_string_native()
        );

        let mut pgf_fundings = pgf::get_payments(&self.wl_storage)?;
        // we want to pay first the oldest fundings
        pgf_fundings.sort_by(|a, b| a.id.cmp(&b.id));

        for funding in pgf_fundings {
            if credit_tokens(
                &mut self.wl_storage,
                &staking_token,
                &funding.detail.target,
                funding.detail.amount,
            )
            .is_ok()
            {
                tracing::info!(
                    "Minted {} tokens for {} project.",
                    funding.detail.amount.to_string_native(),
                    &funding.detail.target,
                );
            } else {
                tracing::warn!(
                    "Failed Minting {} tokens for {} project.",
                    funding.detail.amount.to_string_native(),
                    &funding.detail.target,
                );
            }
        }

        // Pgf steward inflation
        let stewards = pgf::get_stewards(&self.wl_storage)?;

        let pgf_steward_reward = match stewards.len() {
            0 => Dec::zero(),
            _ => pgf_steward_inflation
                .trunc_div(&Dec::from(stewards.len()))
                .unwrap_or_default(),
        };

        for steward in stewards {
            for (address, percentage) in steward.reward_distribution {
                let pgf_steward_reward = pgf_steward_reward
                    .checked_mul(&percentage)
                    .unwrap_or_default();
                let reward_amount = token::Amount::from(pgf_steward_reward);

                if credit_tokens(
                    &mut self.wl_storage,
                    &staking_token,
                    &address,
                    reward_amount,
                )
                .is_ok()
                {
                    tracing::info!(
                        "Minting {} tokens for steward {}.",
                        reward_amount.to_string_native(),
                        address,
                    );
                } else {
                    tracing::warn!(
                        "Failed minting {} tokens for steward {}.",
                        reward_amount.to_string_native(),
                        address,
                    );
                }
            }
        }

        Ok(())
    }

    // Process the proposer and votes in the block to assign their PoS rewards.
    fn log_block_rewards(
        &mut self,
        votes: &[VoteInfo],
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
                let votes = pos_votes_from_abci(&self.wl_storage, votes);
                namada_proof_of_stake::log_block_rewards(
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
                 signed_last_block,
             }| {
                if let Some(
                    crate::facade::tendermint_proto::abci::Validator {
                        address,
                        power,
                    },
                ) = validator
                {
                    let tm_raw_hash_string = HEXUPPER.encode(address);
                    if *signed_last_block {
                        tracing::debug!(
                            "Looking up validator from Tendermint VoteInfo's \
                             raw hash {tm_raw_hash_string}"
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
                            "Must be able to find the native address of \
                             validator from tendermint raw hash",
                        );

                        // Try to convert voting power to u64
                        let validator_vp = u64::try_from(*power).expect(
                            "Must be able to convert voting power from i64 to \
                             u64",
                        );

                        return Some(namada_proof_of_stake::types::VoteInfo {
                            validator_address,
                            validator_vp,
                        });
                    } else {
                        tracing::debug!(
                            "Validator {tm_raw_hash_string} didn't sign last \
                             block"
                        )
                    }
                }
                None
            },
        )
        .collect()
}

/// We test the failure cases of [`finalize_block`]. The happy flows
/// are covered by the e2e tests.
#[cfg(test)]
mod test_finalize_block {
    use std::collections::{BTreeMap, BTreeSet};
    use std::num::NonZeroU64;

    use data_encoding::HEXUPPER;
    use namada::core::ledger::eth_bridge::storage::wrapped_erc20s;
    use namada::core::ledger::governance::storage::keys::get_proposal_execution_key;
    use namada::core::ledger::governance::storage::proposal::ProposalType;
    use namada::core::ledger::governance::storage::vote::{
        StorageProposalVote, VoteType,
    };
    use namada::eth_bridge::storage::bridge_pool::{
        self, get_key_from_hash, get_nonce_key, get_signed_root_key,
    };
    use namada::eth_bridge::storage::min_confirmations_key;
    use namada::ledger::eth_bridge::MinimumConfirmations;
    use namada::ledger::gas::VpGasMeter;
    use namada::ledger::native_vp::parameters::ParametersVp;
    use namada::ledger::native_vp::NativeVp;
    use namada::ledger::parameters::EpochDuration;
    use namada::ledger::pos::PosQueries;
    use namada::ledger::storage_api;
    use namada::ledger::storage_api::StorageWrite;
    use namada::proof_of_stake::btree_set::BTreeSetShims;
    use namada::proof_of_stake::storage::{
        is_validator_slashes_key, slashes_prefix,
    };
    use namada::proof_of_stake::types::{
        BondId, SlashType, ValidatorState, WeightedValidator,
    };
    use namada::proof_of_stake::{
        enqueued_slashes_handle, get_num_consensus_validators,
        read_consensus_validator_set_addresses_with_stake,
        rewards_accumulator_handle, unjail_validator,
        validator_consensus_key_handle, validator_rewards_products_handle,
        validator_slashes_handle, validator_state_handle, write_pos_params,
    };
    use namada::proto::{Code, Data, Section, Signature};
    use namada::types::dec::POS_DECIMAL_PRECISION;
    use namada::types::ethereum_events::{EthAddress, Uint as ethUint};
    use namada::types::hash::Hash;
    use namada::types::keccak::KeccakHash;
    use namada::types::key::tm_consensus_key_raw_hash;
    use namada::types::storage::Epoch;
    use namada::types::time::{DateTimeUtc, DurationSecs};
    use namada::types::token::{Amount, NATIVE_MAX_DECIMAL_PLACES};
    use namada::types::transaction::governance::{
        InitProposalData, VoteProposalData,
    };
    use namada::types::transaction::protocol::EthereumTxData;
    use namada::types::transaction::{Fee, WrapperTx};
    use namada::types::uint::Uint;
    use namada::types::vote_extensions::ethereum_events;
    use namada_test_utils::TestWasms;
    use test_log::test;

    use super::*;
    use crate::facade::tendermint_proto::abci::{
        Misbehavior, Validator, VoteInfo,
    };
    use crate::node::ledger::oracle::control::Command;
    use crate::node::ledger::shell::test_utils::*;
    use crate::node::ledger::shims::abcipp_shim_types::shim::request::{
        FinalizeBlock, ProcessedTx,
    };

    const GAS_LIMIT_MULTIPLIER: u64 = 300_000;

    /// Make a wrapper tx and a processed tx from the wrapped tx that can be
    /// added to `FinalizeBlock` request.
    fn mk_wrapper_tx(
        shell: &TestShell,
        keypair: &common::SecretKey,
    ) -> (Tx, ProcessedTx) {
        let mut wrapper_tx =
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
        wrapper_tx.header.chain_id = shell.chain_id.clone();
        wrapper_tx.set_code(Code::new("wasm_code".as_bytes().to_owned()));
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
                tx,
                result: TxResult {
                    code: ErrorCodes::Ok.into(),
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
                    amount_per_gas_unit: 1.into(),
                    token: shell.wl_storage.storage.native_token.clone(),
                },
                keypair.ref_to(),
                Epoch(0),
                GAS_LIMIT_MULTIPLIER.into(),
                None,
            ))));
        outer_tx.header.chain_id = shell.chain_id.clone();
        outer_tx.set_code(Code::new(tx_code));
        outer_tx.set_data(Data::new(
            "Decrypted transaction data".as_bytes().to_owned(),
        ));
        let gas_limit =
            Gas::from(outer_tx.header().wrapper().unwrap().gas_limit)
                .checked_sub(Gas::from(outer_tx.to_bytes().len() as u64))
                .unwrap();
        shell.enqueue_tx(outer_tx.clone(), gas_limit);
        outer_tx.update_header(TxType::Decrypted(DecryptedTx::Decrypted));
        outer_tx.decrypt(<EllipticCurve as PairingEngine>::G2Affine::prime_subgroup_generator())
                .expect("Test failed");
        ProcessedTx {
            tx: outer_tx.to_bytes(),
            result: TxResult {
                code: ErrorCodes::Ok.into(),
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
        let balance_key = token::balance_key(
            &shell.wl_storage.storage.native_token,
            &Address::from(&keypair.ref_to()),
        );
        shell
            .wl_storage
            .storage
            .write(
                &balance_key,
                Amount::native_whole(1000).try_to_vec().unwrap(),
            )
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
                    amount_per_gas_unit: Default::default(),
                    token: shell.wl_storage.storage.native_token.clone(),
                },
                keypair.ref_to(),
                Epoch(0),
                GAS_LIMIT_MULTIPLIER.into(),
                None,
            ))));
        outer_tx.header.chain_id = shell.chain_id.clone();
        outer_tx.set_code(Code::new("wasm_code".as_bytes().to_owned()));
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
            tx: outer_tx.to_bytes(),
            result: TxResult {
                code: ErrorCodes::InvalidTx.into(),
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
        // not valid tx bytes
        let wrapper = Tx::from_type(TxType::Wrapper(Box::new(WrapperTx::new(
            Fee {
                amount_per_gas_unit: 0.into(),
                token: shell.wl_storage.storage.native_token.clone(),
            },
            keypair.ref_to(),
            Epoch(0),
            GAS_LIMIT_MULTIPLIER.into(),
            None,
        ))));
        let processed_tx = ProcessedTx {
            tx: Tx::from_type(TxType::Decrypted(DecryptedTx::Undecryptable))
                .to_bytes(),
            result: TxResult {
                code: ErrorCodes::Ok.into(),
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

        // Add unshielded balance for fee payment
        let balance_key = token::balance_key(
            &shell.wl_storage.storage.native_token,
            &Address::from(&keypair.ref_to()),
        );
        shell
            .wl_storage
            .storage
            .write(
                &balance_key,
                Amount::native_whole(1000).try_to_vec().unwrap(),
            )
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
            tx: EthereumTxData::EthEventsVext(ext)
                .sign(&protocol_key, shell.chain_id.clone())
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
        let (tx, action) = craft_tx(&mut shell);
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
        use crate::node::ledger::shell::address::nam;
        test_bp(|shell: &mut TestShell| {
            let asset = EthAddress([0xff; 20]);
            let receiver = EthAddress([0xaa; 20]);
            let bertha = crate::wallet::defaults::bertha_address();
            // add bertha's escrowed `asset` to the pool
            {
                let token = wrapped_erc20s::token(&asset);
                let owner_key = token::balance_key(
                    &token,
                    &bridge_pool::BRIDGE_POOL_ADDRESS,
                );
                let supply_key = token::minted_balance_key(&token);
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
                let pool_balance_key = token::balance_key(
                    &nam(),
                    &bridge_pool::BRIDGE_POOL_ADDRESS,
                );
                shell
                    .wl_storage
                    .write(&pool_balance_key, amt)
                    .expect("Test failed");
            }
            // write transfer to storage
            let transfer = {
                use namada::core::types::eth_bridge_pool::{
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
                        token: nam(),
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
                nonce: 0u64.into(),
                transfers: vec![transfer],
                relayer: bertha,
            };
            let (protocol_key, _, _) =
                crate::wallet::defaults::validator_keys();
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
            let tx = EthereumTxData::EthEventsVext(ext)
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
            let tx = EthereumTxData::BridgePoolVext(vext).sign(
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
        let balance_key = token::balance_key(
            &shell.wl_storage.storage.native_token,
            &Address::from(&txs_key.ref_to()),
        );
        shell
            .wl_storage
            .storage
            .write(
                &balance_key,
                Amount::native_whole(1000).try_to_vec().unwrap(),
            )
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

            storage_api::governance::init_proposal(
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
            storage_api::governance::vote_proposal(&mut shell.wl_storage, vote)
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
            namada_proof_of_stake::read_pos_params(&shell.wl_storage).unwrap();
        let consensus_key =
            namada_proof_of_stake::validator_consensus_key_handle(validator)
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
        .unwrap()
        .unwrap();

        let votes = vec![VoteInfo {
            validator: Some(Validator {
                address: proposer_address.clone(),
                power: u128::try_from(val_stake).expect("Test failed") as i64,
            }),
            signed_last_block: true,
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

        let val1 = validator_set.pop_first_shim().unwrap();
        let val2 = validator_set.pop_first_shim().unwrap();
        let val3 = validator_set.pop_first_shim().unwrap();
        let val4 = validator_set.pop_first_shim().unwrap();

        let get_pkh = |address, epoch| {
            let ck = validator_consensus_key_handle(&address)
                .get(&shell.wl_storage, epoch, &params)
                .unwrap()
                .unwrap();
            let hash_string = tm_consensus_key_raw_hash(&ck);
            HEXUPPER.decode(hash_string.as_bytes()).unwrap()
        };

        let pkh1 = get_pkh(val1.address.clone(), Epoch::default());
        let pkh2 = get_pkh(val2.address.clone(), Epoch::default());
        let pkh3 = get_pkh(val3.address.clone(), Epoch::default());
        let pkh4 = get_pkh(val4.address.clone(), Epoch::default());

        // All validators sign blocks initially
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
                    address: pkh2.clone(),
                    power: u128::try_from(val2.bonded_stake)
                        .expect("Test failed")
                        as i64,
                }),
                signed_last_block: true,
            },
            VoteInfo {
                validator: Some(Validator {
                    address: pkh3.clone(),
                    power: u128::try_from(val3.bonded_stake)
                        .expect("Test failed")
                        as i64,
                }),
                signed_last_block: true,
            },
            VoteInfo {
                validator: Some(Validator {
                    address: pkh4.clone(),
                    power: u128::try_from(val4.bonded_stake)
                        .expect("Test failed")
                        as i64,
                }),
                signed_last_block: true,
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
        next_block_for_inflation(&mut shell, pkh1.clone(), vec![], None);
        assert!(
            rewards_accumulator_handle()
                .is_empty(&shell.wl_storage)
                .unwrap()
        );

        // FINALIZE BLOCK 2. Tell Namada that val1 is the block proposer.
        // Include votes that correspond to block 1. Make val2 the next block's
        // proposer.
        next_block_for_inflation(&mut shell, pkh2.clone(), votes.clone(), None);
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
        next_block_for_inflation(&mut shell, pkh1.clone(), votes, None);
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
            VoteInfo {
                validator: Some(Validator {
                    address: pkh3,
                    power: u128::try_from(val3.bonded_stake)
                        .expect("Test failed")
                        as i64,
                }),
                signed_last_block: true,
            },
            VoteInfo {
                validator: Some(Validator {
                    address: pkh4,
                    power: u128::try_from(val4.bonded_stake)
                        .expect("Test failed")
                        as i64,
                }),
                signed_last_block: false,
            },
        ];

        // FINALIZE BLOCK 4. The next block proposer will be val1. Only val1,
        // val2, and val3 vote on this block.
        next_block_for_inflation(&mut shell, pkh1.clone(), votes.clone(), None);
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
                pkh1.clone(),
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
        let wrapper_hash_key = replay_protection::get_replay_protection_key(
            &wrapper_tx.header_hash(),
        );
        let mut decrypted_tx = wrapper_tx;

        decrypted_tx.update_header(TxType::Raw);
        let decrypted_hash_key = replay_protection::get_replay_protection_key(
            &decrypted_tx.header_hash(),
        );

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
        assert_eq!(code, String::from(ErrorCodes::Ok).as_str());

        // the merkle tree root should not change after finalize_block
        let root_post = shell.shell.wl_storage.storage.block.tree.root();
        assert_eq!(root_pre.0, root_post.0);

        // Check transactions' hashes in storage
        assert!(shell.shell.wl_storage.has_key(&wrapper_hash_key).unwrap());
        assert!(shell.shell.wl_storage.has_key(&decrypted_hash_key).unwrap());
        // Check that non of the hashes is present in the merkle tree
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
        assert!(
            !shell
                .shell
                .wl_storage
                .storage
                .block
                .tree
                .has_key(&decrypted_hash_key)
                .unwrap()
        );
    }

    /// Test that if a decrypted transaction fails because of out-of-gas, its
    /// hash is removed from storage to allow rewrapping it
    #[test]
    fn test_remove_tx_hash() {
        let (mut shell, _, _, _) = setup();
        let keypair = gen_keypair();

        let mut wasm_path = top_level_directory();
        wasm_path.push("wasm_for_tests/tx_no_op.wasm");
        let tx_code = std::fs::read(wasm_path)
            .expect("Expected a file at given code path");
        let mut wrapper_tx =
            Tx::from_type(TxType::Wrapper(Box::new(WrapperTx::new(
                Fee {
                    amount_per_gas_unit: Amount::zero(),
                    token: shell.wl_storage.storage.native_token.clone(),
                },
                keypair.ref_to(),
                Epoch(0),
                GAS_LIMIT_MULTIPLIER.into(),
                None,
            ))));
        wrapper_tx.header.chain_id = shell.chain_id.clone();
        wrapper_tx.set_code(Code::new(tx_code));
        wrapper_tx.set_data(Data::new(
            "Encrypted transaction data".as_bytes().to_owned(),
        ));
        let mut decrypted_tx = wrapper_tx.clone();

        decrypted_tx.update_header(TxType::Decrypted(DecryptedTx::Decrypted));

        // Write inner hash in storage
        let inner_hash_key = replay_protection::get_replay_protection_key(
            &wrapper_tx.clone().update_header(TxType::Raw).header_hash(),
        );
        shell
            .wl_storage
            .storage
            .write(&inner_hash_key, vec![])
            .expect("Test failed");

        let processed_tx = ProcessedTx {
            tx: decrypted_tx.to_bytes(),
            result: TxResult {
                code: ErrorCodes::Ok.into(),
                info: "".into(),
            },
        };
        shell.enqueue_tx(wrapper_tx, Gas::default());
        // merkle tree root before finalize_block
        let root_pre = shell.shell.wl_storage.storage.block.tree.root();

        let event = &shell
            .finalize_block(FinalizeBlock {
                txs: vec![processed_tx],
                ..Default::default()
            })
            .expect("Test failed")[0];

        // the merkle tree root should not change after finalize_block
        let root_post = shell.shell.wl_storage.storage.block.tree.root();
        assert_eq!(root_pre.0, root_post.0);

        // Check inner tx hash has been removed from storage
        assert_eq!(event.event_type.to_string(), String::from("applied"));
        let code = event.attributes.get("code").expect("Testfailed").as_str();
        assert_eq!(code, String::from(ErrorCodes::WasmRuntimeError).as_str());

        assert!(
            !shell
                .wl_storage
                .has_key(&inner_hash_key)
                .expect("Test failed")
        )
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
                    amount_per_gas_unit: 0.into(),
                    token: shell.wl_storage.storage.native_token.clone(),
                },
                keypair.ref_to(),
                Epoch(0),
                0.into(),
                None,
            ))));
        wrapper.header.chain_id = shell.chain_id.clone();
        wrapper.set_code(Code::new("wasm_code".as_bytes().to_owned()));
        wrapper.set_data(Data::new(
            "Encrypted transaction data".as_bytes().to_owned(),
        ));
        wrapper.add_section(Section::Signature(Signature::new(
            wrapper.sechashes(),
            [(0, keypair)].into_iter().collect(),
            None,
        )));

        let wrapper_hash_key = replay_protection::get_replay_protection_key(
            &wrapper.header_hash(),
        );
        let inner_hash_key = replay_protection::get_replay_protection_key(
            &wrapper.clone().update_header(TxType::Raw).header_hash(),
        );

        let processed_tx = ProcessedTx {
            tx: wrapper.to_bytes(),
            result: TxResult {
                code: ErrorCodes::Ok.into(),
                info: "".into(),
            },
        };

        let event = &shell
            .finalize_block(FinalizeBlock {
                txs: vec![processed_tx],
                ..Default::default()
            })
            .expect("Test failed")[0];

        // Check wrapper hash has been committed to storage even if it failed.
        // Check that, instead, the inner hash has been removed
        assert_eq!(event.event_type.to_string(), String::from("accepted"));
        let code = event.attributes.get("code").expect("Testfailed").as_str();
        assert_eq!(code, String::from(ErrorCodes::InvalidTx).as_str());

        assert!(
            shell
                .wl_storage
                .has_key(&wrapper_hash_key)
                .expect("Test failed")
        );
        assert!(
            !shell
                .wl_storage
                .has_key(&inner_hash_key)
                .expect("Test failed")
        )
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
                    amount_per_gas_unit: 100.into(),
                    token: shell.wl_storage.storage.native_token.clone(),
                },
                keypair.ref_to(),
                Epoch(0),
                GAS_LIMIT_MULTIPLIER.into(),
                None,
            ))));
        wrapper.header.chain_id = shell.chain_id.clone();
        wrapper.set_code(Code::new("wasm_code".as_bytes().to_owned()));
        wrapper.set_data(Data::new(
            "Encrypted transaction data".as_bytes().to_owned(),
        ));
        wrapper.add_section(Section::Signature(Signature::new(
            wrapper.sechashes(),
            [(0, keypair.clone())].into_iter().collect(),
            None,
        )));

        let processed_tx = ProcessedTx {
            tx: wrapper.to_bytes(),
            result: TxResult {
                code: ErrorCodes::Ok.into(),
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
        assert_eq!(code, String::from(ErrorCodes::InvalidTx).as_str());
        let balance_key = namada::core::types::token::balance_key(
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
            namada_proof_of_stake::read_pos_params(&shell.wl_storage).unwrap();
        let consensus_key =
            namada_proof_of_stake::validator_consensus_key_handle(&validator)
                .get(&shell.wl_storage, Epoch::default(), &pos_params)
                .unwrap()
                .unwrap();
        let proposer_address = HEXUPPER
            .decode(consensus_key.tm_raw_hash().as_bytes())
            .unwrap();

        let proposer_balance = storage_api::token::read_balance(
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
                    amount_per_gas_unit: 1.into(),
                    token: shell.wl_storage.storage.native_token.clone(),
                },
                crate::wallet::defaults::albert_keypair().ref_to(),
                Epoch(0),
                5_000_000.into(),
                None,
            ))));
        wrapper.header.chain_id = shell.chain_id.clone();
        wrapper.set_code(Code::new(tx_code));
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

        let signer_balance = storage_api::token::read_balance(
            &shell.wl_storage,
            &shell.wl_storage.storage.native_token,
            &wrapper.header().wrapper().unwrap().fee_payer(),
        )
        .unwrap();

        let processed_tx = ProcessedTx {
            tx: wrapper.to_bytes(),
            result: TxResult {
                code: ErrorCodes::Ok.into(),
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
        assert_eq!(code, String::from(ErrorCodes::Ok).as_str());

        let new_proposer_balance = storage_api::token::read_balance(
            &shell.wl_storage,
            &shell.wl_storage.storage.native_token,
            &validator,
        )
        .unwrap();
        assert_eq!(
            new_proposer_balance,
            proposer_balance.checked_add(fee_amount).unwrap()
        );

        let new_signer_balance = storage_api::token::read_balance(
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
    fn test_ledger_slashing() -> storage_api::Result<()> {
        let num_validators = 7_u64;
        let (mut shell, _recv, _, _) = setup_with_cfg(SetupCfg {
            last_height: 0,
            num_validators,
        });
        let mut params = read_pos_params(&shell.wl_storage).unwrap();
        params.unbonding_len = 4;
        write_pos_params(&mut shell.wl_storage, params.clone())?;

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
            HEXUPPER.decode(hash_string.as_bytes()).unwrap()
        };

        let mut all_pkhs: Vec<Vec<u8>> = Vec::new();
        let mut behaving_pkhs: Vec<Vec<u8>> = Vec::new();
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

        let pkh1 = all_pkhs[0].clone();
        let pkh2 = all_pkhs[1].clone();

        // Finalize block 1 (no votes since this is the first block)
        next_block_for_inflation(&mut shell, pkh1.clone(), vec![], None);

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
                r#type: 1,
                validator: Some(Validator {
                    address: pkh1.clone(),
                    power: Default::default(),
                }),
                height: 1,
                time: Default::default(),
                total_voting_power: Default::default(),
            },
            Misbehavior {
                r#type: 2,
                validator: Some(Validator {
                    address: pkh2,
                    power: Default::default(),
                }),
                height: 1,
                time: Default::default(),
                total_voting_power: Default::default(),
            },
        ];
        next_block_for_inflation(
            &mut shell,
            pkh1.clone(),
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
                pkh1.clone(),
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
                )?
                .unwrap();
                let stake2 = read_validator_stake(
                    &shell.wl_storage,
                    &params,
                    &val2.address,
                    shell.wl_storage.storage.block.epoch,
                )?
                .unwrap();
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

        let num_slashes = storage_api::iter_prefix_bytes(
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
        )?
        .unwrap();
        let stake2 = read_validator_stake(
            &shell.wl_storage,
            &params,
            &val2.address,
            pipeline_epoch,
        )?
        .unwrap();
        let total_stake =
            read_total_stake(&shell.wl_storage, &params, pipeline_epoch)?;

        let expected_slashed = cubic_rate * initial_stake;
        assert_eq!(stake1, initial_stake - expected_slashed);
        assert_eq!(stake2, initial_stake - expected_slashed);
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
    fn test_multiple_misbehaviors() -> storage_api::Result<()> {
        for num_validators in 4u64..10u64 {
            println!("NUM VALIDATORS = {}", num_validators);
            test_multiple_misbehaviors_by_num_vals(num_validators)?;
        }
        Ok(())
    }

    /// Current test procedure (prefixed by epoch in which the event occurs):
    /// 0) Validator initial stake of 200_000
    /// 1) Delegate 67_231 to validator
    /// 1) Self-unbond 154_654
    /// 2) Unbond delegation of 18_000
    /// 3) Self-bond 9_123
    /// 4) Self-unbond 15_000
    /// 5) Delegate 8_144 to validator
    /// 6) Discover misbehavior in epoch 3
    /// 7) Discover misbehavior in epoch 3
    /// 7) Discover misbehavior in epoch 4
    fn test_multiple_misbehaviors_by_num_vals(
        num_validators: u64,
    ) -> storage_api::Result<()> {
        // Setup the network with pipeline_len = 2, unbonding_len = 4
        // let num_validators = 8_u64;
        let (mut shell, _recv, _, _) = setup_with_cfg(SetupCfg {
            last_height: 0,
            num_validators,
        });
        let mut params = read_pos_params(&shell.wl_storage).unwrap();
        params.unbonding_len = 4;
        params.max_validator_slots = 4;
        write_pos_params(&mut shell.wl_storage, params.clone())?;

        // Slash pool balance
        let nam_address = shell.wl_storage.storage.native_token.clone();
        let slash_balance_key = token::balance_key(
            &nam_address,
            &namada_proof_of_stake::SLASH_POOL_ADDRESS,
        );
        let slash_pool_balance_init: token::Amount = shell
            .wl_storage
            .read(&slash_balance_key)
            .expect("must be able to read")
            .unwrap_or_default();
        debug_assert_eq!(slash_pool_balance_init, token::Amount::default());

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
        next_block_for_inflation(&mut shell, pkh1.clone(), vec![], None);

        let votes = get_default_true_votes(&shell.wl_storage, Epoch::default());
        assert!(!votes.is_empty());

        // Advance to epoch 1 and
        // 1. Delegate 67231 NAM to validator
        // 2. Validator self-unbond 154654 NAM
        let current_epoch = advance_epoch(&mut shell, &pkh1, &votes, None);
        assert_eq!(shell.wl_storage.storage.block.epoch.0, 1_u64);

        // Make an account with balance and delegate some tokens
        let delegator = address::testing::gen_implicit_address();
        let del_1_amount = token::Amount::native_whole(67_231);
        let staking_token = shell.wl_storage.storage.native_token.clone();
        credit_tokens(
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
        )
        .unwrap();

        // Self-unbond
        let self_unbond_1_amount = token::Amount::native_whole(154_654);
        namada_proof_of_stake::unbond_tokens(
            &mut shell.wl_storage,
            None,
            &val1.address,
            self_unbond_1_amount,
            current_epoch,
        )
        .unwrap();

        let val_stake = namada_proof_of_stake::read_validator_stake(
            &shell.wl_storage,
            &params,
            &val1.address,
            current_epoch + params.pipeline_len,
        )
        .unwrap()
        .unwrap_or_default();

        let total_stake = namada_proof_of_stake::read_total_stake(
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
        let current_epoch = advance_epoch(&mut shell, &pkh1, &votes, None);
        println!("\nUnbonding in epoch 2");
        let del_unbond_1_amount = token::Amount::native_whole(18_000);
        namada_proof_of_stake::unbond_tokens(
            &mut shell.wl_storage,
            Some(&delegator),
            &val1.address,
            del_unbond_1_amount,
            current_epoch,
        )
        .unwrap();

        let val_stake = namada_proof_of_stake::read_validator_stake(
            &shell.wl_storage,
            &params,
            &val1.address,
            current_epoch + params.pipeline_len,
        )
        .unwrap()
        .unwrap_or_default();
        let total_stake = namada_proof_of_stake::read_total_stake(
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
        let current_epoch = advance_epoch(&mut shell, &pkh1, &votes, None);
        println!("\nBonding in epoch 3");

        let self_bond_1_amount = token::Amount::native_whole(9_123);
        namada_proof_of_stake::bond_tokens(
            &mut shell.wl_storage,
            None,
            &val1.address,
            self_bond_1_amount,
            current_epoch,
        )
        .unwrap();

        // Advance to epoch 4
        // 1. Validator self-unbond 15000 NAM
        let votes = get_default_true_votes(
            &shell.wl_storage,
            shell.wl_storage.storage.block.epoch,
        );
        let current_epoch = advance_epoch(&mut shell, &pkh1, &votes, None);
        assert_eq!(current_epoch.0, 4_u64);

        let self_unbond_2_amount = token::Amount::native_whole(15_000);
        namada_proof_of_stake::unbond_tokens(
            &mut shell.wl_storage,
            None,
            &val1.address,
            self_unbond_2_amount,
            current_epoch,
        )
        .unwrap();

        // Advance to epoch 5 and
        // Delegate 8144 NAM to validator
        let votes = get_default_true_votes(
            &shell.wl_storage,
            shell.wl_storage.storage.block.epoch,
        );
        let current_epoch = advance_epoch(&mut shell, &pkh1, &votes, None);
        assert_eq!(current_epoch.0, 5_u64);
        println!("Delegating in epoch 5");

        // Delegate
        let del_2_amount = token::Amount::native_whole(8_144);
        namada_proof_of_stake::bond_tokens(
            &mut shell.wl_storage,
            Some(&delegator),
            &val1.address,
            del_2_amount,
            current_epoch,
        )
        .unwrap();

        println!("Advancing to epoch 6");

        // Advance to epoch 6
        let votes = get_default_true_votes(
            &shell.wl_storage,
            shell.wl_storage.storage.block.epoch,
        );
        let current_epoch = advance_epoch(&mut shell, &pkh1, &votes, None);
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
            r#type: 1,
            validator: Some(Validator {
                address: pkh1.clone(),
                power: Default::default(),
            }),
            height: height.0 as i64,
            time: Default::default(),
            total_voting_power: Default::default(),
        }];
        let votes = get_default_true_votes(
            &shell.wl_storage,
            shell.wl_storage.storage.block.epoch,
        );
        next_block_for_inflation(
            &mut shell,
            pkh1.clone(),
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
            namada_proof_of_stake::read_validator_last_slash_epoch(
                &shell.wl_storage,
                &val1.address,
            )
            .unwrap();
        assert_eq!(last_slash, Some(misbehavior_epoch));
        assert!(
            namada_proof_of_stake::validator_slashes_handle(&val1.address)
                .is_empty(&shell.wl_storage)
                .unwrap()
        );

        println!("Advancing to epoch 7");

        // Advance to epoch 7
        let current_epoch = advance_epoch(&mut shell, &pkh1, &votes, None);

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
                r#type: 1,
                validator: Some(Validator {
                    address: pkh1.clone(),
                    power: Default::default(),
                }),
                height: height.0 as i64,
                time: Default::default(),
                total_voting_power: Default::default(),
            },
            Misbehavior {
                r#type: 2,
                validator: Some(Validator {
                    address: pkh1.clone(),
                    power: Default::default(),
                }),
                height: height4.0 as i64,
                time: Default::default(),
                total_voting_power: Default::default(),
            },
        ];
        let votes = get_default_true_votes(
            &shell.wl_storage,
            shell.wl_storage.storage.block.epoch,
        );
        next_block_for_inflation(
            &mut shell,
            pkh1.clone(),
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
            namada_proof_of_stake::read_validator_last_slash_epoch(
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
            namada_proof_of_stake::validator_slashes_handle(&val1.address)
                .is_empty(&shell.wl_storage)
                .unwrap()
        );

        let pre_stake_10 = namada_proof_of_stake::read_validator_stake(
            &shell.wl_storage,
            &params,
            &val1.address,
            Epoch(10),
        )
        .unwrap()
        .unwrap_or_default();
        assert_eq!(
            pre_stake_10,
            initial_stake + del_1_amount
                - self_unbond_1_amount
                - del_unbond_1_amount
                + self_bond_1_amount
                - self_unbond_2_amount
                + del_2_amount
        );

        println!("\nNow processing the infractions\n");

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
        let current_epoch = advance_epoch(&mut shell, &pkh1, &votes, None);
        assert_eq!(current_epoch.0, 9_u64);

        let val_stake_3 = namada_proof_of_stake::read_validator_stake(
            &shell.wl_storage,
            &params,
            &val1.address,
            Epoch(3),
        )
        .unwrap()
        .unwrap_or_default();
        let val_stake_4 = namada_proof_of_stake::read_validator_stake(
            &shell.wl_storage,
            &params,
            &val1.address,
            Epoch(4),
        )
        .unwrap()
        .unwrap_or_default();

        let tot_stake_3 = namada_proof_of_stake::read_total_stake(
            &shell.wl_storage,
            &params,
            Epoch(3),
        )
        .unwrap();
        let tot_stake_4 = namada_proof_of_stake::read_total_stake(
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
            namada_proof_of_stake::validator_slashes_handle(&val1.address);
        assert_eq!(val_slashes.len(&shell.wl_storage).unwrap(), 2u64);
        let is_rate_good = val_slashes
            .iter(&shell.wl_storage)
            .unwrap()
            .all(|s| equal_enough(s.unwrap().rate, cubic_rate));
        assert!(is_rate_good);

        // Check the amount of stake deducted from the futuremost epoch while
        // processing the slashes
        let post_stake_10 = namada_proof_of_stake::read_validator_stake(
            &shell.wl_storage,
            &params,
            &val1.address,
            Epoch(10),
        )
        .unwrap()
        .unwrap_or_default();
        // The amount unbonded after the infraction that affected the deltas
        // before processing is `del_unbond_1_amount + self_bond_1_amount -
        // self_unbond_2_amount` (since this self-bond was enacted then unbonded
        // all after the infraction). Thus, the additional deltas to be
        // deducted is the (infraction stake - this) * rate
        let slash_rate_3 = std::cmp::min(Dec::one(), Dec::two() * cubic_rate);
        let exp_slashed_during_processing_9 = slash_rate_3
            * (initial_stake + del_1_amount
                - self_unbond_1_amount
                - del_unbond_1_amount
                + self_bond_1_amount
                - self_unbond_2_amount);
        assert!(
            ((pre_stake_10 - post_stake_10).change()
                - exp_slashed_during_processing_9.change())
            .abs()
                < Uint::from(1000)
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
                <= Dec::new(1, NATIVE_MAX_DECIMAL_PLACES).unwrap()
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

        let _pre_stake_11 = namada_proof_of_stake::read_validator_stake(
            &shell.wl_storage,
            &params,
            &val1.address,
            Epoch(10),
        )
        .unwrap()
        .unwrap_or_default();

        // Advance to epoch 10, where the infraction committed in epoch 4 will
        // be processed
        let votes = get_default_true_votes(
            &shell.wl_storage,
            shell.wl_storage.storage.block.epoch,
        );
        let current_epoch = advance_epoch(&mut shell, &pkh1, &votes, None);
        assert_eq!(current_epoch.0, 10_u64);

        // Check the balance of the Slash Pool
        // TODO: finish once implemented
        // let slash_pool_balance: token::Amount = shell
        //     .wl_storage
        //     .read(&slash_balance_key)
        //     .expect("must be able to read")
        //     .unwrap_or_default();

        // let exp_slashed_4 = if dec!(2) * cubic_rate >= Decimal::ONE {
        //     token::Amount::default()
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
        )?
        .unwrap_or_default();

        let post_stake_11 = namada_proof_of_stake::read_validator_stake(
            &shell.wl_storage,
            &params,
            &val1.address,
            Epoch(10),
        )
        .unwrap()
        .unwrap_or_default();

        assert_eq!(post_stake_11, val_stake);
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

        println!("\nCHECK BOND AND UNBOND DETAILS");
        let details = namada_proof_of_stake::bonds_and_unbonds(
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
        // TODO: decimal mult issues should be resolved with PR 1282
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
        // TODO: not sure why this is correct??? (with + self_bond_1_amount -
        // self_unbond_2_amount)
        // TODO: Make sure this is sound and what we expect
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
        assert_eq!(
            self_details.unbonds[1].slashed_amount,
            Some(
                std::cmp::min(Dec::one(), Dec::new(3, 0).unwrap() * cubic_rate)
                    * (self_unbond_2_amount - self_bond_1_amount)
            )
        );
        assert_eq!(self_details.unbonds[2].amount, self_bond_1_amount);
        assert_eq!(self_details.unbonds[2].slashed_amount, None);

        println!("\nWITHDRAWING DELEGATION UNBOND");
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
            slash_rate_3 * del_unbond_1_amount;
        assert_eq!(
            del_withdraw,
            del_unbond_1_amount - exp_del_withdraw_slashed_amount
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
                    validator: Some(Validator {
                        address: pkh,
                        power: u128::try_from(val.bonded_stake).unwrap() as i64,
                    }),
                    signed_last_block: true,
                }
            })
            .collect::<Vec<_>>()
    }

    fn advance_epoch(
        shell: &mut TestShell,
        proposer_address: &[u8],
        consensus_votes: &[VoteInfo],
        misbehaviors: Option<Vec<Misbehavior>>,
    ) -> Epoch {
        let current_epoch = shell.wl_storage.storage.block.epoch;
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
        shell.wl_storage.storage.block.epoch
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
        tx.add_code_from_hash(Hash::default()).add_data(0u64);
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
            validator: Some(Validator {
                address: pkh1.clone(),
                power: u128::try_from(val1.bonded_stake).expect("Test failed")
                    as i64,
            }),
            signed_last_block: true,
        }];
        next_block_for_inflation(&mut shell, pkh1.clone(), votes, None);
        let Command::UpdateConfig(cmd) =
            control_receiver.recv().await.expect("Test failed");
        assert_eq!(u64::from(cmd.min_confirmations), 42);
    }
}
