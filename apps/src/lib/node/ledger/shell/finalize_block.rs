//! Implementation of the `FinalizeBlock` ABCI++ method for the Shell

use std::collections::HashMap;

use namada::ledger::inflation::{self, RewardsController};
use namada::ledger::parameters::storage as params_storage;
use namada::ledger::pos::types::{
    decimal_mult_u64, into_tm_voting_power, VoteInfo,
};
use namada::ledger::pos::{
    namada_proof_of_stake, staking_token_address, ADDRESS as POS_ADDRESS,
};
use namada::ledger::protocol;
use namada::ledger::storage_api::StorageRead;
#[cfg(feature = "abcipp")]
use namada::proof_of_stake::find_validator_by_raw_hash;
use namada::proof_of_stake::{
    delegator_rewards_products_handle, read_current_block_proposer_address,
    read_last_block_proposer_address, read_pos_params, read_total_stake,
    read_validator_stake, rewards_accumulator_handle,
    validator_commission_rate_handle, validator_rewards_products_handle,
    write_last_block_proposer_address,
};
use namada::types::address::Address;
#[cfg(feature = "abcipp")]
use namada::types::key::{tm_consensus_key_raw_hash, tm_raw_hash_to_string};
use namada::types::storage::{BlockHash, BlockResults, Epoch, Header};
use namada::types::token::{total_supply_key, Amount};
use rust_decimal::prelude::Decimal;

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

        // Begin the new block and check if a new epoch has begun
        let (height, new_epoch) =
            self.update_state(req.header, req.hash, req.byzantine_validators);

        let (current_epoch, _gas) = self.wl_storage.storage.get_current_epoch();
        let update_for_tendermint =
            self.wl_storage.storage.epoch_update_tracker.0
                && self.wl_storage.storage.epoch_update_tracker.1 == 2;

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
                TxType::Protocol(_) => {
                    tracing::error!(
                        "Internal logic error: FinalizeBlock received a \
                         TxType::Protocol transaction"
                    );
                    continue;
                }
            };

            match protocol::apply_tx(
                tx_type,
                tx_length,
                TxIndex(
                    tx_index
                        .try_into()
                        .expect("transaction index out of bounds"),
                ),
                &mut self.gas_meter,
                &mut self.wl_storage.write_log,
                &self.wl_storage.storage,
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

        if update_for_tendermint {
            self.update_epoch(&mut response);
        }

        // Read the block proposer of the previously committed block in storage
        // (n-1 if we are in the process of finalizing n right now).
        match read_last_block_proposer_address(&self.wl_storage)? {
            Some(proposer_address) => {
                println!("FOUND LAST BLOCK PROPOSER");
                if new_epoch {
                    println!("APPLYING INFLATION");
                    self.apply_inflation(
                        current_epoch,
                        &proposer_address,
                        &req.votes,
                    )?;
                } else {
                    // TODO: watch out because this is likely not using the
                    // proper block proposer address
                    println!("LOGGING BLOCK REWARDS (NOT NEW EPOCH)");
                    namada_proof_of_stake::log_block_rewards(
                        &mut self.wl_storage,
                        current_epoch,
                        &proposer_address,
                        &req.votes,
                    )
                    .unwrap();
                }
                #[cfg(feature = "abcipp")]
                {
                    // TODO: better error handling that converts
                    // storage_api::Error -> shell::Error
                    let tm_raw_hash_string =
                        tm_raw_hash_to_string(req.proposer_address);
                    let native_proposer_address = find_validator_by_raw_hash(
                        &self.wl_storage,
                        tm_raw_hash_string,
                    )
                    .unwrap()
                    .expect(
                        "Unable to find native validator address of block \
                         proposer from tendermint raw hash",
                    );
                    write_last_block_proposer_address(
                        &mut self.wl_storage,
                        native_proposer_address,
                    )?;
                }

                #[cfg(not(feature = "abcipp"))]
                {
                    let cur_proposer =
                        read_current_block_proposer_address(&self.wl_storage)?
                            .expect(
                                "Should have found the current block proposer \
                                 address",
                            );
                    write_last_block_proposer_address(
                        &mut self.wl_storage,
                        cur_proposer,
                    )?;
                }
            }
            None => {
                println!("NO BLOCK PROPOSER FOUND SET IN STORAGE");
                #[cfg(feature = "abcipp")]
                if req.votes.is_empty() && !req.proposer_address.is_empty() {
                    // Get proposer address from storage based on the consensus
                    // key hash
                    let tm_raw_hash_string =
                        tm_raw_hash_to_string(req.proposer_address);
                    let native_proposer_address = find_validator_by_raw_hash(
                        &self.wl_storage,
                        tm_raw_hash_string,
                    )
                    .unwrap()
                    .expect(
                        "Unable to find native validator address of block \
                         proposer from tendermint raw hash",
                    );
                    write_last_block_proposer_address(
                        &mut self.wl_storage,
                        native_proposer_address,
                    )?;
                }
                #[cfg(not(feature = "abcipp"))]
                {
                    let proposer =
                        read_current_block_proposer_address(&self.wl_storage)?;
                    // .expect(
                    //     "Current block proposer should always be set in \
                    //      ProcessProposal",
                    // );
                    if let Some(proposer) = proposer {
                        write_last_block_proposer_address(
                            &mut self.wl_storage,
                            proposer,
                        )?;
                    }
                }
            }
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
                let update = ValidatorUpdate { pub_key, power };
                response.validator_updates.push(update);
            },
        );
    }

    /// Calculate the new inflation rate, mint the new tokens to the PoS
    /// account, then update the reward products of the validators. This is
    /// executed while finalizing the first block of a new epoch and is applied
    /// with respect to the previous epoch.
    fn apply_inflation(
        &mut self,
        current_epoch: Epoch,
        proposer_address: &Address,
        votes: &[VoteInfo],
    ) -> Result<()> {
        let last_epoch = current_epoch - 1;
        // Get input values needed for the PD controller for PoS and MASP.
        // Run the PD controllers to calculate new rates.
        //
        // MASP is included below just for some completeness.

        // Calculate the fractional block rewards for the previous block (final
        // block of the previous epoch), which also gives the final
        // accumulator value updates
        namada_proof_of_stake::log_block_rewards(
            &mut self.wl_storage,
            last_epoch,
            proposer_address,
            votes,
        )?;

        // TODO: review if the appropriate epoch is being used (last vs now)
        let params = read_pos_params(&self.wl_storage)?;

        // Read from Parameters storage
        let epochs_per_year: u64 = self
            .read_storage_key(&params_storage::get_epochs_per_year_key())
            .expect("Epochs per year should exist in storage");
        let pos_p_gain_nom: Decimal = self
            .read_storage_key(&params_storage::get_pos_gain_p_key())
            .expect("PoS P-gain factor should exist in storage");
        let pos_d_gain_nom: Decimal = self
            .read_storage_key(&params_storage::get_pos_gain_d_key())
            .expect("PoS D-gain factor should exist in storage");

        let pos_last_staked_ratio: Decimal = self
            .read_storage_key(&params_storage::get_staked_ratio_key())
            .expect("PoS staked ratio should exist in storage");
        let pos_last_inflation_amount: u64 = self
            .read_storage_key(&params_storage::get_pos_inflation_amount_key())
            .expect("PoS inflation rate should exist in storage");
        // Read from PoS storage
        let total_tokens = self
            .read_storage_key(&total_supply_key(&staking_token_address()))
            .expect("Total NAM balance should exist in storage");
        let pos_locked_supply =
            read_total_stake(&self.wl_storage, &params, last_epoch)?;
        let pos_locked_ratio_target = params.target_staked_ratio;
        let pos_max_inflation_rate = params.max_inflation_rate;

        // TODO: properly fetch these values (arbitrary for now)
        let masp_locked_supply: Amount = Amount::default();
        let masp_locked_ratio_target = Decimal::new(5, 1);
        let masp_locked_ratio_last = Decimal::new(5, 1);
        let masp_max_inflation_rate = Decimal::new(2, 1);
        let masp_last_inflation_rate = Decimal::new(12, 2);
        let masp_p_gain = Decimal::new(1, 1);
        let masp_d_gain = Decimal::new(1, 1);

        // Run rewards PD controller
        let pos_controller = inflation::RewardsController::new(
            pos_locked_supply,
            total_tokens,
            pos_locked_ratio_target,
            pos_last_staked_ratio,
            pos_max_inflation_rate,
            token::Amount::from(pos_last_inflation_amount),
            pos_p_gain_nom,
            pos_d_gain_nom,
            epochs_per_year,
        );
        let _masp_controller = inflation::RewardsController::new(
            masp_locked_supply,
            total_tokens,
            masp_locked_ratio_target,
            masp_locked_ratio_last,
            masp_max_inflation_rate,
            token::Amount::from(masp_last_inflation_rate),
            masp_p_gain,
            masp_d_gain,
            epochs_per_year,
        );

        // Run the rewards controllers
        let new_pos_vals = RewardsController::run(&pos_controller);
        // let new_masp_vals = RewardsController::run(&_masp_controller);

        // Mint tokens to the PoS account for the last epoch's inflation
        let pos_minted_tokens = new_pos_vals.inflation;
        inflation::mint_tokens(
            &mut self.wl_storage,
            &POS_ADDRESS,
            &staking_token_address(),
            Amount::from(pos_minted_tokens),
        )?;

        // For each consensus validator, update the rewards products
        //
        // TODO: update implementation using lazy DS and be more
        // memory-efficient

        // Get the number of blocks in the last epoch
        let first_block_of_last_epoch = self
            .wl_storage
            .storage
            .block
            .pred_epochs
            .first_block_heights[last_epoch.0 as usize]
            .0;
        let num_blocks_in_last_epoch = if first_block_of_last_epoch == 0 {
            self.wl_storage.storage.block.height.0
                - first_block_of_last_epoch
                - 1
        } else {
            self.wl_storage.storage.block.height.0 - first_block_of_last_epoch
        };

        // Read the rewards accumulator, which was last updated when finalizing
        // the previous block
        // TODO: can/should this be optimized? Since we are reading and writing
        // to the accumulator storage earlier in apply_inflation

        // TODO: think about changing the reward to Decimal
        let mut reward_tokens_remaining = pos_minted_tokens;
        let mut new_rewards_products: HashMap<Address, (Decimal, Decimal)> =
            HashMap::new();

        for acc in rewards_accumulator_handle().iter(&self.wl_storage)? {
            let (address, value) = acc?;

            // Get reward token amount for this validator
            let fractional_claim =
                value / Decimal::from(num_blocks_in_last_epoch);
            let reward = decimal_mult_u64(fractional_claim, pos_minted_tokens);

            // Get validator data at the last epoch
            let stake = read_validator_stake(
                &self.wl_storage,
                &params,
                &address,
                last_epoch,
            )?
            .map(Decimal::from)
            .unwrap_or_default();
            let last_rewards_product =
                validator_rewards_products_handle(&address)
                    .get(&self.wl_storage, &last_epoch)?
                    .unwrap_or(Decimal::ONE);
            let last_delegation_product =
                delegator_rewards_products_handle(&address)
                    .get(&self.wl_storage, &last_epoch)?
                    .unwrap_or(Decimal::ONE);
            let commission_rate = validator_commission_rate_handle(&address)
                .get(&self.wl_storage, last_epoch, &params)?
                .expect("Should be able to find validator commission rate");

            let new_product = last_rewards_product
                * (Decimal::ONE + Decimal::from(reward) / stake);
            let new_delegation_product = last_delegation_product
                * (Decimal::ONE
                    + (Decimal::ONE - commission_rate) * Decimal::from(reward)
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

        // TODO: Figure out how to deal with round-off to a whole number of
        // tokens. May be tricky. TODO: Storing reward products
        // as a Decimal suggests that no round-off should be done here,
        // TODO: perhaps only upon withdrawal. But by truncating at
        // withdrawal, may leave tokens in TDOD: the PoS account
        // that are not accounted for. Is this an issue?
        if reward_tokens_remaining > 0 {
            // TODO: do something here?
        }

        // Write new rewards parameters that will be used for the inflation of
        // the current new epoch
        self.wl_storage
            .storage
            .write(
                &params_storage::get_pos_inflation_amount_key(),
                new_pos_vals
                    .inflation
                    .try_to_vec()
                    .expect("encode new reward rate"),
            )
            .expect("unable to encode new reward rate (Decimal)");
        self.wl_storage
            .storage
            .write(
                &params_storage::get_staked_ratio_key(),
                new_pos_vals
                    .locked_ratio
                    .try_to_vec()
                    .expect("encode new locked ratio"),
            )
            .expect("unable to encode new locked ratio (Decimal)");

        // Delete the accumulators from storage
        // TODO: may want better way to implement this (for lazy PoS in general)
        let addresses_to_drop: HashSet<Address> = rewards_accumulator_handle()
            .iter(&self.wl_storage)?
            .map(|a| a.unwrap().0)
            .collect();
        for address in addresses_to_drop.into_iter() {
            rewards_accumulator_handle()
                .remove(&mut self.wl_storage, &address)?;
        }

        // self.wl_storage
        //     .storage
        //     .delete(&consensus_validator_rewards_accumulator_key())
        //     .unwrap();

        Ok(())
    }
}

/// We test the failure cases of [`finalize_block`]. The happy flows
/// are covered by the e2e tests.
#[cfg(test)]
mod test_finalize_block {
    use std::collections::BTreeMap;
    use std::str::FromStr;

    use namada::ledger::parameters::EpochDuration;
    use namada::ledger::storage_api;
    use namada::types::governance::ProposalVote;
    use namada::types::storage::Epoch;
    use namada::types::time::DurationSecs;
    use namada::types::transaction::governance::{
        InitProposalData, VoteProposalData,
    };
    use namada::types::transaction::{EncryptionKey, Fee, WrapperTx, MIN_FEE};

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
        let (mut shell, _) = setup(1);
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
        let (mut shell, _) = setup(1);
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
        let (mut shell, _) = setup(1);

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
        let (mut shell, _) = setup(1);
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

    /// Test that the finalize block handler never commits changes directly to
    /// the DB.
    #[test]
    fn test_finalize_doesnt_commit_db() {
        let (mut shell, _) = setup(1);

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
                .storage
                .db
                .iter_prefix(&prefix)
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
