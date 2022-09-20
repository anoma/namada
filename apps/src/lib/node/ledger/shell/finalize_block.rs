//! Implementation of the `FinalizeBlock` ABCI++ method for the Shell

use namada::ledger::pos::types::into_tm_voting_power;
use namada::ledger::protocol;
use namada::ledger::governance::storage as gov_storage;
use namada::ledger::governance::utils::{
    compute_tally, get_proposal_votes, ProposalEvent,
};
use namada::ledger::governance::vp::ADDRESS as gov_address;
use namada::ledger::inflation::{self, RewardsController};
use namada::ledger::parameters::storage as params_storage;
use namada::ledger::pos::staking_token_address;
use namada::ledger::pos::types::{decimal_mult_u64, VoteInfo};
use namada::ledger::storage::types::encode;
use namada::ledger::treasury::ADDRESS as treasury_address;
use namada::types::address::{xan as m1t, Address};
use namada::types::governance::TallyResult;
use namada::types::key::tm_raw_hash_to_string;
use namada::types::storage::{BlockHash, Epoch, Header};
use namada::types::token::{total_supply_key, Amount};
use rust_decimal::prelude::Decimal;
use super::governance::execute_governance_proposals;
use super::*;
use crate::facade::tendermint_proto::abci::Misbehavior as Evidence;
use crate::facade::tendermint_proto::crypto::PublicKey as TendermintPublicKey;

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

        if new_epoch {
            let _proposals_result =
                execute_governance_proposals(self, &mut response)?;
        }

        for processed_tx in &req.txs {
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
                    self.storage.tx_queue.pop();
                }
                continue;
            }

            let mut tx_event = match &tx_type {
                TxType::Wrapper(_wrapper) => {
                    self.storage.tx_queue.push(_wrapper.clone());
                    Event::new_tx_event(&tx_type, height.0)
                }
                TxType::Decrypted(inner) => {
                    // We remove the corresponding wrapper tx from the queue
                    self.storage.tx_queue.pop();
                    let mut event = Event::new_tx_event(&tx_type, height.0);
                    if let DecryptedTx::Undecryptable(_) = inner {
                        event["log"] =
                            "Transaction could not be decrypted.".into();
                        event["code"] = ErrorCodes::Undecryptable.into();
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
                &mut self.gas_meter,
                &mut self.write_log,
                &self.storage,
                &mut self.vp_wasm_cache,
                &mut self.tx_wasm_cache,
            )
            .map_err(Error::TxApply)
            {
                Ok(result) => {
                    if result.is_accepted() {
                        tracing::info!(
                            "all VPs accepted transaction {} storage \
                             modification {:#?}",
                            tx_event["hash"],
                            result
                        );
                        self.write_log.commit_tx();
                        if !tx_event.contains_key("code") {
                            tx_event["code"] = ErrorCodes::Ok.into();
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
                        tracing::info!(
                            "some VPs rejected transaction {} storage \
                             modification {:#?}",
                            tx_event["hash"],
                            result.vps_result.rejected_vps
                        );
                        self.write_log.drop_tx();
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
                    self.write_log.drop_tx();
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

        if new_epoch {
            self.update_epoch(&mut response);
            self.apply_inflation(&req.proposer_address, &req.votes);
        }

        let _ = self
            .gas_meter
            .finalize_transaction()
            .map_err(|_| Error::GasOverflow)?;
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
        let height = self.storage.last_height + 1;

        self.gas_meter.reset();

        self.storage
            .begin_block(hash, height)
            .expect("Beginning a block shouldn't fail");

        self.storage
            .set_header(header)
            .expect("Setting a header shouldn't fail");

        self.byzantine_validators = byzantine_validators;

        let header = self
            .storage
            .header
            .as_ref()
            .expect("Header must have been set in prepare_proposal.");
        let time = header.time;
        let new_epoch = self
            .storage
            .update_epoch(height, time)
            .expect("Must be able to update epoch");

        self.slash();
        (height, new_epoch)
    }

    /// If a new epoch begins, we update the response to include
    /// changes to the validator sets and consensus parameters
    fn update_epoch(&self, response: &mut shim::response::FinalizeBlock) {
        // Apply validator set update
        let (current_epoch, _gas) = self.storage.get_current_epoch();
        let pos_params = self.storage.read_pos_params();
        // TODO ABCI validator updates on block H affects the validator set
        // on block H+2, do we need to update a block earlier?
        self.storage.validator_set_update(current_epoch, |update| {
            let (consensus_key, power) = match update {
                ValidatorSetUpdate::Active(ActiveValidator {
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
                    // Any validators that have become inactive must
                    // have voting power set to 0 to remove them from
                    // the active set
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
        });
    }

    /// Calculate the new inflation rate, mint the new tokens to the PoS
    /// account, then update the reward products of the validators
    fn apply_inflation(
        &mut self,
        proposer_address: &Vec<u8>,
        votes: &Vec<VoteInfo>,
    ) {
        let (current_epoch, _gas) = self.storage.get_current_epoch();
        let last_epoch = current_epoch - 1;
        // Get input values needed for the PD controller for PoS and MASP.
        // Run the PD controllers to calculate new rates.
        //
        // TODO:
        // Mint new tokens to POS address and update reward products
        //
        // MASP is included below just for some completeness.

        // read from Parameters storage
        let epochs_per_year: u64 = self
            .read_storage_key(&params_storage::get_epochs_per_year_key())
            .unwrap();
        let pos_locked_ratio_last: Decimal = self
            .read_storage_key(&params_storage::get_staked_ratio_key())
            .unwrap();
        let pos_last_reward_rate = self
            .read_storage_key(&params_storage::get_pos_reward_rate_key())
            .unwrap();
        let pos_p_gain: Decimal = self
            .read_storage_key(&params_storage::get_pos_gain_p_key())
            .unwrap();
        let pos_d_gain: Decimal = self
            .read_storage_key(&params_storage::get_pos_gain_d_key())
            .unwrap();

        // read from PoS storage
        let total_tokens = self
            .read_storage_key(&total_supply_key(&staking_token_address()))
            .unwrap();
        let total_deltas = self.storage.read_total_deltas();
        let pos_locked_supply = total_deltas
            .get(last_epoch)
            .expect("maximum possible sum should fit within an i128");
        let pos_locked_supply: Amount = u64::try_from(pos_locked_supply)
            .expect("pos_locked_supply should be positive")
            .into();
        let pos_params = self.storage.read_pos_params();
        let pos_locked_ratio_target = pos_params.target_staked_ratio;
        let pos_max_inflation_rate = pos_params.max_inflation_rate;

        // Arbitrary default values until real ones can be fetched
        // TODO: these need to be properly fetched.
        let masp_locked_supply: Amount = Amount::default();
        let masp_locked_ratio_target = Decimal::new(5, 1);
        let masp_locked_ratio_last = Decimal::new(5, 1);
        let masp_max_reward_rate = Decimal::new(2, 1);
        let masp_last_reward_rate = Decimal::new(12, 2);
        let masp_p_gain = Decimal::new(1, 1);
        let masp_d_gain = Decimal::new(1, 1);

        let pos_controller = inflation::RewardsController::new(
            pos_locked_supply,
            total_tokens,
            pos_locked_ratio_target,
            pos_locked_ratio_last,
            pos_max_reward_rate,
            pos_last_reward_rate,
            pos_p_gain,
            pos_d_gain,
            epochs_per_year,
        );
        let _masp_controller = inflation::RewardsController::new(
            masp_locked_supply,
            total_tokens,
            masp_locked_ratio_target,
            masp_locked_ratio_last,
            masp_max_reward_rate,
            masp_last_reward_rate,
            masp_p_gain,
            masp_d_gain,
            epochs_per_year,
        );

        let new_pos_vals = RewardsController::run(&pos_controller);
        let new_masp_vals = RewardsController::run(&_masp_controller);

        let new_pos_reward_rate = new_pos_vals.last_reward_rate;
        let new_masp_reward_rate = new_masp_vals.last_reward_rate;

        self.storage
            .write(
                &params_storage::get_pos_reward_rate_key(),
                new_pos_reward_rate
                    .try_to_vec()
                    .expect("encode new reward rate"),
            )
            .expect("unable to encode new reward rate (Decimal)");
        self.storage
            .write(
                &params_storage::get_staked_ratio_key(),
                new_pos_vals
                    .locked_ratio_last
                    .try_to_vec()
                    .expect("encode new locked ratio"),
            )
            .expect("unable to encode new locked ratio (Decimal)");
        self.storage
            .write(
                &params_storage::get_pos_gain_p_key(),
                new_pos_vals.p_gain.try_to_vec().expect("encode new p gain"),
            )
            .expect("unable to encode new p gain (Decimal)");
        self.storage
            .write(
                &params_storage::get_pos_gain_d_key(),
                new_pos_vals.d_gain.try_to_vec().expect("encode new d gain"),
            )
            .expect("unable to encode new d gain (Decimal)");


        let pos_minted_tokens =
            decimal_mult_u64(new_pos_reward_rate, u64::from(total_tokens));
        let _masp_minted_tokens =
            decimal_mult_u64(new_masp_reward_rate, u64::from(total_tokens));

        // Mint tokens to PoS account
        let pos_address = self.storage.read_pos_address();
        inflation::mint_tokens(
            &mut self.storage,
            &pos_address,
            &staking_token_address(),
            Amount::from(pos_minted_tokens),
        )
        .unwrap();

        // Get proposer address from storage based on the consensus key hash
        let tm_raw_hash_string = tm_raw_hash_to_string(proposer_address);
        let native_proposer_address = self
            .storage
            .read_validator_address_raw_hash(tm_raw_hash_string)
            .expect(
                "Unable to find native validator address of block proposer \
                 from tendermint raw hash",
            );

        // TODO: reward distribution should be written in such a way that the reward products
        // for each validator are updated rather than actually transferring tokens to the addresses.
        // Must follow convention of auto-bonding the rewards basically

        self.storage
            .distribute_rewards(
                current_epoch,
                Amount::from(pos_minted_tokens),
                &native_proposer_address,
                votes,
            )
            .unwrap();
    }
}

/// We test the failure cases of [`finalize_block`]. The happy flows
/// are covered by the e2e tests.
#[cfg(test)]
mod test_finalize_block {
    use namada::types::address::nam;
    use namada::types::storage::Epoch;
    use namada::types::transaction::{EncryptionKey, Fee};

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
        let (mut shell, _) = setup();
        let keypair = gen_keypair();
        let mut processed_txs = vec![];
        let mut valid_wrappers = vec![];
        // create some wrapper txs
        for i in 1..5 {
            let raw_tx = Tx::new(
                "wasm_code".as_bytes().to_owned(),
                Some(format!("transaction data: {}", i).as_bytes().to_owned()),
            );
            let wrapper = WrapperTx::new(
                Fee {
                    amount: i.into(),
                    token: nam(),
                },
                &keypair,
                Epoch(0),
                0.into(),
                raw_tx.clone(),
                Default::default(),
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
                wrapper.tx_hash,
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
        let (mut shell, _) = setup();
        let keypair = gen_keypair();
        let raw_tx = Tx::new(
            "wasm_code".as_bytes().to_owned(),
            Some(String::from("transaction data").as_bytes().to_owned()),
        );
        let wrapper = WrapperTx::new(
            Fee {
                amount: 0.into(),
                token: nam(),
            },
            &keypair,
            Epoch(0),
            0.into(),
            raw_tx.clone(),
            Default::default(),
        );

        let processed_tx = ProcessedTx {
            tx: Tx::from(TxType::Decrypted(DecryptedTx::Decrypted(raw_tx)))
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
        assert!(shell.storage.tx_queue.is_empty());
    }

    /// Test that if a tx is undecryptable, it is applied
    /// but the tx result contains the appropriate error code.
    #[test]
    fn test_undecryptable_returns_error_code() {
        let (mut shell, _) = setup();

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
                token: nam(),
            },
            pk: keypair.ref_to(),
            epoch: Epoch(0),
            gas_limit: 0.into(),
            inner_tx,
            tx_hash: hash_tx(&tx),
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
        assert!(shell.storage.tx_queue.is_empty());
    }

    /// Test that the wrapper txs are queued in the order they
    /// are received from the block. Tests that the previously
    /// decrypted txs are de-queued.
    #[test]
    fn test_mixed_txs_queued_in_correct_order() {
        let (mut shell, _) = setup();
        let keypair = gen_keypair();
        let mut processed_txs = vec![];
        let mut valid_txs = vec![];

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
                    amount: 0.into(),
                    token: nam(),
                },
                &keypair,
                Epoch(0),
                0.into(),
                raw_tx.clone(),
                Default::default(),
            );
            shell.enqueue_tx(wrapper_tx);
            processed_txs.push(ProcessedTx {
                tx: Tx::from(TxType::Decrypted(DecryptedTx::Decrypted(raw_tx)))
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
                    amount: 0.into(),
                    token: nam(),
                },
                &keypair,
                Epoch(0),
                0.into(),
                raw_tx.clone(),
                Default::default(),
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
                wrapper.tx_hash,
                txs.next().expect("Test failed").tx_hash
            );
            counter += 1;
        }
        assert_eq!(counter, 2);
    }
}
