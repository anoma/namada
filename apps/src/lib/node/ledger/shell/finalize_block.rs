//! Implementation of the [`FinalizeBlock`] ABCI++ method for the Shell

use super::*;

impl Shell {
    /// Updates the chain with new header, height, etc. Also keeps track
    /// of epoch changes and applies associated updates to validator sets,
    /// etc. as necessary.
    ///
    /// Validate and apply decrypted transactions unless [`process_proposal`]
    /// detected that they were not submitted in correct order or more
    /// decrypted txs arrived than expected. In that case, all decrypted
    /// transactions are not applied and must be included in the next
    /// [`prepare_proposal`] call.
    ///
    /// Incoming wrapper txs need no further validation. They
    /// are added to the block.
    ///
    /// Error codes:
    ///   0: Ok
    ///   1: Invalid tx
    ///   2: Invalid order of decrypted txs
    ///   3. More decrypted txs than expected
    ///   4. Runtime error in WASM
    pub fn finalize_block(
        &mut self,
        req: shim::request::FinalizeBlock,
    ) -> Result<shim::response::FinalizeBlock> {
        let height = BlockHeight(req.header.height.into());
        self.storage
            .begin_block(req.hash, height)
            .expect("Beginning a block shouldn't fail");

        self.storage
            .set_header(req.header)
            .expect("Setting a header shouldn't fail");

        self.byzantine_validators = req.byzantine_validators;

        let header = self
            .storage
            .header
            .as_ref()
            .expect("Header must have been set in prepare_proposal.");
        let height = BlockHeight(header.height.into());
        let time: DateTime<Utc> = header.time.into();
        let time: DateTimeUtc = time.into();
        let new_epoch = self
            .storage
            .update_epoch(height, time)
            .expect("Must be able to update epoch");

        self.slash();

        let mut response = shim::response::FinalizeBlock::default();
        for tx in &req.txs {
            // This has already been verified as safe by [`process_proposal`]
            let tx_length = tx.tx.len();
            let processed_tx =
                process_tx(Tx::try_from(&tx.tx as &[u8]).unwrap()).unwrap();
            // If [`process_proposal`] rejected a Tx, emit an event here and
            // move on to next tx
            // If we are rejecting all decrypted txs because they were submitted
            // in an incorrect order, we do that later.
            if tx.result.code != 0 && !req.reject_all_decrypted {
                let mut tx_result =
                    Event::new_tx_event(&processed_tx, height.0);
                tx_result["code"] = tx.result.code.to_string();
                tx_result["info"] = format!("Tx rejected: {}", &tx.result.info);
                response.events.push(tx_result.into());
                continue;
            }

            let mut tx_result = match &processed_tx {
                TxType::Wrapper(wrapper) => {
                    self.storage.wrapper_txs.push(wrapper.clone());
                    Event::new_tx_event(&processed_tx, height.0)
                }
                TxType::Decrypted(_) => {
                    // If [`process_proposal`] detected that decrypted txs were
                    // submitted out of order, we apply none
                    // of those. New encrypted txs may still
                    // be accepted.
                    if req.reject_all_decrypted {
                        let mut tx_result =
                            Event::new_tx_event(&processed_tx, height.0);
                        tx_result["code"] = "2".into();
                        tx_result["info"] = "All decrypted txs rejected as \
                                             they were not submitted in \
                                             correct order"
                            .into();
                        response.events.push(tx_result.into());
                        continue;
                    }
                    Event::new_tx_event(&processed_tx, height.0)
                }
                TxType::Raw(_) => unreachable!(),
            };

            match protocol::apply_tx(
                processed_tx,
                tx_length,
                &mut self.gas_meter,
                &mut self.write_log,
                &self.storage,
            )
            .map_err(Error::TxApply)
            {
                Ok(result) => {
                    if result.is_accepted() {
                        tracing::info!(
                            "all VPs accepted apply_tx storage modification \
                             {:#?}",
                            result
                        );
                        self.write_log.commit_tx();
                        tx_result["code"] = "0".into();
                        match serde_json::to_string(
                            &result.initialized_accounts,
                        ) {
                            Ok(initialized_accounts) => {
                                tx_result["initialized_accounts"] =
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
                            "some VPs rejected apply_tx storage modification \
                             {:#?}",
                            result.vps_result.rejected_vps
                        );
                        self.write_log.drop_tx();
                        tx_result["code"] = "1".into();
                    }
                    tx_result["gas_used"] = result.gas_used.to_string();
                    tx_result["info"] = result.to_string();
                }
                Err(msg) => {
                    tx_result["gas_used"] = self
                        .gas_meter
                        .get_current_transaction_gas()
                        .to_string();
                    tx_result["info"] = msg.to_string();
                    tx_result["code"] = "4".into();
                }
            }
            response.events.push(tx_result.into());
        }

        if new_epoch {
            self.update_epoch(&mut response);
        }

        response.gas_used = self
            .gas_meter
            .finalize_transaction()
            .map_err(|_| Error::GasOverflow)?;
        self.revert_wrapper_txs();
        Ok(response)
    }

    /// If a new epoch begins, we update the response to include
    /// changes to the validator sets and consensus parameters
    fn update_epoch(&self, response: &mut shim::response::FinalizeBlock) {
        // Apply validator set update
        let (current_epoch, _gas) = self.storage.get_current_epoch();
        // TODO ABCI validator updates on block H affects the validator set
        // on block H+2, do we need to update a block earlier?
        self.storage.validator_set_update(current_epoch, |update| {
            let (consensus_key, power) = match update {
                ValidatorSetUpdate::Active(ActiveValidator {
                    consensus_key,
                    voting_power,
                }) => {
                    let power: u64 = voting_power.into();
                    let power: i64 = power
                        .try_into()
                        .expect("unexpected validator's voting power");
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
            let consensus_key: ed25519_dalek::PublicKey = consensus_key.into();
            let pub_key = tendermint_proto::crypto::PublicKey {
                sum: Some(tendermint_proto::crypto::public_key::Sum::Ed25519(
                    consensus_key.to_bytes().to_vec(),
                )),
            };
            let pub_key = Some(pub_key);
            let update = ValidatorUpdate { pub_key, power };
            response.validator_updates.push(update);
        });

        // Update evidence parameters
        let (parameters, _gas) = parameters::read(&self.storage)
            .expect("Couldn't read protocol parameters");
        let pos_params = self.storage.read_pos_params();
        let evidence_params =
            queries::get_evidence_params(&parameters, &pos_params);
        response.consensus_param_updates = Some(ConsensusParams {
            evidence: Some(evidence_params),
            ..response.consensus_param_updates.take().unwrap_or_default()
        });
    }
}
