//! Implementation of the ['VerifyHeader`], [`ProcessProposal`],
//! and [`RevertProposal`] ABCI++ methods for the Shell

use data_encoding::HEXUPPER;
use namada::core::hints;
use namada::ledger::pos::PosQueries;
use namada::ledger::protocol::get_fee_unshielding_transaction;
use namada::ledger::storage::tx_queue::TxInQueue;
use namada::parameters::validate_tx_bytes;
use namada::proof_of_stake::storage::find_validator_by_raw_hash;
use namada::state::{TempWlStorage, WlStorage};
use namada::tx::data::protocol::ProtocolTxType;
use namada::vote_ext::ethereum_tx_data_variants;
use namada_sdk::eth_bridge::{EthBridgeQueries, SendValsetUpd};

use super::block_alloc::{BlockSpace, EncryptedTxsBins};
use super::*;
use crate::facade::tendermint_proto::v0_37::abci::RequestProcessProposal;
use crate::node::ledger::shell::block_alloc::{AllocFailure, TxBin};
use crate::node::ledger::shims::abcipp_shim_types::shim::response::ProcessProposal;
use crate::node::ledger::shims::abcipp_shim_types::shim::TxBytes;

/// Validation metadata, to keep track of used resources or
/// transaction numbers, in a block proposal.
#[derive(Default)]
pub struct ValidationMeta {
    /// Space and gas utilized by encrypted txs.
    pub encrypted_txs_bins: EncryptedTxsBins,
    /// Vote extension digest counters.
    /// Space utilized by all txs.
    pub txs_bin: TxBin<BlockSpace>,
    /// Check if the decrypted tx queue has any elements
    /// left.
    ///
    /// This field will only evaluate to true if a block
    /// proposer didn't include all decrypted txs in a block.
    pub decrypted_queue_has_remaining_txs: bool,
    /// Check if a block has decrypted txs.
    pub has_decrypted_txs: bool,
}

impl<D, H> From<&WlStorage<D, H>> for ValidationMeta
where
    D: 'static + DB + for<'iter> DBIter<'iter>,
    H: 'static + StorageHasher,
{
    fn from(wl_storage: &WlStorage<D, H>) -> Self {
        let max_proposal_bytes =
            wl_storage.pos_queries().get_max_proposal_bytes().get();
        let max_block_gas =
            namada::parameters::get_max_block_gas(wl_storage).unwrap();
        let encrypted_txs_bin =
            EncryptedTxsBins::new(max_proposal_bytes, max_block_gas);
        let txs_bin = TxBin::init(max_proposal_bytes);
        Self {
            decrypted_queue_has_remaining_txs: false,
            has_decrypted_txs: false,
            encrypted_txs_bins: encrypted_txs_bin,
            txs_bin,
        }
    }
}

impl<D, H> Shell<D, H>
where
    D: DB + for<'iter> DBIter<'iter> + Sync + 'static,
    H: StorageHasher + Sync + 'static,
{
    /// INVARIANT: This method must be stateless.
    pub fn verify_header(
        &self,
        _req: shim::request::VerifyHeader,
    ) -> shim::response::VerifyHeader {
        Default::default()
    }

    /// Check all the txs in a block. Some txs may be incorrect,
    /// but we only reject the entire block if the order of the
    /// included txs violates the order decided upon in the previous
    /// block.
    pub fn process_proposal(
        &self,
        req: RequestProcessProposal,
    ) -> (ProcessProposal, Vec<TxResult>) {
        tracing::info!(
            proposer = ?HEXUPPER.encode(&req.proposer_address),
            height = req.height,
            hash = ?HEXUPPER.encode(&req.hash),
            n_txs = req.txs.len(),
            "Received block proposal",
        );
        let native_block_proposer_address = {
            let tm_raw_hash_string =
                tm_raw_hash_to_string(&req.proposer_address);
            find_validator_by_raw_hash(&self.wl_storage, tm_raw_hash_string)
                .unwrap()
                .expect(
                    "Unable to find native validator address of block \
                     proposer from tendermint raw hash",
                )
        };

        let (tx_results, meta) = self.process_txs(
            &req.txs,
            self.get_block_timestamp(req.time),
            &native_block_proposer_address,
        );

        // Erroneous transactions were detected when processing
        // the leader's proposal. We allow txs that do not
        // deserialize properly, that have invalid signatures
        // and that have invalid wasm code to reach FinalizeBlock.
        let invalid_txs = tx_results.iter().any(|res| {
            let error = ResultCode::from_u32(res.code).expect(
                "All error codes returned from process_single_tx are valid",
            );
            !error.is_recoverable()
        });
        if invalid_txs {
            tracing::warn!(
                proposer = ?HEXUPPER.encode(&req.proposer_address),
                height = req.height,
                hash = ?HEXUPPER.encode(&req.hash),
                "Found invalid transactions, proposed block will be rejected"
            );
        }

        let has_remaining_decrypted_txs =
            meta.decrypted_queue_has_remaining_txs;
        if has_remaining_decrypted_txs {
            tracing::warn!(
                proposer = ?HEXUPPER.encode(&req.proposer_address),
                height = req.height,
                hash = ?HEXUPPER.encode(&req.hash),
                "Not all decrypted txs from the previous height were included in
                 the proposal, the block will be rejected"
            );
        }

        let will_reject_proposal = invalid_txs || has_remaining_decrypted_txs;
        (
            if will_reject_proposal {
                ProcessProposal::Reject
            } else {
                ProcessProposal::Accept
            },
            tx_results,
        )
    }

    /// Evaluates the corresponding [`TxResult`] for each tx in the
    /// proposal. Additionally, counts the number of digest
    /// txs and the bytes used by encrypted txs in the proposal.
    ///
    /// `ProcessProposal` should be able to make a decision on whether a
    /// proposed block is acceptable or not based solely on what this
    /// function returns.
    pub fn process_txs(
        &self,
        txs: &[TxBytes],
        block_time: DateTimeUtc,
        block_proposer: &Address,
    ) -> (Vec<TxResult>, ValidationMeta) {
        let mut tx_queue_iter = self.wl_storage.storage.tx_queue.iter();
        let mut temp_wl_storage = TempWlStorage::new(&self.wl_storage.storage);
        let mut metadata = ValidationMeta::from(&self.wl_storage);
        let mut vp_wasm_cache = self.vp_wasm_cache.clone();
        let mut tx_wasm_cache = self.tx_wasm_cache.clone();

        let tx_results: Vec<_> = txs
            .iter()
            .map(|tx_bytes| {
                let result = self.check_proposal_tx(
                    tx_bytes,
                    &mut tx_queue_iter,
                    &mut metadata,
                    &mut temp_wl_storage,
                    block_time,
                    &mut vp_wasm_cache,
                    &mut tx_wasm_cache,
                    block_proposer,
                );
                let error_code = ResultCode::from_u32(result.code).unwrap();
                if let ResultCode::Ok = error_code {
                    temp_wl_storage.write_log.commit_tx();
                } else {
                    tracing::info!(
                        "Process proposal rejected an invalid tx. Error code: \
                         {:?}, info: {}",
                        error_code,
                        result.info
                    );
                    temp_wl_storage.write_log.drop_tx();
                }
                result
            })
            .collect();
        metadata.decrypted_queue_has_remaining_txs =
            !self.wl_storage.storage.tx_queue.is_empty()
                && tx_queue_iter.next().is_some();
        (tx_results, metadata)
    }

    /// Validates a list of vote extensions, included in PrepareProposal.
    ///
    /// If a vote extension is [`Some`], then it was validated properly,
    /// and the voting power of the validator who signed it is considered
    /// in the sum of the total voting power of all received vote extensions.
    ///
    /// At least 2/3 of validators by voting power must have included vote
    /// extensions for this function to consider a proposal valid.
    fn validate_vexts_in_proposal<I>(&self, mut vote_extensions: I) -> TxResult
    where
        I: Iterator<Item = Option<token::Amount>>,
    {
        if vote_extensions.all(|maybe_ext| maybe_ext.is_some()) {
            TxResult {
                code: ResultCode::Ok.into(),
                info: "Process proposal accepted this transaction".into(),
            }
        } else {
            TxResult {
                code: ResultCode::InvalidVoteExtension.into(),
                info: "Process proposal rejected this proposal because at \
                       least one of the vote extensions included was invalid."
                    .into(),
            }
        }
    }

    /// Checks if the Tx can be deserialized from bytes. Checks the fees and
    /// signatures of the fee payer for a transaction if it is a wrapper tx.
    ///
    /// Checks validity of a decrypted tx or that a tx marked un-decryptable
    /// is in fact so. Also checks that decrypted txs were submitted in
    /// correct order.
    ///
    /// Error codes:
    ///   0: Ok
    ///   1: Invalid tx
    ///   2: Tx is invalidly signed
    ///   3: Wasm runtime error
    ///   4: Invalid order of decrypted txs
    ///   5. More decrypted txs than expected
    ///   6. A transaction could not be decrypted
    ///   7. An error in the vote extensions included in the proposal
    ///   8. Not enough block space was available for some tx
    ///   9. Replay attack
    ///
    /// INVARIANT: Any changes applied in this method must be reverted if the
    /// proposal is rejected (unless we can simply overwrite them in the
    /// next block).
    #[allow(clippy::too_many_arguments)]
    pub fn check_proposal_tx<'a, CA>(
        &self,
        tx_bytes: &[u8],
        tx_queue_iter: &mut impl Iterator<Item = &'a TxInQueue>,
        metadata: &mut ValidationMeta,
        temp_wl_storage: &mut TempWlStorage<D, H>,
        block_time: DateTimeUtc,
        vp_wasm_cache: &mut VpCache<CA>,
        tx_wasm_cache: &mut TxCache<CA>,
        block_proposer: &Address,
    ) -> TxResult
    where
        CA: 'static + WasmCacheAccess + Sync,
    {
        // check tx bytes
        //
        // NB: always keep this as the first tx check,
        // as it is a pretty cheap one
        if !validate_tx_bytes(&self.wl_storage, tx_bytes.len())
            .expect("Failed to get max tx bytes param from storage")
        {
            return TxResult {
                code: ResultCode::TooLarge.into(),
                info: "Tx too large".into(),
            };
        }

        // try to allocate space for this tx
        if let Err(e) = metadata.txs_bin.try_dump(tx_bytes) {
            return TxResult {
                code: ResultCode::AllocationError.into(),
                info: match e {
                    AllocFailure::Rejected { .. } => {
                        "No more space left in the block"
                    }
                    AllocFailure::OverflowsBin { .. } => {
                        "The given tx is larger than the max configured \
                         proposal size"
                    }
                }
                .into(),
            };
        }

        let maybe_tx = Tx::try_from(tx_bytes).map_or_else(
            |err| {
                tracing::debug!(
                    ?err,
                    "Couldn't deserialize transaction received during \
                     PrepareProposal"
                );
                Err(TxResult {
                    code: ResultCode::InvalidTx.into(),
                    info: "The submitted transaction was not deserializable"
                        .into(),
                })
            },
            |tx| {
                let tx_chain_id = tx.header.chain_id.clone();
                let tx_expiration = tx.header.expiration;
                if let Err(err) = tx.validate_tx() {
                    // This occurs if the wrapper / protocol tx signature is
                    // invalid
                    return Err(TxResult {
                        code: ResultCode::InvalidSig.into(),
                        info: err.to_string(),
                    });
                }
                Ok((tx_chain_id, tx_expiration, tx))
            },
        );
        let (tx_chain_id, tx_expiration, tx) = match maybe_tx {
            Ok(tx) => tx,
            Err(tx_result) => return tx_result,
        };

        if let Err(err) = tx.validate_tx() {
            return TxResult {
                code: ResultCode::InvalidSig.into(),
                info: err.to_string(),
            };
        }
        match tx.header().tx_type {
            // If it is a raw transaction, we do no further validation
            TxType::Raw => TxResult {
                code: ResultCode::InvalidTx.into(),
                info: "Transaction rejected: Non-encrypted transactions are \
                       not supported"
                    .into(),
            },
            TxType::Protocol(protocol_tx) => {
                // Tx chain id
                if tx_chain_id != self.chain_id {
                    return TxResult {
                        code: ResultCode::InvalidChainId.into(),
                        info: format!(
                            "Tx carries a wrong chain id: expected {}, found \
                             {}",
                            self.chain_id, tx_chain_id
                        ),
                    };
                }

                // Tx expiration
                if let Some(exp) = tx_expiration {
                    if block_time > exp {
                        return TxResult {
                            code: ResultCode::ExpiredTx.into(),
                            info: format!(
                                "Tx expired at {:#?}, block time: {:#?}",
                                exp, block_time
                            ),
                        };
                    }
                }
                match protocol_tx.tx {
                    ProtocolTxType::EthEventsVext => {
                        ethereum_tx_data_variants::EthEventsVext::try_from(&tx)
                            .map_err(|err| err.to_string())
                            .and_then(|ext| {
                                self.validate_eth_events_vext_and_get_it_back(
                                    ext.0,
                                    self.wl_storage
                                        .storage
                                        .get_last_block_height(),
                                )
                                .map(|_| TxResult {
                                    code: ResultCode::Ok.into(),
                                    info: "Process Proposal accepted this \
                                           transaction"
                                        .into(),
                                })
                                .map_err(|err| err.to_string())
                            })
                            .unwrap_or_else(|err| TxResult {
                                code: ResultCode::InvalidVoteExtension.into(),
                                info: format!(
                                    "Process proposal rejected this proposal \
                                     because one of the included Ethereum \
                                     events vote extensions was invalid: {err}"
                                ),
                            })
                    }
                    ProtocolTxType::BridgePoolVext => {
                        ethereum_tx_data_variants::BridgePoolVext::try_from(&tx)
                            .map_err(|err| err.to_string())
                            .and_then(|ext| {
                                self.validate_bp_roots_vext_and_get_it_back(
                                    ext.0,
                                    self.wl_storage
                                        .storage
                                        .get_last_block_height(),
                                )
                                .map(|_| TxResult {
                                    code: ResultCode::Ok.into(),
                                    info: "Process Proposal accepted this \
                                           transaction"
                                        .into(),
                                })
                                .map_err(|err| err.to_string())
                            })
                            .unwrap_or_else(|err| TxResult {
                                code: ResultCode::InvalidVoteExtension.into(),
                                info: format!(
                                    "Process proposal rejected this proposal \
                                     because one of the included Bridge pool \
                                     root's vote extensions was invalid: {err}"
                                ),
                            })
                    }
                    ProtocolTxType::ValSetUpdateVext => {
                        ethereum_tx_data_variants::ValSetUpdateVext::try_from(
                            &tx,
                        )
                        .map_err(|err| err.to_string())
                        .and_then(|ext| {
                            self.validate_valset_upd_vext_and_get_it_back(
                                ext,
                                // n.b. only accept validator set updates
                                // issued at
                                // the current epoch (signing off on the
                                // validators
                                // of the next epoch)
                                self.wl_storage.storage.get_current_epoch().0,
                            )
                            .map(|_| TxResult {
                                code: ResultCode::Ok.into(),
                                info: "Process Proposal accepted this \
                                       transaction"
                                    .into(),
                            })
                            .map_err(|err| err.to_string())
                        })
                        .unwrap_or_else(|err| {
                            TxResult {
                                code: ResultCode::InvalidVoteExtension.into(),
                                info: format!(
                                    "Process proposal rejected this proposal \
                                     because one of the included validator \
                                     set update vote extensions was invalid: \
                                     {err}"
                                ),
                            }
                        })
                    }
                    ProtocolTxType::EthereumEvents => {
                        let digest =
                            ethereum_tx_data_variants::EthereumEvents::try_from(
                                &tx,
                            )
                            .unwrap();
                        let extensions = digest.decompress(
                            self.wl_storage.storage.get_last_block_height(),
                        );
                        let valid_extensions = self
                            .validate_eth_events_vext_list(extensions)
                            .map(|maybe_ext| {
                                maybe_ext.ok().map(|(power, _)| power)
                            });

                        self.validate_vexts_in_proposal(valid_extensions)
                    }
                    ProtocolTxType::BridgePool => {
                        let digest =
                            ethereum_tx_data_variants::BridgePool::try_from(
                                &tx,
                            )
                            .unwrap()
                            .into_iter()
                            .map(|vext| vext.0);
                        let valid_extensions = self
                            .validate_bp_roots_vext_list(digest)
                            .map(|maybe_ext| {
                                maybe_ext.ok().map(|(power, _)| power)
                            });
                        self.validate_vexts_in_proposal(valid_extensions)
                    }
                    ProtocolTxType::ValidatorSetUpdate => {
                        let digest =
                            ethereum_tx_data_variants::ValidatorSetUpdate::try_from(
                                &tx,
                            )
                            .unwrap();
                        if !self
                            .wl_storage
                            .ethbridge_queries()
                            .must_send_valset_upd(SendValsetUpd::AtPrevHeight)
                        {
                            return TxResult {
                                code: ResultCode::InvalidVoteExtension.into(),
                                info: "Process proposal rejected a validator \
                                       set update vote extension issued at an \
                                       invalid block height"
                                    .into(),
                            };
                        }

                        let extensions = digest.decompress(
                            self.wl_storage.storage.get_current_epoch().0,
                        );
                        let valid_extensions = self
                            .validate_valset_upd_vext_list(extensions)
                            .map(|maybe_ext| {
                                maybe_ext.ok().map(|(power, _)| power)
                            });

                        self.validate_vexts_in_proposal(valid_extensions)
                    }
                }
            }
            TxType::Decrypted(tx_header) => {
                metadata.has_decrypted_txs = true;
                match tx_queue_iter.next() {
                    Some(wrapper) => {
                        if wrapper.tx.raw_header_hash() != tx.raw_header_hash()
                        {
                            TxResult {
                                code: ResultCode::InvalidOrder.into(),
                                info: "Process proposal rejected a decrypted \
                                       transaction that violated the tx order \
                                       determined in the previous block"
                                    .into(),
                            }
                        } else if matches!(
                            tx_header,
                            DecryptedTx::Undecryptable
                        ) {
                            // DKG is disabled, txs are not actually encrypted
                            TxResult {
                                code: ResultCode::InvalidTx.into(),
                                info: "The encrypted payload of tx was \
                                       incorrectly marked as un-decryptable"
                                    .into(),
                            }
                        } else {
                            match tx.header().expiration {
                                Some(tx_expiration)
                                    if block_time > tx_expiration =>
                                {
                                    TxResult {
                                        code: ResultCode::ExpiredDecryptedTx
                                            .into(),
                                        info: format!(
                                            "Tx expired at {:#?}, block time: \
                                             {:#?}",
                                            tx_expiration, block_time
                                        ),
                                    }
                                }
                                _ => TxResult {
                                    code: ResultCode::Ok.into(),
                                    info: "Process Proposal accepted this \
                                           transaction"
                                        .into(),
                                },
                            }
                        }
                    }
                    None => TxResult {
                        code: ResultCode::ExtraTxs.into(),
                        info: "Received more decrypted txs than expected"
                            .into(),
                    },
                }
            }
            TxType::Wrapper(wrapper) => {
                // Account for gas and space. This is done even if the
                // transaction is later deemed invalid, to
                // incentivize the proposer to include only
                // valid transaction and avoid wasting block
                // resources (ABCI only)
                let mut tx_gas_meter = TxGasMeter::new(wrapper.gas_limit);
                if tx_gas_meter.add_wrapper_gas(tx_bytes).is_err() {
                    // Account for the tx's resources even in case of an error.
                    // Ignore any allocation error
                    let _ = metadata
                        .encrypted_txs_bins
                        .try_dump(tx_bytes, u64::from(wrapper.gas_limit));

                    return TxResult {
                        code: ResultCode::TxGasLimit.into(),
                        info: "Wrapper transactions exceeds its gas limit"
                            .to_string(),
                    };
                }

                // try to allocate space and gas for this encrypted tx
                if let Err(e) = metadata
                    .encrypted_txs_bins
                    .try_dump(tx_bytes, u64::from(wrapper.gas_limit))
                {
                    return TxResult {
                        code: ResultCode::AllocationError.into(),
                        info: e,
                    };
                }
                // decrypted txs shouldn't show up before wrapper txs
                if metadata.has_decrypted_txs {
                    return TxResult {
                        code: ResultCode::InvalidTx.into(),
                        info: "Decrypted txs should not be proposed before \
                               wrapper txs"
                            .into(),
                    };
                }
                if hints::unlikely(self.encrypted_txs_not_allowed()) {
                    return TxResult {
                        code: ResultCode::AllocationError.into(),
                        info: "Wrapper txs not allowed at the current block \
                               height"
                            .into(),
                    };
                }

                // ChainId check
                if tx_chain_id != self.chain_id {
                    return TxResult {
                        code: ResultCode::InvalidChainId.into(),
                        info: format!(
                            "Tx carries a wrong chain id: expected {}, found \
                             {}",
                            self.chain_id, tx_chain_id
                        ),
                    };
                }

                // Tx expiration
                if let Some(exp) = tx_expiration {
                    if block_time > exp {
                        return TxResult {
                            code: ResultCode::ExpiredTx.into(),
                            info: format!(
                                "Tx expired at {:#?}, block time: {:#?}",
                                exp, block_time
                            ),
                        };
                    }
                }

                // Replay protection checks
                if let Err(e) =
                    self.replay_protection_checks(&tx, temp_wl_storage)
                {
                    return TxResult {
                        code: ResultCode::ReplayTx.into(),
                        info: e.to_string(),
                    };
                }

                // Check that the fee payer has sufficient balance.
                match self.wrapper_fee_check(
                    &wrapper,
                    get_fee_unshielding_transaction(&tx, &wrapper),
                    temp_wl_storage,
                    vp_wasm_cache,
                    tx_wasm_cache,
                    Some(block_proposer),
                    false,
                ) {
                    Ok(()) => TxResult {
                        code: ResultCode::Ok.into(),
                        info: "Process proposal accepted this transaction"
                            .into(),
                    },
                    Err(e) => TxResult {
                        code: ResultCode::FeeError.into(),
                        info: e.to_string(),
                    },
                }
            }
        }
    }

    pub fn revert_proposal(
        &mut self,
        _req: shim::request::RevertProposal,
    ) -> shim::response::RevertProposal {
        Default::default()
    }

    /// Checks if it is not possible to include encrypted txs at the current
    /// block height.
    pub(super) fn encrypted_txs_not_allowed(&self) -> bool {
        let is_2nd_height_off = self.is_deciding_offset_within_epoch(1);
        let is_3rd_height_off = self.is_deciding_offset_within_epoch(2);
        is_2nd_height_off || is_3rd_height_off
    }
}

/// We test the failure cases of [`process_proposal`]. The happy flows
/// are covered by the e2e tests.
#[cfg(test)]
mod test_process_proposal {
    use namada::ledger::replay_protection;
    use namada::state::StorageWrite;
    use namada::token;
    use namada::token::{read_denom, Amount, DenominatedAmount};
    use namada::tx::data::{Fee, WrapperTx};
    use namada::tx::{
        Code, Data, Section, SignableEthMessage, Signature, Signed,
    };
    use namada::types::ethereum_events::EthereumEvent;
    use namada::types::key::*;
    use namada::types::storage::Epoch;
    use namada::types::time::DateTimeUtc;
    use namada::vote_ext::{
        bridge_pool_roots, ethereum_events, EthereumTxData,
    };

    use super::*;
    use crate::node::ledger::shell::test_utils::{
        self, deactivate_bridge, gen_keypair, get_bp_bytes_to_sign,
        ProcessProposal, TestError, TestShell,
    };
    use crate::node::ledger::shims::abcipp_shim_types::shim::request::ProcessedTx;
    use crate::wallet;

    const GAS_LIMIT_MULTIPLIER: u64 = 100_000;

    /// Check that we reject an eth events protocol tx
    /// if the bridge is not active.
    #[test]
    fn check_rejected_eth_events_bridge_inactive() {
        let (mut shell, _, _, _) = test_utils::setup_at_height(3);
        let protocol_key = shell.mode.get_protocol_key().expect("Test failed");
        let addr = shell.mode.get_validator_address().expect("Test failed");
        let event = EthereumEvent::TransfersToNamada {
            nonce: 0u64.into(),
            transfers: vec![],
        };
        let ext = ethereum_events::Vext {
            validator_addr: addr.clone(),
            block_height: shell.wl_storage.storage.get_last_block_height(),
            ethereum_events: vec![event],
        }
        .sign(protocol_key);
        let tx = EthereumTxData::EthEventsVext(ext.into())
            .sign(protocol_key, shell.chain_id.clone())
            .to_bytes();
        let request = ProcessProposal { txs: vec![tx] };

        let [resp]: [ProcessedTx; 1] = shell
            .process_proposal(request.clone())
            .expect("Test failed")
            .try_into()
            .expect("Test failed");
        assert_eq!(resp.result.code, u32::from(ResultCode::Ok));
        deactivate_bridge(&mut shell);
        let response = if let Err(TestError::RejectProposal(resp)) =
            shell.process_proposal(request)
        {
            if let [resp] = resp.as_slice() {
                resp.clone()
            } else {
                panic!("Test failed")
            }
        } else {
            panic!("Test failed")
        };
        assert_eq!(
            response.result.code,
            u32::from(ResultCode::InvalidVoteExtension)
        );
    }

    /// Check that we reject an bp roots protocol tx
    /// if the bridge is not active.
    #[test]
    fn check_rejected_bp_roots_bridge_inactive() {
        let (mut shell, _a, _b, _c) = test_utils::setup_at_height(1);
        shell.wl_storage.storage.block.height =
            shell.wl_storage.storage.get_last_block_height();
        shell.commit();
        let protocol_key = shell.mode.get_protocol_key().expect("Test failed");
        let addr = shell.mode.get_validator_address().expect("Test failed");
        let to_sign = get_bp_bytes_to_sign();
        let sig = Signed::<_, SignableEthMessage>::new(
            shell.mode.get_eth_bridge_keypair().expect("Test failed"),
            to_sign,
        )
        .sig;
        let vote_ext = bridge_pool_roots::Vext {
            block_height: shell.wl_storage.storage.get_last_block_height(),
            validator_addr: addr.clone(),
            sig,
        }
        .sign(shell.mode.get_protocol_key().expect("Test failed"));
        let tx = EthereumTxData::BridgePoolVext(vote_ext)
            .sign(protocol_key, shell.chain_id.clone())
            .to_bytes();
        let request = ProcessProposal { txs: vec![tx] };

        let [resp]: [ProcessedTx; 1] = shell
            .process_proposal(request.clone())
            .expect("Test failed")
            .try_into()
            .expect("Test failed");

        assert_eq!(resp.result.code, u32::from(ResultCode::Ok));
        deactivate_bridge(&mut shell);
        let response = if let Err(TestError::RejectProposal(resp)) =
            shell.process_proposal(request)
        {
            if let [resp] = resp.as_slice() {
                resp.clone()
            } else {
                panic!("Test failed")
            }
        } else {
            panic!("Test failed")
        };
        assert_eq!(
            response.result.code,
            u32::from(ResultCode::InvalidVoteExtension)
        );
    }

    fn check_rejected_eth_events(
        shell: &mut TestShell,
        vote_extension: ethereum_events::SignedVext,
        protocol_key: common::SecretKey,
    ) {
        let tx = EthereumTxData::EthEventsVext(vote_extension)
            .sign(&protocol_key, shell.chain_id.clone())
            .to_bytes();
        let request = ProcessProposal { txs: vec![tx] };
        let response = if let Err(TestError::RejectProposal(resp)) =
            shell.process_proposal(request)
        {
            if let [resp] = resp.as_slice() {
                resp.clone()
            } else {
                panic!("Test failed")
            }
        } else {
            panic!("Test failed")
        };
        assert_eq!(
            response.result.code,
            u32::from(ResultCode::InvalidVoteExtension)
        );
    }

    /// Test that if a proposal contains Ethereum events with
    /// invalid validator signatures, we reject it.
    #[test]
    fn test_drop_vext_with_invalid_sigs() {
        const LAST_HEIGHT: BlockHeight = BlockHeight(2);
        let (mut shell, _recv, _, _) = test_utils::setup_at_height(LAST_HEIGHT);
        let (protocol_key, _) = wallet::defaults::validator_keys();
        let addr = wallet::defaults::validator_address();
        let event = EthereumEvent::TransfersToNamada {
            nonce: 0u64.into(),
            transfers: vec![],
        };
        let ext = {
            // generate a valid signature
            #[allow(clippy::redundant_clone)]
            let mut ext = ethereum_events::Vext {
                validator_addr: addr.clone(),
                block_height: LAST_HEIGHT,
                ethereum_events: vec![event.clone()],
            }
            .sign(&protocol_key);
            assert!(ext.verify(&protocol_key.ref_to()).is_ok());

            // modify this signature such that it becomes invalid
            ext.sig = test_utils::invalidate_signature(ext.sig);
            ext
        };
        check_rejected_eth_events(&mut shell, ext.into(), protocol_key);
    }

    /// Test that if a proposal contains Ethereum events with
    /// invalid block heights, we reject it.
    #[test]
    fn test_drop_vext_with_invalid_bheights() {
        const LAST_HEIGHT: BlockHeight = BlockHeight(3);
        const INVALID_HEIGHT: BlockHeight = BlockHeight(LAST_HEIGHT.0 + 1);
        let (mut shell, _recv, _, _) = test_utils::setup_at_height(LAST_HEIGHT);
        let (protocol_key, _) = wallet::defaults::validator_keys();
        let addr = wallet::defaults::validator_address();
        let event = EthereumEvent::TransfersToNamada {
            nonce: 0u64.into(),
            transfers: vec![],
        };
        let ext = {
            #[allow(clippy::redundant_clone)]
            let ext = ethereum_events::Vext {
                validator_addr: addr.clone(),
                block_height: INVALID_HEIGHT,
                ethereum_events: vec![event.clone()],
            }
            .sign(&protocol_key);
            assert!(ext.verify(&protocol_key.ref_to()).is_ok());
            ext
        };
        check_rejected_eth_events(&mut shell, ext.into(), protocol_key);
    }

    /// Test that if a proposal contains Ethereum events with
    /// invalid validators, we reject it.
    #[test]
    fn test_drop_vext_with_invalid_validators() {
        const LAST_HEIGHT: BlockHeight = BlockHeight(2);
        let (mut shell, _recv, _, _) = test_utils::setup_at_height(LAST_HEIGHT);
        let (addr, protocol_key) = {
            let bertha_key = wallet::defaults::bertha_keypair();
            let bertha_addr = wallet::defaults::bertha_address();
            (bertha_addr, bertha_key)
        };
        let event = EthereumEvent::TransfersToNamada {
            nonce: 0u64.into(),
            transfers: vec![],
        };
        let ext = {
            #[allow(clippy::redundant_clone)]
            let ext = ethereum_events::Vext {
                validator_addr: addr.clone(),
                block_height: LAST_HEIGHT,
                ethereum_events: vec![event.clone()],
            }
            .sign(&protocol_key);
            assert!(ext.verify(&protocol_key.ref_to()).is_ok());
            ext
        };
        check_rejected_eth_events(&mut shell, ext.into(), protocol_key);
    }

    /// Test that if a wrapper tx is not signed, the block is rejected
    /// by [`process_proposal`].
    #[test]
    fn test_unsigned_wrapper_rejected() {
        let (shell, _recv, _, _) = test_utils::setup_at_height(3u64);
        let keypair = gen_keypair();
        let public_key = keypair.ref_to();
        let mut outer_tx =
            Tx::from_type(TxType::Wrapper(Box::new(WrapperTx::new(
                Fee {
                    amount_per_gas_unit: DenominatedAmount::native(
                        Default::default(),
                    ),
                    token: shell.wl_storage.storage.native_token.clone(),
                },
                public_key,
                Epoch(0),
                GAS_LIMIT_MULTIPLIER.into(),
                None,
            ))));
        outer_tx.header.chain_id = shell.chain_id.clone();
        outer_tx.set_code(Code::new("wasm_code".as_bytes().to_owned(), None));
        outer_tx.set_data(Data::new("transaction data".as_bytes().to_owned()));

        let tx = outer_tx.to_bytes();

        let response = {
            let request = ProcessProposal { txs: vec![tx] };
            if let Err(TestError::RejectProposal(resp)) =
                shell.process_proposal(request)
            {
                if let [resp] = resp.as_slice() {
                    resp.clone()
                } else {
                    panic!("Test failed")
                }
            } else {
                panic!("Test failed")
            }
        };

        println!("{}", response.result.info);

        assert_eq!(response.result.code, u32::from(ResultCode::InvalidSig));
        assert_eq!(
            response.result.info,
            String::from(
                "WrapperTx signature verification failed: The wrapper \
                 signature is invalid."
            )
        );
    }

    /// Test that a block including a wrapper tx with invalid signature is
    /// rejected
    #[test]
    fn test_wrapper_bad_signature_rejected() {
        let (shell, _recv, _, _) = test_utils::setup_at_height(3u64);
        let keypair = gen_keypair();
        let mut outer_tx =
            Tx::from_type(TxType::Wrapper(Box::new(WrapperTx::new(
                Fee {
                    amount_per_gas_unit: DenominatedAmount::native(
                        Amount::from_uint(100, 0).expect("Test failed"),
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
        outer_tx.set_data(Data::new("transaction data".as_bytes().to_owned()));
        outer_tx.add_section(Section::Signature(Signature::new(
            outer_tx.sechashes(),
            [(0, keypair)].into_iter().collect(),
            None,
        )));
        let mut new_tx = outer_tx.clone();
        if let TxType::Wrapper(wrapper) = &mut new_tx.header.tx_type {
            // we mount a malleability attack to try and remove the fee
            wrapper.fee.amount_per_gas_unit =
                DenominatedAmount::native(Default::default());
        } else {
            panic!("Test failed")
        };
        let request = ProcessProposal {
            txs: vec![new_tx.to_bytes()],
        };

        match shell.process_proposal(request) {
            Ok(_) => panic!("Test failed"),
            Err(TestError::RejectProposal(response)) => {
                let response = if let [response] = response.as_slice() {
                    response.clone()
                } else {
                    panic!("Test failed")
                };
                let expected_error = "WrapperTx signature verification \
                                      failed: The wrapper signature is \
                                      invalid.";
                assert_eq!(
                    response.result.code,
                    u32::from(ResultCode::InvalidSig)
                );
                assert!(
                    response.result.info.contains(expected_error),
                    "Result info {} doesn't contain the expected error {}",
                    response.result.info,
                    expected_error
                );
            }
        }
    }

    /// Test that if the account submitting the tx is not known and the fee is
    /// non-zero, [`process_proposal`] rejects that block
    #[test]
    fn test_wrapper_unknown_address() {
        let (mut shell, _recv, _, _) = test_utils::setup_at_height(3u64);
        let keypair = gen_keypair();
        // reduce address balance to match the 100 token min fee
        let balance_key = token::storage_key::balance_key(
            &shell.wl_storage.storage.native_token,
            &Address::from(&keypair.ref_to()),
        );
        shell
            .wl_storage
            .write(&balance_key, Amount::native_whole(99))
            .unwrap();
        let keypair = gen_keypair();
        let mut outer_tx =
            Tx::from_type(TxType::Wrapper(Box::new(WrapperTx::new(
                Fee {
                    amount_per_gas_unit: DenominatedAmount::native(
                        Amount::from_uint(1, 0).expect("Test failed"),
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
        outer_tx.set_data(Data::new("transaction data".as_bytes().to_owned()));
        outer_tx.add_section(Section::Signature(Signature::new(
            outer_tx.sechashes(),
            [(0, keypair)].into_iter().collect(),
            None,
        )));

        let response = {
            let request = ProcessProposal {
                txs: vec![outer_tx.to_bytes()],
            };
            if let Err(TestError::RejectProposal(resp)) =
                shell.process_proposal(request)
            {
                if let [resp] = resp.as_slice() {
                    resp.clone()
                } else {
                    panic!("Test failed")
                }
            } else {
                panic!("Test failed")
            }
        };
        assert_eq!(response.result.code, u32::from(ResultCode::FeeError));
        assert_eq!(
            response.result.info,
            String::from(
                "Error trying to apply a transaction: Error while processing \
                 transaction's fees: Transparent balance of wrapper's signer \
                 was insufficient to pay fee. All the available transparent \
                 funds have been moved to the block proposer"
            )
        );
    }

    /// Test that if the account submitting the tx does
    /// not have sufficient balance to pay the fee,
    /// [`process_proposal`] rejects the entire block
    #[test]
    fn test_wrapper_insufficient_balance_address() {
        let (mut shell, _recv, _, _) = test_utils::setup_at_height(3u64);
        let keypair = crate::wallet::defaults::daewon_keypair();
        // reduce address balance to match the 100 token min fee
        let balance_key = token::storage_key::balance_key(
            &shell.wl_storage.storage.native_token,
            &Address::from(&keypair.ref_to()),
        );
        shell
            .wl_storage
            .write(&balance_key, Amount::native_whole(99))
            .unwrap();
        shell.commit();

        let mut outer_tx =
            Tx::from_type(TxType::Wrapper(Box::new(WrapperTx::new(
                Fee {
                    amount_per_gas_unit: DenominatedAmount::native(
                        Amount::native_whole(1_000_100),
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
        outer_tx.set_data(Data::new("transaction data".as_bytes().to_owned()));
        outer_tx.add_section(Section::Signature(Signature::new(
            outer_tx.sechashes(),
            [(0, keypair)].into_iter().collect(),
            None,
        )));

        let response = {
            let request = ProcessProposal {
                txs: vec![outer_tx.to_bytes()],
            };
            if let Err(TestError::RejectProposal(resp)) =
                shell.process_proposal(request)
            {
                if let [resp] = resp.as_slice() {
                    resp.clone()
                } else {
                    panic!("Test failed")
                }
            } else {
                panic!("Test failed")
            }
        };
        assert_eq!(response.result.code, u32::from(ResultCode::FeeError));
        assert_eq!(
            response.result.info,
            String::from(
                "Error trying to apply a transaction: Error while processing \
                 transaction's fees: Transparent balance of wrapper's signer \
                 was insufficient to pay fee. All the available transparent \
                 funds have been moved to the block proposer"
            )
        );
    }

    /// Test that if the expected order of decrypted txs is
    /// validated, [`process_proposal`] rejects it
    #[test]
    fn test_decrypted_txs_out_of_order() {
        let (mut shell, _recv, _, _) = test_utils::setup_at_height(3u64);
        let keypair = gen_keypair();
        let mut txs = vec![];
        for i in 0..3 {
            let mut outer_tx =
                Tx::from_type(TxType::Wrapper(Box::new(WrapperTx::new(
                    Fee {
                        amount_per_gas_unit: DenominatedAmount::native(
                            Amount::native_whole(i as u64),
                        ),
                        token: shell.wl_storage.storage.native_token.clone(),
                    },
                    keypair.ref_to(),
                    Epoch(0),
                    GAS_LIMIT_MULTIPLIER.into(),
                    None,
                ))));
            outer_tx.header.chain_id = shell.chain_id.clone();
            outer_tx
                .set_code(Code::new("wasm_code".as_bytes().to_owned(), None));
            outer_tx.set_data(Data::new(
                format!("transaction data: {}", i).as_bytes().to_owned(),
            ));
            let gas_limit =
                Gas::from(outer_tx.header().wrapper().unwrap().gas_limit)
                    .checked_sub(Gas::from(outer_tx.to_bytes().len() as u64))
                    .unwrap();
            shell.enqueue_tx(outer_tx.clone(), gas_limit);

            outer_tx.update_header(TxType::Decrypted(DecryptedTx::Decrypted));
            txs.push(outer_tx);
        }
        let response = {
            let request = ProcessProposal {
                txs: vec![
                    txs[0].to_bytes(),
                    txs[2].to_bytes(),
                    txs[1].to_bytes(),
                ],
            };
            if let Err(TestError::RejectProposal(mut resp)) =
                shell.process_proposal(request)
            {
                assert_eq!(resp.len(), 3);
                resp.remove(1)
            } else {
                panic!("Test failed")
            }
        };
        assert_eq!(response.result.code, u32::from(ResultCode::InvalidOrder));
        assert_eq!(
            response.result.info,
            String::from(
                "Process proposal rejected a decrypted transaction that \
                 violated the tx order determined in the previous block"
            ),
        );
    }

    /// Test that a block containing a tx incorrectly labelled as undecryptable
    /// is rejected by [`process_proposal`]
    #[test]
    fn test_incorrectly_labelled_as_undecryptable() {
        let (mut shell, _recv, _, _) = test_utils::setup_at_height(3u64);
        let keypair = gen_keypair();

        let mut tx = Tx::from_type(TxType::Wrapper(Box::new(WrapperTx::new(
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
        tx.header.chain_id = shell.chain_id.clone();
        tx.set_code(Code::new("wasm_code".as_bytes().to_owned(), None));
        tx.set_data(Data::new("transaction data".as_bytes().to_owned()));
        let gas_limit = Gas::from(tx.header().wrapper().unwrap().gas_limit)
            .checked_sub(Gas::from(tx.to_bytes().len() as u64))
            .unwrap();
        shell.enqueue_tx(tx.clone(), gas_limit);

        tx.header.tx_type = TxType::Decrypted(DecryptedTx::Undecryptable);

        let response = {
            let request = ProcessProposal {
                txs: vec![tx.to_bytes()],
            };
            if let Err(TestError::RejectProposal(resp)) =
                shell.process_proposal(request)
            {
                if let [resp] = resp.as_slice() {
                    resp.clone()
                } else {
                    panic!("Test failed")
                }
            } else {
                panic!("Test failed")
            }
        };
        assert_eq!(response.result.code, u32::from(ResultCode::InvalidTx));
        assert_eq!(
            response.result.info,
            String::from(
                "The encrypted payload of tx was incorrectly marked as \
                 un-decryptable"
            ),
        )
    }

    /// Test that if a wrapper tx contains  marked undecryptable the proposal is
    /// rejected
    #[test]
    fn test_undecryptable() {
        let (mut shell, _recv, _, _) = test_utils::setup_at_height(3u64);
        let keypair = crate::wallet::defaults::daewon_keypair();
        // not valid tx bytes
        let wrapper = WrapperTx {
            fee: Fee {
                amount_per_gas_unit: DenominatedAmount::native(
                    Default::default(),
                ),
                token: shell.wl_storage.storage.native_token.clone(),
            },
            pk: keypair.ref_to(),
            epoch: Epoch(0),
            gas_limit: GAS_LIMIT_MULTIPLIER.into(),
            unshield_section_hash: None,
        };

        let tx = Tx::from_type(TxType::Wrapper(Box::new(wrapper)));
        let mut decrypted = tx.clone();
        decrypted.update_header(TxType::Decrypted(DecryptedTx::Undecryptable));

        let gas_limit = Gas::from(tx.header().wrapper().unwrap().gas_limit)
            .checked_sub(Gas::from(tx.to_bytes().len() as u64))
            .unwrap();
        shell.enqueue_tx(tx, gas_limit);

        let request = ProcessProposal {
            txs: vec![decrypted.to_bytes()],
        };
        shell.process_proposal(request).expect_err("Test failed");
    }

    /// Test that if more decrypted txs are submitted to
    /// [`process_proposal`] than expected, they are rejected
    #[test]
    fn test_too_many_decrypted_txs() {
        let (shell, _recv, _, _) = test_utils::setup_at_height(3u64);
        let mut tx = Tx::from_type(TxType::Decrypted(DecryptedTx::Decrypted));
        tx.header.chain_id = shell.chain_id.clone();
        tx.set_code(Code::new("wasm_code".as_bytes().to_owned(), None));
        tx.set_data(Data::new("transaction data".as_bytes().to_owned()));

        let request = ProcessProposal {
            txs: vec![tx.to_bytes()],
        };
        let response = if let Err(TestError::RejectProposal(resp)) =
            shell.process_proposal(request)
        {
            if let [resp] = resp.as_slice() {
                resp.clone()
            } else {
                panic!("Test failed")
            }
        } else {
            panic!("Test failed")
        };
        assert_eq!(response.result.code, u32::from(ResultCode::ExtraTxs));
        assert_eq!(
            response.result.info,
            String::from("Received more decrypted txs than expected"),
        );
    }

    /// Process Proposal should reject a block containing a RawTx, but not panic
    #[test]
    fn test_raw_tx_rejected() {
        let (shell, _recv, _, _) = test_utils::setup_at_height(3u64);

        let keypair = crate::wallet::defaults::daewon_keypair();

        let mut tx = Tx::new(shell.chain_id.clone(), None);
        tx.add_code("wasm_code".as_bytes().to_owned(), None)
            .add_data("transaction data".as_bytes().to_owned())
            .sign_wrapper(keypair);

        let response = {
            let request = ProcessProposal {
                txs: vec![tx.to_bytes()],
            };
            if let Err(TestError::RejectProposal(resp)) =
                shell.process_proposal(request)
            {
                if let [resp] = resp.as_slice() {
                    resp.clone()
                } else {
                    panic!("Test failed")
                }
            } else {
                panic!("Test failed")
            }
        };
        assert_eq!(response.result.code, u32::from(ResultCode::InvalidTx));
        assert_eq!(
            response.result.info,
            String::from(
                "Transaction rejected: Non-encrypted transactions are not \
                 supported"
            ),
        );
    }

    /// Test that if the unsigned wrapper tx hash is known (replay attack), the
    /// block is rejected
    #[test]
    fn test_wrapper_tx_hash() {
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
                GAS_LIMIT_MULTIPLIER.into(),
                None,
            ))));
        wrapper.header.chain_id = shell.chain_id.clone();
        wrapper.set_data(Data::new("transaction data".as_bytes().to_owned()));
        wrapper.set_code(Code::new("wasm_code".as_bytes().to_owned(), None));
        wrapper.add_section(Section::Signature(Signature::new(
            wrapper.sechashes(),
            [(0, keypair)].into_iter().collect(),
            None,
        )));

        // Write wrapper hash to storage
        let mut batch = namada::state::testing::TestStorage::batch();
        let wrapper_unsigned_hash = wrapper.header_hash();
        let hash_key = replay_protection::last_key(&wrapper_unsigned_hash);
        shell
            .wl_storage
            .storage
            .write_replay_protection_entry(&mut batch, &hash_key)
            .expect("Test failed");

        // Run validation
        let request = ProcessProposal {
            txs: vec![wrapper.to_bytes()],
        };

        match shell.process_proposal(request) {
            Ok(_) => panic!("Test failed"),
            Err(TestError::RejectProposal(response)) => {
                assert_eq!(
                    response[0].result.code,
                    u32::from(ResultCode::ReplayTx)
                );
                assert_eq!(
                    response[0].result.info,
                    format!(
                        "Transaction replay attempt: Wrapper transaction hash \
                         {} already in storage",
                        wrapper_unsigned_hash
                    )
                );
            }
        }
    }

    /// Test that a block containing two identical wrapper txs is rejected
    #[test]
    fn test_wrapper_tx_hash_same_block() {
        let (mut shell, _recv, _, _) = test_utils::setup();

        let keypair = crate::wallet::defaults::daewon_keypair();

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

        // Run validation
        let request = ProcessProposal {
            txs: vec![wrapper.to_bytes(); 2],
        };
        match shell.process_proposal(request) {
            Ok(_) => panic!("Test failed"),
            Err(TestError::RejectProposal(response)) => {
                assert_eq!(response[0].result.code, u32::from(ResultCode::Ok));
                assert_eq!(
                    response[1].result.code,
                    u32::from(ResultCode::ReplayTx)
                );
                assert_eq!(
                    response[1].result.info,
                    format!(
                        "Transaction replay attempt: Wrapper transaction hash \
                         {} already in storage",
                        wrapper.header_hash()
                    )
                );
            }
        }
    }

    /// Test that if the unsigned inner tx hash is known (replay attack), the
    /// block is rejected
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

        // Write inner hash to storage
        let mut batch = namada::state::testing::TestStorage::batch();
        let hash_key = replay_protection::last_key(&wrapper.raw_header_hash());
        shell
            .wl_storage
            .storage
            .write_replay_protection_entry(&mut batch, &hash_key)
            .expect("Test failed");

        // Run validation
        let request = ProcessProposal {
            txs: vec![wrapper.to_bytes()],
        };
        match shell.process_proposal(request) {
            Ok(_) => panic!("Test failed"),
            Err(TestError::RejectProposal(response)) => {
                assert_eq!(
                    response[0].result.code,
                    u32::from(ResultCode::ReplayTx)
                );
                assert_eq!(
                    response[0].result.info,
                    format!(
                        "Transaction replay attempt: Inner transaction hash \
                         {} already in storage",
                        wrapper.raw_header_hash()
                    )
                );
            }
        }
    }

    /// Test that a block containing two identical inner transactions is
    /// accepted
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
        wrapper.set_code(Code::new("wasm_code".as_bytes().to_owned(), None));
        wrapper.set_data(Data::new("transaction data".as_bytes().to_owned()));
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

        // Run validation
        let request = ProcessProposal {
            txs: vec![wrapper.to_bytes(), new_wrapper.to_bytes()],
        };
        match shell.process_proposal(request) {
            Ok(received) => assert_eq!(received.len(), 2),
            Err(_) => panic!("Test failed"),
        }
    }

    /// Test that a wrapper or protocol transaction with a mismatching chain id
    /// causes the entire block to be rejected
    #[test]
    fn test_wrong_chain_id() {
        let (shell, _recv, _, _) = test_utils::setup();
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
                GAS_LIMIT_MULTIPLIER.into(),
                None,
            ))));
        let wrong_chain_id = ChainId("Wrong chain id".to_string());
        wrapper.header.chain_id = wrong_chain_id.clone();
        wrapper.set_code(Code::new("wasm_code".as_bytes().to_owned(), None));
        wrapper.set_data(Data::new("transaction data".as_bytes().to_owned()));
        wrapper.add_section(Section::Signature(Signature::new(
            wrapper.sechashes(),
            [(0, keypair)].into_iter().collect(),
            None,
        )));

        let protocol_key = shell.mode.get_protocol_key().expect("Test failed");
        let protocol_tx = EthereumTxData::EthEventsVext({
            let bertha_key = wallet::defaults::bertha_keypair();
            let bertha_addr = wallet::defaults::bertha_address();
            ethereum_events::Vext::empty(1234_u64.into(), bertha_addr)
                .sign(&bertha_key)
                .into()
        })
        .sign(protocol_key, wrong_chain_id.clone());

        // Run validation
        let request = ProcessProposal {
            txs: vec![wrapper.to_bytes(), protocol_tx.to_bytes()],
        };
        match shell.process_proposal(request) {
            Ok(_) => panic!("Test failed"),
            Err(TestError::RejectProposal(response)) => {
                for res in response {
                    assert_eq!(
                        res.result.code,
                        u32::from(ResultCode::InvalidChainId)
                    );
                    assert_eq!(
                        res.result.info,
                        format!(
                            "Tx carries a wrong chain id: expected {}, found \
                             {}",
                            shell.chain_id, wrong_chain_id
                        )
                    );
                }
            }
        }
    }

    /// Test that an expired wrapper transaction causes a block rejection
    #[test]
    fn test_expired_wrapper() {
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
        wrapper.header.expiration = Some(DateTimeUtc::default());
        wrapper.set_code(Code::new("wasm_code".as_bytes().to_owned(), None));
        wrapper.set_data(Data::new("transaction data".as_bytes().to_owned()));
        wrapper.add_section(Section::Signature(Signature::new(
            wrapper.sechashes(),
            [(0, keypair)].into_iter().collect(),
            None,
        )));

        // Run validation
        let request = ProcessProposal {
            txs: vec![wrapper.to_bytes()],
        };
        match shell.process_proposal(request) {
            Ok(_) => panic!("Test failed"),
            Err(TestError::RejectProposal(response)) => {
                assert_eq!(
                    response[0].result.code,
                    u32::from(ResultCode::ExpiredTx)
                );
            }
        }
    }

    /// Test that an expired decrypted transaction is marked as rejected but
    /// still allows the block to be accepted
    #[test]
    fn test_expired_decrypted() {
        let (mut shell, _recv, _, _) = test_utils::setup();
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
        wrapper.header.expiration = Some(DateTimeUtc::default());
        wrapper.set_code(Code::new("wasm_code".as_bytes().to_owned(), None));
        wrapper.set_data(Data::new("transaction data".as_bytes().to_owned()));
        wrapper.add_section(Section::Signature(Signature::new(
            wrapper.sechashes(),
            [(0, keypair)].into_iter().collect(),
            None,
        )));

        shell.enqueue_tx(wrapper.clone(), GAS_LIMIT_MULTIPLIER.into());

        let decrypted =
            wrapper.update_header(TxType::Decrypted(DecryptedTx::Decrypted));

        // Run validation
        let request = ProcessProposal {
            txs: vec![decrypted.to_bytes()],
        };
        match shell.process_proposal(request) {
            Ok(txs) => {
                assert_eq!(txs.len(), 1);
                assert_eq!(
                    txs[0].result.code,
                    u32::from(ResultCode::ExpiredDecryptedTx)
                );
            }
            Err(_) => panic!("Test failed"),
        }
    }

    /// Check that a tx requiring more gas than the block limit causes a block
    /// rejection
    #[test]
    fn test_exceeding_max_block_gas_tx() {
        let (shell, _recv, _, _) = test_utils::setup();

        let block_gas_limit =
            namada::parameters::get_max_block_gas(&shell.wl_storage).unwrap();
        let keypair = super::test_utils::gen_keypair();

        let mut wrapper =
            Tx::from_type(TxType::Wrapper(Box::new(WrapperTx::new(
                Fee {
                    amount_per_gas_unit: DenominatedAmount::native(100.into()),
                    token: shell.wl_storage.storage.native_token.clone(),
                },
                keypair.ref_to(),
                Epoch(0),
                (block_gas_limit + 1).into(),
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

        // Run validation
        let request = ProcessProposal {
            txs: vec![wrapper.to_bytes()],
        };
        match shell.process_proposal(request) {
            Ok(_) => panic!("Test failed"),
            Err(TestError::RejectProposal(response)) => {
                assert_eq!(
                    response[0].result.code,
                    u32::from(ResultCode::AllocationError)
                );
            }
        }
    }

    // Check that a wrapper requiring more gas than its limit causes a block
    // rejection
    #[test]
    fn test_exceeding_gas_limit_wrapper() {
        let (shell, _recv, _, _) = test_utils::setup();
        let keypair = super::test_utils::gen_keypair();

        let mut wrapper =
            Tx::from_type(TxType::Wrapper(Box::new(WrapperTx::new(
                Fee {
                    amount_per_gas_unit: DenominatedAmount::native(100.into()),
                    token: shell.wl_storage.storage.native_token.clone(),
                },
                keypair.ref_to(),
                Epoch(0),
                0.into(),
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

        // Run validation
        let request = ProcessProposal {
            txs: vec![wrapper.to_bytes()],
        };
        match shell.process_proposal(request) {
            Ok(_) => panic!("Test failed"),
            Err(TestError::RejectProposal(response)) => {
                assert_eq!(
                    response[0].result.code,
                    u32::from(ResultCode::TxGasLimit)
                );
            }
        }
    }

    // Check that a wrapper using a non-whitelisted token for fee payment causes
    // a block rejection
    #[test]
    fn test_fee_non_whitelisted_token() {
        let (shell, _recv, _, _) = test_utils::setup();

        let apfel_denom = read_denom(&shell.wl_storage, &address::apfel())
            .expect("unable to read denomination from storage")
            .expect("unable to find denomination of apfels");

        let mut wrapper =
            Tx::from_type(TxType::Wrapper(Box::new(WrapperTx::new(
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
            ))));
        wrapper.header.chain_id = shell.chain_id.clone();
        wrapper.set_code(Code::new("wasm_code".as_bytes().to_owned(), None));
        wrapper.set_data(Data::new("transaction data".as_bytes().to_owned()));
        wrapper.add_section(Section::Signature(Signature::new(
            wrapper.sechashes(),
            [(0, crate::wallet::defaults::albert_keypair())]
                .into_iter()
                .collect(),
            None,
        )));

        // Run validation
        let request = ProcessProposal {
            txs: vec![wrapper.to_bytes()],
        };
        match shell.process_proposal(request) {
            Ok(_) => panic!("Test failed"),
            Err(TestError::RejectProposal(response)) => {
                assert_eq!(
                    response[0].result.code,
                    u32::from(ResultCode::FeeError)
                );
            }
        }
    }

    // Check that a wrapper setting a fee amount lower than the minimum required
    // causes a block rejection
    #[test]
    fn test_fee_wrong_minimum_amount() {
        let (shell, _recv, _, _) = test_utils::setup();

        let mut wrapper =
            Tx::from_type(TxType::Wrapper(Box::new(WrapperTx::new(
                Fee {
                    amount_per_gas_unit: DenominatedAmount::native(0.into()),
                    token: shell.wl_storage.storage.native_token.clone(),
                },
                crate::wallet::defaults::albert_keypair().ref_to(),
                Epoch(0),
                GAS_LIMIT_MULTIPLIER.into(),
                None,
            ))));
        wrapper.header.chain_id = shell.chain_id.clone();
        wrapper.set_code(Code::new("wasm code".as_bytes().to_owned(), None));
        wrapper.set_data(Data::new("transaction data".as_bytes().to_owned()));
        wrapper.add_section(Section::Signature(Signature::new(
            wrapper.sechashes(),
            [(0, crate::wallet::defaults::albert_keypair())]
                .into_iter()
                .collect(),
            None,
        )));

        // Run validation
        let request = ProcessProposal {
            txs: vec![wrapper.to_bytes()],
        };
        match shell.process_proposal(request) {
            Ok(_) => panic!("Test failed"),
            Err(TestError::RejectProposal(response)) => {
                assert_eq!(
                    response[0].result.code,
                    u32::from(ResultCode::FeeError)
                );
            }
        }
    }

    // Check that a wrapper transactions whose fees cannot be paid causes a
    // block rejection
    #[test]
    fn test_insufficient_balance_for_fee() {
        let (shell, _recv, _, _) = test_utils::setup();

        let mut wrapper =
            Tx::from_type(TxType::Wrapper(Box::new(WrapperTx::new(
                Fee {
                    amount_per_gas_unit: DenominatedAmount::native(
                        1_000_000_000.into(),
                    ),
                    token: shell.wl_storage.storage.native_token.clone(),
                },
                crate::wallet::defaults::albert_keypair().ref_to(),
                Epoch(0),
                150_000.into(),
                None,
            ))));
        wrapper.header.chain_id = shell.chain_id.clone();
        wrapper.set_code(Code::new("wasm code".as_bytes().to_owned(), None));
        wrapper.set_data(Data::new("transaction data".as_bytes().to_owned()));
        wrapper.add_section(Section::Signature(Signature::new(
            wrapper.sechashes(),
            [(0, crate::wallet::defaults::albert_keypair())]
                .into_iter()
                .collect(),
            None,
        )));

        // Run validation
        let request = ProcessProposal {
            txs: vec![wrapper.to_bytes()],
        };
        match shell.process_proposal(request) {
            Ok(_) => panic!("Test failed"),
            Err(TestError::RejectProposal(response)) => {
                assert_eq!(
                    response[0].result.code,
                    u32::from(ResultCode::FeeError)
                );
            }
        }
    }

    // Check that a fee overflow in the wrapper transaction causes a block
    // rejection
    #[test]
    fn test_wrapper_fee_overflow() {
        let (shell, _recv, _, _) = test_utils::setup();

        let mut wrapper =
            Tx::from_type(TxType::Wrapper(Box::new(WrapperTx::new(
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
            ))));
        wrapper.header.chain_id = shell.chain_id.clone();
        wrapper.set_code(Code::new("wasm code".as_bytes().to_owned(), None));
        wrapper.set_data(Data::new("transaction data".as_bytes().to_owned()));
        wrapper.add_section(Section::Signature(Signature::new(
            wrapper.sechashes(),
            [(0, crate::wallet::defaults::albert_keypair())]
                .into_iter()
                .collect(),
            None,
        )));

        // Run validation
        let request = ProcessProposal {
            txs: vec![wrapper.to_bytes()],
        };
        match shell.process_proposal(request) {
            Ok(_) => panic!("Test failed"),
            Err(TestError::RejectProposal(response)) => {
                assert_eq!(
                    response[0].result.code,
                    u32::from(ResultCode::FeeError)
                );
            }
        }
    }

    /// Test if we reject wrapper txs when they shouldn't be included in blocks.
    ///
    /// Currently, the conditions to reject wrapper
    /// txs are simply to check if we are at the 2nd
    /// or 3rd height offset within an epoch.
    #[test]
    fn test_include_only_protocol_txs() {
        let (mut shell, _recv, _, _) = test_utils::setup_at_height(1u64);
        let keypair = gen_keypair();
        let mut wrapper =
            Tx::from_type(TxType::Wrapper(Box::new(WrapperTx::new(
                Fee {
                    amount_per_gas_unit: DenominatedAmount::native(0.into()),
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
        let wrapper = wrapper.to_bytes();
        for height in [1u64, 2] {
            if let Some(b) = shell.wl_storage.storage.last_block.as_mut() {
                b.height = height.into();
            }
            let response = {
                let request = ProcessProposal {
                    txs: vec![wrapper.clone()],
                };
                if let Err(TestError::RejectProposal(mut resp)) =
                    shell.process_proposal(request)
                {
                    assert_eq!(resp.len(), 1);
                    resp.remove(0)
                } else {
                    panic!("Test failed")
                }
            };
            assert_eq!(
                response.result.code,
                u32::from(ResultCode::AllocationError)
            );
            assert_eq!(
                response.result.info,
                String::from(
                    "Wrapper txs not allowed at the current block height"
                ),
            );
        }
    }

    /// Test max tx bytes parameter in ProcessProposal
    #[test]
    fn test_max_tx_bytes_process_proposal() {
        use namada::ledger::parameters::storage::get_max_tx_bytes_key;
        let (shell, _recv, _, _) = test_utils::setup_at_height(3u64);

        let max_tx_bytes: u32 = {
            let key = get_max_tx_bytes_key();
            shell
                .wl_storage
                .read(&key)
                .expect("Failed to read from storage")
                .expect("Max tx bytes should have been written to storage")
        };

        let new_tx = |size: u32| {
            let keypair = super::test_utils::gen_keypair();
            let mut wrapper =
                Tx::from_type(TxType::Wrapper(Box::new(WrapperTx::new(
                    Fee {
                        amount_per_gas_unit: DenominatedAmount::native(
                            100.into(),
                        ),
                        token: shell.wl_storage.storage.native_token.clone(),
                    },
                    keypair.ref_to(),
                    Epoch(0),
                    GAS_LIMIT_MULTIPLIER.into(),
                    None,
                ))));
            wrapper.header.chain_id = shell.chain_id.clone();
            wrapper
                .set_code(Code::new("wasm_code".as_bytes().to_owned(), None));
            wrapper.set_data(Data::new(vec![0; size as usize]));
            wrapper.add_section(Section::Signature(Signature::new(
                wrapper.sechashes(),
                [(0, keypair)].into_iter().collect(),
                None,
            )));
            wrapper
        };

        let request = ProcessProposal {
            txs: vec![new_tx(max_tx_bytes + 1).to_bytes()],
        };
        match shell.process_proposal(request) {
            Ok(_) => panic!("Test failed"),
            Err(TestError::RejectProposal(response)) => {
                assert_eq!(
                    response[0].result.code,
                    u32::from(ResultCode::TooLarge)
                );
            }
        }

        let request = ProcessProposal {
            txs: vec![new_tx(0).to_bytes()],
        };
        match shell.process_proposal(request) {
            Ok(_) => panic!("Test failed"),
            Err(TestError::RejectProposal(response)) => {
                assert!(
                    response[0].result.code != u32::from(ResultCode::TooLarge)
                );
            }
        }
    }

    /// Test that Ethereum events with outdated nonces are
    /// not validated by `ProcessProposal`.
    #[test]
    fn test_outdated_nonce_process_proposal() {
        use namada::types::storage::InnerEthEventsQueue;

        const LAST_HEIGHT: BlockHeight = BlockHeight(3);

        let (mut shell, _recv, _, _) = test_utils::setup_at_height(LAST_HEIGHT);
        shell
            .wl_storage
            .storage
            .eth_events_queue
            // sent transfers to namada nonce to 5
            .transfers_to_namada = InnerEthEventsQueue::new_at(5.into());

        let (protocol_key, _) = wallet::defaults::validator_keys();

        // only bad events
        {
            let ethereum_event = EthereumEvent::TransfersToNamada {
                // outdated nonce (3 < 5)
                nonce: 3u64.into(),
                transfers: vec![],
            };
            let ext = {
                let ext = ethereum_events::Vext {
                    validator_addr: wallet::defaults::validator_address(),
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
            let req = ProcessProposal { txs: vec![tx] };
            let rsp = shell.process_proposal(req);
            assert!(rsp.is_err());
        }

        // at least one good event
        {
            let e1 = EthereumEvent::TransfersToNamada {
                nonce: 3u64.into(),
                transfers: vec![],
            };
            let e2 = EthereumEvent::TransfersToNamada {
                nonce: 5u64.into(),
                transfers: vec![],
            };
            let ext = {
                let ext = ethereum_events::Vext {
                    validator_addr: wallet::defaults::validator_address(),
                    block_height: LAST_HEIGHT,
                    ethereum_events: vec![e1, e2],
                }
                .sign(&protocol_key);
                assert!(ext.verify(&protocol_key.ref_to()).is_ok());
                ext
            };
            let tx = EthereumTxData::EthEventsVext(ext.into())
                .sign(&protocol_key, shell.chain_id.clone())
                .to_bytes();
            let req = ProcessProposal { txs: vec![tx] };
            let rsp = shell.process_proposal(req);
            assert!(rsp.is_ok());
        }
    }
}
