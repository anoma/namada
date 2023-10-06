//! Implementation of the ['VerifyHeader`], [`ProcessProposal`],
//! and [`RevertProposal`] ABCI++ methods for the Shell

use data_encoding::HEXUPPER;
use namada::core::hints;
use namada::core::ledger::storage::WlStorage;
use namada::ledger::eth_bridge::{EthBridgeQueries, SendValsetUpd};
use namada::ledger::pos::PosQueries;
use namada::ledger::protocol::get_fee_unshielding_transaction;
use namada::ledger::storage::TempWlStorage;
use namada::proof_of_stake::find_validator_by_raw_hash;
use namada::types::internal::TxInQueue;
use namada::types::transaction::protocol::{
    ethereum_tx_data_variants, ProtocolTxType,
};
#[cfg(feature = "abcipp")]
use namada::types::voting_power::FractionalVotingPower;

use super::block_alloc::{BlockSpace, EncryptedTxsBins};
use super::*;
use crate::facade::tendermint_proto::abci::response_process_proposal::ProposalStatus;
use crate::facade::tendermint_proto::abci::RequestProcessProposal;
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
    #[cfg(feature = "abcipp")]
    pub digests: DigestCounters,
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
            namada::core::ledger::gas::get_max_block_gas(wl_storage).unwrap();
        let encrypted_txs_bin =
            EncryptedTxsBins::new(max_proposal_bytes, max_block_gas);
        let txs_bin = TxBin::init(max_proposal_bytes);
        Self {
            #[cfg(feature = "abcipp")]
            digests: DigestCounters::default(),
            decrypted_queue_has_remaining_txs: false,
            has_decrypted_txs: false,
            encrypted_txs_bins: encrypted_txs_bin,
            txs_bin,
        }
    }
}

/// Contains stateful data about the number of vote extension
/// digests found as protocol transactions in a proposed block.
#[derive(Default)]
#[cfg(feature = "abcipp")]
pub struct DigestCounters {
    /// The number of Ethereum events vote extensions found thus far.
    pub eth_ev_digest_num: usize,
    /// The number of Bridge pool root vote extensions found thus far.
    pub bridge_pool_roots: usize,
    /// The number of validator set update vote extensions found thus far.
    pub valset_upd_digest_num: usize,
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
    #[cfg(feature = "abcipp")]
    pub fn process_proposal(
        &self,
        req: RequestProcessProposal,
    ) -> ProcessProposal {
        let tm_raw_hash_string = tm_raw_hash_to_string(&req.proposer_address);
        let block_proposer =
            find_validator_by_raw_hash(&self.wl_storage, tm_raw_hash_string)
                .unwrap()
                .expect(
                    "Unable to find native validator address of block \
                     proposer from tendermint raw hash",
                );
        tracing::info!(
            proposer = ?HEXUPPER.encode(&req.proposer_address),
            height = req.height,
            hash = ?HEXUPPER.encode(&req.hash),
            n_txs = req.txs.len(),
            "Received block proposal",
        );
        let (tx_results, metadata) =
            self.process_txs(&req.txs, self.get_block_timestamp(req.time));

        // We should not have more than one `ethereum_events::VextDigest` in
        // a proposal from some round's leader.
        let invalid_num_of_eth_ev_digests =
            !self.has_proper_eth_events_num(&metadata);
        if invalid_num_of_eth_ev_digests {
            tracing::warn!(
                proposer = ?HEXUPPER.encode(&req.proposer_address),
                height = req.height,
                hash = ?HEXUPPER.encode(&req.hash),
                eth_ev_digest_num = metadata.digests.eth_ev_digest_num,
                "Found invalid number of Ethereum events vote extension digests, proposed block \
                 will be rejected"
            );
        }

        // We should not have more than one `bridge_pool_roots::VextDigest` in
        // a proposal from some round's leader.
        let invalid_num_of_bp_root_digests =
            !self.has_proper_bp_roots_num(&metadata);
        if invalid_num_of_bp_root_digests {
            tracing::warn!(
                proposer = ?HEXUPPER.encode(&req.proposer_address),
                height = req.height,
                hash = ?HEXUPPER.encode(&req.hash),
                eth_ev_digest_num = metadata.digests.bridge_pool_roots,
                "Found invalid number of Ethereum bridge pool root vote extension \
                 digests, proposed block will be rejected."
            );
        }

        let invalid_num_of_valset_upd_digests =
            !self.has_proper_valset_upd_num(&metadata);
        if invalid_num_of_valset_upd_digests {
            tracing::warn!(
                proposer = ?HEXUPPER.encode(&req.proposer_address),
                height = req.height,
                hash = ?HEXUPPER.encode(&req.hash),
                valset_upd_digest_num = metadata.digests.valset_upd_digest_num,
                "Found invalid number of validator set update vote extension digests, proposed block \
                 will be rejected"
            );
        }

        // Erroneous transactions were detected when processing
        // the leader's proposal. We allow txs that do not
        // deserialize properly, that have invalid signatures
        // and that have invalid wasm code to reach FinalizeBlock.
        let invalid_txs = tx_results.iter().any(|res| {
            let error = ErrorCodes::from_u32(res.code).expect(
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
            metadata.decrypted_queue_has_remaining_txs;
        if has_remaining_decrypted_txs {
            tracing::warn!(
                proposer = ?HEXUPPER.encode(&req.proposer_address),
                height = req.height,
                hash = ?HEXUPPER.encode(&req.hash),
                "Not all decrypted txs from the previous height were included in
                 the proposal, the block will be rejected"
            );
        }

        let will_reject_proposal = invalid_num_of_eth_ev_digests
            || invalid_num_of_bp_root_digests
            || invalid_num_of_valset_upd_digests
            || invalid_txs
            || has_remaining_decrypted_txs;

        let status = if will_reject_proposal {
            ProposalStatus::Reject
        } else {
            ProposalStatus::Accept
        };

        ProcessProposal {
            status: status as i32,
            tx_results,
        }
    }

    /// Check all the txs in a block. Some txs may be incorrect,
    /// but we only reject the entire block if the order of the
    /// included txs violates the order decided upon in the previous
    /// block.
    #[cfg(not(feature = "abcipp"))]
    pub fn process_proposal(
        &self,
        req: RequestProcessProposal,
    ) -> ProcessProposal {
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
            let error = ErrorCodes::from_u32(res.code).expect(
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

        let status = if will_reject_proposal {
            ProposalStatus::Reject
        } else {
            ProposalStatus::Accept
        };

        ProcessProposal {
            status: status as i32,
            tx_results,
        }
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
                let error_code = ErrorCodes::from_u32(result.code).unwrap();
                if let ErrorCodes::Ok = error_code {
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
        I: Iterator<Item = Option<namada::types::token::Amount>>,
    {
        #[cfg(feature = "abcipp")]
        let mut voting_power = FractionalVotingPower::default();
        #[cfg(feature = "abcipp")]
        let total_power = {
            let epoch = self
                .wl_storage
                .pos_queries()
                .get_epoch(self.wl_storage.storage.get_last_block_height());
            u64::from(
                self.wl_storage.pos_queries().get_total_voting_power(epoch),
            )
        };

        if vote_extensions.all(|maybe_ext| {
            maybe_ext
                .map(|_power| {
                    #[cfg(feature = "abcipp")]
                    {
                        voting_power += FractionalVotingPower::new(
                            u64::from(_power),
                            total_power,
                        )
                        .expect(
                            "The voting power we obtain from storage should \
                             always be valid",
                        );
                    }
                })
                .is_some()
        }) {
            #[cfg(feature = "abcipp")]
            if voting_power > FractionalVotingPower::TWO_THIRDS {
                TxResult {
                    code: ErrorCodes::Ok.into(),
                    info: "Process proposal accepted this transaction".into(),
                }
            } else {
                TxResult {
                    code: ErrorCodes::InvalidVoteExtension.into(),
                    info: "Process proposal rejected this proposal because \
                           the backing stake of the vote extensions published \
                           in the proposal was insufficient"
                        .into(),
                }
            }

            #[cfg(not(feature = "abcipp"))]
            {
                TxResult {
                    code: ErrorCodes::Ok.into(),
                    info: "Process proposal accepted this transaction".into(),
                }
            }
        } else {
            TxResult {
                code: ErrorCodes::InvalidVoteExtension.into(),
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
        // try to allocate space for this tx
        if let Err(e) = metadata.txs_bin.try_dump(tx_bytes) {
            return TxResult {
                code: ErrorCodes::AllocationError.into(),
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
                    code: ErrorCodes::InvalidTx.into(),
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
                        code: ErrorCodes::InvalidSig.into(),
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

        // TODO: This should not be hardcoded
        let privkey = <EllipticCurve as PairingEngine>::G2Affine::prime_subgroup_generator();

        if let Err(err) = tx.validate_tx() {
            return TxResult {
                code: ErrorCodes::InvalidSig.into(),
                info: err.to_string(),
            };
        }
        match tx.header().tx_type {
            // If it is a raw transaction, we do no further validation
            TxType::Raw => TxResult {
                code: ErrorCodes::InvalidTx.into(),
                info: "Transaction rejected: Non-encrypted transactions are \
                       not supported"
                    .into(),
            },
            TxType::Protocol(protocol_tx) => {
                // Tx chain id
                if tx_chain_id != self.chain_id {
                    return TxResult {
                        code: ErrorCodes::InvalidChainId.into(),
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
                            code: ErrorCodes::ExpiredTx.into(),
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
                                    ext,
                                    self.wl_storage
                                        .storage
                                        .get_last_block_height(),
                                )
                                .map(|_| TxResult {
                                    code: ErrorCodes::Ok.into(),
                                    info: "Process Proposal accepted this \
                                           transaction"
                                        .into(),
                                })
                                .map_err(|err| err.to_string())
                            })
                            .unwrap_or_else(|err| TxResult {
                                code: ErrorCodes::InvalidVoteExtension.into(),
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
                                    ext,
                                    self.wl_storage
                                        .storage
                                        .get_last_block_height(),
                                )
                                .map(|_| TxResult {
                                    code: ErrorCodes::Ok.into(),
                                    info: "Process Proposal accepted this \
                                           transaction"
                                        .into(),
                                })
                                .map_err(|err| err.to_string())
                            })
                            .unwrap_or_else(|err| TxResult {
                                code: ErrorCodes::InvalidVoteExtension.into(),
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
                                code: ErrorCodes::Ok.into(),
                                info: "Process Proposal accepted this \
                                       transaction"
                                    .into(),
                            })
                            .map_err(|err| err.to_string())
                        })
                        .unwrap_or_else(|err| {
                            TxResult {
                                code: ErrorCodes::InvalidVoteExtension.into(),
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
                        #[cfg(feature = "abcipp")]
                        {
                            metadata.digests.eth_ev_digest_num += 1;
                        }
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
                            .unwrap();
                        #[cfg(feature = "abcipp")]
                        {
                            metadata.digests.bridge_pool_roots += 1;
                        }
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
                                code: ErrorCodes::InvalidVoteExtension.into(),
                                info: "Process proposal rejected a validator \
                                       set update vote extension issued at an \
                                       invalid block height"
                                    .into(),
                            };
                        }
                        #[cfg(feature = "abcipp")]
                        {
                            metadata.digests.valset_upd_digest_num += 1;
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
                    _ => TxResult {
                        code: ErrorCodes::InvalidTx.into(),
                        info: "Unsupported protocol transaction type".into(),
                    },
                }
            }
            TxType::Decrypted(tx_header) => {
                metadata.has_decrypted_txs = true;
                match tx_queue_iter.next() {
                    Some(wrapper) => {
                        let mut inner_tx = tx.clone();
                        inner_tx.update_header(TxType::Raw);
                        if wrapper
                            .tx
                            .clone()
                            .update_header(TxType::Raw)
                            .header_hash()
                            != inner_tx.header_hash()
                        {
                            TxResult {
                                code: ErrorCodes::InvalidOrder.into(),
                                info: "Process proposal rejected a decrypted \
                                       transaction that violated the tx order \
                                       determined in the previous block"
                                    .into(),
                            }
                        } else if verify_decrypted_correctly(
                            &tx_header,
                            wrapper.tx.clone(),
                            privkey,
                        ) {
                            // Tx chain id
                            if wrapper.tx.header.chain_id != self.chain_id {
                                return TxResult {
                                    code: ErrorCodes::InvalidDecryptedChainId
                                        .into(),
                                    info: format!(
                                        "Decrypted tx carries a wrong chain \
                                         id: expected {}, found {}",
                                        self.chain_id,
                                        wrapper.tx.header.chain_id
                                    ),
                                };
                            }

                            // Tx expiration
                            if let Some(exp) = wrapper.tx.header.expiration {
                                if block_time > exp {
                                    return TxResult {
                                        code: ErrorCodes::ExpiredDecryptedTx
                                            .into(),
                                        info: format!(
                                            "Decrypted tx expired at {:#?}, \
                                             block time: {:#?}",
                                            exp, block_time
                                        ),
                                    };
                                }
                            }

                            TxResult {
                                code: ErrorCodes::Ok.into(),
                                info: "Process Proposal accepted this \
                                       tranasction"
                                    .into(),
                            }
                        } else {
                            TxResult {
                                code: ErrorCodes::InvalidTx.into(),
                                info: "The encrypted payload of tx was \
                                       incorrectly marked as un-decryptable"
                                    .into(),
                            }
                        }
                    }
                    None => TxResult {
                        code: ErrorCodes::ExtraTxs.into(),
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
                if tx_gas_meter.add_tx_size_gas(tx_bytes).is_err() {
                    // Account for the tx's resources even in case of an error.
                    // Ignore any allocation error
                    let _ = metadata
                        .encrypted_txs_bins
                        .try_dump(tx_bytes, u64::from(wrapper.gas_limit));

                    return TxResult {
                        code: ErrorCodes::TxGasLimit.into(),
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
                        code: ErrorCodes::AllocationError.into(),
                        info: e,
                    };
                }
                // decrypted txs shouldn't show up before wrapper txs
                if metadata.has_decrypted_txs {
                    return TxResult {
                        code: ErrorCodes::InvalidTx.into(),
                        info: "Decrypted txs should not be proposed before \
                               wrapper txs"
                            .into(),
                    };
                }
                if hints::unlikely(self.encrypted_txs_not_allowed()) {
                    return TxResult {
                        code: ErrorCodes::AllocationError.into(),
                        info: "Wrapper txs not allowed at the current block \
                               height"
                            .into(),
                    };
                }

                // ChainId check
                if tx_chain_id != self.chain_id {
                    return TxResult {
                        code: ErrorCodes::InvalidChainId.into(),
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
                            code: ErrorCodes::ExpiredTx.into(),
                            info: format!(
                                "Tx expired at {:#?}, block time: {:#?}",
                                exp, block_time
                            ),
                        };
                    }
                }

                // validate the ciphertext via Ferveo
                if !tx.validate_ciphertext() {
                    TxResult {
                        code: ErrorCodes::InvalidTx.into(),
                        info: format!(
                            "The ciphertext of the wrapped tx {} is invalid",
                            hash_tx(tx_bytes)
                        ),
                    }
                } else {
                    // Replay protection checks
                    if let Err(e) = self.replay_protection_checks(
                        &tx,
                        tx_bytes,
                        temp_wl_storage,
                    ) {
                        return TxResult {
                            code: ErrorCodes::ReplayTx.into(),
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
                    ) {
                        Ok(()) => TxResult {
                            code: ErrorCodes::Ok.into(),
                            info: "Process proposal accepted this transaction"
                                .into(),
                        },
                        Err(e) => TxResult {
                            code: ErrorCodes::FeeError.into(),
                            info: e.to_string(),
                        },
                    }
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

    /// Checks if we have found the correct number of Ethereum events
    /// vote extensions in [`DigestCounters`].
    #[cfg(feature = "abcipp")]
    fn has_proper_eth_events_num(&self, meta: &ValidationMeta) -> bool {
        if self.wl_storage.ethbridge_queries().is_bridge_active() {
            meta.digests.eth_ev_digest_num
                == usize::from(self.wl_storage.storage.last_block.is_some())
        } else {
            meta.digests.eth_ev_digest_num == 0
        }
    }

    /// Checks if we have found the correct number of Ethereum bridge pool
    /// root vote extensions in [`DigestCounters`].
    #[cfg(feature = "abcipp")]
    fn has_proper_bp_roots_num(&self, meta: &ValidationMeta) -> bool {
        if self.wl_storage.ethbridge_queries().is_bridge_active() {
            meta.digests.bridge_pool_roots
                == usize::from(self.wl_storage.storage.last_block.is_some())
        } else {
            meta.digests.bridge_pool_roots == 0
        }
    }

    /// Checks if we have found the correct number of validator set update
    /// vote extensions in [`DigestCounters`].
    #[cfg(feature = "abcipp")]
    fn has_proper_valset_upd_num(&self, meta: &ValidationMeta) -> bool {
        // TODO: check if this logic is correct for ABCI++
        self.wl_storage
            .ethbridge_queries()
            .is_bridge_active()
            .then(|| {
                if self
                    .wl_storage
                    .ethbridge_queries()
                    .must_send_valset_upd(SendValsetUpd::AtPrevHeight)
                {
                    meta.digests.valset_upd_digest_num
                        == usize::from(
                            self.wl_storage.storage.last_block.is_some(),
                        )
                } else {
                    true
                }
            })
            .unwrap_or(meta.digests.valset_upd_digest_num == 0)
    }

    /// Checks if it is not possible to include encrypted txs at the current
    /// block height.
    pub(super) fn encrypted_txs_not_allowed(&self) -> bool {
        let pos_queries = self.wl_storage.pos_queries();
        let is_2nd_height_off = pos_queries.is_deciding_offset_within_epoch(1);
        let is_3rd_height_off = pos_queries.is_deciding_offset_within_epoch(2);
        is_2nd_height_off || is_3rd_height_off
    }
}

/// We test the failure cases of [`process_proposal`]. The happy flows
/// are covered by the e2e tests.
#[cfg(test)]
mod test_process_proposal {
    #[cfg(feature = "abcipp")]
    use std::collections::HashMap;

    #[cfg(feature = "abcipp")]
    use assert_matches::assert_matches;
    use namada::ledger::replay_protection;
    use namada::ledger::storage_api::StorageWrite;
    use namada::proto::{
        Code, Data, Section, SignableEthMessage, Signature, Signed,
    };
    use namada::types::ethereum_events::EthereumEvent;
    use namada::types::hash::Hash;
    use namada::types::key::*;
    use namada::types::storage::Epoch;
    use namada::types::time::DateTimeUtc;
    use namada::types::token;
    use namada::types::token::Amount;
    use namada::types::transaction::protocol::EthereumTxData;
    use namada::types::transaction::{Fee, WrapperTx};
    #[cfg(feature = "abcipp")]
    use namada::types::vote_extensions::bridge_pool_roots::MultiSignedVext;
    #[cfg(feature = "abcipp")]
    use namada::types::vote_extensions::ethereum_events::MultiSignedEthEvent;
    use namada::types::vote_extensions::{bridge_pool_roots, ethereum_events};

    use super::*;
    use crate::node::ledger::shell::test_utils::{
        self, deactivate_bridge, gen_keypair, get_bp_bytes_to_sign,
        ProcessProposal, TestError, TestShell,
    };
    use crate::node::ledger::shims::abcipp_shim_types::shim::request::ProcessedTx;
    #[cfg(feature = "abcipp")]
    use crate::node::ledger::shims::abcipp_shim_types::shim::TxBytes;
    use crate::wallet;

    const GAS_LIMIT_MULTIPLIER: u64 = 100_000;

    #[cfg(feature = "abcipp")]
    fn get_empty_eth_ev_digest(shell: &TestShell) -> TxBytes {
        let protocol_key = shell.mode.get_protocol_key().expect("Test failed");
        let addr = shell
            .mode
            .get_validator_address()
            .expect("Test failed")
            .clone();
        let ext = ethereum_events::Vext::empty(
            shell.wl_storage.storage.get_last_block_height(),
            addr.clone(),
        )
        .sign(protocol_key);
        EthereumTxData::EthereumEvents(ethereum_events::VextDigest {
            signatures: {
                let mut s = HashMap::new();
                s.insert(
                    (addr, shell.wl_storage.storage.get_last_block_height()),
                    ext.sig,
                );
                s
            },
            events: vec![],
        })
        .sign(protocol_key, shell.chain_id.clone())
        .to_bytes()
    }

    /// Craft the tx bytes for the block proposal digest containing
    /// all the Bridge pool root vote extensions.
    #[cfg(feature = "abcipp")]
    fn get_bp_roots_vext(shell: &TestShell) -> Vec<u8> {
        let bp_root = shell.extend_vote_with_bp_roots().expect("Test failed");
        let tx = shell
            .compress_bridge_pool_roots(vec![bp_root])
            .expect("Test failed");
        EthereumTxData::BridgePool(tx)
            .sign(
                shell.mode.get_protocol_key().expect("Test failed"),
                shell.chain_id.clone(),
            )
            .to_bytes()
    }

    /// Test that if a proposal contains more than one
    /// `ethereum_events::VextDigest`, we reject it.
    #[test]
    #[cfg(feature = "abcipp")]
    fn test_more_than_one_vext_digest_rejected() {
        const LAST_HEIGHT: BlockHeight = BlockHeight(2);
        let (shell, _recv, _, _) = test_utils::setup_at_height(LAST_HEIGHT);
        let (protocol_key, _, _) = wallet::defaults::validator_keys();
        let vote_extension_digest = {
            let validator_addr = wallet::defaults::validator_address();
            let signed_vote_extension = {
                let ext = ethereum_events::Vext::empty(
                    LAST_HEIGHT,
                    validator_addr.clone(),
                )
                .sign(&protocol_key);
                assert!(ext.verify(&protocol_key.ref_to()).is_ok());
                ext
            };
            // Ethereum events digest with no observed events
            ethereum_events::VextDigest {
                signatures: {
                    let mut s = HashMap::new();
                    s.insert(
                        (
                            validator_addr,
                            shell.wl_storage.storage.get_last_block_height(),
                        ),
                        signed_vote_extension.sig,
                    );
                    s
                },
                events: vec![],
            }
        };
        let tx = EthereumTxData::EthereumEvents(vote_extension_digest)
            .sign(&protocol_key, shell.chain_id.clone())
            .to_bytes();
        let request = ProcessProposal {
            txs: vec![tx.clone(), tx],
        };
        let results = shell.process_proposal(request);
        assert_matches!(
            results, Err(TestError::RejectProposal(s)) if s.len() == 2
        );
    }

    /// Test that if more than one bridge pool root vote extension
    /// is added to a block, we reject the proposal.
    #[cfg(feature = "abcipp")]
    #[test]
    fn check_multiple_bp_root_vexts_rejected() {
        let (mut shell, _recv, _, _) = test_utils::setup_at_height(3u64);
        let vext = shell.extend_vote_with_bp_roots().expect("Test failed");
        let tx =
            EthereumTxData::BridgePool(MultiSignedVext(HashSet::from([vext])))
                .sign(
                    shell.mode.get_protocol_key().expect("Test failed."),
                    shell.chain_id.clone(),
                )
                .to_bytes();
        assert!(
            shell
                .process_proposal(ProcessProposal {
                    txs: vec![tx.clone(), tx]
                })
                .is_err()
        );
    }

    #[cfg(feature = "abcipp")]
    fn check_rejected_eth_events_digest(
        shell: &mut TestShell,
        vote_extension_digest: ethereum_events::VextDigest,
        protocol_key: common::SecretKey,
    ) {
        let tx = EthereumTxData::EthereumEvents(vote_extension_digest)
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
            u32::from(ErrorCodes::InvalidVoteExtension)
        );
    }

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
        let tx = EthereumTxData::EthEventsVext(ext)
            .sign(protocol_key, shell.chain_id.clone())
            .to_bytes();
        let request = ProcessProposal { txs: vec![tx] };

        #[cfg(not(feature = "abcipp"))]
        {
            let [resp]: [ProcessedTx; 1] = shell
                .process_proposal(request.clone())
                .expect("Test failed")
                .try_into()
                .expect("Test failed");
            assert_eq!(resp.result.code, u32::from(ErrorCodes::Ok));
        }
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
            u32::from(ErrorCodes::InvalidVoteExtension)
        );
    }

    /// Check that we reject an bp roots protocol tx
    /// if the bridge is not active.
    #[test]
    fn check_rejected_bp_roots_bridge_inactive() {
        let (mut shell, _a, _b, _c) = test_utils::setup_at_height(3);
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

        #[cfg(not(feature = "abcipp"))]
        {
            let [resp]: [ProcessedTx; 1] = shell
                .process_proposal(request.clone())
                .expect("Test failed")
                .try_into()
                .expect("Test failed");

            assert_eq!(resp.result.code, u32::from(ErrorCodes::Ok));
        }
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
            u32::from(ErrorCodes::InvalidVoteExtension)
        );
    }

    /// Check that we reject an bp roots vext
    /// if the bridge is not active.
    #[cfg(feature = "abcipp")]
    #[test]
    fn check_rejected_vext_bridge_inactive() {
        let (mut shell, _a, _b, _c) = test_utils::setup_at_height(3);
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
        let mut txs = vec![
            EthereumTxData::BridgePool(vote_ext.into())
                .sign(protocol_key, shell.chain_id.clone())
                .to_bytes(),
        ];

        let event = EthereumEvent::TransfersToNamada {
            nonce: 0u64.into(),
            transfers: vec![],
        };
        let ext = ethereum_events::Vext {
            validator_addr: addr.clone(),
            block_height: shell.wl_storage.storage.get_last_block_height(),
            ethereum_events: vec![event.clone()],
        }
        .sign(protocol_key);
        let vote_extension_digest = ethereum_events::VextDigest {
            signatures: {
                let mut s = HashMap::new();
                s.insert(
                    (
                        addr.clone(),
                        shell.wl_storage.storage.get_last_block_height(),
                    ),
                    ext.sig,
                );
                s
            },
            events: vec![MultiSignedEthEvent {
                event,
                signers: {
                    let mut s = BTreeSet::new();
                    s.insert((
                        addr.clone(),
                        shell.wl_storage.storage.get_last_block_height(),
                    ));
                    s
                },
            }],
        };
        txs.push(
            EthereumTxData::EthereumEvents(vote_extension_digest)
                .sign(protocol_key, shell.chain_id.clone())
                .to_bytes(),
        );
        let request = ProcessProposal { txs };
        let resps: [ProcessedTx; 2] = shell
            .process_proposal(request.clone())
            .expect("Test failed")
            .try_into()
            .expect("Test failed");
        for resp in resps {
            assert_eq!(resp.result.code, u32::from(ErrorCodes::Ok));
        }
        deactivate_bridge(&mut shell);
        if let Err(TestError::RejectProposal(resp)) =
            shell.process_proposal(request)
        {
            if let [resp1, resp2] = resp.as_slice() {
                assert_eq!(
                    resp1.result.code,
                    u32::from(ErrorCodes::InvalidVoteExtension)
                );
                assert_eq!(
                    resp2.result.code,
                    u32::from(ErrorCodes::InvalidVoteExtension)
                );
            } else {
                panic!("Test failed")
            }
        } else {
            panic!("Test failed")
        };
    }

    #[cfg(not(feature = "abcipp"))]
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
            u32::from(ErrorCodes::InvalidVoteExtension)
        );
    }

    /// Test that if a proposal contains Ethereum events with
    /// invalid validator signatures, we reject it.
    #[test]
    fn test_drop_vext_with_invalid_sigs() {
        const LAST_HEIGHT: BlockHeight = BlockHeight(2);
        let (mut shell, _recv, _, _) = test_utils::setup_at_height(LAST_HEIGHT);
        let (protocol_key, _, _) = wallet::defaults::validator_keys();
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
        #[cfg(feature = "abcipp")]
        {
            let vote_extension_digest = ethereum_events::VextDigest {
                signatures: {
                    let mut s = HashMap::new();
                    s.insert(
                        (
                            addr.clone(),
                            shell.wl_storage.storage.get_last_block_height(),
                        ),
                        ext.sig,
                    );
                    s
                },
                events: vec![MultiSignedEthEvent {
                    event,
                    signers: {
                        let mut s = BTreeSet::new();
                        s.insert((
                            addr,
                            shell.wl_storage.storage.get_last_block_height(),
                        ));
                        s
                    },
                }],
            };
            check_rejected_eth_events_digest(
                &mut shell,
                vote_extension_digest,
                protocol_key,
            );
        }
        #[cfg(not(feature = "abcipp"))]
        {
            check_rejected_eth_events(&mut shell, ext, protocol_key);
        }
    }

    /// Test that if a proposal contains Ethereum events with
    /// invalid block heights, we reject it.
    #[test]
    fn test_drop_vext_with_invalid_bheights() {
        const LAST_HEIGHT: BlockHeight = BlockHeight(3);
        #[cfg(feature = "abcipp")]
        const INVALID_HEIGHT: BlockHeight = BlockHeight(LAST_HEIGHT.0 - 1);
        #[cfg(not(feature = "abcipp"))]
        const INVALID_HEIGHT: BlockHeight = BlockHeight(LAST_HEIGHT.0 + 1);
        let (mut shell, _recv, _, _) = test_utils::setup_at_height(LAST_HEIGHT);
        let (protocol_key, _, _) = wallet::defaults::validator_keys();
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
        #[cfg(feature = "abcipp")]
        {
            let vote_extension_digest = ethereum_events::VextDigest {
                signatures: {
                    let mut s = HashMap::new();
                    s.insert((addr.clone(), INVALID_HEIGHT), ext.sig);
                    s
                },
                events: vec![MultiSignedEthEvent {
                    event,
                    signers: {
                        let mut s = BTreeSet::new();
                        s.insert((addr, INVALID_HEIGHT));
                        s
                    },
                }],
            };
            check_rejected_eth_events_digest(
                &mut shell,
                vote_extension_digest,
                protocol_key,
            );
        }
        #[cfg(not(feature = "abcipp"))]
        {
            check_rejected_eth_events(&mut shell, ext, protocol_key);
        }
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
        #[cfg(feature = "abcipp")]
        {
            let vote_extension_digest = ethereum_events::VextDigest {
                signatures: {
                    let mut s = HashMap::new();
                    s.insert((addr.clone(), LAST_HEIGHT), ext.sig);
                    s
                },
                events: vec![MultiSignedEthEvent {
                    event,
                    signers: {
                        let mut s = BTreeSet::new();
                        s.insert((addr, LAST_HEIGHT));
                        s
                    },
                }],
            };
            check_rejected_eth_events_digest(
                &mut shell,
                vote_extension_digest,
                protocol_key,
            );
        }
        #[cfg(not(feature = "abcipp"))]
        {
            check_rejected_eth_events(&mut shell, ext, protocol_key);
        }
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
                    amount_per_gas_unit: Default::default(),
                    token: shell.wl_storage.storage.native_token.clone(),
                },
                public_key,
                Epoch(0),
                GAS_LIMIT_MULTIPLIER.into(),
                None,
            ))));
        outer_tx.header.chain_id = shell.chain_id.clone();
        outer_tx.set_code(Code::new("wasm_code".as_bytes().to_owned()));
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

        assert_eq!(response.result.code, u32::from(ErrorCodes::InvalidSig));
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
                    amount_per_gas_unit: Amount::from_uint(100, 0)
                        .expect("Test failed"),
                    token: shell.wl_storage.storage.native_token.clone(),
                },
                keypair.ref_to(),
                Epoch(0),
                GAS_LIMIT_MULTIPLIER.into(),
                None,
            ))));
        outer_tx.header.chain_id = shell.chain_id.clone();
        outer_tx.set_code(Code::new("wasm_code".as_bytes().to_owned()));
        outer_tx.set_data(Data::new("transaction data".as_bytes().to_owned()));
        outer_tx.add_section(Section::Signature(Signature::new(
            outer_tx.sechashes(),
            [(0, keypair)].into_iter().collect(),
            None,
        )));
        let mut new_tx = outer_tx.clone();
        if let TxType::Wrapper(wrapper) = &mut new_tx.header.tx_type {
            // we mount a malleability attack to try and remove the fee
            wrapper.fee.amount_per_gas_unit = Default::default();
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
                    u32::from(ErrorCodes::InvalidSig)
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
        let balance_key = token::balance_key(
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
                    amount_per_gas_unit: Amount::from_uint(1, 0)
                        .expect("Test failed"),
                    token: shell.wl_storage.storage.native_token.clone(),
                },
                keypair.ref_to(),
                Epoch(0),
                GAS_LIMIT_MULTIPLIER.into(),
                None,
            ))));
        outer_tx.header.chain_id = shell.chain_id.clone();
        outer_tx.set_code(Code::new("wasm_code".as_bytes().to_owned()));
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
        assert_eq!(response.result.code, u32::from(ErrorCodes::FeeError));
        assert_eq!(
            response.result.info,
            String::from(
                "Error trying to apply a transaction: Error while processing \
                 transaction's fees: Insufficient transparent balance to pay \
                 fees"
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
        let balance_key = token::balance_key(
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
                    amount_per_gas_unit: Amount::native_whole(1_000_100),
                    token: shell.wl_storage.storage.native_token.clone(),
                },
                keypair.ref_to(),
                Epoch(0),
                GAS_LIMIT_MULTIPLIER.into(),
                None,
            ))));
        outer_tx.header.chain_id = shell.chain_id.clone();
        outer_tx.set_code(Code::new("wasm_code".as_bytes().to_owned()));
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
        assert_eq!(response.result.code, u32::from(ErrorCodes::FeeError));
        assert_eq!(
            response.result.info,
            String::from(
                "Error trying to apply a transaction: Error while processing \
                 transaction's fees: Insufficient transparent balance to pay \
                 fees"
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
                        amount_per_gas_unit: Amount::native_whole(i as u64),
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
        #[cfg(feature = "abcipp")]
        let response = {
            let request = ProcessProposal {
                txs: vec![
                    txs[0].to_bytes(),
                    txs[2].to_bytes(),
                    txs[1].to_bytes(),
                    get_empty_eth_ev_digest(&shell),
                ],
            };
            if let Err(TestError::RejectProposal(mut resp)) =
                shell.process_proposal(request)
            {
                assert_eq!(resp.len(), 4);
                resp.remove(1)
            } else {
                panic!("Test failed")
            }
        };
        #[cfg(not(feature = "abcipp"))]
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
        assert_eq!(response.result.code, u32::from(ErrorCodes::InvalidOrder));
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
                amount_per_gas_unit: Default::default(),
                token: shell.wl_storage.storage.native_token.clone(),
            },
            keypair.ref_to(),
            Epoch(0),
            GAS_LIMIT_MULTIPLIER.into(),
            None,
        ))));
        tx.header.chain_id = shell.chain_id.clone();
        tx.set_code(Code::new("wasm_code".as_bytes().to_owned()));
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
        assert_eq!(response.result.code, u32::from(ErrorCodes::InvalidTx));
        assert_eq!(
            response.result.info,
            String::from(
                "The encrypted payload of tx was incorrectly marked as \
                 un-decryptable"
            ),
        )
    }

    /// Test that a wrapper tx whose inner_tx does not have
    /// the same hash as the wrappers tx_hash field is marked
    /// undecryptable but still accepted
    #[test]
    fn test_invalid_hash_commitment() {
        let (mut shell, _recv, _, _) = test_utils::setup_at_height(3u64);
        let keypair = crate::wallet::defaults::daewon_keypair();

        let mut tx = Tx::from_type(TxType::Wrapper(Box::new(WrapperTx::new(
            Fee {
                amount_per_gas_unit: Default::default(),
                token: shell.wl_storage.storage.native_token.clone(),
            },
            keypair.ref_to(),
            Epoch(0),
            GAS_LIMIT_MULTIPLIER.into(),
            None,
        ))));
        tx.header.chain_id = shell.chain_id.clone();
        tx.set_code(Code::new("wasm_code".as_bytes().to_owned()));
        tx.set_data(Data::new("transaction data".as_bytes().to_owned()));
        tx.set_code_sechash(Hash([0u8; 32]));
        tx.set_data_sechash(Hash([0u8; 32]));

        let gas_limit = Gas::from(tx.header().wrapper().unwrap().gas_limit)
            .checked_sub(Gas::from(tx.to_bytes().len() as u64))
            .unwrap();
        shell.enqueue_tx(tx.clone(), gas_limit);

        tx.header.tx_type = TxType::Decrypted(DecryptedTx::Undecryptable);

        let response = {
            let request = ProcessProposal {
                txs: vec![tx.to_bytes()],
            };
            if let [resp] = shell
                .process_proposal(request)
                .expect("Test failed")
                .as_slice()
            {
                resp.clone()
            } else {
                panic!("Test failed")
            }
        };
        assert_eq!(response.result.code, u32::from(ErrorCodes::Ok));
    }

    /// Test that if a wrapper tx contains garbage bytes
    /// as its encrypted inner tx, it is correctly
    /// marked undecryptable and the errors handled correctly
    #[test]
    fn test_undecryptable() {
        let (mut shell, _recv, _, _) = test_utils::setup_at_height(3u64);
        let keypair = crate::wallet::defaults::daewon_keypair();
        // not valid tx bytes
        let wrapper = WrapperTx {
            fee: Fee {
                amount_per_gas_unit: Default::default(),
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

        let response = {
            let request = ProcessProposal {
                txs: vec![decrypted.to_bytes()],
            };
            if let [resp] = shell
                .process_proposal(request)
                .expect("Test failed")
                .as_slice()
            {
                resp.clone()
            } else {
                panic!("Test failed")
            }
        };
        assert_eq!(response.result.code, u32::from(ErrorCodes::Ok));
    }

    /// Test that if more decrypted txs are submitted to
    /// [`process_proposal`] than expected, they are rejected
    #[test]
    fn test_too_many_decrypted_txs() {
        let (shell, _recv, _, _) = test_utils::setup_at_height(3u64);
        let mut tx = Tx::from_type(TxType::Decrypted(DecryptedTx::Decrypted));
        tx.header.chain_id = shell.chain_id.clone();
        tx.set_code(Code::new("wasm_code".as_bytes().to_owned()));
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
        assert_eq!(response.result.code, u32::from(ErrorCodes::ExtraTxs));
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
        tx.add_code("wasm_code".as_bytes().to_owned())
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
        assert_eq!(response.result.code, u32::from(ErrorCodes::InvalidTx));
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
                    amount_per_gas_unit: Amount::zero(),
                    token: shell.wl_storage.storage.native_token.clone(),
                },
                keypair.ref_to(),
                Epoch(0),
                GAS_LIMIT_MULTIPLIER.into(),
                None,
            ))));
        wrapper.header.chain_id = shell.chain_id.clone();
        wrapper.set_data(Data::new("transaction data".as_bytes().to_owned()));
        wrapper.set_code(Code::new("wasm_code".as_bytes().to_owned()));
        wrapper.add_section(Section::Signature(Signature::new(
            wrapper.sechashes(),
            [(0, keypair)].into_iter().collect(),
            None,
        )));

        // Write wrapper hash to storage
        let wrapper_unsigned_hash = wrapper.header_hash();
        let hash_key = replay_protection::get_replay_protection_last_key(
            &wrapper_unsigned_hash,
        );
        shell
            .wl_storage
            .storage
            .write(&hash_key, vec![])
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
                    u32::from(ErrorCodes::ReplayTx)
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

        let mut wrapper =
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
        wrapper.header.chain_id = shell.chain_id.clone();
        wrapper.set_code(Code::new("wasm_code".as_bytes().to_owned()));
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
                assert_eq!(response[0].result.code, u32::from(ErrorCodes::Ok));
                assert_eq!(
                    response[1].result.code,
                    u32::from(ErrorCodes::ReplayTx)
                );
                // The checks happens on the inner hash first, so the tx is
                // rejected because of this hash, not the
                // wrapper one
                assert_eq!(
                    response[1].result.info,
                    format!(
                        "Transaction replay attempt: Inner transaction hash \
                         {} already in storage",
                        wrapper
                            .clone()
                            .update_header(TxType::Raw)
                            .header_hash(),
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
                    amount_per_gas_unit: Amount::zero(),
                    token: shell.wl_storage.storage.native_token.clone(),
                },
                keypair.ref_to(),
                Epoch(0),
                GAS_LIMIT_MULTIPLIER.into(),
                None,
            ))));
        wrapper.header.chain_id = shell.chain_id.clone();
        wrapper.set_code(Code::new("wasm_code".as_bytes().to_owned()));
        wrapper.set_data(Data::new("transaction data".as_bytes().to_owned()));
        wrapper.add_section(Section::Signature(Signature::new(
            wrapper.sechashes(),
            [(0, keypair)].into_iter().collect(),
            None,
        )));
        let inner_unsigned_hash =
            wrapper.clone().update_header(TxType::Raw).header_hash();

        // Write inner hash to storage
        let hash_key = replay_protection::get_replay_protection_last_key(
            &inner_unsigned_hash,
        );
        shell
            .wl_storage
            .storage
            .write(&hash_key, vec![])
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
                    u32::from(ErrorCodes::ReplayTx)
                );
                assert_eq!(
                    response[0].result.info,
                    format!(
                        "Transaction replay attempt: Inner transaction hash \
                         {} already in storage",
                        inner_unsigned_hash
                    )
                );
            }
        }
    }

    /// Test that a block containing two identical inner transactions is
    /// rejected
    #[test]
    fn test_inner_tx_hash_same_block() {
        let (shell, _recv, _, _) = test_utils::setup();

        let keypair = crate::wallet::defaults::daewon_keypair();
        let keypair_2 = crate::wallet::defaults::daewon_keypair();

        let mut wrapper =
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
        wrapper.header.chain_id = shell.chain_id.clone();
        wrapper.set_code(Code::new("wasm_code".as_bytes().to_owned()));
        wrapper.set_data(Data::new("transaction data".as_bytes().to_owned()));
        let mut new_wrapper = wrapper.clone();
        wrapper.add_section(Section::Signature(Signature::new(
            wrapper.sechashes(),
            [(0, keypair)].into_iter().collect(),
            None,
        )));
        let inner_unsigned_hash =
            wrapper.clone().update_header(TxType::Raw).header_hash();

        new_wrapper.update_header(TxType::Wrapper(Box::new(WrapperTx::new(
            Fee {
                amount_per_gas_unit: 1.into(),
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
            Ok(_) => panic!("Test failed"),
            Err(TestError::RejectProposal(response)) => {
                assert_eq!(response[0].result.code, u32::from(ErrorCodes::Ok));
                assert_eq!(
                    response[1].result.code,
                    u32::from(ErrorCodes::ReplayTx)
                );
                assert_eq!(
                    response[1].result.info,
                    format!(
                        "Transaction replay attempt: Inner transaction hash \
                         {} already in storage",
                        inner_unsigned_hash
                    )
                );
            }
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
                    amount_per_gas_unit: Amount::zero(),
                    token: shell.wl_storage.storage.native_token.clone(),
                },
                keypair.ref_to(),
                Epoch(0),
                GAS_LIMIT_MULTIPLIER.into(),
                None,
            ))));
        let wrong_chain_id = ChainId("Wrong chain id".to_string());
        wrapper.header.chain_id = wrong_chain_id.clone();
        wrapper.set_code(Code::new("wasm_code".as_bytes().to_owned()));
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
                        u32::from(ErrorCodes::InvalidChainId)
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

    /// Test that a decrypted transaction with a mismatching chain id gets
    /// rejected without rejecting the entire block
    #[test]
    fn test_decrypted_wrong_chain_id() {
        let (mut shell, _recv, _, _) = test_utils::setup();
        let keypair = crate::wallet::defaults::daewon_keypair();

        let wrong_chain_id = ChainId("Wrong chain id".to_string());
        let mut wrapper =
            Tx::from_type(TxType::Wrapper(Box::new(WrapperTx::new(
                Fee {
                    amount_per_gas_unit: token::Amount::zero(),
                    token: shell.wl_storage.storage.native_token.clone(),
                },
                keypair.ref_to(),
                Epoch(0),
                GAS_LIMIT_MULTIPLIER.into(),
                None,
            ))));
        wrapper.header.chain_id = wrong_chain_id.clone();
        wrapper.set_code(Code::new("wasm_code".as_bytes().to_owned()));
        wrapper
            .set_data(Data::new("new transaction data".as_bytes().to_owned()));
        let mut decrypted = wrapper.clone();

        decrypted.update_header(TxType::Decrypted(DecryptedTx::Decrypted));
        decrypted.add_section(Section::Signature(Signature::new(
            decrypted.sechashes(),
            [(0, keypair)].into_iter().collect(),
            None,
        )));
        let gas_limit = Gas::from(wrapper.header.wrapper().unwrap().gas_limit)
            .checked_sub(Gas::from(wrapper.to_bytes().len() as u64))
            .unwrap();
        let wrapper_in_queue = TxInQueue {
            tx: wrapper,
            gas: gas_limit,
        };
        shell.wl_storage.storage.tx_queue.push(wrapper_in_queue);

        // Run validation
        let request = ProcessProposal {
            txs: vec![decrypted.to_bytes()],
        };

        match shell.process_proposal(request) {
            Ok(response) => {
                assert_eq!(
                    response[0].result.code,
                    u32::from(ErrorCodes::InvalidDecryptedChainId)
                );
                assert_eq!(
                    response[0].result.info,
                    format!(
                        "Decrypted tx carries a wrong chain id: expected {}, \
                         found {}",
                        shell.chain_id, wrong_chain_id
                    )
                )
            }
            Err(_) => panic!("Test failed"),
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
                    amount_per_gas_unit: 1.into(),
                    token: shell.wl_storage.storage.native_token.clone(),
                },
                keypair.ref_to(),
                Epoch(0),
                GAS_LIMIT_MULTIPLIER.into(),
                None,
            ))));
        wrapper.header.chain_id = shell.chain_id.clone();
        wrapper.header.expiration = Some(DateTimeUtc::default());
        wrapper.set_code(Code::new("wasm_code".as_bytes().to_owned()));
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
                    u32::from(ErrorCodes::ExpiredTx)
                );
            }
        }
    }

    /// Test that an expired decrypted transaction is correctly marked as so
    /// without rejecting the entire block
    #[test]
    fn test_expired_decrypted() {
        let (mut shell, _recv, _, _) = test_utils::setup();
        let keypair = crate::wallet::defaults::daewon_keypair();

        let mut wrapper =
            Tx::from_type(TxType::Wrapper(Box::new(WrapperTx::new(
                Fee {
                    amount_per_gas_unit: token::Amount::zero(),
                    token: shell.wl_storage.storage.native_token.clone(),
                },
                keypair.ref_to(),
                Epoch(0),
                GAS_LIMIT_MULTIPLIER.into(),
                None,
            ))));
        wrapper.header.chain_id = shell.chain_id.clone();
        wrapper.header.expiration = Some(DateTimeUtc::default());
        wrapper.set_code(Code::new("wasm_code".as_bytes().to_owned()));
        wrapper
            .set_data(Data::new("new transaction data".as_bytes().to_owned()));
        let mut decrypted = wrapper.clone();

        decrypted.update_header(TxType::Decrypted(DecryptedTx::Decrypted));
        decrypted.add_section(Section::Signature(Signature::new(
            decrypted.sechashes(),
            [(0, keypair)].into_iter().collect(),
            None,
        )));
        let gas_limit = Gas::from(wrapper.header.wrapper().unwrap().gas_limit)
            .checked_sub(Gas::from(wrapper.to_bytes().len() as u64))
            .unwrap();
        let wrapper_in_queue = TxInQueue {
            tx: wrapper,
            gas: gas_limit,
        };
        shell.wl_storage.storage.tx_queue.push(wrapper_in_queue);

        // Run validation
        let request = ProcessProposal {
            txs: vec![decrypted.to_bytes()],
        };
        match shell.process_proposal(request) {
            Ok(response) => {
                assert_eq!(response.len(), 1);
                assert_eq!(
                    response[0].result.code,
                    u32::from(ErrorCodes::ExpiredDecryptedTx)
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
            namada::core::ledger::gas::get_max_block_gas(&shell.wl_storage)
                .unwrap();
        let keypair = super::test_utils::gen_keypair();

        let mut wrapper =
            Tx::from_type(TxType::Wrapper(Box::new(WrapperTx::new(
                Fee {
                    amount_per_gas_unit: 100.into(),
                    token: shell.wl_storage.storage.native_token.clone(),
                },
                keypair.ref_to(),
                Epoch(0),
                (block_gas_limit + 1).into(),
                None,
            ))));
        wrapper.header.chain_id = shell.chain_id.clone();
        wrapper.set_code(Code::new("wasm_code".as_bytes().to_owned()));
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
                    u32::from(ErrorCodes::AllocationError)
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
                    amount_per_gas_unit: 100.into(),
                    token: shell.wl_storage.storage.native_token.clone(),
                },
                keypair.ref_to(),
                Epoch(0),
                0.into(),
                None,
            ))));
        wrapper.header.chain_id = shell.chain_id.clone();
        wrapper.set_code(Code::new("wasm_code".as_bytes().to_owned()));
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
                    u32::from(ErrorCodes::TxGasLimit)
                );
            }
        }
    }

    // Check that a wrapper using a non-whitelisted token for fee payment causes
    // a block rejection
    #[test]
    fn test_fee_non_whitelisted_token() {
        let (shell, _recv, _, _) = test_utils::setup();

        let mut wrapper =
            Tx::from_type(TxType::Wrapper(Box::new(WrapperTx::new(
                Fee {
                    amount_per_gas_unit: 100.into(),
                    token: address::btc(),
                },
                crate::wallet::defaults::albert_keypair().ref_to(),
                Epoch(0),
                GAS_LIMIT_MULTIPLIER.into(),
                None,
            ))));
        wrapper.header.chain_id = shell.chain_id.clone();
        wrapper.set_code(Code::new("wasm_code".as_bytes().to_owned()));
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
                    u32::from(ErrorCodes::FeeError)
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
                    amount_per_gas_unit: 0.into(),
                    token: shell.wl_storage.storage.native_token.clone(),
                },
                crate::wallet::defaults::albert_keypair().ref_to(),
                Epoch(0),
                GAS_LIMIT_MULTIPLIER.into(),
                None,
            ))));
        wrapper.header.chain_id = shell.chain_id.clone();
        wrapper.set_code(Code::new("wasm code".as_bytes().to_owned()));
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
                    u32::from(ErrorCodes::FeeError)
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
                    amount_per_gas_unit: 1_000_000_000.into(),
                    token: shell.wl_storage.storage.native_token.clone(),
                },
                crate::wallet::defaults::albert_keypair().ref_to(),
                Epoch(0),
                150_000.into(),
                None,
            ))));
        wrapper.header.chain_id = shell.chain_id.clone();
        wrapper.set_code(Code::new("wasm code".as_bytes().to_owned()));
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
                    u32::from(ErrorCodes::FeeError)
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
                    amount_per_gas_unit: token::Amount::max(),
                    token: shell.wl_storage.storage.native_token.clone(),
                },
                crate::wallet::defaults::albert_keypair().ref_to(),
                Epoch(0),
                GAS_LIMIT_MULTIPLIER.into(),
                None,
            ))));
        wrapper.header.chain_id = shell.chain_id.clone();
        wrapper.set_code(Code::new("wasm code".as_bytes().to_owned()));
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
                    u32::from(ErrorCodes::FeeError)
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
                    amount_per_gas_unit: 0.into(),
                    token: shell.wl_storage.storage.native_token.clone(),
                },
                keypair.ref_to(),
                Epoch(0),
                GAS_LIMIT_MULTIPLIER.into(),
                None,
            ))));
        wrapper.header.chain_id = shell.chain_id.clone();
        wrapper.set_code(Code::new("wasm_code".as_bytes().to_owned()));
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
                u32::from(ErrorCodes::AllocationError)
            );
            assert_eq!(
                response.result.info,
                String::from(
                    "Wrapper txs not allowed at the current block height"
                ),
            );
        }
    }
}
