//! Implementation of the ['VerifyHeader`], [`ProcessProposal`],
//! and [`RevertProposal`] ABCI++ methods for the Shell

use std::collections::BTreeMap;

use data_encoding::HEXUPPER;
use namada::core::hints;
use namada::core::ledger::storage::WlStorage;
use namada::ledger::gas::GasMetering;
use namada::ledger::storage::TempWlStorage;
use namada::proof_of_stake::find_validator_by_raw_hash;
use namada::proof_of_stake::pos_queries::PosQueries;
use namada::proto::Commitment;
use namada::types::hash::{Hash, HASH_LENGTH};
use namada::types::internal::TxInQueue;

use super::block_alloc::EncryptedTxsBins;
use super::*;
use crate::facade::tendermint_proto::abci::response_process_proposal::ProposalStatus;
use crate::facade::tendermint_proto::abci::RequestProcessProposal;
use crate::node::ledger::shell::block_alloc::{
    AllocFailure, DumpResource, TxBin,
};
use crate::node::ledger::shims::abcipp_shim_types::shim::response::ProcessProposal;
use crate::node::ledger::shims::abcipp_shim_types::shim::TxBytes;

/// Validation metadata, to keep track of used resources or
/// transaction numbers, in a block proposal.
#[derive(Default)]
pub struct ValidationMeta {
    /// Space and gas utilized by encrypted txs.
    pub encrypted_txs_bins: EncryptedTxsBins,
    /// Space utilized by all txs.
    pub txs_bin: TxBin,
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
    fn from(storage: &WlStorage<D, H>) -> Self {
        let max_proposal_bytes =
            storage.pos_queries().get_max_proposal_bytes().get();
        let max_block_gas = storage
            .read(&parameters::storage::get_max_block_gas_key())
            .expect("Error while reading from storage")
            .expect("Missing max_block_gas parameter in storage");
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

    /// Check all the txs in a block.
    /// We reject the entire block when:
    ///    - decrypted txs violate the committed order
    ///    - more decrypted txs than expected
    ///    - checks on wrapper tx fail
    ///
    /// We cannot reject the block for failed checks on the decrypted txs since
    /// their order has already been committed in storage, so we simply discard
    /// the single invalid inner tx
    pub fn process_proposal(
        &self,
        req: RequestProcessProposal,
    ) -> ProcessProposal {
        let tm_raw_hash_string = tm_raw_hash_to_string(&req.proposer_address);
        let block_proposer = find_validator_by_raw_hash(
            &self.wl_storage,
            tm_raw_hash_string,
        )
        .unwrap()
        .expect(
            "Unable to find native validator address of block proposer from tendermint raw hash",
        );
        let (tx_results, metadata) = self.process_txs(
            &req.txs,
            self.get_block_timestamp(req.time),
            &block_proposer,
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

    /// Check all the given txs.
    pub fn process_txs(
        &self,
        txs: &[TxBytes],
        block_time: DateTimeUtc,
        block_proposer: &Address,
    ) -> (Vec<TxResult>, ValidationMeta) {
        let mut tx_queue_iter = self.wl_storage.storage.tx_queue.iter();
        let mut temp_wl_storage = TempWlStorage::new(&self.wl_storage.storage);
        let mut metadata = ValidationMeta::from(&self.wl_storage);
        let gas_table: BTreeMap<String, u64> = self
            .wl_storage
            .read(&parameters::storage::get_gas_table_storage_key())
            .expect("Error while reading from storage")
            .expect("Missing gas table in storage");
        let mut vp_wasm_cache = self.vp_wasm_cache.clone();
        let mut tx_wasm_cache = self.tx_wasm_cache.clone();

        let mut wrapper_index = 0;

        let tx_results = txs
            .iter()
            .map(|tx_bytes| {
                let result = self.process_single_tx(
                    tx_bytes,
                    &mut tx_queue_iter,
                    &mut metadata,
                    &mut temp_wl_storage,
                    block_time,
                    &gas_table,
                    &mut wrapper_index,
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
    ///   7. Not enough block space was available for some tx
    ///   8: Replay attack  
    ///
    /// INVARIANT: Any changes applied in this method must be reverted if the
    /// proposal is rejected (unless we can simply overwrite them in the
    /// next block).
    #[allow(clippy::too_many_arguments)]
    pub fn process_single_tx<'a, CA>(
        &self,
        tx_bytes: &[u8],
        tx_queue_iter: &mut impl Iterator<Item = &'a TxInQueue>,
        metadata: &mut ValidationMeta,
        temp_wl_storage: &mut TempWlStorage<D, H>,
        block_time: DateTimeUtc,
        gas_table: &BTreeMap<String, u64>,
        wrapper_index: &mut usize,
        vp_wasm_cache: &mut VpCache<CA>,
        tx_wasm_cache: &mut TxCache<CA>,
        block_proposer: &Address,
    ) -> TxResult
    where
        CA: 'static + WasmCacheAccess + Sync,
    {
        // try to allocate space for this tx
        if let Err(e) = metadata.txs_bin.try_dump(DumpResource::Space(tx_bytes))
        {
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
                if let Err(err) = tx.validate_header() {
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

        if let Err(err) = tx.validate_header() {
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
            TxType::Protocol(_) => {
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
                TxResult {
                    code: ErrorCodes::InvalidTx.into(),
                    info: "Protocol transactions are a fun new feature that \
                           is coming soon to a blockchain near you. Patience."
                        .into(),
                }
            }
            TxType::Decrypted(tx_header) => {
                // Increase wrapper index
                let tx_index = *wrapper_index;
                *wrapper_index += 1;
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

                            // Tx gas (partial check)
                            let tx_hash = match tx
                                .get_section(tx.code_sechash())
                                .and_then(Section::code_sec)
                            {
                                Some(code) => match code.code {
                                    Commitment::Hash(hash) => hash,
                                    Commitment::Id(code) => {
                                        hash::Hash::sha256(&code)
                                    }
                                },
                                #[cfg(not(test))]
                                None => {
                                    return TxResult {
                                        code: ErrorCodes::DecryptedTxGasLimit
                                            .into(),
                                        info: "Missing transaction code"
                                            .to_string(),
                                    }
                                }
                                #[cfg(test)]
                                None => Hash::zero(),
                            };

                            let tx_gas = match gas_table
                                .get(&tx_hash.to_string().to_ascii_lowercase())
                            {
                                Some(gas) => gas.to_owned(),
                                #[cfg(test)]
                                None => 1_000,
                                #[cfg(not(test))]
                                None => 0, /* VPs will rejected the
                                            * non-whitelisted tx */
                            };
                            let inner_tx_gas_limit = temp_wl_storage
                                .storage
                                .tx_queue
                                .get(tx_index)
                                .map_or(0, |wrapper| wrapper.gas);
                            let mut tx_gas_meter =
                                TxGasMeter::new(inner_tx_gas_limit);
                            if let Err(e) = tx_gas_meter.consume(tx_gas) {
                                return TxResult {
                                    code: ErrorCodes::DecryptedTxGasLimit
                                        .into(),
                                    info: format!(
                                        "Decrypted transaction gas error: \
                                             {}",
                                        e
                                    ),
                                };
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
                // Account for gas and space. This is done even if the transaction is
                // later deemed invalid, to incentivize the proposer to
                // include only valid transaction and avoid wasting block
                // resources (ABCI only)
                let mut tx_gas_meter =
                    TxGasMeter::new(u64::from(&wrapper.gas_limit));
                if tx_gas_meter.add_tx_size_gas(tx_bytes).is_err() {
                    // Account for the tx's resources even in case of an error. Ignore any allocation error
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
                    .try_dump(tx_bytes, u64::from(wrapper.gas_limit.clone()))
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
                    let fee_unshield = wrapper
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

                    match self.wrapper_fee_check(
                        &wrapper,
                        fee_unshield,
                        temp_wl_storage,
                        Some(Cow::Borrowed(gas_table)),
                        vp_wasm_cache,
                        tx_wasm_cache,
                        Some(block_proposer),
                    ) {
                        Ok(()) => TxResult {
                            code: ErrorCodes::Ok.into(),
                            info: "Process proposal accepted this \
                                       transaction"
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

    /// Checks if it is not possible to include encrypted txs at the current
    /// block height.
    fn encrypted_txs_not_allowed(&self) -> bool {
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
    use borsh::BorshDeserialize;
    use namada::ledger::storage_api::StorageWrite;
    use namada::proto::{Code, Data, Section, Signature};
    use namada::types::hash::Hash;
    use namada::types::key::*;
    use namada::types::storage::Epoch;
    use namada::types::token::Amount;
    use namada::types::transaction::protocol::{ProtocolTx, ProtocolTxType};
    use namada::types::transaction::{EncryptionKey, Fee, WrapperTx};

    use super::*;
    use crate::node::ledger::shell::test_utils::{
        self, gen_keypair, ProcessProposal, TestError,
    };

    const GAS_LIMIT_MULTIPLIER: u64 = 300_000;

    /// Test that if a wrapper tx is not signed, the block is rejected
    /// by [`process_proposal`].
    #[test]
    fn test_unsigned_wrapper_rejected() {
        let (shell, _) = test_utils::setup(1);
        let keypair = gen_keypair();
        let mut outer_tx = Tx::new(TxType::Wrapper(Box::new(WrapperTx::new(
            Fee {
                amount_per_gas_unit: 0.into(),
                token: shell.wl_storage.storage.native_token.clone(),
            },
            &keypair,
            Epoch(0),
            GAS_LIMIT_MULTIPLIER.into(),
            #[cfg(not(feature = "mainnet"))]
            None,
            None,
        ))));
        outer_tx.header.chain_id = shell.chain_id.clone();
        outer_tx.set_code(Code::new("wasm_code".as_bytes().to_owned()));
        outer_tx.set_data(Data::new("transaction data".as_bytes().to_owned()));
        outer_tx.encrypt(&Default::default());
        let tx = outer_tx.to_bytes();
        #[allow(clippy::redundant_clone)]
        let request = ProcessProposal {
            txs: vec![tx.clone()],
        };

        match shell.process_proposal(request) {
            Ok(_) => panic!("Test failed"),
            Err(TestError::RejectProposal(response)) => {
                assert_eq!(
                    response[0].result.code,
                    u32::from(ErrorCodes::InvalidSig)
                );
                assert_eq!(
                    response[0].result.info,
                    String::from(
                        "WrapperTx signature verification failed: Transaction \
                         doesn't have any data with a signature."
                    )
                );
            }
        }
    }

    /// Test that a block including a wrapper tx with invalid signature is
    /// rejected
    #[test]
    fn test_wrapper_bad_signature_rejected() {
        let (shell, _) = test_utils::setup(1);
        let keypair = gen_keypair();
        let mut outer_tx = Tx::new(TxType::Wrapper(Box::new(WrapperTx::new(
            Fee {
                amount_per_gas_unit: 100.into(),
                token: shell.wl_storage.storage.native_token.clone(),
            },
            &keypair,
            Epoch(0),
            GAS_LIMIT_MULTIPLIER.into(),
            #[cfg(not(feature = "mainnet"))]
            None,
            None,
        ))));
        outer_tx.header.chain_id = shell.chain_id.clone();
        outer_tx.set_code(Code::new("wasm_code".as_bytes().to_owned()));
        outer_tx.set_data(Data::new("transaction data".as_bytes().to_owned()));
        outer_tx.add_section(Section::Signature(Signature::new(
            &outer_tx.header_hash(),
            &keypair,
        )));
        outer_tx.encrypt(&Default::default());
        let mut new_tx = outer_tx.clone();
        if let TxType::Wrapper(wrapper) = &mut new_tx.header.tx_type {
            // we mount a malleability attack to try and remove the fee
            wrapper.fee.amount_per_gas_unit = 0.into();
        } else {
            panic!("Test failed")
        };
        let request = ProcessProposal {
            txs: vec![new_tx.to_bytes()],
        };

        match shell.process_proposal(request) {
            Ok(_) => panic!("Test failed"),
            Err(TestError::RejectProposal(response)) => {
                let expected_error = "WrapperTx signature verification \
                                      failed: Transaction doesn't have any \
                                      data with a signature.";
                assert_eq!(
                    response[0].result.code,
                    u32::from(ErrorCodes::InvalidSig)
                );
                assert!(
                    response[0].result.info.contains(expected_error),
                    "Result info {} doesn't contain the expected error {}",
                    response[0].result.info,
                    expected_error
                );
            }
        }
    }

    /// Test that if the account submitting the tx is not known and the fee is
    /// non-zero, [`process_proposal`] rejects that block
    #[test]
    fn test_wrapper_unknown_address() {
        let (mut shell, _) = test_utils::setup(1);
        let keypair = gen_keypair();
        // reduce address balance to match the 100 token min fee
        let balance_key = token::balance_key(
            &shell.wl_storage.storage.native_token,
            &Address::from(&keypair.ref_to()),
        );
        shell
            .wl_storage
            .write(&balance_key, Amount::whole(99))
            .unwrap();
        let keypair = gen_keypair();
        let mut outer_tx = Tx::new(TxType::Wrapper(Box::new(WrapperTx::new(
            Fee {
                amount_per_gas_unit: 1.into(),
                token: shell.wl_storage.storage.native_token.clone(),
            },
            &keypair,
            Epoch(0),
            GAS_LIMIT_MULTIPLIER.into(),
            #[cfg(not(feature = "mainnet"))]
            None,
            None,
        ))));
        outer_tx.header.chain_id = shell.chain_id.clone();
        outer_tx.set_code(Code::new("wasm_code".as_bytes().to_owned()));
        outer_tx.set_data(Data::new("transaction data".as_bytes().to_owned()));
        outer_tx.add_section(Section::Signature(Signature::new(
            &outer_tx.header_hash(),
            &keypair,
        )));
        outer_tx.encrypt(&Default::default());

        let request = ProcessProposal {
            txs: vec![outer_tx.to_bytes()],
        };

        match shell.process_proposal(request) {
            Ok(_) => panic!("Test failed"),
            Err(TestError::RejectProposal(response)) => {
                assert_eq!(
                    response[0].result.code,
                    u32::from(ErrorCodes::FeeError)
                );
                assert_eq!(
                    response[0].result.info,
                    "Error trying to apply a transaction: Error while processing transaction's fees: Insufficient transparent \
                     balance to pay fees"
                        .to_string()
                );
            }
        }
    }

    /// Test that if the account submitting the tx does
    /// not have sufficient balance to pay the fee,
    /// [`process_proposal`] rejects the entire block
    #[test]
    fn test_wrapper_insufficient_balance_address() {
        let (mut shell, _) = test_utils::setup(1);
        let keypair = crate::wallet::defaults::daewon_keypair();
        // reduce address balance to match the 100 token min fee
        let balance_key = token::balance_key(
            &shell.wl_storage.storage.native_token,
            &Address::from(&keypair.ref_to()),
        );
        shell
            .wl_storage
            .write(&balance_key, Amount::whole(99))
            .unwrap();
        shell.commit();

        let mut outer_tx = Tx::new(TxType::Wrapper(Box::new(WrapperTx::new(
            Fee {
                amount_per_gas_unit: Amount::from(1_000_000),
                token: shell.wl_storage.storage.native_token.clone(),
            },
            &keypair,
            Epoch(0),
            GAS_LIMIT_MULTIPLIER.into(),
            #[cfg(not(feature = "mainnet"))]
            None,
            None,
        ))));
        outer_tx.header.chain_id = shell.chain_id.clone();
        outer_tx.set_code(Code::new("wasm_code".as_bytes().to_owned()));
        outer_tx.set_data(Data::new("transaction data".as_bytes().to_owned()));
        outer_tx.add_section(Section::Signature(Signature::new(
            &outer_tx.header_hash(),
            &keypair,
        )));
        outer_tx.encrypt(&Default::default());

        let request = ProcessProposal {
            txs: vec![outer_tx.to_bytes()],
        };

        match shell.process_proposal(request) {
            Ok(_) => panic!("Test failed"),
            Err(TestError::RejectProposal(response)) => {
                assert_eq!(
                    response[0].result.code,
                    u32::from(ErrorCodes::FeeError)
                );
                assert_eq!(
                    response[0].result.info,
                    "Error trying to apply a transaction: Error while processing transaction's fees: Insufficient transparent \
                                                     balance to pay fees"
                        .to_string()
                );
            }
        }
    }

    /// Test that if the expected order of decrypted txs is
    /// validated, [`process_proposal`] rejects it
    #[test]
    fn test_decrypted_txs_out_of_order() {
        let (mut shell, _) = test_utils::setup(1);
        let keypair = gen_keypair();
        let mut txs = vec![];
        for i in 0..3 {
            let mut outer_tx =
                Tx::new(TxType::Wrapper(Box::new(WrapperTx::new(
                    Fee {
                        amount_per_gas_unit: i.into(),
                        token: shell.wl_storage.storage.native_token.clone(),
                    },
                    &keypair,
                    Epoch(0),
                    GAS_LIMIT_MULTIPLIER.into(),
                    #[cfg(not(feature = "mainnet"))]
                    None,
                    None,
                ))));
            outer_tx.header.chain_id = shell.chain_id.clone();
            outer_tx.set_code(Code::new("wasm_code".as_bytes().to_owned()));
            outer_tx.set_data(Data::new(
                format!("transaction data: {}", i).as_bytes().to_owned(),
            ));
            outer_tx.encrypt(&Default::default());
            let gas_limit =
                u64::from(&outer_tx.header().wrapper().unwrap().gas_limit)
                    - outer_tx.to_bytes().len() as u64;
            shell.enqueue_tx(outer_tx.clone(), gas_limit);

            outer_tx.update_header(TxType::Decrypted(DecryptedTx::Decrypted {
                #[cfg(not(feature = "mainnet"))]
                has_valid_pow: false,
            }));
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
        let (mut shell, _) = test_utils::setup(1);
        let keypair = gen_keypair();

        let mut tx = Tx::new(TxType::Wrapper(Box::new(WrapperTx::new(
            Fee {
                amount_per_gas_unit: 0.into(),
                token: shell.wl_storage.storage.native_token.clone(),
            },
            &keypair,
            Epoch(0),
            GAS_LIMIT_MULTIPLIER.into(),
            #[cfg(not(feature = "mainnet"))]
            None,
            None,
        ))));
        tx.header.chain_id = shell.chain_id.clone();
        tx.set_code(Code::new("wasm_code".as_bytes().to_owned()));
        tx.set_data(Data::new("transaction data".as_bytes().to_owned()));
        tx.encrypt(&Default::default());
        let gas_limit = u64::from(&tx.header().wrapper().unwrap().gas_limit)
            - tx.to_bytes().len() as u64;
        shell.enqueue_tx(tx.clone(), gas_limit);

        tx.header.tx_type = TxType::Decrypted(DecryptedTx::Undecryptable);
        let request = ProcessProposal {
            txs: vec![tx.to_bytes()],
        };

        match shell.process_proposal(request) {
            Ok(_) => panic!("Test failed"),
            Err(TestError::RejectProposal(response)) => {
                assert_eq!(
                    response[0].result.code,
                    u32::from(ErrorCodes::InvalidTx)
                );
                assert_eq!(
                    response[0].result.info,
                    String::from(
                        "The encrypted payload of tx was incorrectly marked \
                         as un-decryptable"
                    ),
                );
            }
        }
    }

    /// Test that a wrapper tx whose inner_tx does not have
    /// the same hash as the wrappers tx_hash field is marked
    /// undecryptable but still accepted
    #[test]
    fn test_invalid_hash_commitment() {
        let (mut shell, _) = test_utils::setup(1);
        let keypair = crate::wallet::defaults::daewon_keypair();

        let mut tx = Tx::new(TxType::Wrapper(Box::new(WrapperTx::new(
            Fee {
                amount_per_gas_unit: 0.into(),
                token: shell.wl_storage.storage.native_token.clone(),
            },
            &keypair,
            Epoch(0),
            GAS_LIMIT_MULTIPLIER.into(),
            #[cfg(not(feature = "mainnet"))]
            None,
            None,
        ))));
        tx.header.chain_id = shell.chain_id.clone();
        tx.set_code(Code::new("wasm_code".as_bytes().to_owned()));
        tx.set_data(Data::new("transaction data".as_bytes().to_owned()));
        tx.set_code_sechash(Hash([0u8; 32]));
        tx.set_data_sechash(Hash([0u8; 32]));
        tx.encrypt(&Default::default());

        let gas_limit = u64::from(&tx.header().wrapper().unwrap().gas_limit)
            - tx.to_bytes().len() as u64;
        shell.enqueue_tx(tx.clone(), gas_limit);

        tx.header.tx_type = TxType::Decrypted(DecryptedTx::Undecryptable);
        let request = ProcessProposal {
            txs: vec![tx.to_bytes()],
        };
        let response = if let [resp] = shell
            .process_proposal(request)
            .expect("Test failed")
            .as_slice()
        {
            resp.clone()
        } else {
            panic!("Test failed")
        };
        assert_eq!(response.result.code, u32::from(ErrorCodes::Ok));
    }

    /// Test that if a wrapper tx contains garbage bytes
    /// as its encrypted inner tx, it is correctly
    /// marked undecryptable and the errors handled correctly
    #[test]
    fn test_undecryptable() {
        let (mut shell, _) = test_utils::setup(1);
        let keypair = crate::wallet::defaults::daewon_keypair();
        // not valid tx bytes
        let wrapper = WrapperTx {
            fee: Fee {
                amount_per_gas_unit: 0.into(),
                token: shell.wl_storage.storage.native_token.clone(),
            },
            pk: keypair.ref_to(),
            epoch: Epoch(0),
            gas_limit: GAS_LIMIT_MULTIPLIER.into(),
            #[cfg(not(feature = "mainnet"))]
            pow_solution: None,
            unshield_section_hash: None,
        };

        let tx = Tx::new(TxType::Wrapper(Box::new(wrapper)));
        let mut decrypted = tx.clone();
        decrypted.update_header(TxType::Decrypted(DecryptedTx::Undecryptable));

        let gas_limit = u64::from(&tx.header().wrapper().unwrap().gas_limit)
            - tx.to_bytes().len() as u64;
        shell.enqueue_tx(tx, gas_limit);

        let request = ProcessProposal {
            txs: vec![decrypted.to_bytes()],
        };
        let response = if let [resp] = shell
            .process_proposal(request)
            .expect("Test failed")
            .as_slice()
        {
            resp.clone()
        } else {
            panic!("Test failed")
        };
        assert_eq!(response.result.code, u32::from(ErrorCodes::Ok));
    }

    /// Test that if more decrypted txs are submitted to
    /// [`process_proposal`] than expected, they are rejected
    #[test]
    fn test_too_many_decrypted_txs() {
        let (mut shell, _) = test_utils::setup(1);
        let mut tx = Tx::new(TxType::Decrypted(DecryptedTx::Decrypted {
            #[cfg(not(feature = "mainnet"))]
            has_valid_pow: false,
        }));
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
        let (shell, _) = test_utils::setup(1);

        let mut tx = Tx::new(TxType::Raw);
        tx.header.chain_id = shell.chain_id.clone();
        tx.set_code(Code::new("wasm_code".as_bytes().to_owned()));
        tx.set_data(Data::new("transaction data".as_bytes().to_owned()));

        let request = ProcessProposal {
            txs: vec![tx.to_bytes()],
        };

        match shell.process_proposal(request) {
            Ok(_) => panic!("Test failes"),
            Err(TestError::RejectProposal(response)) => {
                assert_eq!(
                    response[0].result.code,
                    u32::from(ErrorCodes::InvalidTx)
                );
                assert_eq!(
                    response[0].result.info,
                    String::from(
                        "Transaction rejected: Non-encrypted transactions are \
                         not supported"
                    ),
                );
            }
        }
    }

    /// Test that if the unsigned wrapper tx hash is known (replay attack), the
    /// block is rejected
    #[test]
    fn test_wrapper_tx_hash() {
        let (mut shell, _) = test_utils::setup(1);

        let keypair = crate::wallet::defaults::daewon_keypair();

        let mut wrapper = Tx::new(TxType::Wrapper(Box::new(WrapperTx::new(
            Fee {
                amount_per_gas_unit: 0.into(),
                token: shell.wl_storage.storage.native_token.clone(),
            },
            &keypair,
            Epoch(0),
            GAS_LIMIT_MULTIPLIER.into(),
            #[cfg(not(feature = "mainnet"))]
            None,
            None,
        ))));
        wrapper.header.chain_id = shell.chain_id.clone();
        wrapper.set_data(Data::new("transaction data".as_bytes().to_owned()));
        wrapper.set_code(Code::new("wasm_code".as_bytes().to_owned()));
        wrapper.add_section(Section::Signature(Signature::new(
            &wrapper.header_hash(),
            &keypair,
        )));
        wrapper.encrypt(&Default::default());

        // Write wrapper hash to storage
        let wrapper_unsigned_hash = wrapper.header_hash();
        let hash_key =
            replay_protection::get_tx_hash_key(&wrapper_unsigned_hash);
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
        let (mut shell, _) = test_utils::setup(1);

        let keypair = crate::wallet::defaults::daewon_keypair();

        // Add unshielded balance for fee payment
        let balance_key = token::balance_key(
            &shell.wl_storage.storage.native_token,
            &Address::from(&keypair.ref_to()),
        );
        shell
            .wl_storage
            .storage
            .write(&balance_key, Amount::whole(1000).try_to_vec().unwrap())
            .unwrap();

        let mut wrapper = Tx::new(TxType::Wrapper(Box::new(WrapperTx::new(
            Fee {
                amount_per_gas_unit: 1.into(),
                token: shell.wl_storage.storage.native_token.clone(),
            },
            &keypair,
            Epoch(0),
            GAS_LIMIT_MULTIPLIER.into(),
            #[cfg(not(feature = "mainnet"))]
            None,
            None,
        ))));
        wrapper.header.chain_id = shell.chain_id.clone();
        wrapper.set_code(Code::new("wasm_code".as_bytes().to_owned()));
        wrapper.set_data(Data::new("transaction data".as_bytes().to_owned()));
        wrapper.add_section(Section::Signature(Signature::new(
            &wrapper.header_hash(),
            &keypair,
        )));
        wrapper.encrypt(&Default::default());

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
        let (mut shell, _) = test_utils::setup(1);

        let keypair = crate::wallet::defaults::daewon_keypair();

        let mut wrapper = Tx::new(TxType::Wrapper(Box::new(WrapperTx::new(
            Fee {
                amount_per_gas_unit: 0.into(),
                token: shell.wl_storage.storage.native_token.clone(),
            },
            &keypair,
            Epoch(0),
            GAS_LIMIT_MULTIPLIER.into(),
            #[cfg(not(feature = "mainnet"))]
            None,
            None,
        ))));
        wrapper.header.chain_id = shell.chain_id.clone();
        wrapper.set_code(Code::new("wasm_code".as_bytes().to_owned()));
        wrapper.set_data(Data::new("transaction data".as_bytes().to_owned()));
        wrapper.add_section(Section::Signature(Signature::new(
            &wrapper.header_hash(),
            &keypair,
        )));
        wrapper.encrypt(&Default::default());
        let inner_unsigned_hash =
            wrapper.clone().update_header(TxType::Raw).header_hash();

        // Write inner hash to storage
        let hash_key = replay_protection::get_tx_hash_key(&inner_unsigned_hash);
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
        let (shell, _) = test_utils::setup(1);

        let keypair = crate::wallet::defaults::daewon_keypair();
        let keypair_2 = crate::wallet::defaults::daewon_keypair();

        let mut wrapper = Tx::new(TxType::Wrapper(Box::new(WrapperTx::new(
            Fee {
                amount_per_gas_unit: 1.into(),
                token: shell.wl_storage.storage.native_token.clone(),
            },
            &keypair,
            Epoch(0),
            GAS_LIMIT_MULTIPLIER.into(),
            #[cfg(not(feature = "mainnet"))]
            None,
            None,
        ))));
        wrapper.header.chain_id = shell.chain_id.clone();
        wrapper.set_code(Code::new("wasm_code".as_bytes().to_owned()));
        wrapper.set_data(Data::new("transaction data".as_bytes().to_owned()));
        let mut new_wrapper = wrapper.clone();
        wrapper.add_section(Section::Signature(Signature::new(
            &wrapper.header_hash(),
            &keypair,
        )));
        wrapper.encrypt(&Default::default());
        let inner_unsigned_hash =
            wrapper.clone().update_header(TxType::Raw).header_hash();

        new_wrapper.update_header(TxType::Wrapper(Box::new(WrapperTx::new(
            Fee {
                amount_per_gas_unit: 1.into(),
                token: shell.wl_storage.storage.native_token.clone(),
            },
            &keypair_2,
            Epoch(0),
            GAS_LIMIT_MULTIPLIER.into(),
            #[cfg(not(feature = "mainnet"))]
            None,
            None,
        ))));
        new_wrapper.add_section(Section::Signature(Signature::new(
            &new_wrapper.header_hash(),
            &keypair_2,
        )));
        new_wrapper.encrypt(&Default::default());

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
    fn test_wong_chain_id() {
        let (shell, _) = test_utils::setup(1);
        let keypair = crate::wallet::defaults::daewon_keypair();

        let mut wrapper = Tx::new(TxType::Wrapper(Box::new(WrapperTx::new(
            Fee {
                amount_per_gas_unit: 0.into(),
                token: shell.wl_storage.storage.native_token.clone(),
            },
            &keypair,
            Epoch(0),
            GAS_LIMIT_MULTIPLIER.into(),
            #[cfg(not(feature = "mainnet"))]
            None,
            None,
        ))));
        let wrong_chain_id = ChainId("Wrong chain id".to_string());
        wrapper.header.chain_id = wrong_chain_id.clone();
        wrapper.set_code(Code::new("wasm_code".as_bytes().to_owned()));
        wrapper.set_data(Data::new("transaction data".as_bytes().to_owned()));
        let mut protocol_tx = wrapper.clone();
        wrapper.add_section(Section::Signature(Signature::new(
            &wrapper.header_hash(),
            &keypair,
        )));
        wrapper.encrypt(&Default::default());

        protocol_tx.update_header(TxType::Protocol(Box::new(ProtocolTx {
            pk: keypair.ref_to(),
            tx: ProtocolTxType::EthereumStateUpdate,
        })));
        protocol_tx.add_section(Section::Signature(Signature::new(
            &protocol_tx.header_hash(),
            &keypair,
        )));

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
        let (mut shell, _) = test_utils::setup(1);
        let keypair = crate::wallet::defaults::daewon_keypair();

        let wrong_chain_id = ChainId("Wrong chain id".to_string());
        let mut wrapper = Tx::new(TxType::Wrapper(Box::new(WrapperTx::new(
            Fee {
                amount_per_gas_unit: 0.into(),
                token: shell.wl_storage.storage.native_token.clone(),
            },
            &keypair,
            Epoch(0),
            GAS_LIMIT_MULTIPLIER.into(),
            #[cfg(not(feature = "mainnet"))]
            None,
            None,
        ))));
        wrapper.header.chain_id = wrong_chain_id.clone();
        wrapper.set_code(Code::new("wasm_code".as_bytes().to_owned()));
        wrapper
            .set_data(Data::new("new transaction data".as_bytes().to_owned()));
        let mut decrypted = wrapper.clone();
        wrapper.encrypt(&Default::default());

        decrypted.update_header(TxType::Decrypted(DecryptedTx::Decrypted {
            has_valid_pow: false,
        }));
        decrypted.add_section(Section::Signature(Signature::new(
            &decrypted.header_hash(),
            &keypair,
        )));
        let gas_limit = u64::from(wrapper.header.wrapper().unwrap().gas_limit)
            - wrapper.to_bytes().len() as u64;
        let wrapper_in_queue = TxInQueue {
            tx: wrapper,
            gas: gas_limit,
            has_valid_pow: false,
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
        let (shell, _) = test_utils::setup(1);
        let keypair = crate::wallet::defaults::daewon_keypair();

        let mut wrapper = Tx::new(TxType::Wrapper(Box::new(WrapperTx::new(
            Fee {
                amount_per_gas_unit: 1.into(),
                token: shell.wl_storage.storage.native_token.clone(),
            },
            &keypair,
            Epoch(0),
            GAS_LIMIT_MULTIPLIER.into(),
            #[cfg(not(feature = "mainnet"))]
            None,
            None,
        ))));
        wrapper.header.chain_id = shell.chain_id.clone();
        wrapper.header.expiration = Some(DateTimeUtc::default());
        wrapper.set_code(Code::new("wasm_code".as_bytes().to_owned()));
        wrapper.set_data(Data::new("transaction data".as_bytes().to_owned()));
        wrapper.add_section(Section::Signature(Signature::new(
            &wrapper.header_hash(),
            &keypair,
        )));
        wrapper.encrypt(&Default::default());

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
        let (mut shell, _) = test_utils::setup(1);
        let keypair = crate::wallet::defaults::daewon_keypair();

        let mut wrapper = Tx::new(TxType::Wrapper(Box::new(WrapperTx::new(
            Fee {
                amount_per_gas_unit: 0.into(),
                token: shell.wl_storage.storage.native_token.clone(),
            },
            &keypair,
            Epoch(0),
            GAS_LIMIT_MULTIPLIER.into(),
            #[cfg(not(feature = "mainnet"))]
            None,
            None,
        ))));
        wrapper.header.chain_id = shell.chain_id.clone();
        wrapper.header.expiration = Some(DateTimeUtc::default());
        wrapper.set_code(Code::new("wasm_code".as_bytes().to_owned()));
        wrapper
            .set_data(Data::new("new transaction data".as_bytes().to_owned()));
        let mut decrypted = wrapper.clone();
        wrapper.encrypt(&Default::default());

        decrypted.update_header(TxType::Decrypted(DecryptedTx::Decrypted {
            has_valid_pow: false,
        }));
        decrypted.add_section(Section::Signature(Signature::new(
            &decrypted.header_hash(),
            &keypair,
        )));
        let gas_limit = u64::from(wrapper.header.wrapper().unwrap().gas_limit)
            - wrapper.to_bytes().len() as u64;
        let wrapper_in_queue = TxInQueue {
            tx: wrapper,
            gas: gas_limit,
            has_valid_pow: false,
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
                    u32::from(ErrorCodes::ExpiredDecryptedTx)
                );
            }
            Err(_) => panic!("Test failed"),
        }
    }

    /// Test that a decrypted transaction requiring more gas than the limit
    /// imposed by its wrapper is rejected.
    #[test]
    fn test_decrypted_gas_limit() {
        let (mut shell, _) = test_utils::setup(1);
        let keypair = crate::wallet::defaults::daewon_keypair();

        let mut wrapper = Tx::new(TxType::Wrapper(Box::new(WrapperTx::new(
            Fee {
                amount_per_gas_unit: 1.into(),
                token: shell.wl_storage.storage.native_token.clone(),
            },
            &keypair,
            Epoch(0),
            GAS_LIMIT_MULTIPLIER.into(),
            #[cfg(not(feature = "mainnet"))]
            None,
            None,
        ))));
        wrapper.header.chain_id = shell.chain_id.clone();
        wrapper.set_code(Code::new("wasm_code".as_bytes().to_owned()));
        wrapper.set_data(Data::new("transaction data".as_bytes().to_owned()));

        let mut decrypted_tx = wrapper.clone();
        decrypted_tx.update_header(TxType::Decrypted(DecryptedTx::Decrypted {
            #[cfg(not(feature = "mainnet"))]
            has_valid_pow: false,
        }));
        decrypted_tx.add_section(Section::Signature(Signature::new(
            &decrypted_tx.header_hash(),
            &keypair,
        )));

        let wrapper_in_queue = TxInQueue {
            tx: wrapper,
            gas: 0,
            has_valid_pow: false,
        };
        shell.wl_storage.storage.tx_queue.push(wrapper_in_queue);

        // Run validation
        let request = ProcessProposal {
            txs: vec![decrypted_tx.to_bytes()],
        };
        match shell.process_proposal(request) {
            Ok(response) => {
                assert_eq!(
                    response[0].result.code,
                    u32::from(ErrorCodes::DecryptedTxGasLimit)
                );
            }
            Err(_) => panic!("Test failed"),
        }
    }

    /// Check that a tx requiring more gas than the block limit causes a block
    /// rejection
    #[test]
    fn test_exceeding_max_block_gas_tx() {
        let (shell, _) = test_utils::setup(1);

        let block_gas_limit: u64 = shell
            .wl_storage
            .read(&parameters::storage::get_max_block_gas_key())
            .expect("Error while reading from storage")
            .expect("Missing max_block_gas parameter in storage");
        let keypair = super::test_utils::gen_keypair();

        let mut wrapper = Tx::new(TxType::Wrapper(Box::new(WrapperTx::new(
            Fee {
                amount_per_gas_unit: 100.into(),
                token: shell.wl_storage.storage.native_token.clone(),
            },
            &keypair,
            Epoch(0),
            (block_gas_limit + 1).into(),
            #[cfg(not(feature = "mainnet"))]
            None,
            None,
        ))));
        wrapper.header.chain_id = shell.chain_id.clone();
        wrapper.set_code(Code::new("wasm_code".as_bytes().to_owned()));
        wrapper.set_data(Data::new("transaction data".as_bytes().to_owned()));
        wrapper.add_section(Section::Signature(Signature::new(
            &wrapper.header_hash(),
            &keypair,
        )));
        wrapper.encrypt(&Default::default());

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
        let (shell, _) = test_utils::setup(1);
        let keypair = super::test_utils::gen_keypair();

        let mut wrapper = Tx::new(TxType::Wrapper(Box::new(WrapperTx::new(
            Fee {
                amount_per_gas_unit: 100.into(),
                token: shell.wl_storage.storage.native_token.clone(),
            },
            &keypair,
            Epoch(0),
            0.into(),
            #[cfg(not(feature = "mainnet"))]
            None,
            None,
        ))));
        wrapper.header.chain_id = shell.chain_id.clone();
        wrapper.set_code(Code::new("wasm_code".as_bytes().to_owned()));
        wrapper.set_data(Data::new("transaction data".as_bytes().to_owned()));
        wrapper.add_section(Section::Signature(Signature::new(
            &wrapper.header_hash(),
            &keypair,
        )));
        wrapper.encrypt(&Default::default());

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

    // Check that a wrapper using a non-whitelisted token for fee payment causes a block rejection
    #[test]
    fn test_fee_non_whitelisted_token() {
        let (shell, _) = test_utils::setup(1);

        let mut wrapper = Tx::new(TxType::Wrapper(Box::new(WrapperTx::new(
            Fee {
                amount_per_gas_unit: 100.into(),
                token: address::btc(),
            },
            &crate::wallet::defaults::albert_keypair(),
            Epoch(0),
            GAS_LIMIT_MULTIPLIER.into(),
            #[cfg(not(feature = "mainnet"))]
            None,
            None,
        ))));
        wrapper.header.chain_id = shell.chain_id.clone();
        wrapper.set_code(Code::new("wasm_code".as_bytes().to_owned()));
        wrapper.set_data(Data::new("transaction data".as_bytes().to_owned()));
        wrapper.add_section(Section::Signature(Signature::new(
            &wrapper.header_hash(),
            &crate::wallet::defaults::albert_keypair(),
        )));
        wrapper.encrypt(&Default::default());

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

    // Check that a wrapper setting a fee amount lower than the minimum required causes a block rejection
    #[test]
    fn test_fee_wrong_minimum_amount() {
        let (shell, _) = test_utils::setup(1);

        let mut wrapper = Tx::new(TxType::Wrapper(Box::new(WrapperTx::new(
            Fee {
                amount_per_gas_unit: 0.into(),
                token: shell.wl_storage.storage.native_token.clone(),
            },
            &crate::wallet::defaults::albert_keypair(),
            Epoch(0),
            GAS_LIMIT_MULTIPLIER.into(),
            #[cfg(not(feature = "mainnet"))]
            None,
            None,
        ))));
        wrapper.header.chain_id = shell.chain_id.clone();
        wrapper.set_code(Code::new("wasm code".as_bytes().to_owned()));
        wrapper.set_data(Data::new("transaction data".as_bytes().to_owned()));
        wrapper.add_section(Section::Signature(Signature::new(
            &wrapper.header_hash(),
            &crate::wallet::defaults::albert_keypair(),
        )));
        wrapper.encrypt(&Default::default());

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

    // Check that a wrapper transactions whose fees cannot be paid causes a block rejection
    #[test]
    fn test_insufficient_balance_for_fee() {
        let (shell, _) = test_utils::setup(1);

        let mut wrapper = Tx::new(TxType::Wrapper(Box::new(WrapperTx::new(
            Fee {
                amount_per_gas_unit: 1_000_000.into(),
                token: shell.wl_storage.storage.native_token.clone(),
            },
            &crate::wallet::defaults::albert_keypair(),
            Epoch(0),
            GAS_LIMIT_MULTIPLIER.into(),
            #[cfg(not(feature = "mainnet"))]
            None,
            None,
        ))));
        wrapper.header.chain_id = shell.chain_id.clone();
        wrapper.set_code(Code::new("wasm code".as_bytes().to_owned()));
        wrapper.set_data(Data::new("transaction data".as_bytes().to_owned()));
        wrapper.add_section(Section::Signature(Signature::new(
            &wrapper.header_hash(),
            &crate::wallet::defaults::albert_keypair(),
        )));
        wrapper.encrypt(&Default::default());

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

    // Check that a fee overflow in the wrapper transaction causes a block rejection
    #[test]
    fn test_wrapper_fee_overflow() {
        let (shell, _) = test_utils::setup(1);

        let mut wrapper = Tx::new(TxType::Wrapper(Box::new(WrapperTx::new(
            Fee {
                amount_per_gas_unit: token::Amount::max(),
                token: shell.wl_storage.storage.native_token.clone(),
            },
            &crate::wallet::defaults::albert_keypair(),
            Epoch(0),
            GAS_LIMIT_MULTIPLIER.into(),
            #[cfg(not(feature = "mainnet"))]
            None,
            None,
        ))));
        wrapper.header.chain_id = shell.chain_id.clone();
        wrapper.set_code(Code::new("wasm code".as_bytes().to_owned()));
        wrapper.set_data(Data::new("transaction data".as_bytes().to_owned()));
        wrapper.add_section(Section::Signature(Signature::new(
            &wrapper.header_hash(),
            &crate::wallet::defaults::albert_keypair(),
        )));
        wrapper.encrypt(&Default::default());

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
}
