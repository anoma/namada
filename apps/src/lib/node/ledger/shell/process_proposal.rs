//! Implementation of the ['VerifyHeader`], [`ProcessProposal`],
//! and [`RevertProposal`] ABCI++ methods for the Shell

use data_encoding::HEXUPPER;
use namada::core::hints;
use namada::core::ledger::storage::WlStorage;
use namada::ledger::storage::TempWlStorage;
use namada::proof_of_stake::pos_queries::PosQueries;
use namada::types::internal::WrapperTxInQueue;

use super::*;
use crate::facade::tendermint_proto::abci::response_process_proposal::ProposalStatus;
use crate::facade::tendermint_proto::abci::RequestProcessProposal;
use crate::node::ledger::shell::block_space_alloc::{
    threshold, AllocFailure, TxBin,
};
use crate::node::ledger::shims::abcipp_shim_types::shim::response::ProcessProposal;
use crate::node::ledger::shims::abcipp_shim_types::shim::TxBytes;

/// Validation metadata, to keep track of used resources or
/// transaction numbers, in a block proposal.
#[derive(Default)]
pub struct ValidationMeta {
    /// Space utilized by encrypted txs.
    pub encrypted_txs_bin: TxBin,
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
        let encrypted_txs_bin =
            TxBin::init_over_ratio(max_proposal_bytes, threshold::ONE_THIRD);
        let txs_bin = TxBin::init(max_proposal_bytes);
        Self {
            decrypted_queue_has_remaining_txs: false,
            has_decrypted_txs: false,
            encrypted_txs_bin,
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
        let (tx_results, metadata) =
            self.process_txs(&req.txs, self.get_block_timestamp(req.time));

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
    ) -> (Vec<TxResult>, ValidationMeta) {
        let mut tx_queue_iter = self.wl_storage.storage.tx_queue.iter();
        let mut temp_wl_storage = TempWlStorage::new(&self.wl_storage.storage);
        let mut metadata = ValidationMeta::from(&self.wl_storage);
        let tx_results = txs
            .iter()
            .map(|tx_bytes| {
                let result = self.process_single_tx(
                    tx_bytes,
                    &mut tx_queue_iter,
                    &mut metadata,
                    &mut temp_wl_storage,
                    block_time,
                );
                if let ErrorCodes::Ok =
                    ErrorCodes::from_u32(result.code).unwrap()
                {
                    temp_wl_storage.write_log.commit_tx();
                } else {
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
    pub(crate) fn process_single_tx<'a>(
        &self,
        tx_bytes: &[u8],
        tx_queue_iter: &mut impl Iterator<Item = &'a WrapperTxInQueue>,
        metadata: &mut ValidationMeta,
        temp_wl_storage: &mut TempWlStorage<D, H>,
        block_time: DateTimeUtc,
    ) -> TxResult {
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
                let tx_chain_id = tx.chain_id.clone();
                let tx_expiration = tx.expiration;
                let tx_type = process_tx(tx).map_err(|err| {
                    // This occurs if the wrapper / protocol tx signature is
                    // invalid
                    TxResult {
                        code: ErrorCodes::InvalidSig.into(),
                        info: err.to_string(),
                    }
                })?;
                Ok((tx_chain_id, tx_expiration, tx_type))
            },
        );
        let (tx_chain_id, tx_expiration, tx) = match maybe_tx {
            Ok(tx) => tx,
            Err(tx_result) => return tx_result,
        };

        // TODO: This should not be hardcoded
        let privkey = <EllipticCurve as PairingEngine>::G2Affine::prime_subgroup_generator();

        match tx {
            // If it is a raw transaction, we do no further validation
            TxType::Raw(_) => TxResult {
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
            TxType::Decrypted(tx) => {
                metadata.has_decrypted_txs = true;
                match tx_queue_iter.next() {
                    Some(wrapper) => {
                        if wrapper.tx.tx_hash != tx.hash_commitment() {
                            TxResult {
                                code: ErrorCodes::InvalidOrder.into(),
                                info: "Process proposal rejected a decrypted \
                                       transaction that violated the tx order \
                                       determined in the previous block"
                                    .into(),
                            }
                        } else if verify_decrypted_correctly(&tx, privkey) {
                            if let DecryptedTx::Decrypted {
                                tx,
                                has_valid_pow: _,
                            } = tx
                            {
                                // Tx chain id
                                if tx.chain_id != self.chain_id {
                                    return TxResult {
                                        code:
                                            ErrorCodes::InvalidDecryptedChainId
                                                .into(),
                                        info: format!(
                                            "Decrypted tx carries a wrong \
                                             chain id: expected {}, found {}",
                                            self.chain_id, tx.chain_id
                                        ),
                                    };
                                }

                                // Tx expiration
                                if let Some(exp) = tx.expiration {
                                    if block_time > exp {
                                        return TxResult {
                                            code:
                                                ErrorCodes::ExpiredDecryptedTx
                                                    .into(),
                                            info: format!(
                                                "Decrypted tx expired at \
                                                 {:#?}, block time: {:#?}",
                                                exp, block_time
                                            ),
                                        };
                                    }
                                }
                            }
                            TxResult {
                                code: ErrorCodes::Ok.into(),
                                info: "Process Proposal accepted this \
                                       transaction"
                                    .into(),
                            }
                        } else {
                            // Wrong inner tx commitment
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
                // decrypted txs shouldn't show up before wrapper txs
                if metadata.has_decrypted_txs {
                    return TxResult {
                        code: ErrorCodes::InvalidTx.into(),
                        info: "Decrypted txs should not be proposed before \
                               wrapper txs"
                            .into(),
                    };
                }
                // try to allocate space for this encrypted tx
                if let Err(e) = metadata.encrypted_txs_bin.try_dump(tx_bytes) {
                    return TxResult {
                        code: ErrorCodes::AllocationError.into(),
                        info: match e {
                            AllocFailure::Rejected { .. } => {
                                "No more space left in the block for wrapper \
                                 txs"
                            }
                            AllocFailure::OverflowsBin { .. } => {
                                "The given wrapper tx is larger than 1/3 of \
                                 the available block space"
                            }
                        }
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
                if !wrapper.validate_ciphertext() {
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
                        &wrapper,
                        tx_bytes,
                        temp_wl_storage,
                    ) {
                        return TxResult {
                            code: ErrorCodes::ReplayTx.into(),
                            info: e.to_string(),
                        };
                    }

                    // If the public key corresponds to the MASP sentinel
                    // transaction key, then the fee payer is effectively
                    // the MASP, otherwise derive
                    // they payer from public key.
                    let fee_payer = if wrapper.pk != masp_tx_key().ref_to() {
                        wrapper.fee_payer()
                    } else {
                        masp()
                    };
                    // check that the fee payer has sufficient balance
                    let balance =
                        self.get_balance(&wrapper.fee.token, &fee_payer);

                    // In testnets, tx is allowed to skip fees if it
                    // includes a valid PoW
                    #[cfg(not(feature = "mainnet"))]
                    let has_valid_pow = self.has_valid_pow_solution(&wrapper);
                    #[cfg(feature = "mainnet")]
                    let has_valid_pow = false;

                    if has_valid_pow || self.get_wrapper_tx_fees() <= balance {
                        TxResult {
                            code: ErrorCodes::Ok.into(),
                            info: "Process proposal accepted this transaction"
                                .into(),
                        }
                    } else {
                        TxResult {
                            code: ErrorCodes::InvalidTx.into(),
                            info: "The address given does not have sufficient \
                                   balance to pay fee"
                                .into(),
                        }
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
    use namada::ledger::parameters::storage::get_wrapper_tx_fees_key;
    use namada::proto::SignedTxData;
    use namada::types::hash::Hash;
    use namada::types::key::*;
    use namada::types::storage::Epoch;
    use namada::types::token::Amount;
    use namada::types::transaction::encrypted::EncryptedTx;
    use namada::types::transaction::protocol::ProtocolTxType;
    use namada::types::transaction::{EncryptionKey, Fee, WrapperTx, MIN_FEE};

    use super::*;
    use crate::node::ledger::shell::test_utils::{
        self, gen_keypair, ProcessProposal, TestError,
    };

    /// Test that if a wrapper tx is not signed, the block is rejected
    /// by [`process_proposal`].
    #[test]
    fn test_unsigned_wrapper_rejected() {
        let (mut shell, _) = test_utils::setup(1);
        let keypair = gen_keypair();
        let tx = Tx::new(
            "wasm_code".as_bytes().to_owned(),
            Some("transaction data".as_bytes().to_owned()),
            shell.chain_id.clone(),
            None,
        );
        let wrapper = WrapperTx::new(
            Fee {
                amount: 0.into(),
                token: shell.wl_storage.storage.native_token.clone(),
            },
            &keypair,
            Epoch(0),
            0.into(),
            tx,
            Default::default(),
            #[cfg(not(feature = "mainnet"))]
            None,
        );
        let tx = Tx::new(
            vec![],
            Some(TxType::Wrapper(wrapper).try_to_vec().expect("Test failed")),
            shell.chain_id.clone(),
            None,
        )
        .to_bytes();
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
                    String::from("Wrapper transactions must be signed")
                );
            }
        }
    }

    /// Test that a block including a wrapper tx with invalid signature is
    /// rejected
    #[test]
    fn test_wrapper_bad_signature_rejected() {
        let (mut shell, _) = test_utils::setup(1);
        let keypair = gen_keypair();
        let tx = Tx::new(
            "wasm_code".as_bytes().to_owned(),
            Some("transaction data".as_bytes().to_owned()),
            shell.chain_id.clone(),
            None,
        );
        let timestamp = tx.timestamp;
        let mut wrapper = WrapperTx::new(
            Fee {
                amount: 100.into(),
                token: shell.wl_storage.storage.native_token.clone(),
            },
            &keypair,
            Epoch(0),
            0.into(),
            tx,
            Default::default(),
            #[cfg(not(feature = "mainnet"))]
            None,
        )
        .sign(&keypair, shell.chain_id.clone(), None)
        .expect("Test failed");
        let new_tx = if let Some(Ok(SignedTxData {
            data: Some(data),
            sig,
        })) = wrapper
            .data
            .take()
            .map(|data| SignedTxData::try_from_slice(&data[..]))
        {
            let mut new_wrapper = if let TxType::Wrapper(wrapper) =
                <TxType as BorshDeserialize>::deserialize(&mut data.as_ref())
                    .expect("Test failed")
            {
                wrapper
            } else {
                panic!("Test failed")
            };

            // we mount a malleability attack to try and remove the fee
            new_wrapper.fee.amount = 0.into();
            let new_data = TxType::Wrapper(new_wrapper)
                .try_to_vec()
                .expect("Test failed");
            Tx {
                code_or_hash: vec![],
                data: Some(
                    SignedTxData {
                        sig,
                        data: Some(new_data),
                    }
                    .try_to_vec()
                    .expect("Test failed"),
                ),
                timestamp,
                chain_id: shell.chain_id.clone(),
                expiration: None,
            }
        } else {
            panic!("Test failed");
        };
        let request = ProcessProposal {
            txs: vec![new_tx.to_bytes()],
        };

        match shell.process_proposal(request) {
            Ok(_) => panic!("Test failed"),
            Err(TestError::RejectProposal(response)) => {
                let expected_error =
                    "Signature verification failed: Invalid signature";
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
        shell
            .wl_storage
            .write_log
            .write(
                &get_wrapper_tx_fees_key(),
                token::Amount::whole(MIN_FEE).try_to_vec().unwrap(),
            )
            .unwrap();
        let keypair = gen_keypair();
        let tx = Tx::new(
            "wasm_code".as_bytes().to_owned(),
            Some("transaction data".as_bytes().to_owned()),
            shell.chain_id.clone(),
            None,
        );
        let wrapper = WrapperTx::new(
            Fee {
                amount: 1.into(),
                token: shell.wl_storage.storage.native_token.clone(),
            },
            &keypair,
            Epoch(0),
            0.into(),
            tx,
            Default::default(),
            #[cfg(not(feature = "mainnet"))]
            None,
        )
        .sign(&keypair, shell.chain_id.clone(), None)
        .expect("Test failed");
        let request = ProcessProposal {
            txs: vec![wrapper.to_bytes()],
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
                    "The address given does not have sufficient balance to \
                     pay fee"
                        .to_string(),
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
        // reduce address balance to match the 100 token fee
        let balance_key = token::balance_key(
            &shell.wl_storage.storage.native_token,
            &Address::from(&keypair.ref_to()),
        );
        shell
            .wl_storage
            .write_log
            .write(&balance_key, Amount::whole(99).try_to_vec().unwrap())
            .unwrap();
        shell
            .wl_storage
            .write_log
            .write(
                &get_wrapper_tx_fees_key(),
                token::Amount::whole(MIN_FEE).try_to_vec().unwrap(),
            )
            .unwrap();

        let tx = Tx::new(
            "wasm_code".as_bytes().to_owned(),
            Some("transaction data".as_bytes().to_owned()),
            shell.chain_id.clone(),
            None,
        );
        let wrapper = WrapperTx::new(
            Fee {
                amount: Amount::whole(1_000_100),
                token: shell.wl_storage.storage.native_token.clone(),
            },
            &keypair,
            Epoch(0),
            0.into(),
            tx,
            Default::default(),
            #[cfg(not(feature = "mainnet"))]
            None,
        )
        .sign(&keypair, shell.chain_id.clone(), None)
        .expect("Test failed");

        let request = ProcessProposal {
            txs: vec![wrapper.to_bytes()],
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
                        "The address given does not have sufficient balance \
                         to pay fee"
                    )
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
            let tx = Tx::new(
                "wasm_code".as_bytes().to_owned(),
                Some(format!("transaction data: {}", i).as_bytes().to_owned()),
                shell.chain_id.clone(),
                None,
            );
            let wrapper = WrapperTx::new(
                Fee {
                    amount: i.into(),
                    token: shell.wl_storage.storage.native_token.clone(),
                },
                &keypair,
                Epoch(0),
                0.into(),
                tx.clone(),
                Default::default(),
                #[cfg(not(feature = "mainnet"))]
                None,
            );
            shell.enqueue_tx(wrapper);
            let mut decrypted_tx =
                Tx::from(TxType::Decrypted(DecryptedTx::Decrypted {
                    tx,
                    #[cfg(not(feature = "mainnet"))]
                    has_valid_pow: false,
                }));
            decrypted_tx.chain_id = shell.chain_id.clone();
            txs.push(decrypted_tx);
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

        let tx = Tx::new(
            "wasm_code".as_bytes().to_owned(),
            Some("transaction data".as_bytes().to_owned()),
            shell.chain_id.clone(),
            None,
        );
        let wrapper = WrapperTx::new(
            Fee {
                amount: 0.into(),
                token: shell.wl_storage.storage.native_token.clone(),
            },
            &keypair,
            Epoch(0),
            0.into(),
            tx,
            Default::default(),
            #[cfg(not(feature = "mainnet"))]
            None,
        );
        shell.enqueue_tx(wrapper.clone());

        let mut tx =
            Tx::from(TxType::Decrypted(DecryptedTx::Undecryptable(wrapper)));
        tx.chain_id = shell.chain_id.clone();

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

        let tx = Tx::new(
            "wasm_code".as_bytes().to_owned(),
            Some("transaction data".as_bytes().to_owned()),
            shell.chain_id.clone(),
            None,
        );
        let mut wrapper = WrapperTx::new(
            Fee {
                amount: 0.into(),
                token: shell.wl_storage.storage.native_token.clone(),
            },
            &keypair,
            Epoch(0),
            0.into(),
            tx,
            Default::default(),
            #[cfg(not(feature = "mainnet"))]
            None,
        );
        wrapper.tx_hash = Hash([0; 32]);

        shell.enqueue_tx(wrapper.clone());
        let mut tx = Tx::from(TxType::Decrypted(DecryptedTx::Undecryptable(
            #[allow(clippy::redundant_clone)]
            wrapper.clone(),
        )));
        tx.chain_id = shell.chain_id.clone();

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
        let pubkey = EncryptionKey::default();
        // not valid tx bytes
        let tx = "garbage data".as_bytes().to_owned();
        let inner_tx = EncryptedTx::encrypt(&tx, pubkey);
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

        shell.enqueue_tx(wrapper.clone());
        let mut signed =
            Tx::from(TxType::Decrypted(DecryptedTx::Undecryptable(
                #[allow(clippy::redundant_clone)]
                wrapper.clone(),
            )));
        signed.chain_id = shell.chain_id.clone();
        let request = ProcessProposal {
            txs: vec![signed.to_bytes()],
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

        let tx = Tx::new(
            "wasm_code".as_bytes().to_owned(),
            Some("transaction data".as_bytes().to_owned()),
            shell.chain_id.clone(),
            None,
        );

        let mut tx = Tx::from(TxType::Decrypted(DecryptedTx::Decrypted {
            tx,
            #[cfg(not(feature = "mainnet"))]
            has_valid_pow: false,
        }));
        tx.chain_id = shell.chain_id.clone();

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
        let (mut shell, _) = test_utils::setup(1);

        let tx = Tx::new(
            "wasm_code".as_bytes().to_owned(),
            Some("transaction data".as_bytes().to_owned()),
            shell.chain_id.clone(),
            None,
        );
        let mut tx = Tx::from(TxType::Raw(tx));
        tx.chain_id = shell.chain_id.clone();
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

        let tx = Tx::new(
            "wasm_code".as_bytes().to_owned(),
            Some("transaction data".as_bytes().to_owned()),
            shell.chain_id.clone(),
            None,
        );
        let wrapper = WrapperTx::new(
            Fee {
                amount: 0.into(),
                token: shell.wl_storage.storage.native_token.clone(),
            },
            &keypair,
            Epoch(0),
            0.into(),
            tx,
            Default::default(),
            #[cfg(not(feature = "mainnet"))]
            None,
        );
        let signed = wrapper
            .sign(&keypair, shell.chain_id.clone(), None)
            .expect("Test failed");

        // Write wrapper hash to storage
        let wrapper_unsigned_hash = Hash(signed.unsigned_hash());
        let hash_key =
            replay_protection::get_tx_hash_key(&wrapper_unsigned_hash);
        shell
            .wl_storage
            .storage
            .write(&hash_key, vec![])
            .expect("Test failed");

        // Run validation
        let request = ProcessProposal {
            txs: vec![signed.to_bytes()],
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

        let tx = Tx::new(
            "wasm_code".as_bytes().to_owned(),
            Some("transaction data".as_bytes().to_owned()),
            shell.chain_id.clone(),
            None,
        );
        let wrapper = WrapperTx::new(
            Fee {
                amount: 0.into(),
                token: shell.wl_storage.storage.native_token.clone(),
            },
            &keypair,
            Epoch(0),
            0.into(),
            tx,
            Default::default(),
            #[cfg(not(feature = "mainnet"))]
            None,
        );
        let signed = wrapper
            .sign(&keypair, shell.chain_id.clone(), None)
            .expect("Test failed");

        // Run validation
        let request = ProcessProposal {
            txs: vec![signed.to_bytes(); 2],
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
                        wrapper.tx_hash
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

        let tx = Tx::new(
            "wasm_code".as_bytes().to_owned(),
            Some("transaction data".as_bytes().to_owned()),
            shell.chain_id.clone(),
            None,
        );
        let wrapper = WrapperTx::new(
            Fee {
                amount: 0.into(),
                token: shell.wl_storage.storage.native_token.clone(),
            },
            &keypair,
            Epoch(0),
            0.into(),
            tx,
            Default::default(),
            #[cfg(not(feature = "mainnet"))]
            None,
        );
        let inner_unsigned_hash = wrapper.tx_hash.clone();
        let signed = wrapper
            .sign(&keypair, shell.chain_id.clone(), None)
            .expect("Test failed");

        // Write inner hash to storage
        let hash_key = replay_protection::get_tx_hash_key(&inner_unsigned_hash);
        shell
            .wl_storage
            .storage
            .write(&hash_key, vec![])
            .expect("Test failed");

        // Run validation
        let request = ProcessProposal {
            txs: vec![signed.to_bytes()],
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
        let (mut shell, _) = test_utils::setup(1);

        let keypair = crate::wallet::defaults::daewon_keypair();
        let keypair_2 = crate::wallet::defaults::daewon_keypair();

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

        // Add unshielded balance for fee payment
        let balance_key = token::balance_key(
            &shell.wl_storage.storage.native_token,
            &Address::from(&keypair_2.ref_to()),
        );
        shell
            .wl_storage
            .storage
            .write(&balance_key, Amount::whole(1000).try_to_vec().unwrap())
            .unwrap();

        let tx = Tx::new(
            "wasm_code".as_bytes().to_owned(),
            Some("transaction data".as_bytes().to_owned()),
            shell.chain_id.clone(),
            None,
        );
        let wrapper = WrapperTx::new(
            Fee {
                amount: 0.into(),
                token: shell.wl_storage.storage.native_token.clone(),
            },
            &keypair,
            Epoch(0),
            0.into(),
            tx.clone(),
            Default::default(),
            #[cfg(not(feature = "mainnet"))]
            None,
        );
        let inner_unsigned_hash = wrapper.tx_hash.clone();
        let signed = wrapper
            .sign(&keypair, shell.chain_id.clone(), None)
            .expect("Test failed");

        let new_wrapper = WrapperTx::new(
            Fee {
                amount: 0.into(),
                token: shell.wl_storage.storage.native_token.clone(),
            },
            &keypair_2,
            Epoch(0),
            0.into(),
            tx,
            Default::default(),
            #[cfg(not(feature = "mainnet"))]
            None,
        );
        let new_signed = new_wrapper
            .sign(&keypair, shell.chain_id.clone(), None)
            .expect("Test failed");

        // Run validation
        let request = ProcessProposal {
            txs: vec![signed.to_bytes(), new_signed.to_bytes()],
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
        let (mut shell, _) = test_utils::setup(1);
        let keypair = crate::wallet::defaults::daewon_keypair();

        let tx = Tx::new(
            "wasm_code".as_bytes().to_owned(),
            Some("transaction data".as_bytes().to_owned()),
            shell.chain_id.clone(),
            None,
        );
        let wrapper = WrapperTx::new(
            Fee {
                amount: 0.into(),
                token: shell.wl_storage.storage.native_token.clone(),
            },
            &keypair,
            Epoch(0),
            0.into(),
            tx.clone(),
            Default::default(),
            #[cfg(not(feature = "mainnet"))]
            None,
        );
        let wrong_chain_id = ChainId("Wrong chain id".to_string());
        let signed = wrapper
            .sign(&keypair, wrong_chain_id.clone(), None)
            .expect("Test failed");

        let protocol_tx = ProtocolTxType::EthereumStateUpdate(tx).sign(
            &keypair.ref_to(),
            &keypair,
            wrong_chain_id.clone(),
        );

        // Run validation
        let request = ProcessProposal {
            txs: vec![signed.to_bytes(), protocol_tx.to_bytes()],
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
        let tx = Tx::new(
            "wasm_code".as_bytes().to_owned(),
            Some("new transaction data".as_bytes().to_owned()),
            wrong_chain_id.clone(),
            None,
        );
        let decrypted: Tx = DecryptedTx::Decrypted {
            tx: tx.clone(),
            has_valid_pow: false,
        }
        .into();
        let signed_decrypted = decrypted.sign(&keypair);
        let wrapper = WrapperTx::new(
            Fee {
                amount: 0.into(),
                token: shell.wl_storage.storage.native_token.clone(),
            },
            &keypair,
            Epoch(0),
            0.into(),
            tx,
            Default::default(),
            #[cfg(not(feature = "mainnet"))]
            None,
        );
        let wrapper_in_queue = WrapperTxInQueue {
            tx: wrapper,
            has_valid_pow: false,
        };
        shell.wl_storage.storage.tx_queue.push(wrapper_in_queue);

        // Run validation
        let request = ProcessProposal {
            txs: vec![signed_decrypted.to_bytes()],
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
        let (mut shell, _) = test_utils::setup(1);
        let keypair = crate::wallet::defaults::daewon_keypair();

        let tx = Tx::new(
            "wasm_code".as_bytes().to_owned(),
            Some("transaction data".as_bytes().to_owned()),
            shell.chain_id.clone(),
            None,
        );
        let wrapper = WrapperTx::new(
            Fee {
                amount: 0.into(),
                token: shell.wl_storage.storage.native_token.clone(),
            },
            &keypair,
            Epoch(0),
            0.into(),
            tx,
            Default::default(),
            #[cfg(not(feature = "mainnet"))]
            None,
        );
        let signed = wrapper
            .sign(&keypair, shell.chain_id.clone(), Some(DateTimeUtc::now()))
            .expect("Test failed");

        // Run validation
        let request = ProcessProposal {
            txs: vec![signed.to_bytes()],
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

        let tx = Tx::new(
            "wasm_code".as_bytes().to_owned(),
            Some("new transaction data".as_bytes().to_owned()),
            shell.chain_id.clone(),
            Some(DateTimeUtc::now()),
        );
        let decrypted: Tx = DecryptedTx::Decrypted {
            tx: tx.clone(),
            has_valid_pow: false,
        }
        .into();
        let signed_decrypted = decrypted.sign(&keypair);
        let wrapper = WrapperTx::new(
            Fee {
                amount: 0.into(),
                token: shell.wl_storage.storage.native_token.clone(),
            },
            &keypair,
            Epoch(0),
            0.into(),
            tx,
            Default::default(),
            #[cfg(not(feature = "mainnet"))]
            None,
        );
        let wrapper_in_queue = WrapperTxInQueue {
            tx: wrapper,
            has_valid_pow: false,
        };
        shell.wl_storage.storage.tx_queue.push(wrapper_in_queue);

        // Run validation
        let request = ProcessProposal {
            txs: vec![signed_decrypted.to_bytes()],
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
}
