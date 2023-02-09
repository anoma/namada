//! Implementation of the ['VerifyHeader`], [`ProcessProposal`],
//! and [`RevertProposal`] ABCI++ methods for the Shell

use namada::types::internal::WrapperTxInQueue;

use super::*;
use crate::facade::tendermint_proto::abci::response_process_proposal::ProposalStatus;
use crate::facade::tendermint_proto::abci::RequestProcessProposal;
use crate::node::ledger::shims::abcipp_shim_types::shim::response::ProcessProposal;

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
    ) -> ProcessProposal {
        let tx_results = self.process_txs(&req.txs);

        ProcessProposal {
            status: if tx_results.iter().any(|res| res.code > 3) {
                ProposalStatus::Reject as i32
            } else {
                ProposalStatus::Accept as i32
            },
            tx_results,
        }
    }

    /// Check all the given txs.
    pub fn process_txs(&self, txs: &[Vec<u8>]) -> Vec<TxResult> {
        let mut tx_queue_iter = self.wl_storage.storage.tx_queue.iter();
        txs.iter()
            .map(|tx_bytes| {
                self.process_single_tx(tx_bytes, &mut tx_queue_iter)
            })
            .collect()
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
    ///
    /// INVARIANT: Any changes applied in this method must be reverted if the
    /// proposal is rejected (unless we can simply overwrite them in the
    /// next block).
    pub(crate) fn process_single_tx<'a>(
        &self,
        tx_bytes: &[u8],
        tx_queue_iter: &mut impl Iterator<Item = &'a WrapperTxInQueue>,
    ) -> TxResult {
        let tx = match Tx::try_from(tx_bytes) {
            Ok(tx) => tx,
            Err(_) => {
                return TxResult {
                    code: ErrorCodes::InvalidTx.into(),
                    info: "The submitted transaction was not deserializable"
                        .into(),
                };
            }
        };
        // TODO: This should not be hardcoded
        let privkey = <EllipticCurve as PairingEngine>::G2Affine::prime_subgroup_generator();

        match process_tx(tx) {
            // This occurs if the wrapper / protocol tx signature is invalid
            Err(err) => TxResult {
                code: ErrorCodes::InvalidSig.into(),
                info: err.to_string(),
            },
            Ok(result) => match result {
                // If it is a raw transaction, we do no further validation
                TxType::Raw(_) => TxResult {
                    code: ErrorCodes::InvalidTx.into(),
                    info: "Transaction rejected: Non-encrypted transactions \
                           are not supported"
                        .into(),
                },
                TxType::Protocol(_) => TxResult {
                    code: ErrorCodes::InvalidTx.into(),
                    info: "Protocol transactions are a fun new feature that \
                           is coming soon to a blockchain near you. Patience."
                        .into(),
                },
                TxType::Decrypted(tx) => match tx_queue_iter.next() {
                    Some(WrapperTxInQueue {
                        tx: wrapper,
                        #[cfg(not(feature = "mainnet"))]
                            has_valid_pow: _,
                    }) => {
                        if wrapper.tx_hash != tx.hash_commitment() {
                            TxResult {
                                code: ErrorCodes::InvalidOrder.into(),
                                info: "Process proposal rejected a decrypted \
                                       transaction that violated the tx order \
                                       determined in the previous block"
                                    .into(),
                            }
                        } else if verify_decrypted_correctly(&tx, privkey) {
                            TxResult {
                                code: ErrorCodes::Ok.into(),
                                info: "Process Proposal accepted this \
                                       transaction"
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
                },
                TxType::Wrapper(tx) => {
                    // validate the ciphertext via Ferveo
                    if !tx.validate_ciphertext() {
                        TxResult {
                            code: ErrorCodes::InvalidTx.into(),
                            info: format!(
                                "The ciphertext of the wrapped tx {} is \
                                 invalid",
                                hash_tx(tx_bytes)
                            ),
                        }
                    } else {
                        // If the public key corresponds to the MASP sentinel
                        // transaction key, then the fee payer is effectively
                        // the MASP, otherwise derive
                        // they payer from public key.
                        let fee_payer = if tx.pk != masp_tx_key().ref_to() {
                            tx.fee_payer()
                        } else {
                            masp()
                        };
                        // check that the fee payer has sufficient balance
                        let balance =
                            self.get_balance(&tx.fee.token, &fee_payer);

                        // In testnets, tx is allowed to skip fees if it
                        // includes a valid PoW
                        #[cfg(not(feature = "mainnet"))]
                        let has_valid_pow = self.has_valid_pow_solution(&tx);
                        #[cfg(feature = "mainnet")]
                        let has_valid_pow = false;

                        if has_valid_pow
                            || self.get_wrapper_tx_fees() <= balance
                        {
                            TxResult {
                                code: ErrorCodes::Ok.into(),
                                info: "Process proposal accepted this \
                                       transaction"
                                    .into(),
                            }
                        } else {
                            TxResult {
                                code: ErrorCodes::InvalidTx.into(),
                                info: "The address given does not have \
                                       sufficient balance to pay fee"
                                    .into(),
                            }
                        }
                    }
                }
            },
        }
    }

    pub fn revert_proposal(
        &mut self,
        _req: shim::request::RevertProposal,
    ) -> shim::response::RevertProposal {
        Default::default()
    }
}

/// We test the failure cases of [`process_proposal`]. The happy flows
/// are covered by the e2e tests.
#[cfg(test)]
mod test_process_proposal {
    use borsh::BorshDeserialize;
    use namada::proto::SignedTxData;
    use namada::types::hash::Hash;
    use namada::types::key::*;
    use namada::types::storage::Epoch;
    use namada::types::token::Amount;
    use namada::types::transaction::encrypted::EncryptedTx;
    use namada::types::transaction::{EncryptionKey, Fee, WrapperTx};

    use super::*;
    use crate::facade::tendermint_proto::abci::RequestInitChain;
    use crate::facade::tendermint_proto::google::protobuf::Timestamp;
    use crate::node::ledger::shell::test_utils::{
        gen_keypair, ProcessProposal, TestError, TestShell,
    };

    /// Test that if a wrapper tx is not signed, it is rejected
    /// by [`process_proposal`].
    #[test]
    fn test_unsigned_wrapper_rejected() {
        let (mut shell, _) = TestShell::new();
        let keypair = gen_keypair();
        let tx = Tx::new(
            "wasm_code".as_bytes().to_owned(),
            Some("transaction data".as_bytes().to_owned()),
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
        )
        .to_bytes();
        #[allow(clippy::redundant_clone)]
        let request = ProcessProposal {
            txs: vec![tx.clone()],
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
        assert_eq!(response.result.code, u32::from(ErrorCodes::InvalidSig));
        assert_eq!(
            response.result.info,
            String::from("Wrapper transactions must be signed")
        );
    }

    /// Test that a wrapper tx with invalid signature is rejected
    #[test]
    fn test_wrapper_bad_signature_rejected() {
        let (mut shell, _) = TestShell::new();
        let keypair = gen_keypair();
        let tx = Tx::new(
            "wasm_code".as_bytes().to_owned(),
            Some("transaction data".as_bytes().to_owned()),
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
        .sign(&keypair)
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
                code: vec![],
                data: Some(
                    SignedTxData {
                        sig,
                        data: Some(new_data),
                    }
                    .try_to_vec()
                    .expect("Test failed"),
                ),
                timestamp,
            }
        } else {
            panic!("Test failed");
        };
        let request = ProcessProposal {
            txs: vec![new_tx.to_bytes()],
        };
        let response = if let [response] = shell
            .process_proposal(request)
            .expect("Test failed")
            .as_slice()
        {
            response.clone()
        } else {
            panic!("Test failed")
        };
        let expected_error = "Signature verification failed: Invalid signature";
        assert_eq!(response.result.code, u32::from(ErrorCodes::InvalidSig));
        assert!(
            response.result.info.contains(expected_error),
            "Result info {} doesn't contain the expected error {}",
            response.result.info,
            expected_error
        );
    }

    /// Test that if the account submitting the tx is not known and the fee is
    /// non-zero, [`process_proposal`] rejects that tx
    #[test]
    fn test_wrapper_unknown_address() {
        let (mut shell, _) = TestShell::new();
        let keypair = crate::wallet::defaults::keys().remove(0).1;
        let tx = Tx::new(
            "wasm_code".as_bytes().to_owned(),
            Some("transaction data".as_bytes().to_owned()),
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
        .sign(&keypair)
        .expect("Test failed");
        let request = ProcessProposal {
            txs: vec![wrapper.to_bytes()],
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
        assert_eq!(response.result.code, u32::from(ErrorCodes::InvalidTx));
        assert_eq!(
            response.result.info,
            "The address given does not have sufficient balance to pay fee"
                .to_string(),
        );
    }

    /// Test that if the account submitting the tx does
    /// not have sufficient balance to pay the fee,
    /// [`process_proposal`] rejects that tx
    #[test]
    fn test_wrapper_insufficient_balance_address() {
        let (mut shell, _) = TestShell::new();
        let keypair = crate::wallet::defaults::daewon_keypair();
        // reduce address balance to match the 100 token fee
        let balance_key = token::balance_key(
            &shell.wl_storage.storage.native_token,
            &Address::from(&keypair.ref_to()),
        );
        shell
            .wl_storage
            .storage
            .write(&balance_key, Amount::whole(99).try_to_vec().unwrap())
            .unwrap();

        let tx = Tx::new(
            "wasm_code".as_bytes().to_owned(),
            Some("transaction data".as_bytes().to_owned()),
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
        .sign(&keypair)
        .expect("Test failed");

        let request = ProcessProposal {
            txs: vec![wrapper.to_bytes()],
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
        assert_eq!(response.result.code, u32::from(ErrorCodes::InvalidTx));
        assert_eq!(
            response.result.info,
            String::from(
                "The address given does not have sufficient balance to pay fee"
            )
        );
    }

    /// Test that if the expected order of decrypted txs is
    /// validated, [`process_proposal`] rejects it
    #[test]
    fn test_decrypted_txs_out_of_order() {
        let (mut shell, _) = TestShell::new();
        let keypair = gen_keypair();
        let mut txs = vec![];
        for i in 0..3 {
            let tx = Tx::new(
                "wasm_code".as_bytes().to_owned(),
                Some(format!("transaction data: {}", i).as_bytes().to_owned()),
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
            txs.push(Tx::from(TxType::Decrypted(DecryptedTx::Decrypted {
                tx,
                #[cfg(not(feature = "mainnet"))]
                has_valid_pow: false,
            })));
        }
        let req_1 = ProcessProposal {
            txs: vec![txs[0].to_bytes()],
        };
        let response_1 = if let [resp] = shell
            .process_proposal(req_1)
            .expect("Test failed")
            .as_slice()
        {
            resp.clone()
        } else {
            panic!("Test failed")
        };
        assert_eq!(response_1.result.code, u32::from(ErrorCodes::Ok));

        let req_2 = ProcessProposal {
            txs: vec![txs[2].to_bytes()],
        };

        let response_2 = if let Err(TestError::RejectProposal(resp)) =
            shell.process_proposal(req_2)
        {
            if let [resp] = resp.as_slice() {
                resp.clone()
            } else {
                panic!("Test failed")
            }
        } else {
            panic!("Test failed")
        };
        assert_eq!(response_2.result.code, u32::from(ErrorCodes::InvalidOrder));
        assert_eq!(
            response_2.result.info,
            String::from(
                "Process proposal rejected a decrypted transaction that \
                 violated the tx order determined in the previous block"
            ),
        );
    }

    /// Test that a tx incorrectly labelled as undecryptable
    /// is rejected by [`process_proposal`]
    #[test]
    fn test_incorrectly_labelled_as_undecryptable() {
        let (mut shell, _) = TestShell::new();
        let keypair = gen_keypair();

        let tx = Tx::new(
            "wasm_code".as_bytes().to_owned(),
            Some("transaction data".as_bytes().to_owned()),
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

        let tx =
            Tx::from(TxType::Decrypted(DecryptedTx::Undecryptable(wrapper)));

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
        let (mut shell, _) = TestShell::new();
        shell.init_chain(
            RequestInitChain {
                time: Some(Timestamp {
                    seconds: 0,
                    nanos: 0,
                }),
                chain_id: ChainId::default().to_string(),
                ..Default::default()
            },
            1,
        );
        let keypair = crate::wallet::defaults::daewon_keypair();

        let tx = Tx::new(
            "wasm_code".as_bytes().to_owned(),
            Some("transaction data".as_bytes().to_owned()),
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
        let tx = Tx::from(TxType::Decrypted(DecryptedTx::Undecryptable(
            #[allow(clippy::redundant_clone)]
            wrapper.clone(),
        )));

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
        let (mut shell, _) = TestShell::new();
        shell.init_chain(
            RequestInitChain {
                time: Some(Timestamp {
                    seconds: 0,
                    nanos: 0,
                }),
                chain_id: ChainId::default().to_string(),
                ..Default::default()
            },
            1,
        );
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
        let signed = Tx::from(TxType::Decrypted(DecryptedTx::Undecryptable(
            #[allow(clippy::redundant_clone)]
            wrapper.clone(),
        )));
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
        let (mut shell, _) = TestShell::new();

        let tx = Tx::new(
            "wasm_code".as_bytes().to_owned(),
            Some("transaction data".as_bytes().to_owned()),
        );

        let tx = Tx::from(TxType::Decrypted(DecryptedTx::Decrypted {
            tx,
            #[cfg(not(feature = "mainnet"))]
            has_valid_pow: false,
        }));

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

    /// Process Proposal should reject a RawTx, but not panic
    #[test]
    fn test_raw_tx_rejected() {
        let (mut shell, _) = TestShell::new();

        let tx = Tx::new(
            "wasm_code".as_bytes().to_owned(),
            Some("transaction data".as_bytes().to_owned()),
        );
        let tx = Tx::from(TxType::Raw(tx));
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
        assert_eq!(response.result.code, u32::from(ErrorCodes::InvalidTx));
        assert_eq!(
            response.result.info,
            String::from(
                "Transaction rejected: Non-encrypted transactions are not \
                 supported"
            ),
        );
    }
}
