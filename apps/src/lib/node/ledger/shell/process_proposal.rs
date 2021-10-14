//! Implementation of the ['VerifyHeader`], [`ProcessProposal`],
//! and [`RevertProposal`] ABCI++ methods for the Shell
use super::*;

impl Shell {
    /// INVARIANT: This method must be stateless.
    pub fn verify_header(
        &self,
        _req: shim::request::VerifyHeader,
    ) -> shim::response::VerifyHeader {
        Default::default()
    }

    /// Validate a transaction request. On success, the transaction will
    /// included in the mempool and propagated to peers, otherwise it will be
    /// rejected.
    ///
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
    ///   2: Invalid order of decrypted txs
    ///   3. More decrypted txs than expected
    ///
    /// INVARIANT: Any changes applied in this method must be reverted if the
    /// proposal is rejected (unless we can simply overwrite them in the
    /// next block).
    pub fn process_proposal(
        &mut self,
        req: shim::request::ProcessProposal,
    ) -> shim::response::ProcessProposal {
        let tx = Tx::try_from(req.tx.as_ref())
            .expect("Deserializing tx should not fail");
        // TODO: This should not be hardcoded
        let privkey = <EllipticCurve as PairingEngine>::G2Affine::prime_subgroup_generator();

        match process_tx(tx) {
            // This occurs if the wrapper tx signature is invalid
            Err(err) => TxResult::from(err),
            Ok(result) => match result {
                // If it is a raw transaction, we do no further validation
                TxType::Raw(_) => TxResult {
                    code: 1,
                    info: "Transaction rejected: Non-encrypted transactions \
                           are not supported"
                        .into(),
                },
                TxType::Decrypted(tx) => match self.get_next_wrapper() {
                    Some(wrapper) => {
                        if wrapper.tx_hash != tx.hash_commitment() {
                            TxResult {
                                code: 2,
                                info: "Process proposal rejected a decrypted \
                                       transaction that violated the tx order \
                                       determined in the previous block"
                                    .into(),
                            }
                        } else if verify_decrypted_correctly(&tx, privkey) {
                            TxResult {
                                code: 0,
                                info: "Process Proposal accepted this \
                                       transaction"
                                    .into(),
                            }
                        } else {
                            TxResult {
                                code: 1,
                                info: "The encrypted payload of tx was \
                                       incorrectly marked as un-decryptable"
                                    .into(),
                            }
                        }
                    }
                    None => TxResult {
                        code: 3,
                        info: "Received more decrypted txs than expected"
                            .into(),
                    },
                },
                TxType::Wrapper(tx) => {
                    // validate the ciphertext via Ferveo
                    if !tx.validate_ciphertext() {
                        TxResult {
                            code: 1,
                            info: format!(
                                "The ciphertext of the wrapped tx {} is \
                                 invalid",
                                hash_tx(&req.tx)
                            ),
                        }
                    } else {
                        // check that the fee payer has sufficient balance
                        match queries::get_balance(
                            &self.storage,
                            &tx.fee.token,
                            &tx.fee_payer(),
                        ) {
                            Ok(balance) if tx.fee.amount <= balance => {
                                shim::response::TxResult {
                                    code: 0,
                                    info: "Process proposal accepted this \
                                           transaction"
                                        .into(),
                                }
                            }
                            Ok(_) => shim::response::TxResult {
                                code: 1,
                                info: "The address given does not have \
                                       sufficient balance to pay fee"
                                    .into(),
                            },
                            Err(err) => {
                                shim::response::TxResult { code: 1, info: err }
                            }
                        }
                    }
                }
            },
        }
        .into()
    }

    pub fn revert_proposal(
        &mut self,
        _req: shim::request::RevertProposal,
    ) -> shim::response::RevertProposal {
        Default::default()
    }
}

#[cfg(test)]
mod test_process_proposal {
    use std::path::PathBuf;

    use anoma::types::address::xan;
    use anoma::types::key::ed25519::{Keypair, SignedTxData};
    use anoma::types::storage::Epoch;
    use anoma::types::transaction::{Fee, Hash};
    use borsh::BorshDeserialize;
    use tendermint_proto::abci::RequestInitChain;
    use tendermint_proto::google::protobuf::Timestamp;

    use super::*;
    use crate::node::ledger::shims::abcipp_shim_types::shim::request::ProcessProposal;

    fn gen_keypair() -> Keypair {
        use rand::prelude::ThreadRng;
        use rand::thread_rng;

        let mut rng: ThreadRng = thread_rng();
        Keypair::generate(&mut rng)
    }

    struct TestShell {
        shell: Shell,
    }

    impl TestShell {
        /// Create a new shell
        fn new() -> Self {
            Self {
                shell: Shell::new(
                    PathBuf::from(".anoma")
                        .join("db")
                        .join("anoma-devchain-00000"),
                    "".into(),
                ),
            }
        }

        /// Forward a InitChain request and expect a success
        fn init_chain(&mut self, req: RequestInitChain) {
            self.shell
                .init_chain(req)
                .expect("Test shell failed to initialize");
        }

        /// Forward a ProcessProposal request and extract the relevant
        /// response data to return
        fn process_proposal(&mut self, req: ProcessProposal) -> TxResult {
            self.shell.process_proposal(req).result
        }

        /// Add a wrapper tx to the queue of txs to be decrypted
        /// in the current block proposal
        fn add_wrapper_tx(&mut self, wrapper: WrapperTx) {
            self.shell.storage.wrapper_txs.push(wrapper);
            self.shell.revert_wrapper_txs();
        }
    }

    impl Drop for TestShell {
        fn drop(&mut self) {
            std::fs::remove_dir_all(".anoma")
                .expect("Unable to clean up test shell");
        }
    }

    /// Test that if a wrapper tx is not signed, it is rejected
    /// by [`process_proposal`].
    #[test]
    fn test_unsigned_wrapper_rejected() {
        let mut shell = TestShell::new();
        let keypair = gen_keypair();
        let tx = Tx::new(
            "wasm_code".as_bytes().to_owned(),
            Some("transaction data".as_bytes().to_owned()),
        );
        let wrapper = WrapperTx::new(
            Fee {
                amount: 0.into(),
                token: xan(),
            },
            &keypair,
            Epoch(0),
            0.into(),
            tx,
        );
        let request = ProcessProposal {
            tx: Tx::new(
                vec![],
                Some(wrapper.try_to_vec().expect("Test failed")),
            )
            .to_bytes(),
        };
        let result = shell.process_proposal(request);
        assert_eq!(result.code, 1);
        assert_eq!(result.info, String::from("Expected signed WrapperTx data"));
    }

    /// Test that a wrapper tx with invalid signature is rejected
    #[test]
    fn test_wrapper_bad_signature_rejected() {
        let mut shell = TestShell::new();
        let keypair = gen_keypair();
        let tx = Tx::new(
            "wasm_code".as_bytes().to_owned(),
            Some("transaction data".as_bytes().to_owned()),
        );
        let timestamp = tx.timestamp;
        let mut wrapper = WrapperTx::new(
            Fee {
                amount: 100.into(),
                token: xan(),
            },
            &keypair,
            Epoch(0),
            0.into(),
            tx,
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
            let mut new_wrapper = <WrapperTx as BorshDeserialize>::deserialize(
                &mut data.as_ref(),
            )
            .expect("Test failed");

            // we mount a malleability attack to try and remove the fee
            new_wrapper.fee.amount = 0.into();
            let new_data = new_wrapper.try_to_vec().expect("Test failed");
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
            tx: new_tx.to_bytes(),
        };
        let result = shell.process_proposal(request);
        assert_eq!(result.code, 1);
        assert_eq!(
            result.info,
            String::from("Signature verification failed: signature error")
        );
    }

    /// Test that if the account submitting the tx is
    /// not known, [`process_proposal`] rejects that tx
    #[test]
    fn test_wrapper_unknown_address() {
        let mut shell = TestShell::new();
        let keypair = crate::wallet::defaults::keys().remove(0).1;
        let tx = Tx::new(
            "wasm_code".as_bytes().to_owned(),
            Some("transaction data".as_bytes().to_owned()),
        );
        let wrapper = WrapperTx::new(
            Fee {
                amount: 0.into(),
                token: xan(),
            },
            &keypair,
            Epoch(0),
            0.into(),
            tx,
        )
        .sign(&keypair)
        .expect("Test failed");
        let request = ProcessProposal {
            tx: wrapper.to_bytes(),
        };
        let result = shell.process_proposal(request);
        assert_eq!(result.code, 1);
        assert_eq!(
            result.info,
            String::from("Unable to read balance of the given address")
        );
    }

    /// Test that if the account submitting the tx does
    /// not have sufficient balance to pay the fee,
    /// [`process_proposal`] rejects that tx
    #[test]
    fn test_wrapper_insufficient_balance_address() {
        let mut shell = TestShell::new();
        shell.init_chain(RequestInitChain {
            time: Some(Timestamp {
                seconds: 0,
                nanos: 0,
            }),
            ..Default::default()
        });
        let keypair = crate::wallet::defaults::keys().remove(0).1;

        let tx = Tx::new(
            "wasm_code".as_bytes().to_owned(),
            Some("transaction data".as_bytes().to_owned()),
        );
        let wrapper = WrapperTx::new(
            Fee {
                amount: Amount::whole(1_000_100),
                token: xan(),
            },
            &keypair,
            Epoch(0),
            0.into(),
            tx,
        )
        .sign(&keypair)
        .expect("Test failed");

        let request = ProcessProposal {
            tx: wrapper.to_bytes(),
        };

        let result = shell.process_proposal(request);
        assert_eq!(result.code, 1);
        assert_eq!(
            result.info,
            String::from(
                "The address given does not have sufficient balance to pay fee"
            )
        );
    }

    /// Test that if the expected order of decrypted txs is
    /// validated, [`process_proposal`] rejects it
    #[test]
    fn test_decrypted_txs_out_of_order() {
        let mut shell = TestShell::new();
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
                    token: xan(),
                },
                &keypair,
                Epoch(0),
                0.into(),
                tx.clone(),
            );
            shell.add_wrapper_tx(wrapper);
            txs.push(Tx::from(TxType::Decrypted(DecryptedTx::Decrypted(tx))));
        }
        txs.reverse();
        let req_1 = ProcessProposal {
            tx: txs[0].to_bytes(),
        };
        let result_1 = shell.process_proposal(req_1);
        assert_eq!(result_1.code, 0);

        let req_2 = ProcessProposal {
            tx: txs[2].to_bytes(),
        };

        let result_2 = shell.process_proposal(req_2);
        assert_eq!(result_2.code, 2);
        assert_eq!(
            result_2.info,
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
        let mut shell = TestShell::new();
        let keypair = gen_keypair();

        let tx = Tx::new(
            "wasm_code".as_bytes().to_owned(),
            Some("transaction data".as_bytes().to_owned()),
        );
        let wrapper = WrapperTx::new(
            Fee {
                amount: 0.into(),
                token: xan(),
            },
            &keypair,
            Epoch(0),
            0.into(),
            tx,
        );
        shell.add_wrapper_tx(wrapper.clone());

        let tx =
            Tx::from(TxType::Decrypted(DecryptedTx::Undecryptable(wrapper)));

        let request = ProcessProposal { tx: tx.to_bytes() };

        let result = shell.process_proposal(request);
        assert_eq!(result.code, 1);
        assert_eq!(
            result.info,
            String::from(
                "The encrypted payload of tx was incorrectly marked as \
                 un-decryptable"
            ),
        )
    }

    /// Test that undecryptable txs are accepted
    #[test]
    fn test_undecryptable() {
        let mut shell = TestShell::new();
        let keypair = gen_keypair();

        let tx = Tx::new(
            "wasm_code".as_bytes().to_owned(),
            Some("transaction data".as_bytes().to_owned()),
        );
        let mut wrapper = WrapperTx::new(
            Fee {
                amount: 0.into(),
                token: xan(),
            },
            &keypair,
            Epoch(0),
            0.into(),
            tx,
        );
        wrapper.tx_hash = Hash([0; 32]);
        shell.add_wrapper_tx(wrapper.clone());

        let tx =
            Tx::from(TxType::Decrypted(DecryptedTx::Undecryptable(wrapper)));

        let request = ProcessProposal { tx: tx.to_bytes() };

        let result = shell.process_proposal(request);
        assert_eq!(result.code, 0);
    }

    /// Test that if more decrypted txs are submitted to
    /// [`process_proposal`] than expected, they are rejected
    #[test]
    fn test_too_many_decrypted_txs() {
        let mut shell = TestShell::new();

        let tx = Tx::new(
            "wasm_code".as_bytes().to_owned(),
            Some("transaction data".as_bytes().to_owned()),
        );

        let tx = Tx::from(TxType::Decrypted(DecryptedTx::Decrypted(tx)));

        let request = ProcessProposal { tx: tx.to_bytes() };
        let result = shell.process_proposal(request);
        assert_eq!(result.code, 3);
        assert_eq!(
            result.info,
            String::from("Received more decrypted txs than expected"),
        );
    }
}
