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
                        if wrapper.tx_hash != hash_tx(&tx.to_bytes()) {
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
