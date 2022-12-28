//! Implementation of the [`RequestPrepareProposal`] ABCI++ method for the Shell

use namada::ledger::storage::{DBIter, StorageHasher, DB};
use namada::proto::Tx;
use namada::types::transaction::tx_types::TxType;
use namada::types::transaction::wrapper::wrapper_tx::PairingEngine;
use namada::types::transaction::{AffineCurve, DecryptedTx, EllipticCurve};

use super::super::*;
use crate::facade::tendermint_proto::abci::RequestPrepareProposal;
#[cfg(feature = "abcipp")]
use crate::facade::tendermint_proto::abci::{tx_record::TxAction, TxRecord};
use crate::node::ledger::shell::{process_tx, ShellMode};
use crate::node::ledger::shims::abcipp_shim_types::shim::TxBytes;

// TODO: remove this hard-coded value; Tendermint, and thus
// Namada uses 20 MiB max block sizes by default; 16 MiB leaves
// plenty of room for header data, evidence and protobuf serialization
// overhead
const MAX_PROPOSAL_SIZE: usize = 16 << 20;
const HALF_MAX_PROPOSAL_SIZE: usize = MAX_PROPOSAL_SIZE / 2;

impl<D, H> Shell<D, H>
where
    D: DB + for<'iter> DBIter<'iter> + Sync + 'static,
    H: StorageHasher + Sync + 'static,
{
    /// Begin a new block.
    ///
    /// We fill half the block space with new wrapper txs given to us
    /// from the mempool by tendermint. The rest of the block is filled
    /// with decryptions of the wrapper txs from the previously
    /// committed block.
    ///
    /// INVARIANT: Any changes applied in this method must be reverted if
    /// the proposal is rejected (unless we can simply overwrite
    /// them in the next block).
    pub fn prepare_proposal(
        &self,
        req: RequestPrepareProposal,
    ) -> response::PrepareProposal {
        let txs = if let ShellMode::Validator { .. } = self.mode {
            // TODO: This should not be hardcoded
            let privkey = <EllipticCurve as PairingEngine>::G2Affine::prime_subgroup_generator();

            // TODO: Craft the Ethereum state update tx
            // filter in half of the new txs from Tendermint, only keeping
            // wrappers
            let mut total_proposal_size = 0;
            #[cfg(feature = "abcipp")]
            let mut txs: Vec<TxRecord> = req
                .txs
                .into_iter()
                .map(|tx_bytes| {
                    if let Ok(Ok(TxType::Wrapper(_))) =
                        Tx::try_from(tx_bytes.as_slice()).map(process_tx)
                    {
                        record::keep(tx_bytes)
                    } else {
                        record::remove(tx_bytes)
                    }
                })
                .take_while(|tx_record| {
                    let new_size = total_proposal_size + tx_record.tx.len();
                    if new_size > HALF_MAX_PROPOSAL_SIZE
                        || tx_record.action != TxAction::Unmodified as i32
                    {
                        false
                    } else {
                        total_proposal_size = new_size;
                        true
                    }
                })
                .collect();
            #[cfg(not(feature = "abcipp"))]
            let mut txs: Vec<TxBytes> = req
                .txs
                .into_iter()
                .filter_map(|tx_bytes| {
                    if let Ok(Ok(TxType::Wrapper(_))) =
                        Tx::try_from(tx_bytes.as_slice()).map(process_tx)
                    {
                        Some(tx_bytes)
                    } else {
                        None
                    }
                })
                .take_while(|tx_bytes| {
                    let new_size = total_proposal_size + tx_bytes.len();
                    if new_size > HALF_MAX_PROPOSAL_SIZE {
                        false
                    } else {
                        total_proposal_size = new_size;
                        true
                    }
                })
                .collect();

            // decrypt the wrapper txs included in the previous block
            let decrypted_txs = self.storage.tx_queue.iter().map(|tx| {
                Tx::from(match tx.decrypt(privkey) {
                    Ok(tx) => DecryptedTx::Decrypted(tx),
                    _ => DecryptedTx::Undecryptable(tx.clone()),
                })
                .to_bytes()
            });
            #[cfg(feature = "abcipp")]
            let mut decrypted_txs: Vec<_> =
                decrypted_txs.map(record::add).collect();
            #[cfg(not(feature = "abcipp"))]
            let mut decrypted_txs: Vec<_> = decrypted_txs.collect();

            txs.append(&mut decrypted_txs);
            txs
        } else {
            vec![]
        };

        #[cfg(feature = "abcipp")]
        {
            response::PrepareProposal {
                tx_records: txs,
                ..Default::default()
            }
        }
        #[cfg(not(feature = "abcipp"))]
        {
            response::PrepareProposal { txs }
        }
    }
}

/// Functions for creating the appropriate TxRecord given the
/// numeric code
#[cfg(feature = "abcipp")]
pub(super) mod record {
    use super::*;

    /// Keep this transaction in the proposal
    pub fn keep(tx: TxBytes) -> TxRecord {
        TxRecord {
            action: TxAction::Unmodified as i32,
            tx,
        }
    }

    /// A transaction added to the proposal not provided by
    /// Tendermint from the mempool
    pub fn add(tx: TxBytes) -> TxRecord {
        TxRecord {
            action: TxAction::Added as i32,
            tx,
        }
    }

    /// Remove this transaction from the set provided
    /// by Tendermint from the mempool
    pub fn remove(tx: TxBytes) -> TxRecord {
        TxRecord {
            action: TxAction::Removed as i32,
            tx,
        }
    }
}

#[cfg(test)]
mod test_prepare_proposal {
    use borsh::BorshSerialize;
    use namada::types::storage::Epoch;
    use namada::types::transaction::{Fee, WrapperTx};

    use super::*;
    use crate::node::ledger::shell::test_utils::{gen_keypair, TestShell};

    /// Test that if a tx from the mempool is not a
    /// WrapperTx type, it is not included in the
    /// proposed block.
    #[test]
    fn test_prepare_proposal_rejects_non_wrapper_tx() {
        let (shell, _) = TestShell::new();
        let tx = Tx::new(
            "wasm_code".as_bytes().to_owned(),
            Some("transaction_data".as_bytes().to_owned()),
        );
        let req = RequestPrepareProposal {
            txs: vec![tx.to_bytes()],
            max_tx_bytes: 0,
            ..Default::default()
        };
        #[cfg(feature = "abcipp")]
        assert_eq!(
            shell.prepare_proposal(req).tx_records,
            vec![record::remove(tx.to_bytes())]
        );
        #[cfg(not(feature = "abcipp"))]
        assert!(shell.prepare_proposal(req).txs.is_empty());
    }

    /// Test that if an error is encountered while
    /// trying to process a tx from the mempool,
    /// we simply exclude it from the proposal
    #[test]
    fn test_error_in_processing_tx() {
        let (shell, _) = TestShell::new();
        let keypair = gen_keypair();
        let tx = Tx::new(
            "wasm_code".as_bytes().to_owned(),
            Some("transaction_data".as_bytes().to_owned()),
        );
        // an unsigned wrapper will cause an error in processing
        let wrapper = Tx::new(
            "".as_bytes().to_owned(),
            Some(
                WrapperTx::new(
                    Fee {
                        amount: 0.into(),
                        token: shell.storage.native_token.clone(),
                    },
                    &keypair,
                    Epoch(0),
                    0.into(),
                    tx,
                    Default::default(),
                )
                .try_to_vec()
                .expect("Test failed"),
            ),
        )
        .to_bytes();
        #[allow(clippy::redundant_clone)]
        let req = RequestPrepareProposal {
            txs: vec![wrapper.clone()],
            max_tx_bytes: 0,
            ..Default::default()
        };
        #[cfg(feature = "abcipp")]
        assert_eq!(
            shell.prepare_proposal(req).tx_records,
            vec![record::remove(wrapper)]
        );
        #[cfg(not(feature = "abcipp"))]
        assert!(shell.prepare_proposal(req).txs.is_empty());
    }

    /// Test that the decrypted txs are included
    /// in the proposal in the same order as their
    /// corresponding wrappers
    #[test]
    fn test_decrypted_txs_in_correct_order() {
        let (mut shell, _) = TestShell::new();
        let keypair = gen_keypair();
        let mut expected_wrapper = vec![];
        let mut expected_decrypted = vec![];

        let mut req = RequestPrepareProposal {
            txs: vec![],
            max_tx_bytes: 0,
            ..Default::default()
        };
        // create a request with two new wrappers from mempool and
        // two wrappers from the previous block to be decrypted
        for i in 0..2 {
            let tx = Tx::new(
                "wasm_code".as_bytes().to_owned(),
                Some(format!("transaction data: {}", i).as_bytes().to_owned()),
            );
            expected_decrypted
                .push(Tx::from(DecryptedTx::Decrypted(tx.clone())));
            let wrapper_tx = WrapperTx::new(
                Fee {
                    amount: 0.into(),
                    token: shell.storage.native_token.clone(),
                },
                &keypair,
                Epoch(0),
                0.into(),
                tx,
                Default::default(),
            );
            let wrapper = wrapper_tx.sign(&keypair).expect("Test failed");
            shell.enqueue_tx(wrapper_tx);
            expected_wrapper.push(wrapper.clone());
            req.txs.push(wrapper.to_bytes());
        }
        // we extract the inner data from the txs for testing
        // equality since otherwise changes in timestamps would
        // fail the test
        expected_wrapper.append(&mut expected_decrypted);
        let expected_txs: Vec<Vec<u8>> = expected_wrapper
            .iter()
            .map(|tx| tx.data.clone().expect("Test failed"))
            .collect();
        #[cfg(feature = "abcipp")]
        {
            let received: Vec<Vec<u8>> = shell
                .prepare_proposal(req)
                .tx_records
                .iter()
                .filter_map(
                    |TxRecord {
                         tx: tx_bytes,
                         action,
                     }| {
                        if *action == (TxAction::Unmodified as i32)
                            || *action == (TxAction::Added as i32)
                        {
                            Some(
                                Tx::try_from(tx_bytes.as_slice())
                                    .expect("Test failed")
                                    .data
                                    .expect("Test failed"),
                            )
                        } else {
                            None
                        }
                    },
                )
                .collect();
            // check that the order of the txs is correct
            assert_eq!(received, expected_txs);
        }
        #[cfg(not(feature = "abcipp"))]
        {
            let received: Vec<Vec<u8>> = shell
                .prepare_proposal(req)
                .txs
                .into_iter()
                .map(|tx_bytes| {
                    Tx::try_from(tx_bytes.as_slice())
                        .expect("Test failed")
                        .data
                        .expect("Test failed")
                })
                .collect();
            // check that the order of the txs is correct
            assert_eq!(received, expected_txs);
        }
    }
}
