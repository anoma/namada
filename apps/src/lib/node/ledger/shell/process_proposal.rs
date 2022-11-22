//! Implementation of the ['VerifyHeader`], [`ProcessProposal`],
//! and [`RevertProposal`] ABCI++ methods for the Shell

use data_encoding::HEXUPPER;
use namada::ledger::pos::types::VotingPower;
use namada::ledger::storage_api::queries::{QueriesExt, SendValsetUpd};
use namada::types::transaction::protocol::ProtocolTxType;
#[cfg(feature = "abcipp")]
use namada::types::voting_power::FractionalVotingPower;

use super::*;
use crate::facade::tendermint_proto::abci::response_process_proposal::ProposalStatus;
use crate::facade::tendermint_proto::abci::RequestProcessProposal;
use crate::node::ledger::shims::abcipp_shim_types::shim::response::ProcessProposal;
use crate::node::ledger::shims::abcipp_shim_types::shim::TxBytes;

/// Contains stateful data about the number of vote extension
/// digests found as protocol transactions in a proposed block.
#[derive(Default)]
#[cfg(feature = "abcipp")]
pub struct DigestCounters {
    /// The number of Ethereum events vote extensions found thus far.
    eth_ev_digest_num: usize,
    /// The number of validator set update vote extensions found thus far.
    valset_upd_digest_num: usize,
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
        tracing::info!(
            proposer = ?HEXUPPER.encode(&req.proposer_address),
            height = req.height,
            hash = ?HEXUPPER.encode(&req.hash),
            n_txs = req.txs.len(),
            "Received block proposal",
        );
        let (tx_results, counters) = self.check_proposal(&req.txs);

        // We should not have more than one `ethereum_events::VextDigest` in
        // a proposal from some round's leader.
        let invalid_num_of_eth_ev_digests =
            !self.has_proper_eth_events_num(&counters);
        if invalid_num_of_eth_ev_digests {
            tracing::warn!(
                proposer = ?HEXUPPER.encode(&req.proposer_address),
                height = req.height,
                hash = ?HEXUPPER.encode(&req.hash),
                eth_ev_digest_num = counters.eth_ev_digest_num,
                "Found invalid number of Ethereum events vote extension digests, proposed block \
                 will be rejected"
            );
        }

        let invalid_num_of_valset_upd_digests =
            !self.has_proper_valset_upd_num(&counters);
        if invalid_num_of_valset_upd_digests {
            tracing::warn!(
                proposer = ?HEXUPPER.encode(&req.proposer_address),
                height = req.height,
                hash = ?HEXUPPER.encode(&req.hash),
                valset_upd_digest_num = counters.valset_upd_digest_num,
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

        let will_reject_proposal = invalid_num_of_eth_ev_digests
            || invalid_num_of_valset_upd_digests
            || invalid_txs;

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
        let tx_results = self.check_proposal(&req.txs);

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

        let will_reject_proposal = invalid_txs;

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

    /// Evaluates the corresponding [`TxResult`] for each tx in a
    /// proposed block, and counts the number of digest transactions.
    ///
    /// `ProcessProposal` should be able to make a decision on whether a
    /// proposed block is acceptable or not based solely on what this
    /// function returns.
    #[cfg(feature = "abcipp")]
    pub fn check_proposal(
        &self,
        txs: &[TxBytes],
    ) -> (Vec<TxResult>, DigestCounters) {
        let mut tx_queue_iter = self.storage.tx_queue.iter();
        // the number of vote extension digests included in the block proposal
        let mut counters = DigestCounters::default();
        let tx_results: Vec<_> = txs
            .iter()
            .map(|tx_bytes| {
                self.check_proposal_tx(
                    tx_bytes,
                    &mut tx_queue_iter,
                    &mut counters,
                )
            })
            .collect();
        (tx_results, counters)
    }

    /// Evaluates the corresponding [`TxResult`] for each tx in a
    /// proposed block.
    ///
    /// `ProcessProposal` should be able to make a decision on whether a
    /// proposed block is acceptable or not based solely on what this
    /// function returns.
    #[cfg(not(feature = "abcipp"))]
    pub fn check_proposal(&self, txs: &[TxBytes]) -> Vec<TxResult> {
        let mut tx_queue_iter = self.storage.tx_queue.iter();
        let tx_results: Vec<_> = txs
            .iter()
            .map(|tx_bytes| {
                self.check_proposal_tx(tx_bytes, &mut tx_queue_iter)
            })
            .collect();
        tx_results
    }

    /// Validates a list of vote extensions, included in PrepareProposal.
    ///
    /// If a vote extension is [`Some`], then it was validated properly,
    /// and the voting power of the validator who signed it is considered
    /// in the sum of the total voting power of all received vote extensions.
    #[cfg(feature = "abcipp")]
    fn validate_vexts_in_proposal<I>(&self, mut vote_extensions: I) -> TxResult
    where
        I: Iterator<Item = Option<VotingPower>>,
    {
        #[cfg(feature = "abcipp")]
        let mut voting_power = FractionalVotingPower::default();
        #[cfg(feature = "abcipp")]
        let total_power = {
            let epoch = self.storage.get_epoch(self.storage.last_height);
            u64::from(self.storage.get_total_voting_power(epoch))
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
    ///
    /// INVARIANT: Any changes applied in this method must be reverted if the
    /// proposal is rejected (unless we can simply overwrite them in the
    /// next block).
    pub(crate) fn check_proposal_tx<'a>(
        &self,
        tx_bytes: &[u8],
        tx_queue_iter: &mut impl Iterator<Item = &'a WrapperTx>,
        #[cfg(feature = "abcipp")] counters: &mut DigestCounters,
    ) -> TxResult {
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
                process_tx(tx).map_err(|err| {
                    // This occurs if the wrapper / protocol tx signature is
                    // invalid
                    TxResult {
                        code: ErrorCodes::InvalidSig.into(),
                        info: err.to_string(),
                    }
                })
            },
        );
        let tx = match maybe_tx {
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
            TxType::Protocol(protocol_tx) => match protocol_tx.tx {
                #[cfg(not(feature = "abcipp"))]
                ProtocolTxType::EthEventsVext(_ext) => {
                    // TODO
                }
                #[cfg(not(feature = "abcipp"))]
                ProtocolTxType::ValSetUpdateVext(_ext) => {
                    // TODO
                }
                #[cfg(feature = "abcipp")]
                ProtocolTxType::EthereumEvents(digest) => {
                    counters.eth_ev_digest_num += 1;
                    let extensions =
                        digest.decompress(self.storage.last_height);
                    let valid_extensions =
                        self.validate_eth_events_vext_list(extensions).map(
                            |maybe_ext| maybe_ext.ok().map(|(power, _)| power),
                        );

                    self.validate_vexts_in_proposal(valid_extensions)
                }
                #[cfg(feature = "abcipp")]
                ProtocolTxType::ValidatorSetUpdate(digest) => {
                    if !self.storage.can_send_validator_set_update(
                        SendValsetUpd::AtPrevHeight,
                    ) {
                        return TxResult {
                            code: ErrorCodes::InvalidVoteExtension.into(),
                            info: "Process proposal rejected a validator set \
                                   update vote extension issued at an invalid \
                                   block height"
                                .into(),
                        };
                    }

                    counters.valset_upd_digest_num += 1;

                    let extensions =
                        digest.decompress(self.storage.last_height);
                    let valid_extensions =
                        self.validate_valset_upd_vext_list(extensions).map(
                            |maybe_ext| maybe_ext.ok().map(|(power, _)| power),
                        );

                    self.validate_vexts_in_proposal(valid_extensions)
                }
                _ => TxResult {
                    code: ErrorCodes::InvalidTx.into(),
                    info: "Unsupported protocol transaction type".into(),
                },
            },
            TxType::Decrypted(tx) => match tx_queue_iter.next() {
                Some(wrapper) => {
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
                            info: "Process Proposal accepted this transaction"
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
                    info: "Received more decrypted txs than expected".into(),
                },
            },
            TxType::Wrapper(wrapper) => {
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
                    // check that the fee payer has sufficient balance
                    let balance = self
                        .storage
                        .get_balance(&wrapper.fee.token, &wrapper.fee_payer());

                    if wrapper.fee.amount <= balance {
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

    /// Checks if we have found the correct number of Ethereum events
    /// vote extensions in [`DigestCounters`].
    #[cfg(feature = "abcipp")]
    fn has_proper_eth_events_num(&self, c: &DigestCounters) -> bool {
        #[cfg(feature = "abcipp")]
        {
            self.storage.last_height.0 == 0 || c.eth_ev_digest_num == 1
        }
        #[cfg(not(feature = "abcipp"))]
        {
            c.eth_ev_digest_num <= 1
        }
    }

    /// Checks if we have found the correct number of validator set update
    /// vote extensions in [`DigestCounters`].
    #[cfg(feature = "abcipp")]
    fn has_proper_valset_upd_num(&self, c: &DigestCounters) -> bool {
        #[cfg(feature = "abcipp")]
        if self
            .storage
            .can_send_validator_set_update(SendValsetUpd::AtPrevHeight)
        {
            self.storage.last_height.0 == 0 || c.valset_upd_digest_num == 1
        } else {
            true
        }
        #[cfg(not(feature = "abcipp"))]
        {
            c.valset_upd_digest_num <= 1
        }
    }
}

/// We test the failure cases of [`process_proposal`]. The happy flows
/// are covered by the e2e tests.
#[cfg(test)]
mod test_process_proposal {
    use std::collections::HashMap;

    use assert_matches::assert_matches;
    use borsh::BorshDeserialize;
    use namada::proto::SignedTxData;
    use namada::types::address::nam;
    use namada::types::ethereum_events::EthereumEvent;
    use namada::types::hash::Hash;
    use namada::types::key::*;
    use namada::types::storage::Epoch;
    use namada::types::token::Amount;
    use namada::types::transaction::encrypted::EncryptedTx;
    use namada::types::transaction::{EncryptionKey, Fee};
    use namada::types::vote_extensions::ethereum_events::{
        self, MultiSignedEthEvent,
    };

    use super::*;
    use crate::node::ledger::shell::test_utils::{
        self, gen_keypair, ProcessProposal, TestError, TestShell,
    };
    use crate::node::ledger::shims::abcipp_shim_types::shim::TxBytes;
    use crate::wallet;

    fn get_empty_eth_ev_digest(shell: &TestShell) -> TxBytes {
        let protocol_key = shell.mode.get_protocol_key().expect("Test failed");
        let addr = shell
            .mode
            .get_validator_address()
            .expect("Test failed")
            .clone();
        let ext = ethereum_events::Vext::empty(
            shell.storage.last_height,
            addr.clone(),
        )
        .sign(protocol_key);
        ProtocolTxType::EthereumEvents(ethereum_events::VextDigest {
            #[cfg(feature = "abcipp")]
            signatures: {
                let mut s = HashMap::new();
                s.insert(addr, ext.sig);
                s
            },
            #[cfg(not(feature = "abcipp"))]
            signatures: {
                let mut s = HashMap::new();
                s.insert((addr, shell.storage.last_height), ext.sig);
                s
            },
            events: vec![],
        })
        .sign(protocol_key)
        .to_bytes()
    }

    /// Test that if a proposal contains more than one
    /// `ethereum_events::VextDigest`, we reject it.
    #[test]
    fn test_more_than_one_vext_digest_rejected() {
        const LAST_HEIGHT: BlockHeight = BlockHeight(2);
        let (mut shell, _recv, _) = test_utils::setup();
        shell.storage.last_height = LAST_HEIGHT;
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
                    #[cfg(feature = "abcipp")]
                    s.insert(validator_addr, signed_vote_extension.sig);
                    #[cfg(not(feature = "abcipp"))]
                    s.insert(
                        (validator_addr, LAST_HEIGHT),
                        signed_vote_extension.sig,
                    );
                    s
                },
                events: vec![],
            }
        };
        let tx = ProtocolTxType::EthereumEvents(vote_extension_digest)
            .sign(&protocol_key)
            .to_bytes();
        #[allow(clippy::redundant_clone)]
        let request = ProcessProposal {
            txs: vec![tx.clone(), tx],
        };
        let results = shell.process_proposal(request);
        assert_matches!(
            results, Err(TestError::RejectProposal(s)) if s.len() == 2
        );
    }

    fn check_rejected_eth_events_digest(
        shell: &mut TestShell,
        vote_extension_digest: ethereum_events::VextDigest,
        protocol_key: common::SecretKey,
    ) {
        let tx = ProtocolTxType::EthereumEvents(vote_extension_digest)
            .sign(&protocol_key)
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
    fn test_drop_vext_digest_with_invalid_sigs() {
        const LAST_HEIGHT: BlockHeight = BlockHeight(2);
        let (mut shell, _recv, _) = test_utils::setup();
        shell.storage.last_height = LAST_HEIGHT;
        let (protocol_key, _, _) = wallet::defaults::validator_keys();
        let vote_extension_digest = {
            let addr = wallet::defaults::validator_address();
            let event = EthereumEvent::TransfersToNamada {
                nonce: 1u64.into(),
                transfers: vec![],
            };
            let ext = {
                // generate a valid signature
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
            ethereum_events::VextDigest {
                signatures: {
                    let mut s = HashMap::new();
                    #[cfg(feature = "abcipp")]
                    s.insert(addr.clone(), ext.sig);
                    #[cfg(not(feature = "abcipp"))]
                    s.insert((addr.clone(), LAST_HEIGHT), ext.sig);
                    s
                },
                events: vec![MultiSignedEthEvent {
                    event,
                    signers: {
                        let mut s = BTreeSet::new();
                        #[cfg(feature = "abcipp")]
                        s.insert(addr);
                        #[cfg(not(feature = "abcipp"))]
                        s.insert((addr, LAST_HEIGHT));
                        s
                    },
                }],
            }
        };
        check_rejected_eth_events_digest(
            &mut shell,
            vote_extension_digest,
            protocol_key,
        );
    }

    /// Test that if a proposal contains Ethereum events with
    /// invalid block heights, we reject it.
    #[test]
    fn test_drop_vext_digest_with_invalid_bheights() {
        const LAST_HEIGHT: BlockHeight = BlockHeight(3);
        const PRED_LAST_HEIGHT: BlockHeight = BlockHeight(LAST_HEIGHT.0 - 1);
        let (mut shell, _recv, _) = test_utils::setup();
        shell.storage.last_height = LAST_HEIGHT;
        let (protocol_key, _, _) = wallet::defaults::validator_keys();
        let vote_extension_digest = {
            let addr = wallet::defaults::validator_address();
            let event = EthereumEvent::TransfersToNamada {
                nonce: 1u64.into(),
                transfers: vec![],
            };
            let ext = {
                let ext = ethereum_events::Vext {
                    validator_addr: addr.clone(),
                    block_height: PRED_LAST_HEIGHT,
                    ethereum_events: vec![event.clone()],
                }
                .sign(&protocol_key);
                assert!(ext.verify(&protocol_key.ref_to()).is_ok());
                ext
            };
            ethereum_events::VextDigest {
                signatures: {
                    let mut s = HashMap::new();
                    #[cfg(feature = "abcipp")]
                    s.insert(addr.clone(), ext.sig);
                    #[cfg(not(feature = "abcipp"))]
                    s.insert((addr.clone(), PRED_LAST_HEIGHT), ext.sig);
                    s
                },
                events: vec![MultiSignedEthEvent {
                    event,
                    signers: {
                        let mut s = BTreeSet::new();
                        #[cfg(feature = "abcipp")]
                        s.insert(addr);
                        #[cfg(not(feature = "abcipp"))]
                        s.insert((addr, PRED_LAST_HEIGHT));
                        s
                    },
                }],
            }
        };
        #[cfg(feature = "abcipp")]
        check_rejected_eth_events_digest(
            &mut shell,
            vote_extension_digest,
            protocol_key,
        );
        #[cfg(not(feature = "abcipp"))]
        {
            let tx = ProtocolTxType::EthereumEvents(vote_extension_digest)
                .sign(&protocol_key)
                .to_bytes();
            let request = ProcessProposal { txs: vec![tx] };
            if let Ok(mut resp) = shell.process_proposal(request) {
                assert_eq!(resp.len(), 1);
                let processed = resp.remove(0);
                assert_eq!(processed.result.code, ErrorCodes::Ok as u32);
            } else {
                panic!("Test failed");
            }
        }
    }

    /// Test that if a proposal contains Ethereum events with
    /// invalid validators, we reject it.
    #[test]
    fn test_drop_vext_digest_with_invalid_validators() {
        const LAST_HEIGHT: BlockHeight = BlockHeight(2);
        let (mut shell, _recv, _) = test_utils::setup();
        shell.storage.last_height = LAST_HEIGHT;
        let (addr, protocol_key) = {
            let bertha_key = wallet::defaults::bertha_keypair();
            let bertha_addr = wallet::defaults::bertha_address();
            (bertha_addr, bertha_key)
        };
        let vote_extension_digest = {
            let event = EthereumEvent::TransfersToNamada {
                nonce: 1u64.into(),
                transfers: vec![],
            };
            let ext = {
                let ext = ethereum_events::Vext {
                    validator_addr: addr.clone(),
                    block_height: LAST_HEIGHT,
                    ethereum_events: vec![event.clone()],
                }
                .sign(&protocol_key);
                assert!(ext.verify(&protocol_key.ref_to()).is_ok());
                ext
            };
            ethereum_events::VextDigest {
                signatures: {
                    let mut s = HashMap::new();
                    #[cfg(feature = "abcipp")]
                    s.insert(addr.clone(), ext.sig);
                    #[cfg(not(feature = "abcipp"))]
                    s.insert((addr.clone(), LAST_HEIGHT), ext.sig);
                    s
                },
                events: vec![MultiSignedEthEvent {
                    event,
                    signers: {
                        let mut s = BTreeSet::new();
                        #[cfg(feature = "abcipp")]
                        s.insert(addr);
                        #[cfg(not(feature = "abcipp"))]
                        s.insert((addr, LAST_HEIGHT));
                        s
                    },
                }],
            }
        };
        check_rejected_eth_events_digest(
            &mut shell,
            vote_extension_digest,
            protocol_key,
        );
    }

    /// Test that if a wrapper tx is not signed, it is rejected
    /// by [`process_proposal`].
    #[test]
    fn test_unsigned_wrapper_rejected() {
        let (mut shell, _recv, _) = test_utils::setup_at_height(3u64);
        let keypair = gen_keypair();
        let tx = Tx::new(
            "wasm_code".as_bytes().to_owned(),
            Some("transaction data".as_bytes().to_owned()),
        );
        let wrapper = WrapperTx::new(
            Fee {
                amount: 0.into(),
                token: nam(),
            },
            &keypair,
            Epoch(0),
            0.into(),
            tx,
            Default::default(),
        );
        let tx = Tx::new(
            vec![],
            Some(TxType::Wrapper(wrapper).try_to_vec().expect("Test failed")),
        )
        .to_bytes();
        #[allow(clippy::redundant_clone)]
        let request = ProcessProposal {
            txs: vec![tx.clone(), get_empty_eth_ev_digest(&shell)],
        };

        let response = if let [resp, _] = shell
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
        let (mut shell, _recv, _) = test_utils::setup_at_height(3u64);
        let keypair = gen_keypair();
        let tx = Tx::new(
            "wasm_code".as_bytes().to_owned(),
            Some("transaction data".as_bytes().to_owned()),
        );
        let timestamp = tx.timestamp;
        let mut wrapper = WrapperTx::new(
            Fee {
                amount: 100.into(),
                token: nam(),
            },
            &keypair,
            Epoch(0),
            0.into(),
            tx,
            Default::default(),
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
            txs: vec![new_tx.to_bytes(), get_empty_eth_ev_digest(&shell)],
        };
        let response = if let [response, _] = shell
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
        let (mut shell, _recv, _) = test_utils::setup_at_height(3u64);
        let keypair = gen_keypair();
        let tx = Tx::new(
            "wasm_code".as_bytes().to_owned(),
            Some("transaction data".as_bytes().to_owned()),
        );
        let wrapper = WrapperTx::new(
            Fee {
                amount: 1.into(),
                token: nam(),
            },
            &keypair,
            Epoch(0),
            0.into(),
            tx,
            Default::default(),
        )
        .sign(&keypair)
        .expect("Test failed");
        let request = ProcessProposal {
            txs: vec![wrapper.to_bytes(), get_empty_eth_ev_digest(&shell)],
        };
        let response = if let [resp, _] = shell
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
        let (mut shell, _recv, _) = test_utils::setup_at_height(3u64);
        let keypair = crate::wallet::defaults::daewon_keypair();

        let tx = Tx::new(
            "wasm_code".as_bytes().to_owned(),
            Some("transaction data".as_bytes().to_owned()),
        );
        let wrapper = WrapperTx::new(
            Fee {
                amount: Amount::whole(1_000_100),
                token: nam(),
            },
            &keypair,
            Epoch(0),
            0.into(),
            tx,
            Default::default(),
        )
        .sign(&keypair)
        .expect("Test failed");

        let request = ProcessProposal {
            txs: vec![wrapper.to_bytes(), get_empty_eth_ev_digest(&shell)],
        };

        let response = if let [resp, _] = shell
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
        let (mut shell, _recv, _) = test_utils::setup_at_height(3u64);
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
                    token: nam(),
                },
                &keypair,
                Epoch(0),
                0.into(),
                tx.clone(),
                Default::default(),
            );
            shell.enqueue_tx(wrapper);
            txs.push(Tx::from(TxType::Decrypted(DecryptedTx::Decrypted(tx))));
        }
        let req_1 = ProcessProposal {
            txs: vec![txs[0].to_bytes(), get_empty_eth_ev_digest(&shell)],
        };
        let response_1 = if let [resp, _] = shell
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
            txs: vec![txs[2].to_bytes(), get_empty_eth_ev_digest(&shell)],
        };

        let response_2 = if let Err(TestError::RejectProposal(resp)) =
            shell.process_proposal(req_2)
        {
            if let [resp, _] = resp.as_slice() {
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
        let (mut shell, _recv, _) = test_utils::setup_at_height(3u64);
        let keypair = gen_keypair();

        let tx = Tx::new(
            "wasm_code".as_bytes().to_owned(),
            Some("transaction data".as_bytes().to_owned()),
        );
        let wrapper = WrapperTx::new(
            Fee {
                amount: 0.into(),
                token: nam(),
            },
            &keypair,
            Epoch(0),
            0.into(),
            tx,
            Default::default(),
        );
        shell.enqueue_tx(wrapper.clone());

        let tx =
            Tx::from(TxType::Decrypted(DecryptedTx::Undecryptable(wrapper)));

        let request = ProcessProposal {
            txs: vec![tx.to_bytes(), get_empty_eth_ev_digest(&shell)],
        };

        let response = if let [resp, _] = shell
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
        let (mut shell, _recv, _) = test_utils::setup_at_height(3u64);
        let keypair = crate::wallet::defaults::daewon_keypair();

        let tx = Tx::new(
            "wasm_code".as_bytes().to_owned(),
            Some("transaction data".as_bytes().to_owned()),
        );
        let mut wrapper = WrapperTx::new(
            Fee {
                amount: 0.into(),
                token: nam(),
            },
            &keypair,
            Epoch(0),
            0.into(),
            tx,
            Default::default(),
        );
        wrapper.tx_hash = Hash([0; 32]);

        shell.enqueue_tx(wrapper.clone());
        let tx = Tx::from(TxType::Decrypted(DecryptedTx::Undecryptable(
            #[allow(clippy::redundant_clone)]
            wrapper.clone(),
        )));

        let request = ProcessProposal {
            txs: vec![tx.to_bytes(), get_empty_eth_ev_digest(&shell)],
        };
        let response = if let [resp, _] = shell
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
        let (mut shell, _recv, _) = test_utils::setup_at_height(3u64);
        let keypair = crate::wallet::defaults::daewon_keypair();
        let pubkey = EncryptionKey::default();
        // not valid tx bytes
        let tx = "garbage data".as_bytes().to_owned();
        let inner_tx = EncryptedTx::encrypt(&tx, pubkey);
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

        shell.enqueue_tx(wrapper.clone());
        let signed = Tx::from(TxType::Decrypted(DecryptedTx::Undecryptable(
            #[allow(clippy::redundant_clone)]
            wrapper.clone(),
        )));
        let request = ProcessProposal {
            txs: vec![signed.to_bytes(), get_empty_eth_ev_digest(&shell)],
        };
        let response = if let [resp, _] = shell
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
        let (mut shell, _recv, _) = TestShell::new();

        let tx = Tx::new(
            "wasm_code".as_bytes().to_owned(),
            Some("transaction data".as_bytes().to_owned()),
        );

        let tx = Tx::from(TxType::Decrypted(DecryptedTx::Decrypted(tx)));

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
        let (mut shell, _recv, _) = test_utils::setup_at_height(3u64);

        let tx = Tx::new(
            "wasm_code".as_bytes().to_owned(),
            Some("transaction data".as_bytes().to_owned()),
        );
        let tx = Tx::from(TxType::Raw(tx));
        let request = ProcessProposal {
            txs: vec![tx.to_bytes(), get_empty_eth_ev_digest(&shell)],
        };
        let response = if let [resp, _] = shell
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
