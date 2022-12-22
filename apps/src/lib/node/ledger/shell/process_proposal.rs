//! Implementation of the ['VerifyHeader`], [`ProcessProposal`],
//! and [`RevertProposal`] ABCI++ methods for the Shell

use data_encoding::HEXUPPER;
use namada::core::hints;
use namada::core::ledger::storage::Storage;
use namada::ledger::pos::{PosQueries, SendValsetUpd};
use namada::types::transaction::protocol::ProtocolTxType;
#[cfg(feature = "abcipp")]
use namada::types::voting_power::FractionalVotingPower;

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
    /// Vote extension digest counters.
    #[cfg(feature = "abcipp")]
    pub digests: DigestCounters,
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
}

impl<D, H> From<&Storage<D, H>> for ValidationMeta
where
    D: DB + for<'iter> DBIter<'iter>,
    H: StorageHasher,
{
    fn from(storage: &Storage<D, H>) -> Self {
        let max_proposal_bytes = storage.get_max_proposal_bytes().get();
        let encrypted_txs_bin =
            TxBin::init_over_ratio(max_proposal_bytes, threshold::ONE_THIRD);
        let txs_bin = TxBin::init(max_proposal_bytes);
        Self {
            #[cfg(feature = "abcipp")]
            digests: DigestCounters::default(),
            decrypted_queue_has_remaining_txs: false,
            encrypted_txs_bin,
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
        tracing::info!(
            proposer = ?HEXUPPER.encode(&req.proposer_address),
            height = req.height,
            hash = ?HEXUPPER.encode(&req.hash),
            n_txs = req.txs.len(),
            "Received block proposal",
        );
        let (tx_results, metadata) = self.check_proposal(&req.txs);

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
        let (tx_results, meta) = self.check_proposal(&req.txs);

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

        // TODO: check if tx queue still has txs left in it

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
    pub fn check_proposal(
        &self,
        txs: &[TxBytes],
    ) -> (Vec<TxResult>, ValidationMeta) {
        let mut tx_queue_iter = self.storage.tx_queue.iter();
        let mut metadata = ValidationMeta::from(&self.storage);
        let tx_results: Vec<_> = txs
            .iter()
            .map(|tx_bytes| {
                self.check_proposal_tx(
                    tx_bytes,
                    &mut tx_queue_iter,
                    &mut metadata,
                )
            })
            .collect();
        metadata.decrypted_queue_has_remaining_txs =
            !self.storage.tx_queue.is_empty() && tx_queue_iter.next().is_some();
        (tx_results, metadata)
    }

    /// Validates a list of vote extensions, included in PrepareProposal.
    ///
    /// If a vote extension is [`Some`], then it was validated properly,
    /// and the voting power of the validator who signed it is considered
    /// in the sum of the total voting power of all received vote extensions.
    fn validate_vexts_in_proposal<I>(&self, mut vote_extensions: I) -> TxResult
    where
        I: Iterator<Item = Option<namada::types::token::Amount>>,
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
    ///   8. Not enough block space was available for some tx
    ///
    /// INVARIANT: Any changes applied in this method must be reverted if the
    /// proposal is rejected (unless we can simply overwrite them in the
    /// next block).
    pub(crate) fn check_proposal_tx<'a>(
        &self,
        tx_bytes: &[u8],
        tx_queue_iter: &mut impl Iterator<Item = &'a WrapperTx>,
        metadata: &mut ValidationMeta,
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
                ProtocolTxType::EthEventsVext(ext) => self
                    .validate_eth_events_vext_and_get_it_back(
                        ext,
                        self.storage.last_height,
                    )
                    .map(|_| TxResult {
                        code: ErrorCodes::Ok.into(),
                        info: "Process Proposal accepted this transaction"
                            .into(),
                    })
                    .unwrap_or_else(|err| TxResult {
                        code: ErrorCodes::InvalidVoteExtension.into(),
                        info: format!(
                            "Process proposal rejected this proposal because \
                             one of the included Ethereum events vote \
                             extensions was invalid: {err}"
                        ),
                    }),
                ProtocolTxType::ValSetUpdateVext(ext) => self
                    .validate_valset_upd_vext_and_get_it_back(
                        ext,
                        self.storage.last_height,
                    )
                    .map(|_| TxResult {
                        code: ErrorCodes::Ok.into(),
                        info: "Process Proposal accepted this transaction"
                            .into(),
                    })
                    .unwrap_or_else(|err| TxResult {
                        code: ErrorCodes::InvalidVoteExtension.into(),
                        info: format!(
                            "Process proposal rejected this proposal because \
                             one of the included validator set update vote \
                             extensions was invalid: {err}"
                        ),
                    }),
                ProtocolTxType::EthereumEvents(digest) => {
                    #[cfg(feature = "abcipp")]
                    {
                        metadata.digests.eth_ev_digest_num += 1;
                    }
                    let extensions =
                        digest.decompress(self.storage.last_height);
                    let valid_extensions =
                        self.validate_eth_events_vext_list(extensions).map(
                            |maybe_ext| maybe_ext.ok().map(|(power, _)| power),
                        );

                    self.validate_vexts_in_proposal(valid_extensions)
                }
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
                    #[cfg(feature = "abcipp")]
                    {
                        metadata.digests.valset_upd_digest_num += 1;
                    }

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
            TxType::Wrapper(tx) => {
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
                    // If the public key corresponds to the MASP sentinel
                    // transaction key, then the fee payer is effectively
                    // the MASP, otherwise derive
                    // the payer from public key.
                    let fee_payer = if tx.pk != masp_tx_key().ref_to() {
                        tx.fee_payer()
                    } else {
                        masp()
                    };
                    // check that the fee payer has sufficient balance
                    let balance =
                        self.storage.get_balance(&tx.fee.token, &fee_payer);

                    if tx.fee.amount <= balance {
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
    fn has_proper_eth_events_num(&self, meta: &ValidationMeta) -> bool {
        self.storage.last_height.0 == 0 || meta.digests.eth_ev_digest_num == 1
    }

    /// Checks if we have found the correct number of validator set update
    /// vote extensions in [`DigestCounters`].
    #[cfg(feature = "abcipp")]
    fn has_proper_valset_upd_num(&self, meta: &ValidationMeta) -> bool {
        if self
            .storage
            .can_send_validator_set_update(SendValsetUpd::AtPrevHeight)
        {
            self.storage.last_height.0 == 0
                || meta.digests.valset_upd_digest_num == 1
        } else {
            true
        }
    }

    /// Checks if it is not possible to include encrypted txs at the current
    /// block height.
    fn encrypted_txs_not_allowed(&self) -> bool {
        let is_2nd_height_off = self.storage.is_deciding_offset_within_epoch(1);
        let is_3rd_height_off = self.storage.is_deciding_offset_within_epoch(2);
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
    use borsh::BorshDeserialize;
    use namada::proto::SignedTxData;
    use namada::types::ethereum_events::EthereumEvent;
    use namada::types::hash::Hash;
    use namada::types::key::*;
    use namada::types::storage::Epoch;
    use namada::types::token;
    use namada::types::transaction::encrypted::EncryptedTx;
    use namada::types::transaction::{EncryptionKey, Fee};
    use namada::types::vote_extensions::ethereum_events;
    #[cfg(feature = "abcipp")]
    use namada::types::vote_extensions::ethereum_events::MultiSignedEthEvent;

    use super::*;
    use crate::node::ledger::shell::test_utils::{
        self, gen_keypair, ProcessProposal, TestError, TestShell,
    };
    #[cfg(feature = "abcipp")]
    use crate::node::ledger::shims::abcipp_shim_types::shim::TxBytes;
    use crate::wallet;

    #[cfg(feature = "abcipp")]
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
    #[cfg(feature = "abcipp")]
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
                    s.insert(
                        (validator_addr, shell.storage.last_height),
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
        let request = ProcessProposal {
            txs: vec![tx.clone(), tx],
        };
        let results = shell.process_proposal(request);
        assert_matches!(
            results, Err(TestError::RejectProposal(s)) if s.len() == 2
        );
    }

    #[cfg(feature = "abcipp")]
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

    #[cfg(not(feature = "abcipp"))]
    fn check_rejected_eth_events(
        shell: &mut TestShell,
        vote_extension: ethereum_events::SignedVext,
        protocol_key: common::SecretKey,
    ) {
        let tx = ProtocolTxType::EthEventsVext(vote_extension)
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
    fn test_drop_vext_with_invalid_sigs() {
        const LAST_HEIGHT: BlockHeight = BlockHeight(2);
        let (mut shell, _recv, _) = test_utils::setup();
        shell.storage.last_height = LAST_HEIGHT;
        let (protocol_key, _, _) = wallet::defaults::validator_keys();
        let addr = wallet::defaults::validator_address();
        let event = EthereumEvent::TransfersToNamada {
            nonce: 1u64.into(),
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
                        (addr.clone(), shell.storage.last_height),
                        ext.sig,
                    );
                    s
                },
                events: vec![MultiSignedEthEvent {
                    event,
                    signers: {
                        let mut s = BTreeSet::new();
                        s.insert((addr, shell.storage.last_height));
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
        let (mut shell, _recv, _) = test_utils::setup();
        shell.storage.last_height = LAST_HEIGHT;
        let (protocol_key, _, _) = wallet::defaults::validator_keys();
        let addr = wallet::defaults::validator_address();
        let event = EthereumEvent::TransfersToNamada {
            nonce: 1u64.into(),
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
        let (mut shell, _recv, _) = test_utils::setup();
        shell.storage.last_height = LAST_HEIGHT;
        let (addr, protocol_key) = {
            let bertha_key = wallet::defaults::bertha_keypair();
            let bertha_addr = wallet::defaults::bertha_address();
            (bertha_addr, bertha_key)
        };
        let event = EthereumEvent::TransfersToNamada {
            nonce: 1u64.into(),
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
                token: shell.storage.native_token.clone(),
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

        #[cfg(feature = "abcipp")]
        let response = {
            let request = ProcessProposal {
                txs: vec![tx, get_empty_eth_ev_digest(&shell)],
            };
            if let [resp, _] = shell
                .process_proposal(request)
                .expect("Test failed")
                .as_slice()
            {
                resp.clone()
            } else {
                panic!("Test failed");
            }
        };
        #[cfg(not(feature = "abcipp"))]
        let response = {
            let request = ProcessProposal { txs: vec![tx] };
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
                token: shell.storage.native_token.clone(),
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
        #[cfg(feature = "abcipp")]
        let response = {
            let request = ProcessProposal {
                txs: vec![new_tx.to_bytes(), get_empty_eth_ev_digest(&shell)],
            };

            if let [resp, _] = shell
                .process_proposal(request)
                .expect("Test failed")
                .as_slice()
            {
                resp.clone()
            } else {
                panic!("Test failed");
            }
        };
        #[cfg(not(feature = "abcipp"))]
        let response = {
            let request = ProcessProposal {
                txs: vec![new_tx.to_bytes()],
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
                token: shell.storage.native_token.clone(),
            },
            &keypair,
            Epoch(0),
            0.into(),
            tx,
            Default::default(),
        )
        .sign(&keypair)
        .expect("Test failed");
        #[cfg(feature = "abcipp")]
        let response = {
            let request = ProcessProposal {
                txs: vec![wrapper.to_bytes(), get_empty_eth_ev_digest(&shell)],
            };
            if let [resp, _] = shell
                .process_proposal(request)
                .expect("Test failed")
                .as_slice()
            {
                resp.clone()
            } else {
                panic!("Test failed");
            }
        };
        #[cfg(not(feature = "abcipp"))]
        let response = {
            let request = ProcessProposal {
                txs: vec![wrapper.to_bytes()],
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
                amount: token::Amount::whole(1_000_100),
                token: shell.storage.native_token.clone(),
            },
            &keypair,
            Epoch(0),
            0.into(),
            tx,
            Default::default(),
        )
        .sign(&keypair)
        .expect("Test failed");

        #[cfg(feature = "abcipp")]
        let response = {
            let request = ProcessProposal {
                txs: vec![wrapper.to_bytes(), get_empty_eth_ev_digest(&shell)],
            };
            if let [resp, _] = shell
                .process_proposal(request)
                .expect("Test failed")
                .as_slice()
            {
                resp.clone()
            } else {
                panic!("Test failed");
            }
        };
        #[cfg(not(feature = "abcipp"))]
        let response = {
            let request = ProcessProposal {
                txs: vec![wrapper.to_bytes()],
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
                    token: shell.storage.native_token.clone(),
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
                token: shell.storage.native_token.clone(),
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

        #[cfg(feature = "abcipp")]
        let response = {
            let request = ProcessProposal {
                txs: vec![tx.to_bytes(), get_empty_eth_ev_digest(&shell)],
            };
            if let [resp, _] = shell
                .process_proposal(request)
                .expect("Test failed")
                .as_slice()
            {
                resp.clone()
            } else {
                panic!("Test failed");
            }
        };
        #[cfg(not(feature = "abcipp"))]
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
                token: shell.storage.native_token.clone(),
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

        #[cfg(feature = "abcipp")]
        let response = {
            let request = ProcessProposal {
                txs: vec![tx.to_bytes(), get_empty_eth_ev_digest(&shell)],
            };
            if let [resp, _] = shell
                .process_proposal(request)
                .expect("Test failed")
                .as_slice()
            {
                resp.clone()
            } else {
                panic!("Test failed");
            }
        };
        #[cfg(not(feature = "abcipp"))]
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
        let (mut shell, _recv, _) = test_utils::setup_at_height(3u64);
        let keypair = crate::wallet::defaults::daewon_keypair();
        let pubkey = EncryptionKey::default();
        // not valid tx bytes
        let tx = "garbage data".as_bytes().to_owned();
        let inner_tx = EncryptedTx::encrypt(&tx, pubkey);
        let wrapper = WrapperTx {
            fee: Fee {
                amount: 0.into(),
                token: shell.storage.native_token.clone(),
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
        #[cfg(feature = "abcipp")]
        let response = {
            let request = ProcessProposal {
                txs: vec![signed.to_bytes(), get_empty_eth_ev_digest(&shell)],
            };
            if let [resp, _] = shell
                .process_proposal(request)
                .expect("Test failed")
                .as_slice()
            {
                resp.clone()
            } else {
                panic!("Test failed");
            }
        };
        #[cfg(not(feature = "abcipp"))]
        let response = {
            let request = ProcessProposal {
                txs: vec![signed.to_bytes()],
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
        let (mut shell, _recv, _) = test_utils::setup_at_height(3u64);

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
        #[cfg(feature = "abcipp")]
        let response = {
            let request = ProcessProposal {
                txs: vec![tx.to_bytes(), get_empty_eth_ev_digest(&shell)],
            };
            if let [resp, _] = shell
                .process_proposal(request)
                .expect("Test failed")
                .as_slice()
            {
                resp.clone()
            } else {
                panic!("Test failed");
            }
        };
        #[cfg(not(feature = "abcipp"))]
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
        assert_eq!(response.result.code, u32::from(ErrorCodes::InvalidTx));
        assert_eq!(
            response.result.info,
            String::from(
                "Transaction rejected: Non-encrypted transactions are not \
                 supported"
            ),
        );
    }

    /// Test if we reject wrapper txs when they shouldn't be included in blocks.
    ///
    /// Currently, the conditions to reject wrapper
    /// txs are simply to check if we are at the 2nd
    /// or 3rd height offset within an epoch.
    #[test]
    fn test_include_only_protocol_txs() {
        let (mut shell, _recv, _) = test_utils::setup_at_height(1u64);
        let keypair = gen_keypair();
        let tx = Tx::new(
            "wasm_code".as_bytes().to_owned(),
            Some(b"transaction data".to_vec()),
        );
        let wrapper = WrapperTx::new(
            Fee {
                amount: 1234.into(),
                token: shell.storage.native_token.clone(),
            },
            &keypair,
            Epoch(0),
            0.into(),
            tx,
            Default::default(),
        )
        .sign(&keypair)
        .expect("Test failed")
        .to_bytes();
        for height in [1u64, 2] {
            shell.storage.last_height = height.into();
            #[cfg(feature = "abcipp")]
            let response = {
                let request = ProcessProposal {
                    txs: vec![wrapper.clone(), get_empty_eth_ev_digest(&shell)],
                };
                if let Err(TestError::RejectProposal(mut resp)) =
                    shell.process_proposal(request)
                {
                    assert_eq!(resp.len(), 2);
                    resp.remove(0)
                } else {
                    panic!("Test failed")
                }
            };
            #[cfg(not(feature = "abcipp"))]
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
