//! Implementation of the [`RequestPrepareProposal`] ABCI++ method for the Shell

use namada::ledger::storage::traits::StorageHasher;
use namada::ledger::storage::{DBIter, DB};
#[cfg(feature = "abcipp")]
use namada::ledger::storage_api::queries::QueriesExt;
#[cfg(feature = "abcipp")]
use namada::ledger::storage_api::queries::SendValsetUpd;
use namada::proto::Tx;
use namada::types::storage::BlockHeight;
use namada::types::transaction::tx_types::TxType;
use namada::types::transaction::wrapper::wrapper_tx::PairingEngine;
use namada::types::transaction::{AffineCurve, DecryptedTx, EllipticCurve};
#[cfg(feature = "abcipp")]
use namada::types::vote_extensions::VoteExtensionDigest;

use super::super::*;
use crate::facade::tendermint_proto::abci::RequestPrepareProposal;
#[cfg(feature = "abcipp")]
use crate::facade::tendermint_proto::abci::{
    tx_record::TxAction, ExtendedCommitInfo,
};
#[cfg(not(feature = "abcipp"))]
use crate::node::ledger::shell::vote_extensions::deserialize_vote_extensions;
#[cfg(feature = "abcipp")]
use crate::node::ledger::shell::vote_extensions::iter_protocol_txs;
#[cfg(feature = "abcipp")]
use crate::node::ledger::shell::vote_extensions::split_vote_extensions;
use crate::node::ledger::shell::{process_tx, ShellMode};
use crate::node::ledger::shims::abcipp_shim_types::shim::TxBytes;

impl<D, H> Shell<D, H>
where
    D: DB + for<'iter> DBIter<'iter> + Sync + 'static,
    H: StorageHasher + Sync + 'static,
{
    /// Begin a new block.
    ///
    /// We include half of the new wrapper txs given to us from the mempool
    /// by tendermint. The rest of the block is filled with decryptions
    /// of the wrapper txs from the previously committed block.
    ///
    /// INVARIANT: Any changes applied in this method must be reverted if
    /// the proposal is rejected (unless we can simply overwrite
    /// them in the next block).
    pub fn prepare_proposal(
        &mut self,
        req: RequestPrepareProposal,
    ) -> response::PrepareProposal {
        // We can safely reset meter, because if the block is rejected,
        // we'll reset again on the next proposal, until the
        // proposal is accepted
        self.gas_meter.reset();
        let txs = if let ShellMode::Validator { .. } = self.mode {
            // TODO: add some info logging?

            // add ethereum events and validator set updates as protocol txs
            #[cfg(feature = "abcipp")]
            let txs = self.build_vote_extension_txs(req.local_last_commit);
            #[cfg(not(feature = "abcipp"))]
            let mut txs = self.build_vote_extension_txs(&req.txs);

            // add mempool txs
            let mut mempool_txs = self.build_mempool_txs(req.txs);
            txs.append(&mut mempool_txs);

            // decrypt the wrapper txs included in the previous block
            let mut decrypted_txs = self.build_decrypted_txs();
            txs.append(&mut decrypted_txs);

            txs
        } else {
            vec![]
        };

        tracing::info!(
            height = req.height,
            tx_records = txs.len(),
            "Proposing block"
        );

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

    /// Builds a batch of vote extension transactions, comprised of Ethereum
    /// events and, optionally, a validator set update
    #[cfg(feature = "abcipp")]
    fn build_vote_extension_txs(
        &mut self,
        local_last_commit: Option<ExtendedCommitInfo>,
    ) -> Vec<TxBytes> {
        // genesis should not contain vote extensions
        if self.storage.last_height == BlockHeight(0) {
            return vec![];
        }

        let (eth_events, valset_upds) = split_vote_extensions(
            local_last_commit
                .expect(
                    "Honest Namada validators will always sign \
                     ethereum_events::Vext instances, even if no Ethereum \
                     events were observed at a given block height. In fact, a \
                     quorum of signed empty ethereum_events::Vext instances \
                     commits the fact no events were observed by a majority \
                     of validators. Therefore, for block heights greater than \
                     zero, we should always have vote extensions.",
                )
                .votes,
        );

        let ethereum_events = self
            .compress_ethereum_events(eth_events)
            .unwrap_or_else(|| panic!("{}", not_enough_voting_power_msg()));

        let validator_set_update =
            if self
                .storage
                .can_send_validator_set_update(SendValsetUpd::AtPrevHeight)
            {
                Some(self.compress_valset_updates(valset_upds).unwrap_or_else(
                    || panic!("{}", not_enough_voting_power_msg()),
                ))
            } else {
                None
            };

        let protocol_key = self
            .mode
            .get_protocol_key()
            .expect("Validators should always have a protocol key");

        iter_protocol_txs(VoteExtensionDigest {
            ethereum_events,
            validator_set_update,
        })
        .map(|tx| tx.sign(protocol_key).to_bytes())
        .collect()
    }

    /// Builds a batch of vote extension transactions, comprised of Ethereum
    /// events and, optionally, a validator set update
    #[cfg(not(feature = "abcipp"))]
    fn build_vote_extension_txs(&mut self, txs: &[TxBytes]) -> Vec<TxBytes> {
        if self.storage.last_height != BlockHeight(0) {
            deserialize_vote_extensions(txs).collect()
        } else {
            // genesis should not contain vote extensions
            vec![]
        }
    }

    /// Builds a batch of mempool transactions
    fn build_mempool_txs(&mut self, txs: Vec<Vec<u8>>) -> Vec<TxBytes> {
        // filter in half of the new txs from Tendermint, only keeping
        // wrappers
        let number_of_new_txs = 1 + txs.len() / 2;
        txs.into_iter()
            .take(number_of_new_txs)
            .filter_map(|tx_bytes| {
                if let Ok(Ok(TxType::Wrapper(_))) =
                    Tx::try_from(tx_bytes.as_slice()).map(process_tx)
                {
                    Some(tx_bytes)
                } else {
                    None
                }
            })
            .collect()
    }

    /// Builds a batch of DKG decrypted transactions
    // TODO: we won't have frontrunning protection until V2 of the Anoma
    // protocol; Namada runs V1, therefore this method is
    // essentially a NOOP, and ought to be removed
    //
    // sources:
    // - https://specs.anoma.net/main/releases/v2.html
    // - https://github.com/anoma/ferveo
    fn build_decrypted_txs(&mut self) -> Vec<TxBytes> {
        // TODO: This should not be hardcoded
        let privkey = <EllipticCurve as PairingEngine>::G2Affine::prime_subgroup_generator();

        self.storage
            .tx_queue
            .iter()
            .map(|tx| {
                Tx::from(match tx.decrypt(privkey) {
                    Ok(tx) => DecryptedTx::Decrypted(tx),
                    _ => DecryptedTx::Undecryptable(tx.clone()),
                })
                .to_bytes()
            })
            .collect()
    }
}

/// Returns a suitable message to be displayed when Tendermint
/// somehow decides on a block containing vote extensions
/// reflecting `<= 2/3` of the total stake.
#[cfg(feature = "abcipp")]
const fn not_enough_voting_power_msg() -> &'static str {
    "A Tendermint quorum should never decide on a block including vote \
     extensions reflecting less than or equal to 2/3 of the total stake."
}

#[cfg(test)]
// TODO: write tests for validator set update vote extensions in
// prepare proposals
mod test_prepare_proposal {
    #[cfg(feature = "abcipp")]
    use std::collections::{BTreeSet, HashMap};

    use borsh::{BorshDeserialize, BorshSerialize};
    use namada::ledger::pos::namada_proof_of_stake::types::{
        VotingPower, WeightedValidator,
    };
    use namada::ledger::pos::namada_proof_of_stake::PosBase;
    use namada::ledger::storage_api::queries::QueriesExt;
    use namada::proto::{Signed, SignedTxData};
    use namada::types::address::nam;
    use namada::types::ethereum_events::EthereumEvent;
    #[cfg(feature = "abcipp")]
    use namada::types::key::common;
    use namada::types::key::RefTo;
    use namada::types::storage::{BlockHeight, Epoch};
    use namada::types::transaction::protocol::ProtocolTxType;
    use namada::types::transaction::{Fee, TxType, WrapperTx};
    use namada::types::vote_extensions::ethereum_events;
    #[cfg(feature = "abcipp")]
    use namada::types::vote_extensions::VoteExtension;

    use super::*;
    #[cfg(feature = "abcipp")]
    use crate::facade::tendermint_proto::abci::{
        tx_record::TxAction, ExtendedCommitInfo, ExtendedVoteInfo, TxRecord,
    };
    use crate::node::ledger::shell::test_utils::{
        self, gen_keypair, TestShell,
    };
    use crate::node::ledger::shims::abcipp_shim_types::shim::request::FinalizeBlock;
    use crate::wallet;

    #[cfg(feature = "abcipp")]
    fn get_local_last_commit(shell: &TestShell) -> Option<ExtendedCommitInfo> {
        let evts = {
            let validator_addr = shell
                .mode
                .get_validator_address()
                .expect("Test failed")
                .to_owned();

            let prev_height = shell.storage.last_height;

            let ext = ethereum_events::Vext::empty(prev_height, validator_addr);

            let protocol_key = match &shell.mode {
                ShellMode::Validator { data, .. } => {
                    &data.keys.protocol_keypair
                }
                _ => panic!("Test failed"),
            };

            ext.sign(protocol_key)
        };

        let vote_extension = VoteExtension {
            ethereum_events: evts,
            validator_set_update: None,
        }
        .try_to_vec()
        .expect("Test failed");

        let vote = ExtendedVoteInfo {
            vote_extension,
            ..Default::default()
        };

        Some(ExtendedCommitInfo {
            votes: vec![vote],
            ..Default::default()
        })
    }

    /// Test that if a tx from the mempool is not a
    /// WrapperTx type, it is not included in the
    /// proposed block.
    #[test]
    fn test_prepare_proposal_rejects_non_wrapper_tx() {
        let (mut shell, _recv, _) = test_utils::setup_at_height(3u64);
        let non_wrapper_tx = Tx::new(
            "wasm_code".as_bytes().to_owned(),
            Some("transaction_data".as_bytes().to_owned()),
        );
        let req = RequestPrepareProposal {
            #[cfg(feature = "abcipp")]
            local_last_commit: get_local_last_commit(&shell),
            txs: vec![non_wrapper_tx.to_bytes()],
            max_tx_bytes: 0,
            ..Default::default()
        };
        #[cfg(feature = "abcipp")]
        assert_eq!(
            // NOTE: we process mempool txs after protocol txs
            shell.prepare_proposal(req).tx_records.remove(1),
            record::remove(non_wrapper_tx.to_bytes())
        );
        #[cfg(not(feature = "abcipp"))]
        assert!({
            let mut assertion = true;
            // this includes valset upd and eth events
            // vote extension diggests
            let transactions = shell.prepare_proposal(req).txs;
            assert_eq!(transactions.len(), 2);
            let non_wrapper_tx = non_wrapper_tx.to_bytes();
            for tx in transactions {
                if tx == non_wrapper_tx {
                    assertion = false;
                    break;
                }
            }
            assertion
        });
    }

    /// Check if we are filtering out an invalid vote extension `vext`
    fn check_eth_events_filtering(
        shell: &mut TestShell,
        vext: Signed<ethereum_events::Vext>,
    ) {
        let filtered_votes: Vec<_> =
            shell.filter_invalid_eth_events_vexts(vec![vext]).collect();

        assert_eq!(filtered_votes, vec![]);
    }

    /// Test if we are filtering out Ethereum events with bad
    /// signatures in a prepare proposal.
    #[test]
    fn test_prepare_proposal_filter_out_bad_vext_signatures() {
        const LAST_HEIGHT: BlockHeight = BlockHeight(2);

        let (mut shell, _recv, _) = test_utils::setup();

        // artificially change the block height
        shell.storage.last_height = LAST_HEIGHT;

        let signed_vote_extension = {
            let (protocol_key, _, _) = wallet::defaults::validator_keys();
            let validator_addr = wallet::defaults::validator_address();

            // generate a valid signature
            let mut ext = ethereum_events::Vext {
                validator_addr,
                block_height: LAST_HEIGHT,
                ethereum_events: vec![],
            }
            .sign(&protocol_key);
            assert!(ext.verify(&protocol_key.ref_to()).is_ok());

            // modify this signature such that it becomes invalid
            ext.sig = test_utils::invalidate_signature(ext.sig);
            ext
        };

        check_eth_events_filtering(&mut shell, signed_vote_extension);
    }

    /// Test if we are filtering out Ethereum events seen at
    /// block heights different than the last height.
    #[test]
    fn test_prepare_proposal_filter_out_bad_vext_bheights() {
        const LAST_HEIGHT: BlockHeight = BlockHeight(3);
        const PRED_LAST_HEIGHT: BlockHeight = BlockHeight(LAST_HEIGHT.0 - 1);

        let (mut shell, _recv, _) = test_utils::setup();

        // artificially change the block height
        shell.storage.last_height = LAST_HEIGHT;

        let (protocol_key, _, _) = wallet::defaults::validator_keys();
        let validator_addr = wallet::defaults::validator_address();

        let signed_vote_extension = {
            let ext = ethereum_events::Vext {
                validator_addr,
                block_height: PRED_LAST_HEIGHT,
                ethereum_events: vec![],
            }
            .sign(&protocol_key);
            assert!(ext.verify(&protocol_key.ref_to()).is_ok());
            ext
        };

        #[cfg(feature = "abcipp")]
        check_eth_events_filtering(&mut shell, signed_vote_extension);

        #[cfg(not(feature = "abcipp"))]
        {
            let filtered_votes: Vec<_> = shell
                .filter_invalid_eth_events_vexts(vec![
                    signed_vote_extension.clone(),
                ])
                .collect();
            assert_eq!(
                filtered_votes,
                vec![(
                    test_utils::get_validator_voting_power(),
                    signed_vote_extension
                )]
            )
        }
    }

    /// Test if we are filtering out Ethereum events seen by
    /// non-validator nodes.
    #[test]
    fn test_prepare_proposal_filter_out_bad_vext_validators() {
        const LAST_HEIGHT: BlockHeight = BlockHeight(2);

        let (mut shell, _recv, _) = test_utils::setup();

        // artificially change the block height
        shell.storage.last_height = LAST_HEIGHT;

        let (validator_addr, protocol_key) = {
            let bertha_key = wallet::defaults::bertha_keypair();
            let bertha_addr = wallet::defaults::bertha_address();
            (bertha_addr, bertha_key)
        };

        let signed_vote_extension = {
            let ext = ethereum_events::Vext {
                validator_addr,
                block_height: LAST_HEIGHT,
                ethereum_events: vec![],
            }
            .sign(&protocol_key);
            assert!(ext.verify(&protocol_key.ref_to()).is_ok());
            ext
        };

        check_eth_events_filtering(&mut shell, signed_vote_extension);
    }

    /// Test if we are filtering out duped Ethereum events in
    /// prepare proposals.
    #[test]
    fn test_prepare_proposal_filter_duped_ethereum_events() {
        const LAST_HEIGHT: BlockHeight = BlockHeight(3);

        let (mut shell, _recv, _) = test_utils::setup();

        // artificially change the block height
        shell.storage.last_height = LAST_HEIGHT;

        let (protocol_key, _, _) = wallet::defaults::validator_keys();
        let validator_addr = wallet::defaults::validator_address();

        let ethereum_event = EthereumEvent::TransfersToNamada {
            nonce: 1u64.into(),
            transfers: vec![],
        };
        let signed_vote_extension = {
            let ev = ethereum_event;
            let ext = ethereum_events::Vext {
                validator_addr,
                block_height: LAST_HEIGHT,
                ethereum_events: vec![ev.clone(), ev.clone(), ev],
            }
            .sign(&protocol_key);
            assert!(ext.verify(&protocol_key.ref_to()).is_ok());
            ext
        };

        let maybe_digest =
            shell.compress_ethereum_events(vec![signed_vote_extension]);

        #[cfg(feature = "abcipp")]
        {
            // we should be filtering out the vote extension with
            // duped ethereum events; therefore, no valid vote
            // extensions will remain, and we will get no
            // digest from compressing nil vote extensions
            assert!(maybe_digest.is_none());
        }

        #[cfg(not(feature = "abcipp"))]
        {
            use assert_matches::assert_matches;

            assert_matches!(maybe_digest, Some(d) if d.signatures.is_empty());
        }
    }

    /// Creates an Ethereum events digest manually.
    #[cfg(feature = "abcipp")]
    fn manually_assemble_digest(
        _protocol_key: &common::SecretKey,
        ext: Signed<ethereum_events::Vext>,
        last_height: BlockHeight,
    ) -> ethereum_events::VextDigest {
        use namada::types::vote_extensions::ethereum_events::MultiSignedEthEvent;

        let events = vec![MultiSignedEthEvent {
            event: ext.data.ethereum_events[0].clone(),
            signers: {
                let mut s = BTreeSet::new();
                s.insert(ext.data.validator_addr.clone());
                s
            },
        }];
        let signatures = {
            let mut s = HashMap::new();
            s.insert(ext.data.validator_addr, ext.sig.clone());
            s
        };

        let vote_extension_digest =
            ethereum_events::VextDigest { events, signatures };

        assert_eq!(
            vec![ext],
            vote_extension_digest.clone().decompress(last_height)
        );

        vote_extension_digest
    }

    /// Test if Ethereum events validation and inclusion in a block
    /// behaves as expected, considering honest validators.
    #[cfg(feature = "abcipp")]
    #[test]
    fn test_prepare_proposal_vext_normal_op() {
        const LAST_HEIGHT: BlockHeight = BlockHeight(3);

        let (mut shell, _recv, _) = test_utils::setup();

        // artificially change the block height
        shell.storage.last_height = LAST_HEIGHT;

        let (protocol_key, _, _) = wallet::defaults::validator_keys();
        let validator_addr = wallet::defaults::validator_address();

        let ethereum_event = EthereumEvent::TransfersToNamada {
            nonce: 1u64.into(),
            transfers: vec![],
        };
        let ethereum_events = {
            let ext = ethereum_events::Vext {
                validator_addr,
                block_height: LAST_HEIGHT,
                ethereum_events: vec![ethereum_event],
            }
            .sign(&protocol_key);
            assert!(ext.verify(&protocol_key.ref_to()).is_ok());
            ext
        };
        let vote_extension = VoteExtension {
            ethereum_events,
            validator_set_update: None,
        };
        let vote = ExtendedVoteInfo {
            vote_extension: vote_extension.try_to_vec().unwrap(),
            ..Default::default()
        };

        let mut rsp = shell.prepare_proposal(RequestPrepareProposal {
            local_last_commit: Some(ExtendedCommitInfo {
                votes: vec![vote],
                ..Default::default()
            }),
            ..Default::default()
        });
        let rsp_digest = {
            assert_eq!(rsp.tx_records.len(), 1);
            let tx_record = rsp.tx_records.pop().unwrap();

            assert_eq!(tx_record.action(), TxAction::Added);

            let got = Tx::try_from(&tx_record.tx[..]).unwrap();
            let got_signed_tx =
                SignedTxData::try_from_slice(&got.data.unwrap()[..]).unwrap();
            let protocol_tx =
                TxType::try_from_slice(&got_signed_tx.data.unwrap()[..])
                    .unwrap();

            let protocol_tx = match protocol_tx {
                TxType::Protocol(protocol_tx) => protocol_tx.tx,
                _ => panic!("Test failed"),
            };

            match protocol_tx {
                ProtocolTxType::EthereumEvents(digest) => digest,
                _ => panic!("Test failed"),
            }
        };

        let digest = manually_assemble_digest(
            &protocol_key,
            vote_extension.ethereum_events,
            LAST_HEIGHT,
        );

        assert_eq!(rsp_digest, digest);
    }

    /// Test if Ethereum events validation and inclusion in a block
    /// behaves as expected, considering honest validators.
    #[cfg(not(feature = "abcipp"))]
    #[test]
    fn test_prepare_proposal_vext_normal_op() {
        const LAST_HEIGHT: BlockHeight = BlockHeight(3);

        let (mut shell, _recv, _) = test_utils::setup();

        // artificially change the block height
        shell.storage.last_height = LAST_HEIGHT;

        let (protocol_key, _, _) = wallet::defaults::validator_keys();
        let validator_addr = wallet::defaults::validator_address();

        let ethereum_event = EthereumEvent::TransfersToNamada {
            nonce: 1u64.into(),
            transfers: vec![],
        };
        let ext = {
            let ext = ethereum_events::Vext {
                validator_addr,
                block_height: LAST_HEIGHT,
                ethereum_events: vec![ethereum_event],
            }
            .sign(&protocol_key);
            assert!(ext.verify(&protocol_key.ref_to()).is_ok());
            ext
        };

        let rsp_ext = {
            let tx = ProtocolTxType::EthEventsVext(ext.clone())
                .sign(&protocol_key)
                .to_bytes();
            let mut rsp = shell.prepare_proposal(RequestPrepareProposal {
                txs: vec![tx],
                ..Default::default()
            });
            assert_eq!(rsp.txs.len(), 1);

            let tx_bytes = rsp.txs.remove(0);
            let got = Tx::try_from(&tx_bytes[..]).unwrap();
            let got_signed_tx =
                SignedTxData::try_from_slice(&got.data.unwrap()[..]).unwrap();
            let protocol_tx =
                TxType::try_from_slice(&got_signed_tx.data.unwrap()[..])
                    .unwrap();
            let protocol_tx = match protocol_tx {
                TxType::Protocol(protocol_tx) => protocol_tx.tx,
                _ => panic!("Test failed"),
            };

            match protocol_tx {
                ProtocolTxType::EthEventsVext(ext) => ext,
                _ => panic!("Test failed"),
            }
        };

        assert_eq!(rsp_ext, ext);
    }

    /// Test if Ethereum events validation and inclusion in a block
    /// behaves as expected, considering <= 2/3 voting power.
    #[test]
    #[cfg_attr(
        feature = "abcipp",
        should_panic(expected = "A Tendermint quorum should never")
    )]
    fn test_prepare_proposal_vext_insufficient_voting_power() {
        const FIRST_HEIGHT: BlockHeight = BlockHeight(0);
        const LAST_HEIGHT: BlockHeight = BlockHeight(FIRST_HEIGHT.0 + 11);

        let (mut shell, _recv, _) = test_utils::setup();

        // artificially change the voting power of the default validator to
        // zero, change the block height, and commit a dummy block,
        // to move to a new epoch
        let events_epoch =
            shell.storage.get_epoch(FIRST_HEIGHT).expect("Test failed");
        let validator_set = {
            let params = shell.storage.read_pos_params();
            let mut epochs = shell.storage.read_validator_set();
            let mut data =
                epochs.get(events_epoch).cloned().expect("Test failed");

            data.active = data
                .active
                .iter()
                .cloned()
                .map(|v| WeightedValidator {
                    voting_power: VotingPower::from(0u64),
                    ..v
                })
                .collect();

            epochs.set(data, events_epoch, &params);
            epochs
        };
        shell.storage.write_validator_set(&validator_set);

        let mut req = FinalizeBlock::default();
        req.header.time = namada::types::time::DateTimeUtc::now();
        shell.storage.last_height = LAST_HEIGHT;
        shell.finalize_block(req).expect("Test failed");
        shell.commit();

        assert_eq!(
            shell
                .storage
                .get_epoch(shell.storage.get_current_decision_height()),
            Some(Epoch(1))
        );

        // test prepare proposal
        let (protocol_key, _, _) = wallet::defaults::validator_keys();
        let validator_addr = wallet::defaults::validator_address();

        let ethereum_event = EthereumEvent::TransfersToNamada {
            nonce: 1u64.into(),
            transfers: vec![],
        };
        let signed_eth_ev_vote_extension = {
            let ext = ethereum_events::Vext {
                validator_addr,
                block_height: LAST_HEIGHT,
                ethereum_events: vec![ethereum_event],
            }
            .sign(&protocol_key);
            assert!(ext.verify(&protocol_key.ref_to()).is_ok());
            ext
        };
        #[cfg(feature = "abcipp")]
        {
            let vote_extension = VoteExtension {
                ethereum_events: signed_eth_ev_vote_extension.clone(),
                validator_set_update: None,
            };
            let vote = ExtendedVoteInfo {
                vote_extension: vote_extension.try_to_vec().unwrap(),
                ..Default::default()
            };
            // this should panic
            shell.prepare_proposal(RequestPrepareProposal {
                local_last_commit: Some(ExtendedCommitInfo {
                    votes: vec![vote],
                    ..Default::default()
                }),
                ..Default::default()
            });
        }
        #[cfg(not(feature = "abcipp"))]
        {
            let vote = ProtocolTxType::EthEventsVext(
                signed_eth_ev_vote_extension.clone(),
            )
            .sign(&protocol_key)
            .to_bytes();
            let mut rsp = shell.prepare_proposal(RequestPrepareProposal {
                txs: vec![vote],
                ..Default::default()
            });
            assert_eq!(rsp.txs.len(), 1);

            let tx_bytes = rsp.txs.remove(0);
            let got = Tx::try_from(&tx_bytes[..]).unwrap();
            let got_signed_tx =
                SignedTxData::try_from_slice(&got.data.unwrap()[..]).unwrap();
            let protocol_tx =
                TxType::try_from_slice(&got_signed_tx.data.unwrap()[..])
                    .unwrap();
            let protocol_tx = match protocol_tx {
                TxType::Protocol(protocol_tx) => protocol_tx.tx,
                _ => panic!("Test failed"),
            };

            let rsp_ext = match protocol_tx {
                ProtocolTxType::EthEventsVext(ext) => ext,
                _ => panic!("Test failed"),
            };

            assert_eq!(signed_eth_ev_vote_extension, rsp_ext);
        }
    }

    /// Test that if an error is encountered while
    /// trying to process a tx from the mempool,
    /// we simply exclude it from the proposal
    #[test]
    fn test_error_in_processing_tx() {
        let (mut shell, _recv, _) = test_utils::setup_at_height(3u64);
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
                        token: nam(),
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
            #[cfg(feature = "abcipp")]
            local_last_commit: get_local_last_commit(&shell),
            txs: vec![wrapper.clone()],
            max_tx_bytes: 0,
            ..Default::default()
        };
        #[cfg(feature = "abcipp")]
        assert_eq!(
            // NOTE: we process mempool txs after protocol txs
            shell.prepare_proposal(req).tx_records.remove(1),
            record::remove(wrapper)
        );
        #[cfg(not(feature = "abcipp"))]
        assert_eq!(shell.prepare_proposal(req).txs.len(), 0);
    }

    /// Test that the decrypted txs are included
    /// in the proposal in the same order as their
    /// corresponding wrappers
    #[test]
    fn test_decrypted_txs_in_correct_order() {
        let (mut shell, _recv, _) = test_utils::setup();
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
                    token: nam(),
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
