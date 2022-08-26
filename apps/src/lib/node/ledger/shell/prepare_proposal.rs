//! Implementation of the `PrepareProposal` ABCI++ method for the Shell

use std::collections::{BTreeMap, HashMap, HashSet};

use namada::proto::Signed;
use namada::types::transaction::protocol::ProtocolTxType;
use namada::types::vote_extensions::ethereum_events::{
    self, MultiSignedEthEvent,
};
use namada::types::voting_power::FractionalVotingPower;
#[cfg(feature = "abcipp")]
use tendermint_proto_abcipp::abci::{
    ExtendedCommitInfo, ExtendedVoteInfo, TxRecord,
};

use super::queries::QueriesExt;
use super::vote_extensions::deserialize_vote_extensions;
use super::*;
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
            // TODO: add some info logging

            // add ethereum events as protocol txs
            #[cfg(feature = "abcipp")]
            let vexts = deserialize_vote_extensions(
                req.local_last_commit
                    .map(|ext| ext.votes)
                    .unwrap_or_default(),
            );
            #[cfg(not(feature = "abcipp"))]
            let vexts = deserialize_vote_extensions(&req.txs);

            let mut txs = self.build_vote_extensions_txs(vexts);
            #[cfg(feature = "abcipp")]
            let mut txs: Vec<TxRecord> =
                txs.into_iter().map(|tx| record::add).collect();

            // add mempool txs
            let mut mempool_txs = self.build_mempool_txs(req.txs);
            txs.append(&mut mempool_txs);

            // decrypt the wrapper txs included in the previous block
            let mut decrypted_txs = self.build_decrypted_txs();
            #[cfg(feature = "abcipp")]
            let mut decrypted_txs: Vec<TxRecord> =
                decrypted_txs.into_iter().map(|tx| record::add).collect();

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
    /// events
    // TODO: add `and, optionally, a validator set update` to the docstring,
    // after validator set updates are implemented
    fn build_vote_extensions_txs(
        &mut self,
        vote_extensions: impl Iterator<Item = Signed<ethereum_events::Vext>>,
    ) -> Vec<TxBytes> {
        let protocol_key = self
            .mode
            .get_protocol_key()
            .expect("Validators should always have a protocol key");

        let vote_extension_digest =
            self.compress_ethereum_events(vote_extensions);
        let vote_extension_digest =
            match (vote_extension_digest, self.storage.last_height) {
                // handle genesis block
                (None, BlockHeight(0)) => return vec![],
                (Some(_), BlockHeight(0)) => {
                    unreachable!(
                        "We already handle this scenario in \
                         validate_eth_events_vext."
                    )
                }
                // handle block heights > 0
                (Some(digest), _) => digest,
                #[cfg(feature = "abcipp")]
                _ => unreachable!(
                    "Honest Namada validators will always sign \
                     ethereum_events::Vext instances, even if no Ethereum \
                     events were observed at a given block height. In fact, a \
                     quorum of signed empty ethereum_events::Vext instances \
                     commits the fact no events were observed by a majority \
                     of validators. Likewise, a Tendermint quorum should \
                     never decide on a block including vote extensions \
                     reflecting less than or equal to 2/3 of the total stake. \
                     These scenarios are virtually impossible, so we will \
                     panic here."
                ),
                #[cfg(not(feature = "abcipp"))]
                _ => return vec![],
            };

        let tx = ProtocolTxType::EthEventsDigest(vote_extension_digest)
            .sign(protocol_key)
            .to_bytes();

        // TODO: include here a validator set update tx,
        // if we are at the end of an epoch
        vec![tx]
    }

    /// Builds a batch of mempool transactions
    #[cfg(feature = "abcipp")]
    fn build_mempool_txs(&mut self, txs: Vec<Vec<u8>>) -> Vec<TxRecord> {
        // filter in half of the new txs from Tendermint, only keeping
        // wrappers
        let number_of_new_txs = 1 + txs.len() / 2;
        txs.into_iter()
            .take(number_of_new_txs)
            .map(|tx_bytes| {
                if let Ok(Ok(TxType::Wrapper(_))) =
                    Tx::try_from(tx_bytes.as_slice()).map(process_tx)
                {
                    record::keep(tx_bytes)
                } else {
                    record::remove(tx_bytes)
                }
            })
            .collect()
    }

    /// Builds a batch of mempool transactions
    #[cfg(not(feature = "abcipp"))]
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

    /// Compresses a set of signed Ethereum events into a single
    /// [`ethereum_events::VextDigest`], whilst filtering invalid
    /// [`Signed<ethereum_events::Vext>`] instances in the process
    // TODO: rename this as `compress_vote_extensions`, and return
    // a `VoteExtensionDigest`, which will contain both digests of
    // ethereum events and validator set update vote extensions
    fn compress_ethereum_events(
        &self,
        vote_extensions: impl Iterator<Item = Signed<ethereum_events::Vext>>,
    ) -> Option<ethereum_events::VextDigest> {
        let events_epoch = self
            .storage
            .block
            .pred_epochs
            .get_epoch(self.storage.last_height)
            .expect(
                "The epoch of the last block height should always be known",
            );
        #[cfg(not(feature = "abcipp"))]
        if self.storage.last_height == BlockHeight(0) {
            return None;
        }

        let mut event_observers = BTreeMap::new();
        let mut signatures = HashMap::new();

        let total_voting_power =
            u64::from(self.storage.get_total_voting_power(Some(events_epoch)));
        let mut voting_power = FractionalVotingPower::default();

        for (validator_voting_power, vote_extension) in
            self.filter_invalid_vote_extensions(vote_extensions)
        {
            let validator_addr = vote_extension.data.validator_addr;
            let block_height = vote_extension.data.block_height;

            // update voting power
            let validator_voting_power = u64::from(validator_voting_power);
            voting_power += FractionalVotingPower::new(
                validator_voting_power,
                total_voting_power,
            )
            .expect(
                "The voting power we obtain from storage should always be \
                 valid",
            );

            // register all ethereum events seen by `validator_addr`
            for ev in vote_extension.data.ethereum_events {
                let signers =
                    event_observers.entry(ev).or_insert_with(HashSet::new);
                #[cfg(feature = "abcipp")]
                signers.insert(validator_addr.clone());
                #[cfg(not(feature = "abcipp"))]
                signers.insert((validator_addr.clone(), block_height));
            }

            // register the signature of `validator_addr`
            let addr = validator_addr.clone();
            let sig = vote_extension.sig;

            #[cfg(feature = "abcipp")]
            if let Some(sig) = signatures.insert(addr, sig) {
                tracing::warn!(
                    ?sig,
                    ?validator_addr,
                    "Overwrote old signature from validator while \
                     constructing ethereum_events::VextDigest"
                );
            }

            #[cfg(not(feature = "abcipp"))]
            if let Some(sig) = signatures.insert((addr, block_height), sig) {
                tracing::warn!(
                    ?sig,
                    ?validator_addr,
                    "Overwrote old signature from validator while \
                     constructing ethereum_events::VextDigest"
                );
            }
        }

        #[cfg(feature = "abcipp")]
        if voting_power <= FractionalVotingPower::TWO_THIRDS {
            tracing::error!(
                "Tendermint has decided on a block including Ethereum events \
                 reflecting <= 2/3 of the total stake"
            );
            return None;
        }

        let events: Vec<MultiSignedEthEvent> = event_observers
            .into_iter()
            .map(|(event, signers)| MultiSignedEthEvent { event, signers })
            .collect();
        #[cfg(feature = "abcipp")]
        {
            Some(ethereum_events::VextDigest { events, signatures })
        }

        #[cfg(not(feature = "abcipp"))]
        {
            if !events.is_empty() {
                Some(ethereum_events::VextDigest { events, signatures })
            } else {
                None
            }
        }
    }
}

/// Functions for creating the appropriate TxRecord given the
/// numeric code
#[cfg(feature = "abcipp")]
pub(super) mod record {
    use tendermint_proto_abcipp::abci::tx_record::TxAction;

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
// TODO: write a test to check for unreachable code paths in
// prepare proposals, when processing ethereum events
mod test_prepare_proposal {
    use std::collections::HashSet;

    use namada::ledger::pos::namada_proof_of_stake::types::{
        VotingPower, WeightedValidator,
    };
    use namada::proto::{Signed, SignedTxData};
    use namada::types::address::xan;
    use namada::types::ethereum_events::EthereumEvent;
    use namada::types::key::common;
    use namada::types::storage::{BlockHeight, Epoch};
    use namada::types::transaction::protocol::ProtocolTxType;
    use namada::types::transaction::{Fee, TxType};
    use namada::types::vote_extensions::ethereum_events;
    #[cfg(feature = "abcipp")]
    use tendermint_proto::abci::{
        ExtendedCommitInfo, ExtendedVoteInfo, TxRecord,
    };
    #[cfg(feature = "abcipp")]
    use tendermint_proto_abcipp::abci::tx_record::TxAction;

    use super::*;
    use crate::node::ledger::shell::test_utils::{
        self, gen_keypair, setup, TestShell,
    };
    use crate::node::ledger::shims::abcipp_shim_types::shim::request::FinalizeBlock;
    use crate::wallet;

    /// Test that if a tx from the mempool is not a
    /// WrapperTx type, it is not included in the
    /// proposed block.
    #[test]
    fn test_prepare_proposal_rejects_non_wrapper_tx() {
        let (mut shell, _, _) = TestShell::new();
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

    /// Serialize a [`Signed<ethereum_events::Vext>`] to an
    /// [`ExtendedVoteInfo`]
    #[cfg(feature = "abcipp")]
    fn vote_extension_serialize(
        vext: Signed<ethereum_events::Vext>,
    ) -> ExtendedVoteInfo {
        ExtendedVoteInfo {
            vote_extension: vext.try_to_vec().unwrap(),
            ..Default::default()
        }
    }

    /// Convert a [`Signed<ethereum_events::Vext>`] to
    /// a signed tx and serialize
    #[cfg(not(feature = "abcipp"))]
    fn vote_extension_serialize(
        vext: Signed<ethereum_events::Vext>,
        signing_key: &common::SecretKey,
    ) -> TxBytes {
        ProtocolTxType::EthereumEvents(vext)
            .sign(signing_key)
            .to_bytes()
    }

    /// Creates an Ethereum events digest manually, and encodes it as a
    /// [`TxRecord`].
    fn manually_assemble_digest(
        _protocol_key: &common::SecretKey,
        ext: Signed<ethereum_events::Vext>,
        last_height: BlockHeight,
    ) -> ethereum_events::VextDigest {
        let events = vec![MultiSignedEthEvent {
            event: ext.data.ethereum_events[0].clone(),
            signers: {
                let mut s = HashSet::new();
                #[cfg(feature = "abcipp")]
                s.insert(ext.data.validator_addr.clone());
                #[cfg(not(feature = "abcipp"))]
                s.insert((ext.data.validator_addr.clone(), last_height));

                s
            },
        }];
        let signatures = {
            let mut s = HashMap::new();
            #[cfg(feature = "abcipp")]
            s.insert(ext.data.validator_addr.clone(), ext.sig.clone());
            #[cfg(not(feature = "abcipp"))]
            s.insert(
                (ext.data.validator_addr.clone(), last_height),
                ext.sig.clone(),
            );
            s
        };

        let vote_extension_digest =
            ethereum_events::VextDigest { events, signatures };

        #[cfg(feature = "abcipp")]
        assert_eq!(
            vec![ext],
            vote_extension_digest.clone().decompress(last_height)
        );
        #[cfg(not(feature = "abcipp"))]
        assert_eq!(vec![ext], vote_extension_digest.clone().decompress());

        vote_extension_digest

        // let tx = ProtocolTxType::EthEventsDigest(vote_extension_digest)
        //    .sign(&protocol_key)
        //    .to_bytes();
        // super::record::add(tx)
    }

    /// Check if we are filtering out an invalid vote extension `vext`
    fn check_eth_events_filtering(
        shell: &mut TestShell,
        vext: Signed<ethereum_events::Vext>,
    ) {
        #[cfg(feature = "abcipp")]
        let vexts = vec![vote_extension_serialize(vext)];
        #[cfg(not(feature = "abcipp"))]
        let protocol_key = shell.mode.get_protocol_key().expect("Test failed");
        #[cfg(not(feature = "abcipp"))]
        let vexts = vec![vote_extension_serialize(vext, protocol_key)];

        let votes = deserialize_vote_extensions(&vexts[..]);
        let filtered_votes: Vec<_> =
            shell.filter_invalid_vote_extensions(votes).collect();

        assert_eq!(filtered_votes, vec![]);
    }

    /// Test if we are filtering out Ethereum events with bad
    /// signatures in a prepare proposal.
    #[test]
    fn test_prepare_proposal_filter_out_bad_vext_signatures() {
        const LAST_HEIGHT: BlockHeight = BlockHeight(2);

        let (mut shell, _, _) = test_utils::setup();

        // artificially change the block height
        shell.storage.last_height = LAST_HEIGHT;

        let signed_vote_extension = {
            let (protocol_key, _) = wallet::defaults::validator_keys();
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
    /// block heights different than the last height if vote extensions
    /// are on.
    ///
    /// If vote extensions are on, this is allowed
    #[test]
    fn test_prepare_proposal_filter_out_bad_vext_bheights() {
        const LAST_HEIGHT: BlockHeight = BlockHeight(3);
        const PRED_LAST_HEIGHT: BlockHeight = BlockHeight(LAST_HEIGHT.0 - 1);

        let (mut shell, _, _) = test_utils::setup();

        // artificially change the block height
        shell.storage.last_height = LAST_HEIGHT;

        let (protocol_key, _) = wallet::defaults::validator_keys();
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
            let protocol_key =
                shell.mode.get_protocol_key().expect("Test failed");
            let vexts = vec![vote_extension_serialize(
                signed_vote_extension.clone(),
                protocol_key,
            )];

            let votes = deserialize_vote_extensions(&vexts[..]);
            let filtered_votes: Vec<_> =
                shell.filter_invalid_vote_extensions(votes).collect();
            assert_eq!(
                filtered_votes,
                vec![(200.into(), signed_vote_extension)]
            )
        }
    }

    /// Test if we are filtering out Ethereum events seen by
    /// non-validator nodes.
    #[test]
    fn test_prepare_proposal_filter_out_bad_vext_validators() {
        const LAST_HEIGHT: BlockHeight = BlockHeight(2);

        let (mut shell, _, _) = test_utils::setup();

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

        let (mut shell, _, _) = test_utils::setup();

        // artificially change the block height
        shell.storage.last_height = LAST_HEIGHT;

        let (protocol_key, _) = wallet::defaults::validator_keys();
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

        let maybe_digest = {
            #[cfg(feature = "abcipp")]
            let votes = vec![vote_extension_serialize(signed_vote_extension)];
            #[cfg(not(feature = "abcipp"))]
            let votes = vec![vote_extension_serialize(
                signed_vote_extension,
                &protocol_key,
            )];
            shell.compress_ethereum_events(deserialize_vote_extensions(&votes))
        };

        // we should be filtering out the vote extension with
        // duped ethereum events; therefore, no valid vote
        // extensions will remain, and we will get no
        // digest from compressing nil vote extensions
        assert!(maybe_digest.is_none());
    }

    /// Test if Ethereum events validation and inclusion in a block
    /// behaves as expected, considering honest validators.
    #[cfg(feature = "abcipp")]
    #[test]
    fn test_prepare_proposal_vext_normal_op() {
        const LAST_HEIGHT: BlockHeight = BlockHeight(3);

        let (mut shell, _, _) = test_utils::setup();

        // artificially change the block height
        shell.storage.last_height = LAST_HEIGHT;

        let (protocol_key, _) = wallet::defaults::validator_keys();
        let validator_addr = wallet::defaults::validator_address();

        let ethereum_event = EthereumEvent::TransfersToNamada {
            nonce: 1u64.into(),
            transfers: vec![],
        };
        let signed_vote_extension = {
            let ext = ethereum_events::Vext {
                validator_addr,
                block_height: LAST_HEIGHT,
                ethereum_events: vec![ethereum_event],
            }
            .sign(&protocol_key);
            assert!(ext.verify(&protocol_key.ref_to()).is_ok());
            ext
        };

        let rsp_digest = {
            let vote = ExtendedVoteInfo {
                vote_extension: signed_vote_extension.try_to_vec().unwrap(),
                ..Default::default()
            };
            let mut rsp = shell.prepare_proposal(RequestPrepareProposal {
                local_last_commit: Some(ExtendedCommitInfo {
                    votes: vec![vote],
                    ..Default::default()
                }),
                ..Default::default()
            });
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
                ProtocolTxType::EthEventsDigest(digest) => digest,
                _ => panic!("Test failed"),
            }
        };

        let digest = manually_assemble_digest(
            &protocol_key,
            signed_vote_extension,
            LAST_HEIGHT,
        );

        assert_eq!(rsp_digest, digest);

        // NOTE: this comparison will not work because of timestamps
        // assert_eq!(rsp.tx_records, vec![digest]);
    }

    /// Test if Ethereum events validation and inclusion in a block
    /// behaves as expected, considering honest validators.
    #[cfg(not(feature = "abcipp"))]
    #[test]
    fn test_prepare_proposal_vext_normal_op() {
        const LAST_HEIGHT: BlockHeight = BlockHeight(3);

        let (mut shell, _, _) = test_utils::setup();

        // artificially change the block height
        shell.storage.last_height = LAST_HEIGHT;

        let (protocol_key, _) = wallet::defaults::validator_keys();
        let validator_addr = wallet::defaults::validator_address();

        let ethereum_event = EthereumEvent::TransfersToNamada {
            nonce: 1u64.into(),
            transfers: vec![],
        };
        let signed_vote_extension = {
            let ext = ethereum_events::Vext {
                validator_addr,
                block_height: LAST_HEIGHT,
                ethereum_events: vec![ethereum_event],
            }
            .sign(&protocol_key);
            assert!(ext.verify(&protocol_key.ref_to()).is_ok());
            ext
        };

        let rsp_digest = {
            let tx =
                ProtocolTxType::EthereumEvents(signed_vote_extension.clone())
                    .sign(&protocol_key)
                    .to_bytes();
            let mut rsp = shell.prepare_proposal(RequestPrepareProposal {
                txs: vec![tx],
                ..Default::default()
            });
            assert_eq!(rsp.txs.len(), 1);

            let tx_bytes = rsp.txs.pop().unwrap();
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
                ProtocolTxType::EthEventsDigest(digest) => digest,
                _ => panic!("Test failed"),
            }
        };

        let digest = manually_assemble_digest(
            &protocol_key,
            signed_vote_extension,
            LAST_HEIGHT,
        );

        assert_eq!(rsp_digest, digest);

        // NOTE: this comparison will not work because of timestamps
        // assert_eq!(rsp.tx_records, vec![digest]);
    }

    /// Test if Ethereum events validation and inclusion in a block
    /// behaves as expected, considering <= 2/3 voting power.
    ///
    /// If the abci++ feature is active, this means panicking. If
    /// not, this should proceed as normal
    #[test]
    #[cfg_attr(
        feature = "abcipp",
        should_panic(expected = "Honest Namada validators")
    )]
    fn test_prepare_proposal_vext_insufficient_voting_power() {
        const FIRST_HEIGHT: BlockHeight = BlockHeight(0);
        const LAST_HEIGHT: BlockHeight = BlockHeight(FIRST_HEIGHT.0 + 11);

        // starting the shell like this will contain insufficient voting
        // power
        let (mut shell, mut _broadcaster, _) = test_utils::setup();

        // artificially change the voting power of the default validator to
        // zero, change the block height, and commit a dummy block,
        // to move to a new epoch
        let events_epoch = shell
            .storage
            .block
            .pred_epochs
            .get_epoch(FIRST_HEIGHT)
            .expect("Test failed");
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

        // On commit, a vote extension should be broadcast if
        // the abci++ feature is turned off
        #[cfg(not(feature = "abcipp"))]
        assert!(_broadcaster.try_recv().is_ok());

        // test prepare proposal
        let (protocol_key, _) = wallet::defaults::validator_keys();
        let validator_addr = wallet::defaults::validator_address();

        let ethereum_event = EthereumEvent::TransfersToNamada {
            nonce: 1u64.into(),
            transfers: vec![],
        };
        let signed_vote_extension = {
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
            let vote = ExtendedVoteInfo {
                vote_extension: signed_vote_extension.try_to_vec().unwrap(),
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
            let vote =
                ProtocolTxType::EthereumEvents(signed_vote_extension.clone())
                    .sign(&protocol_key)
                    .to_bytes();
            let mut rsp = shell.prepare_proposal(RequestPrepareProposal {
                txs: vec![vote],
                ..Default::default()
            });
            assert_eq!(rsp.txs.len(), 1);

            let tx_bytes = rsp.txs.pop().unwrap();
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

            let digest = match protocol_tx {
                ProtocolTxType::EthEventsDigest(digest) => digest,
                _ => panic!("Test failed"),
            };

            let expected = manually_assemble_digest(
                &protocol_key,
                signed_vote_extension,
                LAST_HEIGHT,
            );

            assert_eq!(expected, digest);
        }
    }

    /// Test that if an error is encountered while
    /// trying to process a tx from the mempool,
    /// we simply exclude it from the proposal
    #[test]
    fn test_error_in_processing_tx() {
        let (mut shell, _, _) = TestShell::new();
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
                        token: xan(),
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
        let (mut shell, _, _) = setup();
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
                    token: xan(),
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
