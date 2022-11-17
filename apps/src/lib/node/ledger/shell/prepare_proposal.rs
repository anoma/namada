//! Implementation of the [`RequestPrepareProposal`] ABCI++ method for the Shell

mod block_space_alloc;

use namada::ledger::storage::traits::StorageHasher;
use namada::ledger::storage::{DBIter, DB};
use namada::ledger::storage_api::queries::{QueriesExt, SendValsetUpd};
use namada::proto::Tx;
use namada::types::storage::BlockHeight;
use namada::types::transaction::tx_types::TxType;
use namada::types::transaction::wrapper::wrapper_tx::PairingEngine;
use namada::types::transaction::{AffineCurve, DecryptedTx, EllipticCurve};
use namada::types::vote_extensions::VoteExtensionDigest;

use self::block_space_alloc::states::{
    BuildingDecryptedTxBatch, BuildingEncryptedTxBatch,
    BuildingProtocolTxBatch, NextState, NextStateWithEncryptedTxs, State,
};
pub use self::block_space_alloc::LazyProposedTxSet;
use self::block_space_alloc::{AllocStatus, BlockSpaceAllocator};
use super::super::*;
use crate::facade::tendermint_proto::abci::RequestPrepareProposal;
#[cfg(feature = "abcipp")]
use crate::facade::tendermint_proto::abci::{
    tx_record::TxAction, ExtendedCommitInfo, TxRecord,
};
use crate::node::ledger::shell::vote_extensions::{
    iter_protocol_txs, split_vote_extensions,
};
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
    // TODO: change second paragraph of the docstr, to reflect new
    // allotted space per block design
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

            // start counting allotted space for txs
            let mut alloc = BlockSpaceAllocator::from(&req);
            let mut tx_indices = LazyProposedTxSet::default();

            // NOTE: AD-HOC SOLUTION
            // ======================
            // TODO: choose txs in this order:
            // - decrypted txs (ALL OF THEM)
            // - protocol txs (we should give priority to valset upds)
            // - encrypted txs (it's fine if this bin is empty)
            //
            // at the beginning of an epoch, do not pick any
            // encrypted txs :) inspired by solana
            //
            // `tracing::warn!()` log we are not accepting encrypted
            // txs for a given block height

            // decrypt the wrapper txs included in the previous block
            let decrypted_txs = self.build_decrypted_txs(&mut alloc);
            #[cfg(feature = "abcipp")]
            let decrypted_txs: Vec<TxRecord> =
                decrypted_txs.into_iter().map(record::add).collect();
            let mut txs = decrypted_txs;

            // add ethereum events and validator set updates as protocol txs
            let mut alloc = alloc.next_state();
            #[cfg(feature = "abcipp")]
            let protocol_txs = self.build_vote_extensions_txs(
                &mut alloc,
                &mut tx_indices,
                req.local_last_commit,
            );
            #[cfg(not(feature = "abcipp"))]
            let mut protocol_txs = self.build_vote_extensions_txs(
                &mut alloc,
                &mut tx_indices,
                &req.txs,
            );
            #[cfg(feature = "abcipp")]
            let mut protocol_txs: Vec<TxRecord> =
                protocol_txs.into_iter().map(record::add).collect();
            txs.append(&mut protocol_txs);

            // add mempool txs
            // TODO: check if we can add encrypted txs or not
            let mut alloc = alloc.next_state_with_encrypted_txs();
            let mut mempool_txs =
                self.build_mempool_txs(&mut alloc, &mut tx_indices, req.txs);
            txs.append(&mut mempool_txs);

            // TODO: fill up remaining space
            // TODO: check if we can add encrypted txs or not
            let _alloc = alloc.next_state();

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
    fn build_vote_extensions_txs(
        &mut self,
        alloc: &mut BlockSpaceAllocator<BuildingProtocolTxBatch>,
        tx_indices: &mut LazyProposedTxSet,
        #[cfg(feature = "abcipp")] local_last_commit: Option<
            ExtendedCommitInfo,
        >,
        #[cfg(not(feature = "abcipp"))] txs: &[TxBytes],
    ) -> Vec<TxBytes> {
        // genesis block should not contain vote extensions
        if self.storage.last_height == BlockHeight(0) {
            return vec![];
        }

        #[cfg(feature = "abcipp")]
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
        #[cfg(not(feature = "abcipp"))]
        let (protocol_txs, eth_events, valset_upds) =
            split_vote_extensions(tx_indices, txs);

        // TODO: remove this later, when we get rid of `abciplus`
        #[cfg(feature = "abcipp")]
        let protocol_txs = vec![];

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

        let txs: Vec<_> = iter_protocol_txs(VoteExtensionDigest {
            ethereum_events,
            validator_set_update,
        })
        .map(|tx| tx.sign(protocol_key).to_bytes())
        // TODO(feature = "abcipp"): remove this later, when we get rid of
        // `abciplus`
        .chain(protocol_txs.into_iter())
        .collect();

        match alloc.try_alloc_batch(txs.iter().map(Vec::as_slice)) {
            AllocStatus::Accepted => txs,
            AllocStatus::Rejected { tx_len, space_left } => {
                // no space left for tx batch, so we
                // do not include any protocol tx in
                // this block
                //
                // TODO: maybe we should find a way to include
                // validator set updates all the time. for instance,
                // we could have recursive bins -> bin space within
                // a bin is partitioned into yet more bins. so, we
                // could have, say, 2/3 of the bin space available
                // for eth events, and 1/3 available for valset
                // upds
                tracing::debug!(
                    tx_len,
                    space_left,
                    proposal_height =
                        ?self.storage.get_current_decision_height(),
                    "Dropping protocol tx from the current proposal",
                );
                vec![]
            }
            AllocStatus::OverflowsBin { tx_len, bin_size } => {
                // TODO: handle tx whose size is greater
                // than bin size
                tracing::warn!(
                    tx_len,
                    bin_size,
                    proposal_height =
                        ?self.storage.get_current_decision_height(),
                    "Dropping large protocol tx from the current proposal",
                );
                vec![]
            }
        }
    }

    /// Builds a batch of mempool transactions
    #[cfg(feature = "abcipp")]
    fn build_mempool_txs<Mode>(
        &mut self,
        _alloc: &mut BlockSpaceAllocator<BuildingEncryptedTxBatch<Mode>>,
        _tx_indices: &mut LazyProposedTxSet,
        txs: Vec<Vec<u8>>,
    ) -> Vec<TxRecord>
    where
        BlockSpaceAllocator<BuildingEncryptedTxBatch<Mode>>: State,
    {
        // TODO(feature = "abcipp"): implement building batch of mempool txs
        todo!()
    }

    /// Builds a batch of mempool transactions
    #[cfg(not(feature = "abcipp"))]
    fn build_mempool_txs<Mode>(
        &mut self,
        alloc: &mut BlockSpaceAllocator<BuildingEncryptedTxBatch<Mode>>,
        tx_indices: &mut LazyProposedTxSet,
        txs: Vec<Vec<u8>>,
    ) -> Vec<TxBytes>
    where
        BlockSpaceAllocator<BuildingEncryptedTxBatch<Mode>>: State,
    {
        txs.into_iter()
            .enumerate()
            .filter_map(|(index, tx_bytes)| {
                if let Ok(Ok(TxType::Wrapper(_))) =
                    Tx::try_from(tx_bytes.as_slice()).map(process_tx)
                {
                    Some((index, tx_bytes))
                } else {
                    None
                }
            })
            .take_while(|(index, tx_bytes)| match alloc.try_alloc(&*tx_bytes) {
                AllocStatus::Accepted => {
                    tx_indices.include_tx_index(*index);
                    true
                }
                AllocStatus::Rejected { tx_len, space_left } => {
                    tracing::debug!(
                        tx_len,
                        space_left,
                        proposal_height =
                            ?self.storage.get_current_decision_height(),
                        "Dropping encrypted tx from the current proposal",
                    );
                    false
                }
                AllocStatus::OverflowsBin { tx_len, bin_size } => {
                    // TODO: handle tx whose size is greater
                    // than bin size
                    tracing::warn!(
                        tx_len,
                        bin_size,
                        proposal_height =
                            ?self.storage.get_current_decision_height(),
                        "Dropping large encrypted tx from the current proposal",
                    );
                    true
                }
            })
            .map(|(_, tx_bytes)| tx_bytes)
            .collect()
    }

    /// Builds a batch of DKG decrypted transactions
    // NOTE: we won't have frontrunning protection until V2 of the
    // Anoma protocol; Namada runs V1, therefore this method is
    // essentially a NOOP
    //
    // sources:
    // - https://specs.anoma.net/main/releases/v2.html
    // - https://github.com/anoma/ferveo
    fn build_decrypted_txs(
        &mut self,
        alloc: &mut BlockSpaceAllocator<BuildingDecryptedTxBatch>,
    ) -> Vec<TxBytes> {
        // TODO: This should not be hardcoded
        let privkey =
            <EllipticCurve as PairingEngine>::G2Affine::prime_subgroup_generator();

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
            // TODO: make sure all txs are accepted;
            .take_while(|tx_bytes| match alloc.try_alloc(&*tx_bytes) {
                AllocStatus::Accepted => true,
                AllocStatus::Rejected { tx_len, space_left } => {
                    // TODO: handle rejected txs
                    tracing::warn!(
                        tx_len,
                        space_left,
                        proposal_height =
                            ?self.storage.get_current_decision_height(),
                        "Dropping decrypted tx from the current proposal",
                    );
                    false
                }
                AllocStatus::OverflowsBin { tx_len, bin_size } => {
                    // TODO: handle tx whose size is greater
                    // than bin size
                    tracing::warn!(
                        tx_len,
                        bin_size,
                        proposal_height =
                            ?self.storage.get_current_decision_height(),
                        "Dropping large decrypted tx from the current proposal",
                    );
                    true
                }
            })
            .collect()
    }
}

/// Returns a suitable message to be displayed when Tendermint
/// somehow decides on a block containing vote extensions
/// reflecting `<= 2/3` of the total stake.
const fn not_enough_voting_power_msg() -> &'static str {
    #[cfg(feature = "abcipp")]
    {
        "A Tendermint quorum should never decide on a block including vote \
         extensions reflecting less than or equal to 2/3 of the total stake."
    }
    #[cfg(not(feature = "abcipp"))]
    {
        "CONSENSUS FAILURE!!!!!11one!"
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
// TODO: write tests for validator set update vote extensions in
// prepare proposals
mod test_prepare_proposal {
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
    use namada::types::key::{common, RefTo};
    use namada::types::storage::{BlockHeight, Epoch};
    use namada::types::transaction::protocol::ProtocolTxType;
    use namada::types::transaction::{Fee, TxType, WrapperTx};
    use namada::types::vote_extensions::ethereum_events::{
        self, MultiSignedEthEvent,
    };
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

    // https://github.com/tendermint/tendermint/blob/v0.37.x/spec/abci/abci%2B%2B_app_requirements.md#blockparamsmaxbytes
    const MAX_TM_BLK_SIZE: i64 = 100 << 20;

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
            max_tx_bytes: MAX_TM_BLK_SIZE,
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
                let mut s = BTreeSet::new();
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

        assert_eq!(
            vec![ext],
            vote_extension_digest.clone().decompress(last_height)
        );

        vote_extension_digest

        // let tx = ProtocolTxType::EthereumEvents(vote_extension_digest)
        //    .sign(&protocol_key)
        //    .to_bytes();
        // super::record::add(tx)
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
                max_tx_bytes: MAX_TM_BLK_SIZE,
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

        // NOTE: this comparison will not work because of timestamps
        // assert_eq!(rsp.tx_records, vec![digest]);
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
            let vote_extension = VoteExtension {
                ethereum_events: signed_vote_extension.clone(),
                validator_set_update: None,
            };
            let tx = ProtocolTxType::VoteExtension(vote_extension)
                .sign(&protocol_key)
                .to_bytes();
            let mut rsp = shell.prepare_proposal(RequestPrepareProposal {
                max_tx_bytes: MAX_TM_BLK_SIZE,
                txs: vec![tx],
                ..Default::default()
            });
            assert_eq!(rsp.txs.len(), 3);

            // NOTE: we remove the first pos, bc the ethereum events
            // vote extension protocol tx will always precede the
            // valset upd vext protocol tx
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
                ProtocolTxType::EthereumEvents(digest) => digest,
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
        #[allow(clippy::redundant_clone)]
        let vote_extension = VoteExtension {
            ethereum_events: signed_eth_ev_vote_extension.clone(),
            validator_set_update: None,
        };
        #[cfg(feature = "abcipp")]
        {
            let vote = ExtendedVoteInfo {
                vote_extension: vote_extension.try_to_vec().unwrap(),
                ..Default::default()
            };
            // this should panic
            shell.prepare_proposal(RequestPrepareProposal {
                max_tx_bytes: MAX_TM_BLK_SIZE,
                local_last_commit: Some(ExtendedCommitInfo {
                    votes: vec![vote],
                    ..Default::default()
                }),
                ..Default::default()
            });
        }
        #[cfg(not(feature = "abcipp"))]
        {
            let vote = ProtocolTxType::VoteExtension(vote_extension)
                .sign(&protocol_key)
                .to_bytes();
            let mut rsp = shell.prepare_proposal(RequestPrepareProposal {
                max_tx_bytes: MAX_TM_BLK_SIZE,
                txs: vec![vote],
                ..Default::default()
            });
            assert_eq!(rsp.txs.len(), 3);

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

            let digest = match protocol_tx {
                ProtocolTxType::EthereumEvents(digest) => digest,
                _ => panic!("Test failed"),
            };

            let expected = manually_assemble_digest(
                &protocol_key,
                signed_eth_ev_vote_extension,
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
            max_tx_bytes: MAX_TM_BLK_SIZE,
            ..Default::default()
        };
        #[cfg(feature = "abcipp")]
        assert_eq!(
            // NOTE: we process mempool txs after protocol txs
            shell.prepare_proposal(req).tx_records.remove(1),
            record::remove(wrapper)
        );
        #[cfg(not(feature = "abcipp"))]
        assert!({
            let mut assertion = true;
            // this includes valset upd and eth events
            // vote extension diggests
            let transactions = shell.prepare_proposal(req).txs;
            assert_eq!(transactions.len(), 2);
            for tx in transactions {
                if tx == wrapper {
                    assertion = false;
                    break;
                }
            }
            assertion
        });
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
            max_tx_bytes: MAX_TM_BLK_SIZE,
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
        let expected_txs: Vec<TxBytes> = expected_decrypted
            .into_iter()
            .chain(expected_wrapper.into_iter())
            // we extract the inner data from the txs for testing
            // equality since otherwise changes in timestamps would
            // fail the test
            .map(|tx| tx.data.expect("Test failed"))
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
