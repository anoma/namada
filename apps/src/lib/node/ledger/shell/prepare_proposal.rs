//! Implementation of the [`RequestPrepareProposal`] ABCI++ method for the Shell

mod block_space_alloc;

use index_set::IndexSet;
use namada::hints;
use namada::ledger::storage::traits::StorageHasher;
use namada::ledger::storage::{DBIter, DB};
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

use self::block_space_alloc::states::{
    BuildingDecryptedTxBatch, BuildingProtocolTxBatch,
    EncryptedTxBatchAllocator, FillingRemainingSpace, NextState,
    NextStateWithEncryptedTxs, NextStateWithoutEncryptedTxs, TryAlloc,
};
use self::block_space_alloc::{AllocFailure, BlockSpaceAllocator};
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
    /// Block space is roughly divided into three equal parts, which we call
    /// allotments. In the following order, each allotted area is home to:
    /// decrypted, protocol and encrypted transactions, respectively. During
    /// some protocol phases, we might omit encrypted and decrypted transactions
    /// entirely, such as when we negotiate DKG parameters.
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
            // start counting allotted space for txs
            let alloc = BlockSpaceAllocator::from(&req);
            let mut tx_indices = IndexSet::default();

            // decrypt the wrapper txs included in the previous block
            let (decrypted_txs, alloc) = self.build_decrypted_txs(alloc);
            let mut txs = decrypted_txs;

            // add vote extension protocol txs
            let (mut protocol_txs, alloc) = self.build_vote_extension_txs(
                alloc,
                #[cfg(not(feature = "abcipp"))]
                &mut tx_indices,
                #[cfg(feature = "abcipp")]
                req.local_last_commit,
                #[cfg(not(feature = "abcipp"))]
                &req.txs,
            );
            txs.append(&mut protocol_txs);

            // add mempool txs
            let (mut mempool_txs, alloc) =
                self.build_mempool_txs(alloc, &req.txs);
            txs.append(&mut mempool_txs);

            // fill up the remaining block space with
            // arbitrary transactions that can fit in
            // the free space left
            let mut remaining_txs =
                self.build_remaining_batch(alloc, &tx_indices, req.txs);
            txs.append(&mut remaining_txs);

            txs
        } else {
            vec![]
        };

        tracing::info!(
            height = req.height,
            num_of_txs = txs.len(),
            "Proposing block"
        );

        #[cfg(feature = "abcipp")]
        {
            response::PrepareProposal {
                // TODO(feature = "abcipp"): remove tx records
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
    /// events and, optionally, a validator set update.
    #[cfg(feature = "abcipp")]
    fn build_vote_extension_txs(
        &mut self,
        mut alloc: BlockSpaceAllocator<BuildingProtocolTxBatch>,
        local_last_commit: Option<ExtendedCommitInfo>,
    ) -> (Vec<TxBytes>, EncryptedTxBatchAllocator) {
        // genesis should not contain vote extensions
        if self.storage.last_height == BlockHeight(0) {
            return (vec![], self.get_encrypted_txs_allocator(alloc));
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

        let txs: Vec<_> = iter_protocol_txs(VoteExtensionDigest {
            ethereum_events,
            validator_set_update,
        })
        .map(|tx| tx.sign(protocol_key).to_bytes())
        .collect();

        // TODO(feature = "abcipp"):
        // - alloc space for each protocol tx
        // - handle space allocation errors
        // - transition to new allocator state

        todo!()
    }

    /// Builds a batch of vote extension transactions, comprised of Ethereum
    /// events and, optionally, a validator set update
    #[cfg(not(feature = "abcipp"))]
    fn build_vote_extension_txs(
        &mut self,
        mut alloc: BlockSpaceAllocator<BuildingProtocolTxBatch>,
        tx_indices: &mut IndexSet,
        txs: &[TxBytes],
    ) -> (Vec<TxBytes>, EncryptedTxBatchAllocator) {
        if self.storage.last_height == BlockHeight(0) {
            // genesis should not contain vote extensions
            return (vec![], self.get_encrypted_txs_allocator(alloc));
        }

        let txs = deserialize_vote_extensions(txs, tx_indices).take_while(|tx_bytes|
            alloc.try_alloc(&*tx_bytes)
                .map_or_else(
                    |status| match status {
                        AllocFailure::Rejected { bin_space_left } => {
                            // TODO: maybe we should find a way to include
                            // validator set updates all the time. for instance,
                            // we could have recursive bins -> bin space within
                            // a bin is partitioned into yet more bins. so, we
                            // could have, say, 2/3 of the bin space available
                            // for eth events, and 1/3 available for valset
                            // upds
                            tracing::debug!(
                                ?tx_bytes,
                                bin_space_left,
                                proposal_height =
                                    ?self.storage.get_current_decision_height(),
                                "Dropping protocol tx from the current proposal",
                            );
                            false
                        }
                        AllocFailure::OverflowsBin { bin_size } => {
                            // TODO: handle tx whose size is greater
                            // than bin size
                            tracing::warn!(
                                ?tx_bytes,
                                bin_size,
                                proposal_height =
                                    ?self.storage.get_current_decision_height(),
                                "Dropping large protocol tx from the current proposal",
                            );
                            true
                        }
                    },
                    |()| true,
                )
        )
        .collect();

        (txs, self.get_encrypted_txs_allocator(alloc))
    }

    /// Transition to an [`EncryptedTxBatchAllocator`].
    #[inline]
    fn get_encrypted_txs_allocator(
        &self,
        alloc: BlockSpaceAllocator<BuildingProtocolTxBatch>,
    ) -> EncryptedTxBatchAllocator {
        let is_2nd_height_off = self.storage.is_deciding_offset_within_epoch(1);
        let is_3rd_height_off = self.storage.is_deciding_offset_within_epoch(2);

        if hints::unlikely(is_2nd_height_off || is_3rd_height_off) {
            tracing::warn!(
                proposal_height =
                    ?self.storage.get_current_decision_height(),
                "No mempool txs are being included in the current proposal"
            );
            EncryptedTxBatchAllocator::WithoutEncryptedTxs(
                alloc.next_state_without_encrypted_txs(),
            )
        } else {
            EncryptedTxBatchAllocator::WithEncryptedTxs(
                alloc.next_state_with_encrypted_txs(),
            )
        }
    }

    /// Builds a batch of mempool transactions.
    #[cfg(feature = "abcipp")]
    fn build_mempool_txs(
        &mut self,
        _alloc: EncryptedTxBatchAllocator,
        txs: &[TxBytes],
    ) -> (Vec<TxRecord>, BlockSpaceAllocator<FillingRemainingSpace>) {
        // TODO(feature = "abcipp"): implement building batch of mempool txs
        todo!()
    }

    /// Builds a batch of mempool transactions.
    #[cfg(not(feature = "abcipp"))]
    fn build_mempool_txs(
        &mut self,
        mut alloc: EncryptedTxBatchAllocator,
        txs: &[TxBytes],
    ) -> (Vec<TxBytes>, BlockSpaceAllocator<FillingRemainingSpace>) {
        let txs = txs
            .iter()
            .filter_map(|tx_bytes| {
                if let Ok(Ok(TxType::Wrapper(_))) =
                    Tx::try_from(tx_bytes.as_slice()).map(process_tx)
                {
                    Some(tx_bytes.clone())
                } else {
                    None
                }
            })
            .take_while(|tx_bytes| {
                alloc.try_alloc(&*tx_bytes)
                    .map_or_else(
                        |status| match status {
                            AllocFailure::Rejected { bin_space_left } => {
                                tracing::debug!(
                                    ?tx_bytes,
                                    bin_space_left,
                                    proposal_height =
                                        ?self.storage.get_current_decision_height(),
                                    "Dropping encrypted tx from the current proposal",
                                );
                                false
                            }
                            AllocFailure::OverflowsBin { bin_size } => {
                                // TODO: handle tx whose size is greater
                                // than bin size
                                tracing::warn!(
                                    ?tx_bytes,
                                    bin_size,
                                    proposal_height =
                                        ?self.storage.get_current_decision_height(),
                                    "Dropping large encrypted tx from the current proposal",
                                );
                                true
                            }
                        },
                        |()| true,
                    )
            })
            .collect();
        let alloc = alloc.next_state();

        (txs, alloc)
    }

    /// Builds a batch of DKG decrypted transactions.
    // NOTE: we won't have frontrunning protection until V2 of the
    // Anoma protocol; Namada runs V1, therefore this method is
    // essentially a NOOP
    //
    // sources:
    // - https://specs.anoma.net/main/releases/v2.html
    // - https://github.com/anoma/ferveo
    fn build_decrypted_txs(
        &mut self,
        mut alloc: BlockSpaceAllocator<BuildingDecryptedTxBatch>,
    ) -> (Vec<TxBytes>, BlockSpaceAllocator<BuildingProtocolTxBatch>) {
        // TODO: This should not be hardcoded
        let privkey =
            <EllipticCurve as PairingEngine>::G2Affine::prime_subgroup_generator();

        let txs = self
            .storage
            .tx_queue
            .iter()
            .map(|tx| {
                Tx::from(match tx.decrypt(privkey) {
                    Ok(tx) => DecryptedTx::Decrypted(tx),
                    _ => DecryptedTx::Undecryptable(tx.clone()),
                })
                .to_bytes()
            })
            // TODO: make sure all txs are accepted
            .take_while(|tx_bytes| {
                alloc.try_alloc(&*tx_bytes).map_or_else(
                    |status| match status {
                        AllocFailure::Rejected { bin_space_left } => {
                            // TODO: handle rejected txs
                            tracing::warn!(
                                ?tx_bytes,
                                bin_space_left,
                                proposal_height =
                                    ?self.storage.get_current_decision_height(),
                                "Dropping decrypted tx from the current proposal",
                            );
                            false
                        }
                        AllocFailure::OverflowsBin { bin_size } => {
                            // TODO: handle tx whose size is greater
                            // than bin size
                            tracing::warn!(
                                ?tx_bytes,
                                bin_size,
                                proposal_height =
                                    ?self.storage.get_current_decision_height(),
                                "Dropping large decrypted tx from the current proposal",
                            );
                            true
                        }
                    },
                    |()| true,
                )
            })
            .collect();
        let alloc = alloc.next_state();

        (txs, alloc)
    }

    /// Builds a batch of transactions that can fit in the
    /// remaining space of the [`BlockSpaceAllocator`].
    fn build_remaining_batch(
        &mut self,
        mut alloc: BlockSpaceAllocator<FillingRemainingSpace>,
        tx_indices: &IndexSet,
        txs: Vec<TxBytes>,
    ) -> Vec<TxBytes> {
        get_remaining_txs(tx_indices, txs)
            .take_while(|tx_bytes| {
                alloc.try_alloc(&*tx_bytes).map_or_else(
                    |status| match status {
                        AllocFailure::Rejected { bin_space_left } => {
                            tracing::debug!(
                                ?tx_bytes,
                                bin_space_left,
                                proposal_height =
                                    ?self.storage.get_current_decision_height(),
                                "Dropping tx from the current proposal",
                            );
                            false
                        }
                        AllocFailure::OverflowsBin { bin_size } => {
                            // TODO: handle tx whose size is greater
                            // than bin size
                            tracing::warn!(
                                ?tx_bytes,
                                bin_size,
                                proposal_height =
                                    ?self.storage.get_current_decision_height(),
                                "Dropping large tx from the current proposal",
                            );
                            true
                        }
                    },
                    |()| true,
                )
            })
            .collect()
    }
}

/// Return a list of the protocol transactions that haven't
/// been marked for inclusion in the block, yet.
fn get_remaining_txs(
    tx_indices: &IndexSet,
    txs: Vec<TxBytes>,
) -> impl Iterator<Item = TxBytes> + '_ {
    let mut skip_list = tx_indices.iter();
    let mut skip = skip_list.next();

    txs.into_iter().enumerate().filter_map(move |(index, tx)| {
        // this works bc/ tx indices are ordered
        // in ascending order
        if hints::likely(Some(index) == skip) {
            skip = skip_list.next();
            return None;
        }
        if let Ok(Ok(TxType::Protocol(_))) =
            Tx::try_from(&tx[..]).map(process_tx)
        {
            return Some(tx);
        }
        None
    })
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

    // https://github.com/tendermint/tendermint/blob/v0.37.x/spec/abci/abci%2B%2B_app_requirements.md#blockparamsmaxbytes
    const MAX_TM_BLK_SIZE: i64 = 100 << 20;

    /// Extract an [`ethereum_events::SignedVext`], from a set of
    /// serialized [`TxBytes`].
    #[cfg(not(feature = "abcipp"))]
    fn extract_eth_events_vext(
        tx_bytes: TxBytes,
    ) -> ethereum_events::SignedVext {
        let got = Tx::try_from(&tx_bytes[..]).unwrap();
        let got_signed_tx =
            SignedTxData::try_from_slice(&got.data.unwrap()[..]).unwrap();
        let protocol_tx =
            TxType::try_from_slice(&got_signed_tx.data.unwrap()[..]).unwrap();
        let protocol_tx = match protocol_tx {
            TxType::Protocol(protocol_tx) => protocol_tx.tx,
            _ => panic!("Test failed"),
        };
        match protocol_tx {
            ProtocolTxType::EthEventsVext(ext) => ext,
            _ => panic!("Test failed"),
        }
    }

    /// Test if [`get_remaining_txs`] is working as expected.
    #[test]
    fn test_get_remaining_txs() {
        // TODO(feature = "abcipp"): use a different tx type here
        fn bertha_ext(at_height: u64) -> TxBytes {
            let key = wallet::defaults::bertha_keypair();
            let ext = ethereum_events::Vext::empty(
                at_height.into(),
                wallet::defaults::bertha_address(),
            )
            .sign(&key);
            ProtocolTxType::EthEventsVext(ext).sign(&key).to_bytes()
        }

        let excluded_indices = [0, 1, 3, 5, 7];
        let all_txs: Vec<_> = (0..10).map(bertha_ext).collect();
        let expected_txs: Vec<_> = [2, 4, 6, 8, 9]
            .into_iter()
            .map(bertha_ext)
            .map(extract_eth_events_vext)
            .collect();

        let set = {
            let mut s = IndexSet::default();
            for idx in excluded_indices.iter().copied() {
                s.insert(idx as usize);
            }
            s
        };

        let got_txs: Vec<_> = get_remaining_txs(&set, all_txs)
            .map(extract_eth_events_vext)
            .collect();
        assert_eq!(expected_txs, got_txs);
    }

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
    // TODO: remove this test after CheckTx implements
    // filtering of invalid txs; otherwise, we would have
    // needed to return invalid txs from PrepareProposal,
    // for these to get removed from a node's mempool.
    // not returning invalid txs from PrepareProposal is
    // a DoS vector, because the mempool will slowly fill
    // up with garbage. luckily, Tendermint implements a
    // mempool eviction policy, but honest client's txs
    // may get lost in the process
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
            // TODO(feature = "abcipp"): remove tx records
            shell.prepare_proposal(req).tx_records.remove(1),
            record::remove(non_wrapper_tx.to_bytes())
        );
        #[cfg(not(feature = "abcipp"))]
        assert_eq!(shell.prepare_proposal(req).txs.len(), 0);
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
                max_tx_bytes: MAX_TM_BLK_SIZE,
                votes: vec![vote],
                ..Default::default()
            }),
            ..Default::default()
        });
        let rsp_digest = {
            // TODO(feature = "abcipp"): remove tx records
            assert_eq!(rsp.tx_records.len(), 1);
            // TODO(feature = "abcipp"): remove tx records
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
                max_tx_bytes: MAX_TM_BLK_SIZE,
                txs: vec![tx],
                ..Default::default()
            });
            assert_eq!(rsp.txs.len(), 1);

            let tx_bytes = rsp.txs.remove(0);
            extract_eth_events_vext(tx_bytes)
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
            let vote = ProtocolTxType::EthEventsVext(
                signed_eth_ev_vote_extension.clone(),
            )
            .sign(&protocol_key)
            .to_bytes();
            let mut rsp = shell.prepare_proposal(RequestPrepareProposal {
                max_tx_bytes: MAX_TM_BLK_SIZE,
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
    // TODO: see note on `test_prepare_proposal_rejects_non_wrapper_tx`
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
            // TODO(feature = "abcipp"): remove tx records
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
            let received: Vec<TxBytes> = shell
                .prepare_proposal(req)
                // TODO(feature = "abcipp"): remove tx records
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
            let received: Vec<TxBytes> = shell
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
