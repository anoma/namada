//! Implementation of the [`RequestPrepareProposal`] ABCI++ method for the Shell

use namada::core::hints;
use namada::ledger::storage::{DBIter, StorageHasher, DB};
use namada::proof_of_stake::pos_queries::PosQueries;
use namada::core::hints;
#[cfg(feature = "abcipp")]
use namada::ledger::eth_bridge::{EthBridgeQueries, SendValsetUpd};
use namada::ledger::pos::PosQueries;
use namada::ledger::storage::traits::StorageHasher;
use namada::ledger::storage::{DBIter, DB};
use namada::proto::Tx;
use namada::types::internal::WrapperTxInQueue;
use namada::types::time::DateTimeUtc;
use namada::types::storage::BlockHeight;
use namada::types::transaction::tx_types::TxType;
use namada::types::transaction::wrapper::wrapper_tx::PairingEngine;
use namada::types::transaction::{AffineCurve, DecryptedTx, EllipticCurve};
#[cfg(feature = "abcipp")]
use namada::types::vote_extensions::VoteExtensionDigest;

use super::super::*;
#[allow(unused_imports)]
use super::block_space_alloc;
use super::block_space_alloc::states::{
    BuildingDecryptedTxBatch, BuildingProtocolTxBatch,
    EncryptedTxBatchAllocator, NextState, TryAlloc,
};
use super::block_space_alloc::{AllocFailure, BlockSpaceAllocator};
#[allow(unused_imports)]
use super::block_space_alloc;
use super::block_space_alloc::states::{
    BuildingDecryptedTxBatch, BuildingProtocolTxBatch,
    EncryptedTxBatchAllocator, NextState, TryAlloc,
};
use super::block_space_alloc::{AllocFailure, BlockSpaceAllocator};
#[cfg(feature = "abcipp")]
use crate::facade::tendermint_proto::abci::ExtendedCommitInfo;
use crate::facade::tendermint_proto::abci::RequestPrepareProposal;
#[cfg(feature = "abcipp")]
use crate::facade::tendermint_proto::abci::ExtendedCommitInfo;
use crate::facade::tendermint_proto::abci::RequestPrepareProposal;
use crate::facade::tendermint_proto::google::protobuf::Timestamp;
use crate::node::ledger::shell::vote_extensions::iter_protocol_txs;
use crate::node::ledger::shell::{process_tx, ShellMode};
use crate::node::ledger::shims::abcipp_shim_types::shim::{response, TxBytes};

impl<D, H> Shell<D, H>
where
    D: DB + for<'iter> DBIter<'iter> + Sync + 'static,
    H: StorageHasher + Sync + 'static,
{
    /// Begin a new block.
    ///
    /// Block construction is documented in [`block_space_alloc`]
    /// and [`block_space_alloc::states`].
    ///
    /// INVARIANT: Any changes applied in this method must be reverted if
    /// the proposal is rejected (unless we can simply overwrite
    /// them in the next block).
    pub fn prepare_proposal(
        &self,
        req: RequestPrepareProposal,
    ) -> response::PrepareProposal {
        let txs = if let ShellMode::Validator { .. } = self.mode {
            // start counting allotted space for txs
            let alloc = self.get_encrypted_txs_allocator();

            // add encrypted txs
            let (encrypted_txs, alloc) =
                self.build_encrypted_txs(alloc, &req.txs, &req.time);
            let mut txs = encrypted_txs;

            // decrypt the wrapper txs included in the previous block
            let (mut decrypted_txs, alloc) = self.build_decrypted_txs(alloc);
            txs.append(&mut decrypted_txs);

            // add vote extension protocol txs
            let mut protocol_txs = self.build_protocol_txs(
                alloc,
                #[cfg(feature = "abcipp")]
                req.local_last_commit,
                #[cfg(not(feature = "abcipp"))]
                &req.txs,
            );
            txs.append(&mut protocol_txs);

            txs
        } else {
            vec![]
        };

        tracing::info!(
            height = req.height,
            num_of_txs = txs.len(),
            "Proposing block"
        );

        response::PrepareProposal { txs }
    }

    /// Depending on the current block height offset within the epoch,
    /// transition state accordingly, return a block space allocator
    /// with or without encrypted txs.
    ///
    /// # How to determine which path to take in the states DAG
    ///
    /// If we are at the second or third block height offset within an
    /// epoch, we do not allow encrypted transactions to be included in
    /// a block, therefore we return an allocator wrapped in an
    /// [`EncryptedTxBatchAllocator::WithoutEncryptedTxs`] value.
    /// Otherwise, we return an allocator wrapped in an
    /// [`EncryptedTxBatchAllocator::WithEncryptedTxs`] value.
    #[inline]
    fn get_encrypted_txs_allocator(&self) -> EncryptedTxBatchAllocator {
        let pos_queries = self.wl_storage.pos_queries();

        let is_2nd_height_off = pos_queries.is_deciding_offset_within_epoch(1);
        let is_3rd_height_off = pos_queries.is_deciding_offset_within_epoch(2);

        if hints::unlikely(is_2nd_height_off || is_3rd_height_off) {
            tracing::warn!(
                proposal_height =
                    ?pos_queries.get_current_decision_height(),
                "No mempool txs are being included in the current proposal"
            );
            EncryptedTxBatchAllocator::WithoutEncryptedTxs(
                (&self.wl_storage).into(),
            )
        } else {
            EncryptedTxBatchAllocator::WithEncryptedTxs(
                (&self.wl_storage).into(),
            )
        }
    }

    /// Builds a batch of encrypted transactions, retrieved from
    /// Tendermint's mempool.
    fn build_encrypted_txs(
        &self,
        mut alloc: EncryptedTxBatchAllocator,
        txs: &[TxBytes],
        block_time: &Option<Timestamp>,
    ) -> (Vec<TxBytes>, BlockSpaceAllocator<BuildingDecryptedTxBatch>) {
        let pos_queries = self.wl_storage.pos_queries();
        let block_time = block_time.clone().and_then(|block_time| {
            // If error in conversion, default to last block datetime, it's
            // valid because of mempool check
            TryInto::<DateTimeUtc>::try_into(block_time).ok()
        });
        let txs = txs
            .iter()
            .filter_map(|tx_bytes| {
                if let Ok(tx) = Tx::try_from(tx_bytes.as_slice()) {
                    // If tx doesn't have an expiration it is valid. If time cannot be
                    // retrieved from block default to last block datetime which has
                    // already been checked by mempool_validate, so it's valid
                    if let (Some(block_time), Some(exp)) = (block_time.as_ref(), &tx.expiration) {
                        if block_time > exp { return None }
                    }
                    if let Ok(TxType::Wrapper(_)) = process_tx(tx) {
                        return Some(tx_bytes.clone());
                    }
                }
                None
            })
            .take_while(|tx_bytes| {
                alloc.try_alloc(&tx_bytes[..])
                    .map_or_else(
                        |status| match status {
                            AllocFailure::Rejected { bin_space_left } => {
                                tracing::debug!(
                                    tx_bytes_len = tx_bytes.len(),
                                    bin_space_left,
                                    proposal_height =
                                        ?pos_queries.get_current_decision_height(),
                                    "Dropping encrypted tx from the current proposal",
                                );
                                false
                            }
                            AllocFailure::OverflowsBin { bin_size } => {
                                // TODO: handle tx whose size is greater
                                // than bin size
                                tracing::warn!(
                                    tx_bytes_len = tx_bytes.len(),
                                    bin_size,
                                    proposal_height =
                                        ?pos_queries.get_current_decision_height(),
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
    // - https://specs.namada.net/main/releases/v2.html
    // - https://github.com/anoma/ferveo
    fn build_decrypted_txs(
        &self,
        mut alloc: BlockSpaceAllocator<BuildingDecryptedTxBatch>,
    ) -> (Vec<TxBytes>, BlockSpaceAllocator<BuildingProtocolTxBatch>) {
        // TODO: This should not be hardcoded
        let privkey =
            <EllipticCurve as PairingEngine>::G2Affine::prime_subgroup_generator();

        let pos_queries = self.wl_storage.pos_queries();
        let txs = self
            .wl_storage
            .storage
            .tx_queue
            .iter()
            .map(
                |WrapperTxInQueue {
                     tx,
                     #[cfg(not(feature = "mainnet"))]
                     has_valid_pow,
                 }| {
                    Tx::from(match tx.decrypt(privkey) {
                        Ok(tx) => DecryptedTx::Decrypted {
                            tx,
                            #[cfg(not(feature = "mainnet"))]
                            has_valid_pow: *has_valid_pow,
                        },
                        _ => DecryptedTx::Undecryptable(tx.clone()),
                    })
                    .to_bytes()
                },
            )
            // TODO: make sure all decrypted txs are accepted
            .take_while(|tx_bytes| {
                alloc.try_alloc(&tx_bytes[..]).map_or_else(
                    |status| match status {
                        AllocFailure::Rejected { bin_space_left } => {
                            tracing::warn!(
                                ?tx_bytes,
                                bin_space_left,
                                proposal_height =
                                    ?pos_queries.get_current_decision_height(),
                                "Dropping decrypted tx from the current proposal",
                            );
                            false
                        }
                        AllocFailure::OverflowsBin { bin_size } => {
                            tracing::warn!(
                                ?tx_bytes,
                                bin_size,
                                proposal_height =
                                    ?pos_queries.get_current_decision_height(),
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

    /// Builds a batch of protocol transactions.
    #[cfg(feature = "abcipp")]
    fn build_protocol_txs(
        &self,
        _alloc: BlockSpaceAllocator<BuildingProtocolTxBatch>,
        local_last_commit: Option<ExtendedCommitInfo>,
    ) -> Vec<TxBytes> {
        // genesis should not contain vote extensions.
        //
        // this is because we have not decided any block through
        // consensus yet (hence height 0), which in turn means we
        // have not committed any vote extensions to a block either.
        if self.wl_storage.storage.last_height == BlockHeight(0) {
            return vec![];
        }

        let (eth_events, bp_roots, valset_upds) = self.split_vote_extensions(
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

        let ethereum_events = eth_events.map(|events| {
            self.compress_ethereum_events(events)
                .unwrap_or_else(|| panic!("{}", not_enough_voting_power_msg()))
        });

        let bp_roots = bp_roots.map(|bp_roots| {
            self.compress_bridge_pool_roots(bp_roots)
                .unwrap_or_else(|| panic!("{}", not_enough_voting_power_msg()))
        });

        let validator_set_update =
            if self
                .wl_storage
                .ethbridge_queries()
                .must_send_valset_upd(SendValsetUpd::AtPrevHeight)
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

        // TODO(feature = "abcipp"):
        // - alloc space for each protocol tx
        // - handle space allocation errors
        // - transition to new allocator state
        iter_protocol_txs(VoteExtensionDigest {
            ethereum_events,
            bridge_pool_roots: bp_roots,
            validator_set_update,
        })
        .map(|tx| tx.sign(protocol_key).to_bytes())
        .collect()
    }

    /// Builds a batch of protocol transactions.
    #[cfg(not(feature = "abcipp"))]
    fn build_protocol_txs(
        &self,
        mut alloc: BlockSpaceAllocator<BuildingProtocolTxBatch>,
        txs: &[TxBytes],
    ) -> Vec<TxBytes> {
        if self.wl_storage.storage.last_height == BlockHeight(0) {
            // genesis should not contain vote extensions.
            //
            // this is because we have not decided any block through
            // consensus yet (hence height 0), which in turn means we
            // have not committed any vote extensions to a block either.
            return vec![];
        }

        let deserialized_iter = self.deserialize_vote_extensions(txs);
        let pos_queries = self.wl_storage.pos_queries();

        deserialized_iter.take_while(|tx_bytes|
            alloc.try_alloc(&tx_bytes[..])
                .map_or_else(
                    |status| match status {
                        AllocFailure::Rejected { bin_space_left } => {
                            // TODO: maybe we should find a way to include
                            // validator set updates all the time. for instance,
                            // we could have recursive bins -> bin space within
                            // a bin is partitioned into yet more bins. so, we
                            // could have, say, 2/3 of the bin space available
                            // for eth events, and 1/3 available for valset
                            // upds. to be determined, as we implement CheckTx
                            // changes (issue #367)
                            tracing::debug!(
                                ?tx_bytes,
                                bin_space_left,
                                proposal_height =
                                    ?pos_queries.get_current_decision_height(),
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
                                    ?pos_queries.get_current_decision_height(),
                                "Dropping large protocol tx from the current proposal",
                            );
                            true
                        }
                    },
                    |()| true,
                )
        )
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

    use borsh::BorshDeserialize;
    #[cfg(feature = "abcipp")]
    use borsh::BorshSerialize;
    use namada::core::ledger::storage_api::collections::lazy_map::{
        NestedSubKey, SubKey,
    };
    use namada::ledger::pos::PosQueries;
    use namada::proof_of_stake::consensus_validator_set_handle;
    #[cfg(feature = "abcipp")]
    use namada::proto::SignableEthMessage;
    use namada::proto::{Signed, SignedTxData};
    use namada::types::ethereum_events::EthereumEvent;
    #[cfg(feature = "abcipp")]
    use namada::types::key::common;
    use namada::types::key::RefTo;
    use namada::types::storage::{BlockHeight, Epoch};
    use namada::types::transaction::protocol::ProtocolTxType;
    use namada::types::transaction::{Fee, TxType, WrapperTx};
    #[cfg(feature = "abcipp")]
    use namada::types::vote_extensions::bridge_pool_roots;
    use namada::types::vote_extensions::ethereum_events;
    #[cfg(feature = "abcipp")]
    use namada::types::vote_extensions::VoteExtension;

    use super::*;
    use crate::node::ledger::shell::test_utils::{self, gen_keypair};
    #[cfg(feature = "abcipp")]
    use crate::facade::tendermint_proto::abci::{
        ExtendedCommitInfo, ExtendedVoteInfo,
    };
    #[cfg(feature = "abcipp")]
    use crate::node::ledger::shell::test_utils::deactivate_bridge;
    #[cfg(feature = "abcipp")]
    use crate::node::ledger::shell::test_utils::get_bp_bytes_to_sign;
    #[cfg(feature = "abcipp")]
    use crate::node::ledger::shell::test_utils::setup_at_height;
    use crate::node::ledger::shell::test_utils::{
        self, gen_keypair, TestShell,
    };
    use crate::node::ledger::shims::abcipp_shim_types::shim::request::FinalizeBlock;
    use crate::wallet;

    /// Test that if a tx from the mempool is not a
    /// WrapperTx type, it is not included in the
    /// proposed block.
    #[test]
    fn test_prepare_proposal_rejects_non_wrapper_tx() {
        let (shell, _) = test_utils::setup(1);
        let tx = Tx::new(
            "wasm_code".as_bytes().to_owned(),
            Some("transaction_data".as_bytes().to_owned()),
            shell.chain_id.clone(),
            None,
        );
        let req = RequestPrepareProposal {
            txs: vec![tx.to_bytes()],
            ..Default::default()
        };
    }

    #[cfg(feature = "abcipp")]
    fn get_local_last_commit(shell: &TestShell) -> Option<ExtendedCommitInfo> {
        let validator_addr = shell
            .mode
            .get_validator_address()
            .expect("Test failed")
            .to_owned();
        let evts = {
            let prev_height = shell.wl_storage.storage.last_height;
            let ext = ethereum_events::Vext::empty(
                prev_height,
                validator_addr.clone(),
            );
            let protocol_key = match &shell.mode {
                ShellMode::Validator { data, .. } => {
                    &data.keys.protocol_keypair
                }
                _ => panic!("Test failed"),
            };
            ext.sign(protocol_key)
        };

        let bp_root = {
            let to_sign = get_bp_bytes_to_sign();
            let sig = Signed::<_, SignableEthMessage>::new(
                shell.mode.get_eth_bridge_keypair().expect("Test failed"),
                to_sign,
            )
            .sig;
            bridge_pool_roots::Vext {
                block_height: shell.wl_storage.storage.last_height,
                validator_addr,
                sig,
            }
            .sign(shell.mode.get_protocol_key().expect("Test failed"))
        };

        let vote_extension = VoteExtension {
            ethereum_events: Some(evts),
            bridge_pool_root: Some(bp_root),
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

    /// Check if we are filtering out an invalid vote extension `vext`
    fn check_eth_events_filtering(
        shell: &TestShell,
        vext: Signed<ethereum_events::Vext>,
    ) {
        #[cfg(feature = "abcipp")]
        {
            let filtered_votes: Vec<_> =
                shell.filter_invalid_eth_events_vexts(vec![vext]).collect();
            assert_eq!(filtered_votes, vec![]);
        }
        #[cfg(not(feature = "abcipp"))]
        {
            let tx = ProtocolTxType::EthEventsVext(vext)
                .sign(shell.mode.get_protocol_key().expect("Test failed"))
                .to_bytes();
            let rsp = shell.mempool_validate(&tx, Default::default());
            assert!(rsp.code != 0, "{}", rsp.log);
        }
    }

    /// Test if we are filtering out Ethereum events with bad
    /// signatures in a prepare proposal.
    #[test]
    fn test_prepare_proposal_filter_out_bad_vext_signatures() {
        const LAST_HEIGHT: BlockHeight = BlockHeight(2);

        let (mut shell, _recv, _, _) = test_utils::setup();

        // artificially change the block height
        shell.wl_storage.storage.last_height = LAST_HEIGHT;

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

        check_eth_events_filtering(&shell, signed_vote_extension);
    }

    /// Test if we are filtering out Ethereum events seen at
    /// unexpected block heights.
    ///
    /// In case of ABCI++, we should only accept vote extensions
    /// from `last_height`, whereas with ABCI+, vote extensions
    /// before `last_height` are accepted. In either case, vote
    /// extensions after `last_height` aren't accepted.
    #[test]
    fn test_prepare_proposal_filter_out_bad_vext_bheights() {
        const LAST_HEIGHT: BlockHeight = BlockHeight(3);

        fn check_invalid(shell: &TestShell, height: BlockHeight) {
            let (protocol_key, _, _) = wallet::defaults::validator_keys();
            let validator_addr = wallet::defaults::validator_address();

            let signed_vote_extension = {
                let ext = ethereum_events::Vext {
                    validator_addr,
                    block_height: height,
                    ethereum_events: vec![],
                }
                .sign(&protocol_key);
                assert!(ext.verify(&protocol_key.ref_to()).is_ok());
                ext
            };

            check_eth_events_filtering(shell, signed_vote_extension);
        }

        let (shell, _recv, _, _) = test_utils::setup_at_height(LAST_HEIGHT);
        assert_eq!(shell.wl_storage.storage.last_height, LAST_HEIGHT);

        check_invalid(&shell, LAST_HEIGHT + 2);
        check_invalid(&shell, LAST_HEIGHT + 1);
        check_invalid(&shell, 0.into());
        #[cfg(feature = "abcipp")]
        check_invalid(&shell, LAST_HEIGHT - 1);
        #[cfg(feature = "abcipp")]
        check_invalid(&shell, LAST_HEIGHT - 2);
    }

    /// Test if we are filtering out Ethereum events seen by
    /// non-validator nodes.
    #[test]
    fn test_prepare_proposal_filter_out_bad_vext_validators() {
        const LAST_HEIGHT: BlockHeight = BlockHeight(2);

        let (mut shell, _recv, _, _) = test_utils::setup();

        // artificially change the block height
        shell.wl_storage.storage.last_height = LAST_HEIGHT;

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

        check_eth_events_filtering(&shell, signed_vote_extension);
    }

    /// Test if we are filtering out duped Ethereum events in
    /// prepare proposals.
    #[test]
    #[cfg(feature = "abcipp")]
    fn test_prepare_proposal_filter_duped_ethereum_events() {
        const LAST_HEIGHT: BlockHeight = BlockHeight(3);

        let (mut shell, _recv, _, _) = test_utils::setup();

        // artificially change the block height
        shell.wl_storage.storage.last_height = LAST_HEIGHT;

        let (protocol_key, _, _) = wallet::defaults::validator_keys();
        let validator_addr = wallet::defaults::validator_address();

        let ethereum_event = EthereumEvent::TransfersToNamada {
            nonce: 1u64.into(),
            transfers: vec![],
            valid_transfers_map: vec![],
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

        // we should be filtering out the vote extension with
        // duped ethereum events; therefore, no valid vote
        // extensions will remain, and we will get no
        // digest from compressing nil vote extensions
        assert!(maybe_digest.is_none());
    }

    /// Test that we do not include vote extensions voting on ethereum
    /// events or signing bridge pool roots + nonces if the bridge
    /// is inactive.
    #[test]
    #[cfg(feature = "abcipp")]
    fn test_filter_vexts_bridge_inactive() {
        let (mut shell, _, _, _) = setup_at_height(3);
        deactivate_bridge(&mut shell);
        let vext = get_local_last_commit(&shell);
        let rsp = shell.prepare_proposal(RequestPrepareProposal {
            local_last_commit: vext,
            ..Default::default()
        });
        assert!(rsp.txs.is_empty());
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
                s.insert((ext.data.validator_addr.clone(), last_height));
                s
            },
        }];
        let signatures = {
            let mut s = HashMap::new();
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
    }

    /// Test if Ethereum events validation and inclusion in a block
    /// behaves as expected, considering honest validators.
    #[cfg(feature = "abcipp")]
    #[test]
    fn test_prepare_proposal_vext_normal_op() {
        const LAST_HEIGHT: BlockHeight = BlockHeight(3);

        let (mut shell, _recv, _, _) = test_utils::setup();

        // artificially change the block height
        shell.wl_storage.storage.last_height = LAST_HEIGHT;

        let (protocol_key, _, _) = wallet::defaults::validator_keys();
        let validator_addr = wallet::defaults::validator_address();

        let ethereum_event = EthereumEvent::TransfersToNamada {
            nonce: 1u64.into(),
            transfers: vec![],
            valid_transfers_map: vec![],
        };
        let ethereum_events = {
            let ext = ethereum_events::Vext {
                validator_addr: validator_addr.clone(),
                block_height: LAST_HEIGHT,
                ethereum_events: vec![ethereum_event],
            }
            .sign(&protocol_key);
            assert!(ext.verify(&protocol_key.ref_to()).is_ok());
            ext
        };
        let bp_root = {
            let to_sign = get_bp_bytes_to_sign();
            let sig = Signed::<_, SignableEthMessage>::new(
                shell.mode.get_eth_bridge_keypair().expect("Test failed"),
                to_sign,
            )
            .sig;
            bridge_pool_roots::Vext {
                block_height: shell.wl_storage.storage.last_height,
                validator_addr,
                sig,
            }
            .sign(shell.mode.get_protocol_key().expect("Test failed"))
        };
        let vote_extension = VoteExtension {
            ethereum_events: Some(ethereum_events),
            bridge_pool_root: Some(bp_root),
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
            assert_eq!(rsp.txs.len(), 2);
            let tx_bytes = rsp.txs.remove(0);
            let got = Tx::try_from(tx_bytes.as_slice()).expect("Test failed");
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
            vote_extension.ethereum_events.expect("Test failed"),
            LAST_HEIGHT,
        );

        assert_eq!(rsp_digest, digest);
    }

    /// Test if Ethereum events validation and inclusion in a block
    /// behaves as expected, considering <= 2/3 voting power.
    #[test]
    #[cfg_attr(
        feature = "abcipp",
        should_panic(expected = "A Tendermint quorum should never")
    )]
    fn test_prepare_proposal_vext_insufficient_voting_power() {
        const FIRST_HEIGHT: BlockHeight = BlockHeight(1);
        const LAST_HEIGHT: BlockHeight = BlockHeight(FIRST_HEIGHT.0 + 11);

        let (mut shell, _recv, _, _oracle_control_recv) =
            test_utils::setup_at_height(FIRST_HEIGHT);

        // artificially change the voting power of the default validator to
        // zero, change the block height, and commit a dummy block,
        // to move to a new epoch
        let events_epoch = shell
            .wl_storage
            .pos_queries()
            .get_epoch(FIRST_HEIGHT)
            .expect("Test failed");
        let validators_handle =
            consensus_validator_set_handle().at(&events_epoch);
        let consensus_in_mem = validators_handle
            .iter(&shell.wl_storage)
            .expect("Test failed")
            .map(|val| {
                let (
                    NestedSubKey::Data {
                        key: stake,
                        nested_sub_key: SubKey::Data(position),
                    },
                    address,
                ) = val.expect("Test failed");
                (stake, position, address)
            })
            .collect::<Vec<_>>();
        for (val_stake, val_position, address) in consensus_in_mem.into_iter() {
            validators_handle
                .at(&val_stake)
                .remove(&mut shell.wl_storage, &val_position)
                .expect("Test failed");
            validators_handle
                .at(&0.into())
                .insert(&mut shell.wl_storage, val_position, address)
                .expect("Test failed");
        }

        let mut req = FinalizeBlock::default();
        req.header.time = namada::types::time::DateTimeUtc::now();
        shell.wl_storage.storage.last_height = LAST_HEIGHT;
        shell.finalize_block(req).expect("Test failed");
        shell.commit();

        assert_eq!(
            shell.wl_storage.pos_queries().get_epoch(
                shell.wl_storage.pos_queries().get_current_decision_height()
            ),
            Some(Epoch(1))
        );

        // test prepare proposal
        let (protocol_key, _, _) = wallet::defaults::validator_keys();
        let validator_addr = wallet::defaults::validator_address();

        let ethereum_event = EthereumEvent::TransfersToNamada {
            nonce: 1u64.into(),
            transfers: vec![],
            valid_transfers_map: vec![],
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
            let bp_root = {
                let to_sign = get_bp_bytes_to_sign();
                let sig = Signed::<_, SignableEthMessage>::new(
                    shell.mode.get_eth_bridge_keypair().expect("Test failed"),
                    to_sign,
                )
                .sig;
                bridge_pool_roots::Vext {
                    block_height: shell.wl_storage.storage.last_height,
                    validator_addr: shell
                        .mode
                        .get_validator_address()
                        .unwrap()
                        .clone(),
                    sig,
                }
                .sign(shell.mode.get_protocol_key().expect("Test failed"))
            };
            let vote_extension = VoteExtension {
                ethereum_events: Some(signed_eth_ev_vote_extension),
                bridge_pool_root: Some(bp_root),
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

    /// Test that the decrypted txs are included
    /// in the proposal in the same order as their
    /// corresponding wrappers
    #[test]
    fn test_decrypted_txs_in_correct_order() {
        let (mut shell, _recv, _, _) = test_utils::setup();
        let keypair = gen_keypair();
        let mut expected_wrapper = vec![];
        let mut expected_decrypted = vec![];

        let mut req = RequestPrepareProposal {
            txs: vec![],
            ..Default::default()
        };
        // create a request with two new wrappers from mempool and
        // two wrappers from the previous block to be decrypted
        for i in 0..2 {
            let tx = Tx::new(
                "wasm_code".as_bytes().to_owned(),
                Some(format!("transaction data: {}", i).as_bytes().to_owned()),
                shell.chain_id.clone(),
                None,
            );
            expected_decrypted.push(Tx::from(DecryptedTx::Decrypted {
                tx: tx.clone(),
                #[cfg(not(feature = "mainnet"))]
                has_valid_pow: false,
            }));
            let wrapper_tx = WrapperTx::new(
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
            let wrapper = wrapper_tx
                .sign(&keypair, shell.chain_id.clone(), None)
                .expect("Test failed");
            shell.enqueue_tx(wrapper_tx);
            expected_wrapper.push(wrapper.clone());
            req.txs.push(wrapper.to_bytes());
        }
        let expected_txs: Vec<TxBytes> = expected_wrapper
            .into_iter()
            .chain(expected_decrypted.into_iter())
            // we extract the inner data from the txs for testing
            // equality since otherwise changes in timestamps would
            // fail the test
            .map(|tx| tx.data.expect("Test failed"))
            .collect();
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
