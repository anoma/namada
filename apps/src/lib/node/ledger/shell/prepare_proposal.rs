//! Implementation of the [`PrepareProposal`] ABCI++ method for the Shell

#[cfg(not(feature = "ABCI"))]
mod prepare_block {
    use std::collections::{BTreeMap, HashSet};

    use namada::proto::Signed;
    use namada::types::address::Address;
    use namada::types::ethereum_events::vote_extensions::{
        FractionalVotingPower, MultiSignedEthEvent, VoteExtension,
        VoteExtensionDigest,
    };
    use namada::types::transaction::protocol::ProtocolTxType;
    use tendermint_proto::abci::{
        ExtendedCommitInfo, ExtendedVoteInfo, TxRecord,
    };

    use super::super::vote_extensions::SignedExt;
    use super::super::*;
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
                let mut txs =
                    self.build_vote_extensions_txs(req.local_last_commit);

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

            response::PrepareProposal {
                tx_records: txs,
                ..Default::default()
            }
        }

        /// Builds a batch of vote extension transactions, comprised of Ethereum
        /// events
        fn build_vote_extensions_txs(
            &mut self,
            local_last_commit: Option<ExtendedCommitInfo>,
        ) -> Vec<TxRecord> {
            let protocol_key = self
                .mode
                .get_protocol_key()
                .expect("Validators should always have a protocol key");

            let vote_extension_digest =
                local_last_commit.and_then(|local_last_commit| {
                    let votes = local_last_commit.votes;
                    self.compress_vote_extensions(votes)
                });
            let vote_extension_digest =
                match (vote_extension_digest, self.storage.last_height) {
                    // handle genesis block
                    (None, BlockHeight(0)) => return vec![],
                    (Some(_), BlockHeight(0)) => {
                        tracing::error!(
                            "The genesis block should not contain vote \
                             extensions"
                        );
                        // TODO: maybe slash validators who claim to have
                        // seen vote extensions at H=0
                        return vec![];
                    }
                    // handle block heights > 0
                    (Some(digest), _) => digest,
                    _ => unreachable!(
                        "Honest Namada validators will always sign a \
                         VoteExtension, even if no Ethereum events were \
                         observed at a given block height. In fact, signing \
                         an empty VoteExtension commits the fact no events \
                         were observed by a majority of validators. Likewise, \
                         a Tendermint quorum should never decide on a block \
                         including vote extensions reflecting less than or \
                         equal to 2/3 of the total stake. These scenarios are \
                         virtually impossible, so we will panic here."
                    ),
                };

            let tx = ProtocolTxType::EthereumEvents(vote_extension_digest)
                .sign(&protocol_key)
                .to_bytes();
            let tx_record = record::add(tx);

            vec![tx_record]
        }

        /// Builds a batch of mempool transactions
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

        /// Builds a batch of DKG decrypted transactions
        fn build_decrypted_txs(&mut self) -> Vec<TxRecord> {
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
                .map(record::add)
                .collect()
        }

        /// Compresses a set of vote extensions into a single
        /// [`VoteExtensionDigest`], whilst filtering invalid
        /// [`SignedExt`] instances in the process
        fn compress_vote_extensions(
            &self,
            vote_extensions: Vec<ExtendedVoteInfo>,
        ) -> Option<VoteExtensionDigest> {
            let events_epoch = self
                .storage
                .block
                .pred_epochs
                .get_epoch(self.storage.last_height)
                .expect(
                    "The epoch of the last block height should always be known",
                );

            let mut event_observers = BTreeMap::new();
            let mut signatures = Vec::new();

            let total_voting_power =
                self.get_total_voting_power(Some(events_epoch)).into();
            let mut voting_power = 0u64;

            for (validator_addr, vote_extension) in
                self.filter_invalid_vote_extensions(vote_extensions)
            {
                let (validator_voting_power, _) = self
                    .get_validator_from_address(
                        &validator_addr,
                        Some(events_epoch),
                    )
                    .expect(
                        "We already checked that we have a valid Tendermint \
                         address",
                    );

                // update voting power
                voting_power += u64::from(validator_voting_power);

                // register all ethereum events seen by `validator_addr`
                for ev in vote_extension.data.ethereum_events {
                    let signers =
                        event_observers.entry(ev).or_insert_with(HashSet::new);

                    signers.insert(validator_addr.clone());
                }

                // register the signature of `validator_addr`
                let addr = validator_addr;
                let sig = vote_extension.sig;

                signatures.push((sig, addr));
            }

            let voting_power =
                FractionalVotingPower::new(voting_power, total_voting_power)
                    .unwrap();

            if voting_power <= FractionalVotingPower::TWO_THIRDS {
                tracing::error!(
                    "Tendermint has decided on a block including vote \
                     extensions reflecting less than 2/3 of the total stake"
                );
                return None;
            }

            let events = event_observers
                .into_iter()
                .map(|(event, signers)| MultiSignedEthEvent { event, signers })
                .collect();

            Some(VoteExtensionDigest { events, signatures })
        }

        /// Takes a list of signed vote extensions,
        /// and filters out invalid instances.
        fn filter_invalid_vote_extensions(
            &self,
            vote_extensions: Vec<ExtendedVoteInfo>,
        ) -> impl Iterator<Item = (Address, SignedExt)> + '_ {
            vote_extensions.into_iter().filter_map(|vote| {
                let vote_extension = Signed::<VoteExtension>::try_from_slice(
                    &vote.vote_extension[..],
                )
                .map_err(|err| {
                    tracing::error!(
                        "Failed to deserialize signed vote extension: {}",
                        err
                    );
                })
                .ok()?;

                let validator = vote.validator.or_else(|| {
                    tracing::error!("Vote extension has no validator data");
                    None
                })?;

                self.validate_vote_ext_and_get_nam_addr(
                    vote_extension,
                    &validator.address[..],
                    self.storage.last_height,
                )
            })
        }
    }

    /// Functions for creating the appropriate TxRecord given the
    /// numeric code
    pub(super) mod record {
        use tendermint_proto::abci::tx_record::TxAction;

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
    // TODO: write tests for ethereum events on prepare proposal
    mod test_prepare_proposal {
        use namada::types::address::xan;
        use namada::types::ethereum_events::vote_extensions::VoteExtension;
        // use namada::types::ethereum_events::EthereumEvent;
        use namada::types::key::{self, common, ed25519::Signature};
        use namada::types::storage::{BlockHeight, Epoch};
        use namada::types::transaction::Fee;
        use tendermint_proto::abci::tx_record::TxAction;
        use tendermint_proto::abci::{ExtendedCommitInfo, ExtendedVoteInfo};

        use super::super::super::vote_extensions::SignedExt;
        use super::*;
        use crate::node::ledger::shell::test_utils::{gen_keypair, TestShell};

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
            assert_eq!(
                shell.prepare_proposal(req).tx_records,
                vec![record::remove(tx.to_bytes())]
            );
        }

        /// Test if we are filtering out vote extensinos with bad
        /// signatures in a prepare proposal.
        #[test]
        fn test_prepare_proposal_filter_out_bad_signatures() {
            const LAST_HEIGHT: BlockHeight = BlockHeight(2);

            let (mut shell, _, _) = TestShell::new();

            // artificially change the block height
            shell.storage.last_height = LAST_HEIGHT;

            let signed_vote_extensions = vec![
                {
                    let sk = key::testing::keypair_1();
                    VoteExtension {
                        block_height: LAST_HEIGHT,
                        ethereum_events: vec![],
                    }
                    .sign(&sk)
                },
                {
                    // create a fake signature
                    let sig =
                        common::Signature::Ed25519(Signature([0u8; 64].into()));

                    let data = VoteExtension {
                        block_height: LAST_HEIGHT,
                        ethereum_events: vec![],
                    };

                    SignedExt { sig, data }
                },
            ];
            let votes = signed_vote_extensions
                .into_iter()
                .map(|ext| ExtendedVoteInfo {
                    vote_extension: ext.try_to_vec().unwrap(),
                    // TODO: make sure the Tendermint validator we insert here
                    // has an equivalent Namada validator addr in the `shell`
                    //
                    // https://github.com/anoma/namada/blob/tiago/vote-extensions-types/apps/src/lib/config/genesis.rs#L733=
                    validator: Some(todo!()),
                    ..Default::default()
                })
                .collect();

            let req = RequestPrepareProposal {
                local_last_commit: Some(ExtendedCommitInfo { round: 0, votes }),
                ..Default::default()
            };
        }

        // TODO: test if we filter out valid signatures,
        // but for invalid block heights

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
            let req = RequestPrepareProposal {
                txs: vec![wrapper.clone()],
                max_tx_bytes: 0,
                ..Default::default()
            };
            assert_eq!(
                shell.prepare_proposal(req).tx_records,
                vec![record::remove(wrapper)]
            );
        }

        /// Test that the decrypted txs are included
        /// in the proposal in the same order as their
        /// corresponding wrappers
        #[test]
        fn test_decrypted_txs_in_correct_order() {
            let (mut shell, _, _) = TestShell::new();
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
                    Some(
                        format!("transaction data: {}", i)
                            .as_bytes()
                            .to_owned(),
                    ),
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
    }
}

#[allow(unused_imports)]
#[cfg(not(feature = "ABCI"))]
pub use prepare_block::*;
