#[cfg(not(feature = "ABCI"))]
mod extend_votes {
    use anoma::proto::Signed;
    use anoma::types::ethereum_events::vote_extensions::VoteExtension;
    use borsh::BorshDeserialize;

    use super::super::*;

    type SignedExt = Signed<VoteExtension>;

    impl<D, H> Shell<D, H>
    where
        D: DB + for<'iter> DBIter<'iter> + Sync + 'static,
        H: StorageHasher + Sync + 'static,
    {
        /// INVARIANT: This method must be stateless.
        pub fn extend_vote(
            &mut self,
            _req: request::ExtendVote,
        ) -> response::ExtendVote {
            let ext = VoteExtension {
                block_height: self.storage.last_height + 1,
                ethereum_events: self.new_ethereum_events(),
            };
            self.mode
                .get_protocol_key()
                .map(|signing_key| response::ExtendVote {
                    vote_extension: ext.sign(signing_key).try_to_vec().unwrap(),
                })
                .unwrap_or_default()
        }

        /// This checks that the vote extension:
        /// * Correctly deserializes
        /// * Was correctly signed by an active validator.
        /// * The block height signed over is correct (replay protection)
        ///
        /// INVARIANT: This method must be stateless.
        pub fn verify_vote_extension(
            &self,
            req: request::VerifyVoteExtension,
        ) -> response::VerifyVoteExtension {
            let validator_addr = req.validator_address.as_slice();
            if let Ok(signed) =
                SignedExt::try_from_slice(&req.vote_extension[..])
            {
                response::VerifyVoteExtension {
                    status: if self.validate_vote_extension(
                        signed,
                        validator_addr,
                        self.storage.last_height + 1,
                    ) {
                        VerifyStatus::Accept.into()
                    } else {
                        VerifyStatus::Reject.into()
                    },
                }
            } else {
                response::VerifyVoteExtension {
                    status: VerifyStatus::Reject.into(),
                }
            }
        }

        /// Validates a vote extension issued at the provided block height
        /// Checks that at epoch of the provided height
        ///  * The tendermint address corresponds to an active validator
        ///  * The validator correctly signed the extension
        ///  * The validator signed over the correct height inside of the
        ///    extension
        pub fn validate_vote_extension(
            &self,
            ext: SignedExt,
            tm_address: &[u8],
            height: BlockHeight,
        ) -> bool {
            let epoch = self.storage.block.pred_epochs.get_epoch(height);
            // get the validator that issued this vote extension
            // this should not fail
            let validator =
                match self.get_validator_from_tm_address(tm_address, epoch) {
                    Ok(address) => address,
                    _ => return false,
                };
            // get the public key associated with this validator
            let pk = match self.get_validator_from_address(&validator, epoch) {
                Ok((_, pk)) => pk,
                _ => return false,
            };
            ext.verify(&pk).is_ok()
                && ext.data.block_height == height
        }

        /// Checks the channel from the Ethereum oracle monitoring
        /// the fullnode and retrieves all VoteExtensionmessages sent.
        pub fn new_ethereum_events(&mut self) -> Vec<EthereumEvent> {
            let mut events = vec![];
            if let ShellMode::Validator {
                ref mut ethereum_recv,
                ..
            } = &mut self.mode
            {
                while let Ok(eth_event) = ethereum_recv.try_recv() {
                    events.push(eth_event);
                }
            }

            events
        }
    }

    #[cfg(test)]
    mod test_vote_extensions {
        use std::convert::TryInto;

        use anoma::ledger::pos;
        use anoma::ledger::pos::anoma_proof_of_stake::PosBase;
        use anoma::types::ethereum_events::vote_extensions::VoteExtension;
        use anoma::types::ethereum_events::{
            EthAddress, EthereumEvent, TransferToEthereum,
        };
        use anoma::types::key::*;
        use anoma::types::storage::{BlockHeight, Epoch};
        use borsh::{BorshDeserialize, BorshSerialize};
        use tendermint_proto::abci::response_verify_vote_extension::VerifyStatus;
        use tower_abci::request;

        use super::SignedExt;
        use crate::node::ledger::shell::test_utils::*;
        use crate::node::ledger::shims::abcipp_shim_types::shim::request::FinalizeBlock;

        /// Test that we successfully receive ethereum events
        /// from the channel to fullnode process
        ///
        /// We further check that ledger side buffering is done if multiple
        /// events are in the channel
        #[test]
        fn test_get_eth_events() {
            let (mut shell, _, oracle) = setup();
            let event_1 = EthereumEvent::NewContract {
                name: "Test".to_string(),
                address: EthAddress([0; 20]),
            };
            let event_2 = EthereumEvent::TransfersToEthereum {
                nonce: 1.into(),
                transfers: vec![TransferToEthereum {
                    amount: 100.into(),
                    asset: EthAddress([1; 20]),
                    receiver: EthAddress([2; 20]),
                }],
            };
            oracle.send(event_1.clone()).expect("Test failed");
            oracle.send(event_2.clone()).expect("Test failed");
            let [event_first, event_second]: [EthereumEvent; 2] =
                shell.new_ethereum_events().try_into().expect("Test failed");

            assert_eq!(event_first, event_1);
            assert_eq!(event_second, event_2);
        }

        /// Test that ethereum events are added to vote extensions.
        /// Check that vote extensions pass verification.
        #[test]
        fn test_eth_events_vote_extension() {
            let (mut shell, _, oracle) = setup();
            let address = shell
                .mode
                .get_validator_address()
                .expect("Test failed")
                .clone();
            let event_1 = EthereumEvent::NewContract {
                name: "Test".to_string(),
                address: EthAddress([0; 20]),
            };
            let event_2 = EthereumEvent::TransfersToEthereum {
                nonce: 1.into(),
                transfers: vec![TransferToEthereum {
                    amount: 100.into(),
                    asset: EthAddress([1; 20]),
                    receiver: EthAddress([2; 20]),
                }],
            };
            oracle.send(event_1.clone()).expect("Test failed");
            oracle.send(event_2.clone()).expect("Test failed");
            let vote_extension =
                <SignedExt as BorshDeserialize>::try_from_slice(
                    &shell.extend_vote(Default::default()).vote_extension[..],
                )
                .expect("Test failed");

            let [event_first, event_second]: [EthereumEvent; 2] =
                vote_extension
                    .data
                    .ethereum_events
                    .clone()
                    .try_into()
                    .expect("Test failed");

            assert_eq!(event_first, event_1);
            assert_eq!(event_second, event_2);
            let req = request::VerifyVoteExtension {
                hash: vec![],
                validator_address: address
                    .raw_hash()
                    .expect("Test failed")
                    .as_bytes()
                    .to_vec(),
                height: 0,
                vote_extension: vote_extension
                    .try_to_vec()
                    .expect("Test failed"),
            };
            let res = shell.verify_vote_extension(req);
            assert_eq!(res.status, i32::from(VerifyStatus::Accept));
        }

        /// Test that Ethereum headers signed by a non-validator is rejected
        #[test]
        fn test_eth_events_must_be_signed_by_validator() {
            let (shell, _, _) = setup();
            let signing_key = gen_keypair();
            let address = shell
                .mode
                .get_validator_address()
                .expect("Test failed")
                .clone();
            let vote_ext = VoteExtension {
                ethereum_events: vec![EthereumEvent::TransfersToEthereum {
                    nonce: 1.into(),
                    transfers: vec![TransferToEthereum {
                        amount: 100.into(),
                        asset: EthAddress([1; 20]),
                        receiver: EthAddress([2; 20]),
                    }],
                }],
                block_height: shell.storage.last_height + 1,
            }
            .sign(&signing_key)
            .try_to_vec()
            .expect("Test failed");
            let req = request::VerifyVoteExtension {
                hash: vec![],
                validator_address: address
                    .raw_hash()
                    .expect("Test failed")
                    .as_bytes()
                    .to_vec(),
                height: 0,
                vote_extension: vote_ext,
            };
            assert_eq!(
                shell.verify_vote_extension(req).status,
                i32::from(VerifyStatus::Reject)
            );
        }

        /// Test that validation of vote extensions cast during the
        /// previous block are accepted for the current block. This
        /// should pass even if the epoch changed resulting in a
        /// change to the validator set.
        #[test]
        fn test_validate_vote_extensions() {
            let (mut shell, _, _) = setup();
            let signing_key =
                shell.mode.get_protocol_key().expect("Test failed").clone();
            let address = shell
                .mode
                .get_validator_address()
                .expect("Test failed")
                .clone();
            let signed_height = shell.storage.last_height + 1;
            let vote_ext = VoteExtension {
                ethereum_events: vec![EthereumEvent::TransfersToEthereum {
                    nonce: 1.into(),
                    transfers: vec![TransferToEthereum {
                        amount: 100.into(),
                        asset: EthAddress([1; 20]),
                        receiver: EthAddress([2; 20]),
                    }],
                }],
                block_height: signed_height,
            }
            .sign(shell.mode.get_protocol_key().expect("Test failed"));

            assert_eq!(shell.storage.get_current_epoch().0.0, 0);
            // We make a change so that there are no
            // validators in the next epoch
            let mut current_validators = shell.storage.read_validator_set();
            current_validators.data.insert(
                1,
                Some(pos::types::ValidatorSet {
                    active: Default::default(),
                    inactive: Default::default(),
                }),
            );
            shell.storage.write_validator_set(&current_validators);
            // we advance forward to the next epoch
            let mut req = FinalizeBlock::default();
            req.header.time = anoma::types::time::DateTimeUtc::now();
            shell.storage.last_height = BlockHeight(11);
            shell.finalize_block(req).expect("Test failed");
            shell.commit();
            assert_eq!(shell.storage.get_current_epoch().0.0, 1);
            assert!(
                shell
                    .get_validator_from_protocol_pk(&signing_key.ref_to(), None)
                    .is_err()
            );
            let prev_epoch = Epoch(shell.storage.get_current_epoch().0.0 - 1);
            assert!(
                shell
                    .shell
                    .get_validator_from_protocol_pk(
                        &signing_key.ref_to(),
                        Some(prev_epoch)
                    )
                    .is_ok()
            );

            let tm_address = address
                .raw_hash()
                .expect("Test failed")
                .as_bytes()
                .to_vec();
            assert!(shell.validate_vote_extension(vote_ext, &tm_address, signed_height));
        }

        /// Test that that an event that incorrectly labels what block it was
        /// included in a vote extension on is rejected
        #[test]
        fn reject_incorrect_block_number() {
            let (shell, _, _) = setup();
            let address = shell.mode.get_validator_address().unwrap().clone();
            let vote_ext = VoteExtension {
                ethereum_events: vec![EthereumEvent::TransfersToEthereum {
                    nonce: 1.into(),
                    transfers: vec![TransferToEthereum {
                        amount: 100.into(),
                        asset: EthAddress([1; 20]),
                        receiver: EthAddress([2; 20]),
                    }],
                }],
                block_height: shell.storage.last_height,
            }
            .sign(shell.mode.get_protocol_key().expect("Test failed"))
            .try_to_vec()
            .expect("Test failed");

            let req = request::VerifyVoteExtension {
                hash: vec![],
                validator_address: address.try_to_vec().expect("Test failed"),
                height: 0,
                vote_extension: vote_ext,
            };
            assert_eq!(
                shell.verify_vote_extension(req).status,
                i32::from(VerifyStatus::Reject)
            );
        }
    }
}

#[cfg(not(feature = "ABCI"))]
pub use extend_votes::*;
