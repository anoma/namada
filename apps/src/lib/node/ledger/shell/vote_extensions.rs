#[cfg(not(feature = "ABCI"))]
mod extend_votes {
    use anoma::types::ethereum_events::vote_extensions::{
        EpochPower, SignedEthEvent, SignedEvent,
    };

    use super::super::*;

    /// The data we include in a vote extension
    #[derive(Clone, Debug, BorshSerialize, BorshDeserialize)]
    pub struct VoteExtension {
        /// Ethereum events seen since last round
        ethereum_events: Vec<SignedEthEvent>,
    }

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
            response::ExtendVote {
                vote_extension: VoteExtension {
                    ethereum_events: self.new_ethereum_events(),
                }
                .try_to_vec()
                .unwrap(),
            }
        }

        /// At present this checks the signature on all Ethereum headers
        ///
        /// INVARIANT: This method must be stateless.
        pub fn verify_vote_extension(
            &self,
            req: request::VerifyVoteExtension,
        ) -> response::VerifyVoteExtension {
            if let Ok(VoteExtension { ethereum_events }) =
                VoteExtension::try_from_slice(&req.vote_extension[..])
            {
                return if ethereum_events.iter().all(|event| {
                    self.validate_ethereum_event(
                        self.storage.last_height + 1,
                        event,
                    )
                }) {
                    response::VerifyVoteExtension {
                        status: VerifyStatus::Accept.into(),
                    }
                } else {
                    response::VerifyVoteExtension {
                        status: VerifyStatus::Reject.into(),
                    }
                };
            }
            Default::default()
        }

        /// Checks the channel from the Ethereum oracle monitoring
        /// the fullnode and retrieves all messages sent. These are
        /// signed and prepared for inclusion in a vote extension.
        pub fn new_ethereum_events(&mut self) -> Vec<SignedEthEvent> {
            let mut events = vec![];
            let voting_power = self.get_validator_voting_power();
            let address = self.mode.get_validator_address().cloned();
            if let ShellMode::Validator {
                ref mut ethereum_recv,
                data:
                    ValidatorData {
                        keys:
                            ValidatorKeys {
                                protocol_keypair, ..
                            },
                        ..
                    },
                ..
            } = &mut self.mode
            {
                let (voting_power, address) =
                    voting_power.zip(address).unwrap();
                while let Ok(eth_event) = ethereum_recv.try_recv() {
                    events.push(SignedEthEvent::new(
                        eth_event,
                        address.clone(),
                        voting_power.clone(),
                        self.storage.last_height + 1,
                        protocol_keypair,
                    ));
                }
            }
            events
        }

        /// Verify that each ethereum header in a vote extension was signed by
        /// a validator in the correct epoch, the stated voting power is
        /// correct, and the signature is correct.
        pub fn validate_ethereum_event(
            &self,
            height: BlockHeight,
            event: &impl SignedEvent,
        ) -> bool {
            let epoch = self.storage.block.pred_epochs.get_epoch(height);
            let total_voting_power = self.get_total_voting_power(epoch);

            // Get the public keys of each validator. Filter out those that
            // inaccurately stated their voting power at a given block height
            let public_keys: Vec<common::PublicKey> = event
                .get_voting_powers()
                .into_iter()
                .filter_map(
                    |EpochPower {
                         validator,
                         voting_power,
                         block_height,
                     }| {
                        if block_height != height {
                            return None;
                        }
                        if let Some((power, pk)) =
                            self.get_validator_from_address(&validator, epoch)
                        {
                            FractionalVotingPower::new(
                                power,
                                total_voting_power,
                            )
                            .ok()
                            .and_then(|power| {
                                if power == voting_power {
                                    Some(pk)
                                } else {
                                    None
                                }
                            })
                        } else {
                            None
                        }
                    },
                )
                .collect();
            // check that we found all the public keys and
            // check that the signatures are valid
            public_keys.len() == event.number_of_signers()
                && event.verify_signatures(&public_keys).is_ok()
        }
    }

    #[cfg(test)]
    mod test_vote_extensions {
        use std::convert::TryInto;

        use anoma::ledger::pos;
        use anoma::ledger::pos::anoma_proof_of_stake::PosBase;
        use anoma::types::ethereum_events::vote_extensions::{
            FractionalVotingPower, MultiSignedEthEvent, SignedEthEvent,
        };
        use anoma::types::ethereum_events::{
            EthAddress, EthereumEvent, TransferToEthereum,
        };
        use anoma::types::key::*;
        use anoma::types::storage::{BlockHeight, Epoch};
        use borsh::{BorshDeserialize, BorshSerialize};
        use tendermint_proto::abci::response_verify_vote_extension::VerifyStatus;
        use tower_abci::request;

        use crate::node::ledger::shell::test_utils::*;
        use crate::node::ledger::shell::vote_extensions::VoteExtension;
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
            let [event_first, event_second]: [EthereumEvent; 2] = shell
                .new_ethereum_events()
                .into_iter()
                .map(|signed| signed.event.data.0)
                .collect::<Vec<EthereumEvent>>()
                .try_into()
                .expect("Test failed");

            assert_eq!(event_first, event_1);
            assert_eq!(event_second, event_2);
        }

        /// Test that ethereum events are added to vote extensions.
        /// Check that vote extensions pass verification.
        #[test]
        fn test_eth_events_vote_extension() {
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
            let vote_extension: VoteExtension =
                BorshDeserialize::try_from_slice(
                    &shell.extend_vote(Default::default()).vote_extension[..],
                )
                .expect("Test failed");

            let [event_first, event_second]: [EthereumEvent; 2] =
                vote_extension
                    .ethereum_events
                    .clone()
                    .into_iter()
                    .map(|signed| signed.event.data.0)
                    .collect::<Vec<EthereumEvent>>()
                    .try_into()
                    .expect("Test failed");

            assert_eq!(event_first, event_1);
            assert_eq!(event_second, event_2);
            let req = request::VerifyVoteExtension {
                hash: vec![],
                validator_address: vec![],
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
            let voting_power =
                shell.get_validator_voting_power().expect("Test failed");
            let signed_event = SignedEthEvent::new(
                EthereumEvent::TransfersToEthereum {
                    nonce: 1.into(),
                    transfers: vec![TransferToEthereum {
                        amount: 100.into(),
                        asset: EthAddress([1; 20]),
                        receiver: EthAddress([2; 20]),
                    }],
                },
                address,
                voting_power,
                shell.storage.last_height + 1,
                &signing_key,
            );
            assert!(!shell.validate_ethereum_event(
                shell.storage.last_height + 1,
                &signed_event
            ));
            assert!(!shell.validate_ethereum_event(
                shell.storage.last_height + 1,
                &MultiSignedEthEvent::from(signed_event)
            ));
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
            let voting_power =
                shell.get_validator_voting_power().expect("Test failed");
            let height = shell.storage.last_height + 1;

            let signed_event = SignedEthEvent::new(
                EthereumEvent::TransfersToEthereum {
                    nonce: 1.into(),
                    transfers: vec![TransferToEthereum {
                        amount: 100.into(),
                        asset: EthAddress([1; 20]),
                        receiver: EthAddress([2; 20]),
                    }],
                },
                address,
                voting_power,
                shell.storage.last_height + 1,
                &signing_key,
            );
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
                    .is_none()
            );
            let prev_epoch = Epoch(shell.storage.get_current_epoch().0.0 - 1);
            assert!(
                shell
                    .shell
                    .get_validator_from_protocol_pk(
                        &signing_key.ref_to(),
                        Some(prev_epoch)
                    )
                    .is_some()
            );
            assert!(shell.validate_ethereum_event(height, &signed_event));
            assert!(shell.validate_ethereum_event(
                height,
                &MultiSignedEthEvent::from(signed_event)
            ));
        }

        /// Test that if the declared voting power is not correct,
        /// the signed event is rejected
        #[test]
        fn reject_incorrect_voting_power() {
            let (shell, _, _) = setup();
            let signing_key =
                shell.mode.get_protocol_key().expect("Test failed");
            let address = shell.mode.get_validator_address().unwrap().clone();
            let voting_power = 99u64;
            let total_voting_power =
                u64::from(shell.get_total_voting_power(None));
            let signed_event = SignedEthEvent::new(
                EthereumEvent::TransfersToEthereum {
                    nonce: 1.into(),
                    transfers: vec![TransferToEthereum {
                        amount: 100.into(),
                        asset: EthAddress([1; 20]),
                        receiver: EthAddress([2; 20]),
                    }],
                },
                address,
                FractionalVotingPower::new(voting_power, total_voting_power)
                    .expect("Test failed"),
                shell.storage.last_height + 1,
                signing_key,
            );
            assert!(!shell.validate_ethereum_event(
                shell.storage.last_height + 1,
                &signed_event
            ));
            assert!(!shell.validate_ethereum_event(
                shell.storage.last_height + 1,
                &MultiSignedEthEvent::from(signed_event)
            ));
        }

        /// Test that that an event that incorrectly labels what block it was
        /// included in a vote extension on is rejected
        #[test]
        fn reject_incorrect_block_number() {
            let (shell, _, _) = setup();
            let signing_key =
                shell.mode.get_protocol_key().expect("Test failed");
            let address = shell.mode.get_validator_address().unwrap().clone();
            let voting_power = shell.get_validator_voting_power().unwrap();
            let signed_event = SignedEthEvent::new(
                EthereumEvent::TransfersToEthereum {
                    nonce: 1.into(),
                    transfers: vec![TransferToEthereum {
                        amount: 100.into(),
                        asset: EthAddress([1; 20]),
                        receiver: EthAddress([2; 20]),
                    }],
                },
                address,
                voting_power,
                shell.storage.last_height,
                signing_key,
            );
            assert!(!shell.validate_ethereum_event(
                shell.storage.last_height + 1,
                &signed_event
            ));
            assert!(!shell.validate_ethereum_event(
                shell.storage.last_height + 1,
                &MultiSignedEthEvent::from(signed_event)
            ));
        }

        /// Test that that an event with an incorrect address
        /// included in a vote extension is rejected
        #[test]
        fn reject_incorrect_address() {
            let (shell, _, _) = setup();
            let signing_key =
                shell.mode.get_protocol_key().expect("Test failed");
            let voting_power = shell.get_validator_voting_power().unwrap();
            let signed_event = SignedEthEvent::new(
                EthereumEvent::TransfersToEthereum {
                    nonce: 1.into(),
                    transfers: vec![TransferToEthereum {
                        amount: 100.into(),
                        asset: EthAddress([1; 20]),
                        receiver: EthAddress([2; 20]),
                    }],
                },
                crate::wallet::defaults::bertha_address(),
                voting_power,
                shell.storage.last_height,
                signing_key,
            );
            assert!(!shell.validate_ethereum_event(
                shell.storage.last_height + 1,
                &signed_event
            ));
            assert!(!shell.validate_ethereum_event(
                shell.storage.last_height + 1,
                &MultiSignedEthEvent::from(signed_event)
            ));
        }
    }
}

#[cfg(not(feature = "ABCI"))]
pub use extend_votes::*;
