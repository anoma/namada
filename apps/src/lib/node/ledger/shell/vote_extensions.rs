use namada::ledger::pos::namada_proof_of_stake::types::VotingPower;
use namada::proto::Signed;
use namada::types::transaction::protocol::{ProtocolTx, ProtocolTxType};
#[cfg(feature = "abcipp")]
use tendermint_proto_abcipp::abci::ExtendedVoteInfo;

use super::queries::QueriesExt;
use super::*;
use crate::node::ledger::shims::abcipp_shim_types::shim::TxBytes;

/// The error yielded from validating faulty vote extensions in the shell
#[derive(Error, Debug)]
pub enum VoteExtensionError {
    #[error("The vote extension was issued at block height 0.")]
    IssuedAtGenesis,
    #[error("The vote extension has an unexpected block height.")]
    #[cfg(feature = "abcipp")]
    UnexpectedBlockHeight,
    #[error(
        "The vote extension contains duplicate or non-sorted Ethereum events."
    )]
    HaveDupesOrNonSorted,
    #[error(
        "The public key of the vote extension's associated validator could \
         not be found in storage."
    )]
    PubKeyNotInStorage,
    #[error("The vote extension's signature is invalid.")]
    VerifySigFailed,
}

impl<D, H> Shell<D, H>
where
    D: DB + for<'iter> DBIter<'iter> + Sync + 'static,
    H: StorageHasher + Sync + 'static,
{
    /// INVARIANT: This method must be stateless.
    #[cfg(feature = "abcipp")]
    pub fn extend_vote(
        &mut self,
        _req: request::ExtendVote,
    ) -> response::ExtendVote {
        self.mode
            .get_protocol_key()
            .map(|signing_key| response::ExtendVote {
                vote_extension: self.craft_extension().try_to_vec().unwrap(),
            })
            .unwrap_or_default()
    }

    /// Creates the data to be added to a vote extension.
    ///
    /// INVARIANT: This method must be stateless.
    pub fn craft_extension(&mut self) -> Signed<ethereum_events::Vext> {
        let validator_addr = self
            .mode
            .get_validator_address()
            .expect("only validators should receive this method call")
            .to_owned();
        let ext = ethereum_events::Vext {
            block_height: self.storage.last_height + 1,
            ethereum_events: self.new_ethereum_events(),
            validator_addr,
        };
        self.mode
            .get_protocol_key()
            .map(|signing_key| ext.sign(signing_key))
            .expect("only validators should receive this method call")
    }

    /// This checks that the vote extension:
    /// * Correctly deserializes
    /// * Was correctly signed by an active validator.
    /// * The block height signed over is correct (replay protection)
    ///
    /// INVARIANT: This method must be stateless.
    #[cfg(feature = "abcipp")]
    pub fn verify_vote_extension(
        &self,
        req: request::VerifyVoteExtension,
    ) -> response::VerifyVoteExtension {
        // TODO: this should deserialize to
        // `namada::types::vote_extensions::VoteExtension`,
        // which contains an optional validator set update and
        // a set of ethereum events seen at the previous block height
        if let Ok(signed) = Signed::<ethereum_events::Vext>::try_from_slice(
            &req.vote_extension[..],
        ) {
            response::VerifyVoteExtension {
                status: if self
                    .validate_vext(signed, self.storage.last_height + 1)
                {
                    VerifyStatus::Accept.into()
                } else {
                    tracing::warn!(
                        ?req.validator_address,
                        ?req.hash,
                        req.height,
                        "received vote extension that didn't validate"
                    );
                    VerifyStatus::Reject.into()
                },
            }
        } else {
            tracing::warn!(
                ?req.validator_address,
                ?req.hash,
                req.height,
                "received undeserializable vote extension"
            );
            response::VerifyVoteExtension {
                status: VerifyStatus::Reject.into(),
            }
        }
    }

    /// Validates a vote extension issued at the provided
    /// block height
    ///
    /// Checks that at epoch of the provided height:
    ///  * The Tendermint address corresponds to an active validator
    ///  * The validator correctly signed the extension
    ///  * The validator signed over the correct height inside of the extension
    ///  * There are no duplicate Ethereum events in this vote extension, and
    ///    the events are sorted in ascending order
    #[cfg(feature = "abcipp")]
    #[inline]
    pub fn validate_vext(
        &self,
        ext: Signed<ethereum_events::Vext>,
        last_height: BlockHeight,
    ) -> bool {
        self.validate_vexts_and_get_it_back(ext, last_height)
            .is_ok()
    }

    /// This method behaves exactly like [`Self::validate_vext`],
    /// with the added bonus of returning the vote extension back, if it
    /// is valid.
    pub fn validate_vexts_and_get_it_back(
        &self,
        ext: Signed<ethereum_events::Vext>,
        last_height: BlockHeight,
    ) -> std::result::Result<
        (VotingPower, Signed<ethereum_events::Vext>),
        VoteExtensionError,
    > {
        #[cfg(feature = "abcipp")]
        if ext.data.block_height != last_height {
            let ext_height = ext.data.block_height;
            tracing::error!(
                "Vote extension issued for a block height {ext_height} \
                 different from the expected height {last_height}"
            );
            return Err(VoteExtensionError::UnexpectedBlockHeight);
        }
        if last_height.0 == 0 {
            tracing::error!("Dropping vote extension issued at genesis");
            return Err(VoteExtensionError::IssuedAtGenesis);
        }
        // verify if we have any duplicate Ethereum events,
        // and if these are sorted in ascending order
        let have_dupes_or_non_sorted = {
            !ext.data
                .ethereum_events
                // TODO: move to `array_windows` when it reaches Rust stable
                .windows(2)
                .all(|evs| evs[0] < evs[1])
        };
        let validator = &ext.data.validator_addr;
        if have_dupes_or_non_sorted {
            tracing::error!(
                %validator,
                "Found duplicate or non-sorted Ethereum events in a vote extension from validator"
            );
            return Err(VoteExtensionError::HaveDupesOrNonSorted);
        }
        // get the public key associated with this validator
        let epoch = self
            .storage
            .block
            .pred_epochs
            .get_epoch(ext.data.block_height);
        let (voting_power, pk) = self
            .storage
            .get_validator_from_address(validator, epoch)
            .map_err(|err| {
                tracing::error!(
                    ?err,
                    %validator,
                    "Could not get public key from Storage for validator"
                );
                VoteExtensionError::PubKeyNotInStorage
            })?;
        // verify the signature of the vote extension
        ext.verify(&pk)
                .map_err(|err| {
                    tracing::error!(
                        ?err,
                        %validator,
                        "Failed to verify the signature of a vote extension issued by validator"
                    );
                    VoteExtensionError::VerifySigFailed
                })
                .map(|_| (voting_power, ext))
    }

    /// Checks the channel from the Ethereum oracle monitoring
    /// the fullnode and retrieves all seen Ethereum events.
    pub fn new_ethereum_events(&mut self) -> Vec<EthereumEvent> {
        match &mut self.mode {
            ShellMode::Validator {
                ref mut ethereum_recv,
                ..
            } => {
                ethereum_recv.fill_queue();
                ethereum_recv.get_events()
            }
            _ => vec![],
        }
    }

    /// Takes an iterator over vote extension instances,
    /// and returns another iterator. The latter yields
    /// valid vote extensions, or the reason why these
    /// are invalid, in the form of a [`VoteExtensionError`].
    // TODO: the `vote_extensions` iterator should be over `VoteExtension`
    // instances, I guess? to be determined in the next PR
    #[inline]
    pub fn validate_vote_extension_list<'a>(
        &'a self,
        vote_extensions: impl IntoIterator<Item = Signed<ethereum_events::Vext>>
        + 'a,
    ) -> impl Iterator<
        Item = std::result::Result<
            (VotingPower, Signed<ethereum_events::Vext>),
            VoteExtensionError,
        >,
    > + 'a {
        vote_extensions.into_iter().map(|vote_extension| {
            self.validate_vexts_and_get_it_back(
                vote_extension,
                self.storage.last_height,
            )
        })
    }

    /// Takes a list of signed vote extensions,
    /// and filters out invalid instances.
    // TODO: the `vote_extensions` iterator should be over `VoteExtension`
    // instances, I guess? to be determined in the next PR
    #[inline]
    pub fn filter_invalid_vote_extensions<'a>(
        &'a self,
        vote_extensions: impl IntoIterator<Item = Signed<ethereum_events::Vext>>
        + 'a,
    ) -> impl Iterator<Item = (VotingPower, Signed<ethereum_events::Vext>)> + 'a
    {
        self.validate_vote_extension_list(vote_extensions)
            .filter_map(|ext| ext.ok())
    }
}

/// Given a `Vec` of [`ExtendedVoteInfo`], return an iterator over the
/// ones we could deserialize to [`Signed<ethereum_events::Vext>`]
/// instances.
// TODO: we need to return an iterator over instances of `VoteExtension`,
// which contain both the ethereum events vote extensions and validator
// set update vote extensions
#[cfg(feature = "abcipp")]
pub fn deserialize_vote_extensions(
    vote_extensions: Vec<ExtendedVoteInfo>,
) -> impl Iterator<Item = Signed<ethereum_events::Vext>> + 'static {
    vote_extensions.into_iter().filter_map(|vote| {
        Signed::<ethereum_events::Vext>::try_from_slice(
            &vote.vote_extension[..],
        )
        .map_err(|err| {
            tracing::error!(
                ?err,
                // TODO: change this error message, probably, such that
                // it mentions Ethereum events rather than vote
                // extensions
                "Failed to deserialize signed vote extension",
            );
        })
        .ok()
    })
}

/// Given a `Vec` of [`TxBytes`], return an iterator over the
/// ones we could deserialize to [`Signed<ethereum_events::Vext>`]
/// instances.
// TODO: we need to return an iterator over instances of `VoteExtension`,
// which contain both the ethereum events vote extensions and validator
// set update vote extensions
#[cfg(not(feature = "abcipp"))]
pub fn deserialize_vote_extensions(
    txs: &[TxBytes],
) -> impl Iterator<Item = Signed<ethereum_events::Vext>> + '_ {
    txs.iter().filter_map(|tx| {
        if let Ok(tx) = Tx::try_from(tx.as_slice()) {
            match process_tx(tx).ok()? {
                TxType::Protocol(ProtocolTx {
                    tx: ProtocolTxType::EthereumEvents(signed),
                    ..
                }) => Some(signed),
                _ => None,
            }
        } else {
            None
        }
    })
}

#[cfg(test)]
mod test_vote_extensions {
    use std::convert::TryInto;

    #[cfg(feature = "abcipp")]
    use borsh::{BorshDeserialize, BorshSerialize};
    use namada::ledger::pos;
    use namada::ledger::pos::namada_proof_of_stake::PosBase;
    #[cfg(feature = "abcipp")]
    use namada::proto::Signed;
    use namada::types::ethereum_events::{
        EthAddress, EthereumEvent, TransferToEthereum,
    };
    use namada::types::key::*;
    use namada::types::storage::{BlockHeight, Epoch};
    use namada::types::vote_extensions::ethereum_events;
    #[cfg(feature = "abcipp")]
    use tendermint_proto_abcipp::abci::response_verify_vote_extension::VerifyStatus;
    #[cfg(feature = "abcipp")]
    use tower_abci_abcipp::request;

    use crate::node::ledger::shell::queries::QueriesExt;
    use crate::node::ledger::shell::test_utils::*;
    use crate::node::ledger::shims::abcipp_shim_types::shim::request::FinalizeBlock;

    /// Test that we successfully receive ethereum events
    /// from the channel to fullnode process
    ///
    /// We further check that ledger side buffering is done if multiple
    /// events are in the channel and that queueing and de-duplicating is
    /// done
    #[test]
    fn test_get_eth_events() {
        let (mut shell, _, oracle) = setup();
        let event_1 = EthereumEvent::TransfersToEthereum {
            nonce: 1.into(),
            transfers: vec![TransferToEthereum {
                amount: 100.into(),
                asset: EthAddress([1; 20]),
                receiver: EthAddress([2; 20]),
            }],
        };
        let event_2 = EthereumEvent::TransfersToEthereum {
            nonce: 2.into(),
            transfers: vec![TransferToEthereum {
                amount: 100.into(),
                asset: EthAddress([1; 20]),
                receiver: EthAddress([2; 20]),
            }],
        };
        let event_3 = EthereumEvent::NewContract {
            name: "Test".to_string(),
            address: EthAddress([0; 20]),
        };

        oracle.send(event_1.clone()).expect("Test failed");
        oracle.send(event_3.clone()).expect("Test failed");
        let [event_first, event_second]: [EthereumEvent; 2] =
            shell.new_ethereum_events().try_into().expect("Test failed");

        assert_eq!(event_first, event_1);
        assert_eq!(event_second, event_3);
        // check that we queue and de-duplicate events
        oracle.send(event_2.clone()).expect("Test failed");
        oracle.send(event_3.clone()).expect("Test failed");
        let [event_first, event_second, event_third]: [EthereumEvent; 3] =
            shell.new_ethereum_events().try_into().expect("Test failed");

        assert_eq!(event_first, event_1);
        assert_eq!(event_second, event_2);
        assert_eq!(event_third, event_3);
    }

    /// Test that ethereum events are added to vote extensions.
    /// Check that vote extensions pass verification.
    #[cfg(feature = "abcipp")]
    #[test]
    fn test_eth_events_vote_extension() {
        let (mut shell, _, oracle) = setup();
        let address = shell
            .mode
            .get_validator_address()
            .expect("Test failed")
            .clone();
        let event_1 = EthereumEvent::TransfersToEthereum {
            nonce: 1.into(),
            transfers: vec![TransferToEthereum {
                amount: 100.into(),
                asset: EthAddress([1; 20]),
                receiver: EthAddress([2; 20]),
            }],
        };
        let event_2 = EthereumEvent::NewContract {
            name: "Test".to_string(),
            address: EthAddress([0; 20]),
        };
        oracle.send(event_1.clone()).expect("Test failed");
        oracle.send(event_2.clone()).expect("Test failed");
        let vote_extension =
                <Signed<ethereum_events::Vext> as BorshDeserialize>::try_from_slice(
                    &shell.extend_vote(Default::default()).vote_extension[..],
                )
                .expect("Test failed");

        let [event_first, event_second]: [EthereumEvent; 2] = vote_extension
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
            vote_extension: vote_extension.try_to_vec().expect("Test failed"),
        };
        let res = shell.verify_vote_extension(req);
        assert_eq!(res.status, i32::from(VerifyStatus::Accept));
    }

    /// Test that Ethereum events signed by a non-validator are rejected
    #[test]
    fn test_eth_events_must_be_signed_by_validator() {
        let (shell, _, _) = setup();
        let signing_key = gen_keypair();
        let address = shell
            .mode
            .get_validator_address()
            .expect("Test failed")
            .clone();
        let vote_ext = ethereum_events::Vext {
            ethereum_events: vec![EthereumEvent::TransfersToEthereum {
                nonce: 1.into(),
                transfers: vec![TransferToEthereum {
                    amount: 100.into(),
                    asset: EthAddress([1; 20]),
                    receiver: EthAddress([2; 20]),
                }],
            }],
            block_height: shell.storage.last_height + 1,
            #[cfg(feature = "abcipp")]
            validator_addr: address.clone(),
            #[cfg(not(feature = "abcipp"))]
            validator_addr: address,
        }
        .sign(&signing_key);
        #[cfg(feature = "abcipp")]
        let req = request::VerifyVoteExtension {
            hash: vec![],
            validator_address: address
                .raw_hash()
                .expect("Test failed")
                .as_bytes()
                .to_vec(),
            height: shell.storage.last_height + 1,
            vote_extension: vote_ext.try_to_vec().expect("Test failed"),
        };
        #[cfg(feature = "abcipp")]
        assert_eq!(
            shell.verify_vote_extension(req).status,
            i32::from(VerifyStatus::Reject)
        );
        assert!(
            shell
                .validate_vexts_and_get_it_back(
                    vote_ext,
                    shell.storage.last_height + 1
                )
                .is_err()
        )
    }

    /// Test that validation of Ethereum events cast during the
    /// previous block are accepted for the current block. This
    /// should pass even if the epoch changed resulting in a
    /// change to the validator set.
    #[test]
    fn test_validate_vote_extensions() {
        let (mut shell, _recv, _) = setup();
        let signing_key =
            shell.mode.get_protocol_key().expect("Test failed").clone();
        let address = shell
            .mode
            .get_validator_address()
            .expect("Test failed")
            .clone();
        let signed_height = shell.storage.last_height + 1;
        let vote_ext = ethereum_events::Vext {
            ethereum_events: vec![EthereumEvent::TransfersToEthereum {
                nonce: 1.into(),
                transfers: vec![TransferToEthereum {
                    amount: 100.into(),
                    asset: EthAddress([1; 20]),
                    receiver: EthAddress([2; 20]),
                }],
            }],
            block_height: signed_height,
            validator_addr: address,
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
        req.header.time = namada::types::time::DateTimeUtc::now();
        shell.storage.last_height = BlockHeight(11);
        shell.finalize_block(req).expect("Test failed");
        shell.commit();
        assert_eq!(shell.storage.get_current_epoch().0.0, 1);
        assert!(
            shell
                .storage
                .get_validator_from_protocol_pk(&signing_key.ref_to(), None)
                .is_err()
        );
        let prev_epoch = Epoch(shell.storage.get_current_epoch().0.0 - 1);
        assert!(
            shell
                .shell
                .storage
                .get_validator_from_protocol_pk(
                    &signing_key.ref_to(),
                    Some(prev_epoch)
                )
                .is_ok()
        );

        assert!(
            shell
                .validate_vexts_and_get_it_back(vote_ext, signed_height)
                .is_ok()
        );
    }

    /// Test that an [`ethereum_events::Vext`] that incorrectly labels what
    /// block it was included on in a vote extension is rejected if the
    /// abci++ feature is enable. Otherwise accept.
    #[test]
    fn reject_incorrect_block_number() {
        let (mut shell, _, _) = setup();
        let address = shell.mode.get_validator_address().unwrap().clone();
        shell.storage.last_height = BlockHeight(3);
        let vote_ext = ethereum_events::Vext {
            ethereum_events: vec![EthereumEvent::TransfersToEthereum {
                nonce: 1.into(),
                transfers: vec![TransferToEthereum {
                    amount: 100.into(),
                    asset: EthAddress([1; 20]),
                    receiver: EthAddress([2; 20]),
                }],
            }],
            block_height: BlockHeight(1),
            #[cfg(feature = "abcipp")]
            validator_addr: address.clone(),
            #[cfg(not(feature = "abcipp"))]
            validator_addr: address,
        }
        .sign(shell.mode.get_protocol_key().expect("Test failed"));

        #[cfg(feature = "abcipp")]
        let req = request::VerifyVoteExtension {
            hash: vec![],
            validator_address: address.try_to_vec().expect("Test failed"),
            height: 0,
            vote_extension: vote_ext.try_to_vec().expect("Test failed"),
        };
        #[cfg(feature = "abcipp")]
        assert_eq!(
            shell.verify_vote_extension(req).status,
            i32::from(VerifyStatus::Reject)
        );
        assert!(
            shell
                .validate_vexts_and_get_it_back(
                    vote_ext,
                    shell.storage.last_height
                )
                .is_ok()
        )
    }

    /// Test that an [`ethereum_events::Vext`] arriving at
    /// genesis is rejected
    #[test]
    fn reject_at_genesis() {
        let (shell, _, _) = setup();
        let address = shell.mode.get_validator_address().unwrap().clone();
        let vote_ext = ethereum_events::Vext {
            ethereum_events: vec![EthereumEvent::TransfersToEthereum {
                nonce: 1.into(),
                transfers: vec![TransferToEthereum {
                    amount: 100.into(),
                    asset: EthAddress([1; 20]),
                    receiver: EthAddress([2; 20]),
                }],
            }],
            block_height: shell.storage.last_height,
            #[cfg(feature = "abcipp")]
            validator_addr: address.clone(),
            #[cfg(not(feature = "abcipp"))]
            validator_addr: address,
        }
        .sign(shell.mode.get_protocol_key().expect("Test failed"));

        #[cfg(feature = "abcipp")]
        let req = request::VerifyVoteExtension {
            hash: vec![],
            validator_address: address.try_to_vec().expect("Test failed"),
            height: 0,
            vote_extension: vote_ext.try_to_vec().expect("Test failed"),
        };
        #[cfg(feature = "abcipp")]
        assert_eq!(
            shell.verify_vote_extension(req).status,
            i32::from(VerifyStatus::Reject)
        );
        assert!(
            shell
                .validate_vexts_and_get_it_back(
                    vote_ext,
                    shell.storage.last_height
                )
                .is_err()
        )
    }
}
