//! Extend Tendermint votes with Ethereum events seen by a quorum of validators.

use namada::ledger::pos::namada_proof_of_stake::types::VotingPower;
use namada::ledger::storage::{DBIter, StorageHasher, DB};
use namada::proto::Signed;
use namada::types::ethereum_events::EthereumEvent;
use namada::types::storage::BlockHeight;
use namada::types::vote_extensions::ethereum_events;

use super::*;
use crate::node::ledger::shell::queries::QueriesExt;
use crate::node::ledger::shell::{Shell, ShellMode};

impl<D, H> Shell<D, H>
where
    D: DB + for<'iter> DBIter<'iter> + Sync + 'static,
    H: StorageHasher + Sync + 'static,
{
    /// Validates an Ethereum events vote extension issued at the provided
    /// block height
    ///
    /// Checks that at epoch of the provided height:
    ///  * The Tendermint address corresponds to an active validator
    ///  * The validator correctly signed the extension
    ///  * The validator signed over the correct height inside of the extension
    ///  * There are no duplicate Ethereum events in this vote extension, and
    ///    the events are sorted in ascending order
    #[inline]
    pub fn validate_eth_events_vext(
        &self,
        ext: Signed<ethereum_events::Vext>,
        last_height: BlockHeight,
    ) -> bool {
        self.validate_eth_events_vext_and_get_it_back(ext, last_height)
            .is_ok()
    }

    /// This method behaves exactly like [`Self::validate_eth_events_vext`],
    /// with the added bonus of returning the vote extension back, if it
    /// is valid.
    pub fn validate_eth_events_vext_and_get_it_back(
        &self,
        ext: Signed<ethereum_events::Vext>,
        last_height: BlockHeight,
    ) -> std::result::Result<
        (VotingPower, Signed<ethereum_events::Vext>),
        VoteExtensionError,
    > {
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
        let epoch = self.storage.block.pred_epochs.get_epoch(last_height);
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
    pub fn validate_vote_extension_list(
        &self,
        vote_extensions: impl IntoIterator<Item = Signed<ethereum_events::Vext>>
        + 'static,
    ) -> impl Iterator<
        Item = std::result::Result<
            (VotingPower, Signed<ethereum_events::Vext>),
            VoteExtensionError,
        >,
    > + '_ {
        vote_extensions.into_iter().map(|vote_extension| {
            self.validate_eth_events_vext_and_get_it_back(
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
    pub fn filter_invalid_vote_extensions(
        &self,
        vote_extensions: impl IntoIterator<Item = Signed<ethereum_events::Vext>>
        + 'static,
    ) -> impl Iterator<Item = (VotingPower, Signed<ethereum_events::Vext>)> + '_
    {
        self.validate_vote_extension_list(vote_extensions)
            .filter_map(|ext| ext.ok())
    }
}

#[cfg(test)]
mod test_vote_extensions {
    use std::convert::TryInto;

    use borsh::{BorshDeserialize, BorshSerialize};
    use namada::ledger::pos;
    use namada::ledger::pos::namada_proof_of_stake::PosBase;
    use namada::proto::Signed;
    use namada::types::ethereum_events::{
        EthAddress, EthereumEvent, TransferToEthereum,
    };
    use namada::types::key::*;
    use namada::types::storage::{BlockHeight, Epoch};
    use namada::types::vote_extensions::ethereum_events;
    use tendermint_proto::abci::response_verify_vote_extension::VerifyStatus;
    use tower_abci::request;

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
            validator_addr: address.clone(),
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

    /// Test that validation of Ethereum events cast during the
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

        assert!(shell.validate_eth_events_vext(vote_ext, signed_height));
    }

    /// Test that an [`ethereum_events::Vext`] that incorrectly labels what
    /// block it was included on in a vote extension is rejected
    #[test]
    fn reject_incorrect_block_number() {
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
            validator_addr: address.clone(),
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
