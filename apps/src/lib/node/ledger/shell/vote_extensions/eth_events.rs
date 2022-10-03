//! Extend Tendermint votes with Ethereum events seen by a quorum of validators.

use std::collections::{BTreeMap, HashMap, HashSet};

use namada::ledger::pos::namada_proof_of_stake::types::VotingPower;
use namada::ledger::storage::{DBIter, StorageHasher, DB};
use namada::proto::Signed;
use namada::types::ethereum_events::EthereumEvent;
use namada::types::storage::BlockHeight;
use namada::types::vote_extensions::ethereum_events::{
    self, MultiSignedEthEvent,
};
#[cfg(feature = "abcipp")]
use namada::types::voting_power::FractionalVotingPower;

use super::*;
use crate::node::ledger::shell::queries::QueriesExt;
use crate::node::ledger::shell::{Shell, ShellMode};

impl<D, H> Shell<D, H>
where
    D: DB + for<'iter> DBIter<'iter> + Sync + 'static,
    H: StorageHasher + Sync + 'static,
{
    /// Validates an Ethereum events vote extension issued at the provided
    /// block height.
    ///
    /// Checks that at epoch of the provided height:
    ///  * The Tendermint address corresponds to an active validator.
    ///  * The validator correctly signed the extension.
    ///  * The validator signed over the correct height inside of the extension.
    ///  * There are no duplicate Ethereum events in this vote extension, and
    ///    the events are sorted in ascending order.
    #[allow(dead_code)]
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
        #[cfg(feature = "abcipp")]
        if ext.data.block_height != last_height {
            tracing::error!(
                ext_height = ?ext.data.block_height,
                ?last_height,
                "Ethereum events vote extension issued for a block height \
                 different from the expected last height."
            );
            return Err(VoteExtensionError::UnexpectedBlockHeight);
        }
        #[cfg(not(feature = "abcipp"))]
        if ext.data.block_height > last_height {
            tracing::error!(
                ext_height = ?ext.data.block_height,
                ?last_height,
                "Ethereum events vote extension issued for a block height \
                 higher than the chain's last height."
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
                "Found duplicate or non-sorted Ethereum events in a vote extension from \
                 some validator"
            );
            return Err(VoteExtensionError::HaveDupesOrNonSorted);
        }
        // get the public key associated with this validator
        //
        // NOTE(not(feature = "abciplus")): for ABCI++, we should pass
        // `last_height` here, instead of `ext.data.block_height`
        let ext_height_epoch =
            match self.storage.get_epoch(ext.data.block_height) {
                Some(epoch) => epoch,
                _ => {
                    tracing::error!(
                        block_height = ?ext.data.block_height,
                        "The epoch of the Ethereum events vote extension's \
                         block height should always be known",
                    );
                    return Err(VoteExtensionError::UnexpectedEpoch);
                }
            };
        let (voting_power, pk) = self
            .storage
            .get_validator_from_address(validator, Some(ext_height_epoch))
            .map_err(|err| {
                tracing::error!(
                    ?err,
                    %validator,
                    "Could not get public key from Storage for some validator, \
                     while validating Ethereum events vote extension"
                );
                VoteExtensionError::PubKeyNotInStorage
            })?;
        // verify the signature of the vote extension
        ext.verify(&pk)
            .map_err(|err| {
                tracing::error!(
                    ?err,
                    %validator,
                    "Failed to verify the signature of an Ethereum events vote \
                     extension issued by some validator"
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

    /// Takes an iterator over Ethereum events vote extension instances,
    /// and returns another iterator. The latter yields
    /// valid Ethereum events vote extensions, or the reason why these
    /// are invalid, in the form of a [`VoteExtensionError`].
    #[inline]
    pub fn validate_eth_events_vext_list<'iter>(
        &'iter self,
        vote_extensions: impl IntoIterator<Item = Signed<ethereum_events::Vext>>
        + 'iter,
    ) -> impl Iterator<
        Item = std::result::Result<
            (VotingPower, Signed<ethereum_events::Vext>),
            VoteExtensionError,
        >,
    > + 'iter {
        vote_extensions.into_iter().map(|vote_extension| {
            self.validate_eth_events_vext_and_get_it_back(
                vote_extension,
                self.storage.last_height,
            )
        })
    }

    /// Takes a list of signed Ethereum events vote extensions,
    /// and filters out invalid instances.
    #[inline]
    pub fn filter_invalid_eth_events_vexts<'iter>(
        &'iter self,
        vote_extensions: impl IntoIterator<Item = Signed<ethereum_events::Vext>>
        + 'iter,
    ) -> impl Iterator<Item = (VotingPower, Signed<ethereum_events::Vext>)> + 'iter
    {
        self.validate_eth_events_vext_list(vote_extensions)
            .filter_map(|ext| ext.ok())
    }

    /// Compresses a set of signed Ethereum events into a single
    /// [`ethereum_events::VextDigest`], whilst filtering invalid
    /// [`Signed<ethereum_events::Vext>`] instances in the process.
    pub fn compress_ethereum_events(
        &self,
        vote_extensions: Vec<Signed<ethereum_events::Vext>>,
    ) -> Option<ethereum_events::VextDigest> {
        #[cfg(not(feature = "abcipp"))]
        if self.storage.last_height == BlockHeight(0) {
            return None;
        }

        #[cfg(feature = "abcipp")]
        let vexts_epoch =
            self.storage.get_epoch(self.storage.last_height).expect(
                "The epoch of the last block height should always be known",
            );

        #[cfg(feature = "abcipp")]
        let total_voting_power =
            u64::from(self.storage.get_total_voting_power(Some(vexts_epoch)));
        #[cfg(feature = "abcipp")]
        let mut voting_power = FractionalVotingPower::default();

        let mut event_observers = BTreeMap::new();
        let mut signatures = HashMap::new();

        for (_validator_voting_power, vote_extension) in
            self.filter_invalid_eth_events_vexts(vote_extensions)
        {
            let validator_addr = vote_extension.data.validator_addr;
            #[cfg(not(feature = "abcipp"))]
            let block_height = vote_extension.data.block_height;

            // update voting power
            #[cfg(feature = "abcipp")]
            {
                let validator_voting_power = u64::from(_validator_voting_power);
                voting_power += FractionalVotingPower::new(
                    validator_voting_power,
                    total_voting_power,
                )
                .expect(
                    "The voting power we obtain from storage should always be \
                     valid",
                );
            }

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

        Some(ethereum_events::VextDigest { events, signatures })
    }
}

#[cfg(test)]
mod test_vote_extensions {
    use std::convert::TryInto;

    #[cfg(feature = "abcipp")]
    use borsh::{BorshDeserialize, BorshSerialize};
    use namada::ledger::pos;
    use namada::ledger::pos::namada_proof_of_stake::PosBase;
    use namada::types::ethereum_events::{
        EthAddress, EthereumEvent, TransferToEthereum,
    };
    use namada::types::key::*;
    use namada::types::storage::{BlockHeight, Epoch};
    use namada::types::vote_extensions::ethereum_events;
    #[cfg(feature = "abcipp")]
    use namada::types::vote_extensions::VoteExtension;

    #[cfg(feature = "abcipp")]
    use crate::facade::tendermint_proto::abci::response_verify_vote_extension::VerifyStatus;
    #[cfg(feature = "abcipp")]
    use crate::facade::tower_abci::request;
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
            <VoteExtension as BorshDeserialize>::try_from_slice(
                &shell.extend_vote(Default::default()).vote_extension[..],
            )
            .expect("Test failed");

        let [event_first, event_second]: [EthereumEvent; 2] = vote_extension
            .ethereum_events
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
        let (shell, _, _) = setup_at_height(3u64);
        let signing_key = gen_keypair();
        let address = shell
            .mode
            .get_validator_address()
            .expect("Test failed")
            .clone();
        #[allow(clippy::redundant_clone)]
        let ethereum_events = ethereum_events::Vext {
            ethereum_events: vec![EthereumEvent::TransfersToEthereum {
                nonce: 1.into(),
                transfers: vec![TransferToEthereum {
                    amount: 100.into(),
                    asset: EthAddress([1; 20]),
                    receiver: EthAddress([2; 20]),
                }],
            }],
            block_height: shell.storage.get_current_decision_height(),
            validator_addr: address.clone(),
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
            height: 0,
            vote_extension: VoteExtension {
                ethereum_events: ethereum_events.clone(),
                validator_set_update: None,
            }
            .try_to_vec()
            .expect("Test failed"),
        };
        #[cfg(feature = "abcipp")]
        assert_eq!(
            shell.verify_vote_extension(req).status,
            i32::from(VerifyStatus::Reject)
        );
        assert!(!shell.validate_eth_events_vext(
            ethereum_events,
            shell.storage.get_current_decision_height(),
        ))
    }

    /// Test that validation of Ethereum events cast during the
    /// previous block are accepted for the current block. This
    /// should pass even if the epoch changed resulting in a
    /// change to the validator set.
    #[test]
    fn test_validate_eth_events_vexts() {
        let (mut shell, _recv, _) = setup_at_height(3u64);
        let signing_key =
            shell.mode.get_protocol_key().expect("Test failed").clone();
        let address = shell
            .mode
            .get_validator_address()
            .expect("Test failed")
            .clone();
        let signed_height = shell.storage.get_current_decision_height();
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
        let (shell, _, _) = setup_at_height(3u64);
        let address = shell.mode.get_validator_address().unwrap().clone();
        #[allow(clippy::redundant_clone)]
        let ethereum_events = ethereum_events::Vext {
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
        .sign(shell.mode.get_protocol_key().expect("Test failed"));

        #[cfg(feature = "abcipp")]
        {
            let req = request::VerifyVoteExtension {
                hash: vec![],
                validator_address: address.try_to_vec().expect("Test failed"),
                height: 0,
                vote_extension: VoteExtension {
                    ethereum_events: ethereum_events.clone(),
                    validator_set_update: None,
                }
                .try_to_vec()
                .expect("Test failed"),
            };

            assert_eq!(
                shell.verify_vote_extension(req).status,
                i32::from(VerifyStatus::Reject)
            );
        }
        assert!(shell.validate_eth_events_vext(
            ethereum_events,
            shell.storage.last_height
        ))
    }

    /// Test if we reject Ethereum events vote extensions
    /// issued at genesis
    #[test]
    fn test_reject_genesis_vexts() {
        let (shell, _, _) = setup();
        let address = shell.mode.get_validator_address().unwrap().clone();
        #[allow(clippy::redundant_clone)]
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
            !shell
                .validate_eth_events_vext(vote_ext, shell.storage.last_height)
        )
    }
}
