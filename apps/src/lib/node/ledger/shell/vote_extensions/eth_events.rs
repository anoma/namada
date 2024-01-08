//! Extend Tendermint votes with Ethereum events seen by a quorum of validators.

use std::collections::{BTreeMap, HashMap};

use namada::ledger::pos::PosQueries;
use namada::state::{DBIter, StorageHasher, DB};
use namada::tx::Signed;
use namada::types::ethereum_events::EthereumEvent;
use namada::types::storage::BlockHeight;
use namada::types::token;
use namada::vote_ext::ethereum_events::{self, MultiSignedEthEvent};
use namada_sdk::eth_bridge::EthBridgeQueries;

use super::*;
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
    ///  * The inner Namada address corresponds to a consensus validator.
    ///  * The validator correctly signed the extension.
    ///  * The validator signed over the correct height inside of the extension.
    ///  * There are no duplicate Ethereum events in this vote extension, and
    ///    the events are sorted in ascending order.
    #[inline]
    #[allow(dead_code)]
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
        (token::Amount, Signed<ethereum_events::Vext>),
        VoteExtensionError,
    > {
        // NOTE: for ABCI++, we should pass
        // `last_height` here, instead of `ext.data.block_height`
        let ext_height_epoch = match self
            .wl_storage
            .pos_queries()
            .get_epoch(ext.data.block_height)
        {
            Some(epoch) => epoch,
            _ => {
                tracing::debug!(
                    block_height = ?ext.data.block_height,
                    "The epoch of the Ethereum events vote extension's \
                     block height should always be known",
                );
                return Err(VoteExtensionError::UnexpectedEpoch);
            }
        };
        if !self
            .wl_storage
            .ethbridge_queries()
            .is_bridge_active_at(ext_height_epoch)
        {
            tracing::debug!(
                vext_epoch = ?ext_height_epoch,
                "The Ethereum bridge was not enabled when the Ethereum
                 events' vote extension was cast",
            );
            return Err(VoteExtensionError::EthereumBridgeInactive);
        }
        if ext.data.block_height > last_height {
            tracing::debug!(
                ext_height = ?ext.data.block_height,
                ?last_height,
                "Ethereum events vote extension issued for a block height \
                 higher than the chain's last height."
            );
            return Err(VoteExtensionError::UnexpectedBlockHeight);
        }
        if ext.data.block_height.0 == 0 {
            tracing::debug!("Dropping vote extension issued at genesis");
            return Err(VoteExtensionError::UnexpectedBlockHeight);
        }
        self.validate_eth_events(&ext.data)?;
        // get the public key associated with this validator
        let validator = &ext.data.validator_addr;
        let (voting_power, pk) = self
            .wl_storage
            .pos_queries()
            .get_validator_from_address(validator, Some(ext_height_epoch))
            .map_err(|err| {
                tracing::debug!(
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
                tracing::debug!(
                    ?err,
                    ?ext.sig,
                    ?pk,
                    %validator,
                    "Failed to verify the signature of an Ethereum events vote \
                     extension issued by some validator"
                );
                VoteExtensionError::VerifySigFailed
            })
            .map(|_| (voting_power, ext))
    }

    /// Validate a batch of Ethereum events contained in
    /// an [`ethereum_events::Vext`].
    ///
    /// The supplied Ethereum events must be ordered in
    /// ascending ordering, must not contain any dupes
    /// and must have valid nonces.
    fn validate_eth_events(
        &self,
        ext: &ethereum_events::Vext,
    ) -> std::result::Result<(), VoteExtensionError> {
        // verify if we have any duplicate Ethereum events,
        // and if these are sorted in ascending order
        let have_dupes_or_non_sorted = {
            !ext.ethereum_events
                // TODO: move to `array_windows` when it reaches Rust stable
                .windows(2)
                .all(|evs| evs[0] < evs[1])
        };
        let validator = &ext.validator_addr;
        if have_dupes_or_non_sorted {
            tracing::debug!(
                %validator,
                "Found duplicate or non-sorted Ethereum events in a vote extension from \
                 some validator"
            );
            return Err(VoteExtensionError::HaveDupesOrNonSorted);
        }
        // for the proposal to be valid, at least one of the
        // event's nonces must be valid
        if ext.ethereum_events.iter().any(|event| {
            self.wl_storage
                .ethbridge_queries()
                .validate_eth_event_nonce(event)
        }) {
            Ok(())
        } else {
            Err(VoteExtensionError::InvalidEthEventNonce)
        }
    }

    /// Checks the channel from the Ethereum oracle monitoring
    /// the fullnode and retrieves all seen Ethereum events.
    pub fn new_ethereum_events(&mut self) -> Vec<EthereumEvent> {
        let queries = self.wl_storage.ethbridge_queries();
        match &mut self.mode {
            ShellMode::Validator {
                eth_oracle:
                    Some(EthereumOracleChannels {
                        ethereum_receiver, ..
                    }),
                ..
            } => {
                ethereum_receiver.fill_queue(|event| {
                    queries.validate_eth_event_nonce(event)
                });
                ethereum_receiver.get_events()
            }
            _ => vec![],
        }
    }

    /// Takes an iterator over Ethereum events vote extension instances,
    /// and returns another iterator. The latter yields
    /// valid Ethereum events vote extensions, or the reason why these
    /// are invalid, in the form of a `VoteExtensionError`.
    #[inline]
    pub fn validate_eth_events_vext_list<'iter>(
        &'iter self,
        vote_extensions: impl IntoIterator<Item = Signed<ethereum_events::Vext>>
        + 'iter,
    ) -> impl Iterator<
        Item = std::result::Result<
            (token::Amount, Signed<ethereum_events::Vext>),
            VoteExtensionError,
        >,
    > + 'iter {
        vote_extensions.into_iter().map(|vote_extension| {
            self.validate_eth_events_vext_and_get_it_back(
                vote_extension,
                self.wl_storage.storage.get_last_block_height(),
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
    ) -> impl Iterator<Item = (token::Amount, Signed<ethereum_events::Vext>)> + 'iter
    {
        self.validate_eth_events_vext_list(vote_extensions)
            .filter_map(|ext| ext.ok())
    }

    /// Compresses a set of signed Ethereum events into a single
    /// [`ethereum_events::VextDigest`], whilst filtering invalid
    /// [`Signed<ethereum_events::Vext>`] instances in the process.
    ///
    /// When vote extensions are being used, this performs a check
    /// that at least 2/3 of the validators by voting power have
    /// included ethereum events in their vote extension.
    pub fn compress_ethereum_events(
        &self,
        vote_extensions: Vec<Signed<ethereum_events::Vext>>,
    ) -> Option<ethereum_events::VextDigest> {
        #[allow(clippy::question_mark)]
        if self.wl_storage.storage.last_block.is_none() {
            return None;
        }

        let mut event_observers = BTreeMap::new();
        let mut signatures = HashMap::new();

        for (_validator_voting_power, vote_extension) in
            self.filter_invalid_eth_events_vexts(vote_extensions)
        {
            let validator_addr = vote_extension.data.validator_addr;
            let block_height = vote_extension.data.block_height;

            // register all ethereum events seen by `validator_addr`
            for ev in vote_extension.data.ethereum_events {
                let signers =
                    event_observers.entry(ev).or_insert_with(BTreeSet::new);
                signers.insert((validator_addr.clone(), block_height));
            }

            // register the signature of `validator_addr`
            let addr = validator_addr.clone();
            let sig = vote_extension.sig;

            let key = (addr, block_height);
            tracing::debug!(
                ?key,
                ?sig,
                ?validator_addr,
                "Inserting signature into ethereum_events::VextDigest"
            );
            if let Some(existing_sig) = signatures.insert(key, sig.clone()) {
                tracing::warn!(
                    ?sig,
                    ?existing_sig,
                    ?validator_addr,
                    "Overwrote old signature from validator while \
                     constructing ethereum_events::VextDigest - maybe private \
                     key of validator is being used by multiple nodes?"
                );
            }
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

    use borsh_ext::BorshSerializeExt;
    use namada::eth_bridge::storage::bridge_pool;
    use namada::ledger::eth_bridge::EthBridgeQueries;
    use namada::ledger::pos::PosQueries;
    use namada::proof_of_stake::storage::{
        consensus_validator_set_handle,
        read_consensus_validator_set_addresses_with_stake,
    };
    use namada::proof_of_stake::types::WeightedValidator;
    use namada::state::collections::lazy_map::{NestedSubKey, SubKey};
    use namada::tendermint::abci::types::VoteInfo;
    use namada::types::address::testing::gen_established_address;
    use namada::types::ethereum_events::{
        EthAddress, EthereumEvent, TransferToEthereum, Uint,
    };
    use namada::types::hash::Hash;
    use namada::types::key::*;
    use namada::types::storage::{Epoch, InnerEthEventsQueue};
    use namada::vote_ext::ethereum_events;

    use crate::node::ledger::shell::test_utils::*;
    use crate::node::ledger::shims::abcipp_shim_types::shim::request::FinalizeBlock;

    /// Test validating Ethereum events.
    #[test]
    fn test_eth_event_validate() {
        let (mut shell, _, _, _) = setup();
        let nonce: Uint = 10u64.into();

        // write bp nonce to storage
        shell
            .wl_storage
            .storage
            .write(&bridge_pool::get_nonce_key(), nonce.serialize_to_vec())
            .expect("Test failed");

        // write nam nonce to the eth events queue
        shell
            .wl_storage
            .storage
            .eth_events_queue
            .transfers_to_namada = InnerEthEventsQueue::new_at(nonce);

        // eth transfers with the same nonce as the bp nonce in storage are
        // valid
        shell
            .wl_storage
            .ethbridge_queries()
            .validate_eth_event_nonce(&EthereumEvent::TransfersToEthereum {
                nonce,
                transfers: vec![],
                relayer: gen_established_address(),
            })
            .then_some(())
            .ok_or(())
            .expect("Test failed");

        // eth transfers with different nonces are invalid
        shell
            .wl_storage
            .ethbridge_queries()
            .validate_eth_event_nonce(&EthereumEvent::TransfersToEthereum {
                nonce: nonce + 1,
                transfers: vec![],
                relayer: gen_established_address(),
            })
            .then_some(())
            .ok_or(())
            .expect_err("Test failed");
        shell
            .wl_storage
            .ethbridge_queries()
            .validate_eth_event_nonce(&EthereumEvent::TransfersToEthereum {
                nonce: nonce - 1,
                transfers: vec![],
                relayer: gen_established_address(),
            })
            .then_some(())
            .ok_or(())
            .expect_err("Test failed");

        // nam transfers with nonces >= the nonce in storage are valid
        shell
            .wl_storage
            .ethbridge_queries()
            .validate_eth_event_nonce(&EthereumEvent::TransfersToNamada {
                nonce,
                transfers: vec![],
            })
            .then_some(())
            .ok_or(())
            .expect("Test failed");
        shell
            .wl_storage
            .ethbridge_queries()
            .validate_eth_event_nonce(&EthereumEvent::TransfersToNamada {
                nonce: nonce + 5,
                transfers: vec![],
            })
            .then_some(())
            .ok_or(())
            .expect("Test failed");

        // nam transfers with lower nonces are invalid
        shell
            .wl_storage
            .ethbridge_queries()
            .validate_eth_event_nonce(&EthereumEvent::TransfersToNamada {
                nonce: nonce - 1,
                transfers: vec![],
            })
            .then_some(())
            .ok_or(())
            .expect_err("Test failed");
        shell
            .wl_storage
            .ethbridge_queries()
            .validate_eth_event_nonce(&EthereumEvent::TransfersToNamada {
                nonce: nonce - 2,
                transfers: vec![],
            })
            .then_some(())
            .ok_or(())
            .expect_err("Test failed");
    }

    /// Test that we successfully receive ethereum events
    /// from the channel to fullnode process
    ///
    /// We further check that ledger side buffering is done if multiple
    /// events are in the channel and that queueing and de-duplicating is
    /// done
    #[test]
    fn test_get_eth_events() {
        let (mut shell, _, oracle, _) = setup();
        let event_1 = EthereumEvent::TransfersToEthereum {
            nonce: 0.into(),
            transfers: vec![TransferToEthereum {
                amount: 100.into(),
                asset: EthAddress([1; 20]),
                receiver: EthAddress([2; 20]),
                checksum: Hash::default(),
            }],
            relayer: gen_established_address(),
        };
        let event_2 = EthereumEvent::TransfersToEthereum {
            nonce: 1.into(),
            transfers: vec![TransferToEthereum {
                amount: 100.into(),
                asset: EthAddress([1; 20]),
                receiver: EthAddress([2; 20]),
                checksum: Hash::default(),
            }],
            relayer: gen_established_address(),
        };
        let event_3 = EthereumEvent::TransfersToNamada {
            nonce: 0.into(),
            transfers: vec![],
        };
        let event_4 = EthereumEvent::TransfersToNamada {
            nonce: 1.into(),
            transfers: vec![],
        };

        // send valid events
        tokio_test::block_on(oracle.send(event_1.clone()))
            .expect("Test failed");
        tokio_test::block_on(oracle.send(event_3.clone()))
            .expect("Test failed");

        let got_events: [EthereumEvent; 2] =
            shell.new_ethereum_events().try_into().expect("Test failed");
        let expected_events: Vec<_> = std::collections::BTreeSet::from([
            event_1.clone(),
            event_3.clone(),
        ])
        .into_iter()
        .collect();
        assert_eq!(expected_events, got_events);

        // we cannot get two transfer to ethereum events within
        // the same block height on ethereum. this is because we
        // require a confirmation eth event on namada to increment
        // the bridge pool nonce. this event should get ignored
        tokio_test::block_on(oracle.send(event_2)).expect("Test failed");

        // check that we queue and de-duplicate events
        tokio_test::block_on(oracle.send(event_3.clone()))
            .expect("Test failed");
        tokio_test::block_on(oracle.send(event_4.clone()))
            .expect("Test failed");

        let got_events: [EthereumEvent; 3] =
            shell.new_ethereum_events().try_into().expect("Test failed");
        let expected_events: Vec<_> =
            std::collections::BTreeSet::from([event_1, event_3, event_4])
                .into_iter()
                .collect();
        assert_eq!(expected_events, got_events);
    }

    /// Test that Ethereum events signed by a non-validator are rejected
    #[test]
    fn test_eth_events_must_be_signed_by_validator() {
        let (shell, _, _, _) = setup_at_height(3u64);
        let signing_key = gen_keypair();
        let address = shell
            .mode
            .get_validator_address()
            .expect("Test failed")
            .clone();
        #[allow(clippy::redundant_clone)]
        let ethereum_events = ethereum_events::Vext {
            ethereum_events: vec![EthereumEvent::TransfersToEthereum {
                nonce: 0.into(),
                transfers: vec![TransferToEthereum {
                    amount: 100.into(),
                    asset: EthAddress([1; 20]),
                    receiver: EthAddress([2; 20]),
                    checksum: Hash::default(),
                }],
                relayer: gen_established_address(),
            }],
            block_height: shell
                .wl_storage
                .pos_queries()
                .get_current_decision_height(),
            validator_addr: address.clone(),
        }
        .sign(&signing_key);
        assert!(!shell.validate_eth_events_vext(
            ethereum_events,
            shell.wl_storage.pos_queries().get_current_decision_height(),
        ))
    }

    /// Test that validation of Ethereum events cast during the
    /// previous block are accepted for the current block. This
    /// should pass even if the epoch changed resulting in a
    /// change to the validator set.
    #[test]
    fn test_validate_eth_events_vexts() {
        let (mut shell, _recv, _, _oracle_control_recv) = setup_at_height(3u64);
        let signing_key =
            shell.mode.get_protocol_key().expect("Test failed").clone();
        let address = shell
            .mode
            .get_validator_address()
            .expect("Test failed")
            .clone();
        let signed_height =
            shell.wl_storage.pos_queries().get_current_decision_height();
        let vote_ext = ethereum_events::Vext {
            ethereum_events: vec![EthereumEvent::TransfersToEthereum {
                nonce: 0.into(),
                transfers: vec![TransferToEthereum {
                    amount: 100.into(),
                    asset: EthAddress([1; 20]),
                    receiver: EthAddress([2; 20]),
                    checksum: Hash::default(),
                }],
                relayer: gen_established_address(),
            }],
            block_height: signed_height,
            validator_addr: address,
        }
        .sign(shell.mode.get_protocol_key().expect("Test failed"));

        assert_eq!(shell.wl_storage.storage.get_current_epoch().0.0, 0);
        // remove all validators of the next epoch
        let validators_handle = consensus_validator_set_handle().at(&1.into());
        let consensus_in_mem = validators_handle
            .iter(&shell.wl_storage)
            .expect("Test failed")
            .map(|val| {
                let (
                    NestedSubKey::Data {
                        key: stake,
                        nested_sub_key: SubKey::Data(position),
                    },
                    ..,
                ) = val.expect("Test failed");
                (stake, position)
            })
            .collect::<Vec<_>>();
        for (val_stake, val_position) in consensus_in_mem.into_iter() {
            validators_handle
                .at(&val_stake)
                .remove(&mut shell.wl_storage, &val_position)
                .expect("Test failed");
        }
        // we advance forward to the next epoch
        let consensus_set: Vec<WeightedValidator> =
            read_consensus_validator_set_addresses_with_stake(
                &shell.wl_storage,
                Epoch::default(),
            )
            .unwrap()
            .into_iter()
            .collect();

        let params = shell.wl_storage.pos_queries().get_pos_params();
        let val1 = consensus_set[0].clone();
        let pkh1 = get_pkh_from_address(
            &shell.wl_storage,
            &params,
            val1.address.clone(),
            Epoch::default(),
        );
        let votes = vec![VoteInfo {
            validator: crate::facade::tendermint::abci::types::Validator {
                address: pkh1,
                power: (u128::try_from(val1.bonded_stake).expect("Test failed") as u64).try_into().unwrap(),
            },
            sig_info: crate::facade::tendermint::abci::types::BlockSignatureInfo::LegacySigned,
        }];
        let req = FinalizeBlock {
            proposer_address: pkh1.to_vec(),
            votes,
            ..Default::default()
        };
        assert_eq!(shell.start_new_epoch(Some(req)).0, 1);
        assert!(
            shell
                .wl_storage
                .pos_queries()
                .get_validator_from_protocol_pk(&signing_key.ref_to(), None)
                .is_err()
        );
        let prev_epoch =
            Epoch(shell.wl_storage.storage.get_current_epoch().0.0 - 1);
        assert!(
            shell
                .shell
                .wl_storage
                .pos_queries()
                .get_validator_from_protocol_pk(
                    &signing_key.ref_to(),
                    Some(prev_epoch)
                )
                .is_ok()
        );

        assert!(shell.validate_eth_events_vext(vote_ext, signed_height));
    }

    /// Test for ABCI++ that an [`ethereum_events::Vext`] that incorrectly
    /// labels what block it was included on in a vote extension is
    /// rejected. For ABCI+, test that it is rejected if the block height is
    /// greater than latest block height.
    #[test]
    fn reject_incorrect_block_number() {
        let (shell, _, _, _) = setup_at_height(3u64);
        let address = shell.mode.get_validator_address().unwrap().clone();
        #[allow(clippy::redundant_clone)]
        let mut ethereum_events = ethereum_events::Vext {
            ethereum_events: vec![EthereumEvent::TransfersToEthereum {
                nonce: 0.into(),
                transfers: vec![TransferToEthereum {
                    amount: 100.into(),
                    asset: EthAddress([1; 20]),
                    receiver: EthAddress([2; 20]),
                    checksum: Hash::default(),
                }],
                relayer: gen_established_address(),
            }],
            block_height: shell.wl_storage.storage.get_last_block_height(),
            validator_addr: address.clone(),
        };

        ethereum_events.block_height =
            shell.wl_storage.storage.get_last_block_height() + 1;
        let signed_vext = ethereum_events
            .sign(shell.mode.get_protocol_key().expect("Test failed"));
        assert!(!shell.validate_eth_events_vext(
            signed_vext,
            shell.wl_storage.storage.get_last_block_height()
        ))
    }

    /// Test if we reject Ethereum events vote extensions
    /// issued at genesis
    #[test]
    fn test_reject_genesis_vexts() {
        let (shell, _, _, _) = setup();
        let address = shell.mode.get_validator_address().unwrap().clone();
        #[allow(clippy::redundant_clone)]
        let vote_ext = ethereum_events::Vext {
            ethereum_events: vec![EthereumEvent::TransfersToEthereum {
                nonce: 0.into(),
                transfers: vec![TransferToEthereum {
                    amount: 100.into(),
                    asset: EthAddress([1; 20]),
                    receiver: EthAddress([2; 20]),
                    checksum: Hash::default(),
                }],
                relayer: gen_established_address(),
            }],
            block_height: shell.wl_storage.storage.get_last_block_height(),
            validator_addr: address.clone(),
        }
        .sign(shell.mode.get_protocol_key().expect("Test failed"));

        assert!(!shell.validate_eth_events_vext(
            vote_ext,
            shell.wl_storage.storage.get_last_block_height()
        ))
    }
}
