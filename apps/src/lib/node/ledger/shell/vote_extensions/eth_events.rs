//! Extend Tendermint votes with Ethereum events seen by a quorum of validators.

use std::collections::{BTreeMap, HashMap};

use namada::ledger::eth_bridge::EthBridgeQueries;
use namada::ledger::pos::PosQueries;
use namada::ledger::storage::traits::StorageHasher;
use namada::ledger::storage::{DBIter, DB};
use namada::proto::Signed;
use namada::types::ethereum_events::EthereumEvent;
use namada::types::storage::BlockHeight;
use namada::types::token;
use namada::types::vote_extensions::ethereum_events::{
    self, MultiSignedEthEvent,
};
#[cfg(feature = "abcipp")]
use namada::types::voting_power::FractionalVotingPower;

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
        // NOTE(not(feature = "abciplus")): for ABCI++, we should pass
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
        #[cfg(feature = "abcipp")]
        if ext.data.block_height != last_height {
            tracing::debug!(
                ext_height = ?ext.data.block_height,
                ?last_height,
                "Ethereum events vote extension issued for a block height \
                 different from the expected last height."
            );
            return Err(VoteExtensionError::UnexpectedBlockHeight);
        }
        #[cfg(not(feature = "abcipp"))]
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
    /// ascending ordering, and must not contain any dupes.
    ///
    /// A detailed description of the validation applied
    /// to each event kind can be found in the docstring
    /// of [`Shell::validate_eth_event`].
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
        ext.ethereum_events
            .iter()
            .try_for_each(|event| self.validate_eth_event(event))
    }

    /// Valdidate an [`EthereumEvent`] against the current state
    /// of the ledger.
    ///
    /// # Event kinds
    ///
    /// In this section, we shall describe the checks perform for
    /// each kind of relevant Ethereum event.
    ///
    /// ## Transfers to Ethereum
    ///
    /// We need to check if the nonce in the event corresponds to
    /// the most recent bridge pool nonce. Unless the nonces match,
    /// no state updates derived from the event should be applied.
    /// In case the nonces are different, we reject the event, and
    /// thus the inclusion of its container Ethereum events vote
    /// extension.
    ///
    /// Additionally, the length of the transfers array and their
    /// respective validity map must match, for the event to be
    /// considered valid.
    ///
    /// ## Transfers to Namada
    ///
    /// For a transfers to Namada event to be considered valid,
    /// the nonce of this kind of event must not be lower than
    /// the one stored in Namada.
    ///
    /// In this case, the length of the transfers array and their
    /// respective validity map must also match.
    ///
    /// ## Whitelist updates
    ///
    /// For any of these events to be considered valid, the
    /// whitelist update nonce in storage must be greater
    /// than or equal to the nonce in the event.
    fn validate_eth_event(
        &self,
        event: &EthereumEvent,
    ) -> std::result::Result<(), VoteExtensionError> {
        // TODO: on the transfer events, maybe perform additional checks:
        // - some token asset is not whitelisted
        // - do we have enough balance for the transfer
        // in practice, some events may have a variable degree of garbage
        // data in them; we can simply rely on quorum decisions to filter
        // out such events, which will time out in storage
        match event {
            EthereumEvent::TransfersToEthereum {
                nonce: ext_nonce,
                transfers,
                valid_transfers_map,
                ..
            } => {
                if transfers.len() != valid_transfers_map.len() {
                    tracing::debug!(
                        transfers_len = transfers.len(),
                        valid_transfers_map_len = valid_transfers_map.len(),
                        "{}",
                        VoteExtensionError::TransfersLenMismatch
                    );
                    return Err(VoteExtensionError::TransfersLenMismatch);
                }
                let current_bp_nonce =
                    self.wl_storage.ethbridge_queries().get_bridge_pool_nonce();
                if &current_bp_nonce != ext_nonce {
                    tracing::debug!(
                        %current_bp_nonce,
                        %ext_nonce,
                        "The Ethereum events vote extension's BP nonce is \
                         invalid"
                    );
                    return Err(VoteExtensionError::InvalidBpNonce);
                }
            }
            EthereumEvent::TransfersToNamada {
                nonce: ext_nonce,
                transfers,
                valid_transfers_map,
                ..
            } => {
                if transfers.len() != valid_transfers_map.len() {
                    tracing::debug!(
                        transfers_len = transfers.len(),
                        valid_transfers_map_len = valid_transfers_map.len(),
                        "{}",
                        VoteExtensionError::TransfersLenMismatch
                    );
                    return Err(VoteExtensionError::TransfersLenMismatch);
                }
                let next_nam_transfers_nonce = self
                    .wl_storage
                    .ethbridge_queries()
                    .get_next_nam_transfers_nonce();
                if &next_nam_transfers_nonce > ext_nonce {
                    tracing::debug!(
                        ?event,
                        %next_nam_transfers_nonce,
                        "Attempt to replay a transfer to Namada event"
                    );
                    return Err(VoteExtensionError::InvalidNamNonce);
                }
            }
            EthereumEvent::UpdateBridgeWhitelist { .. } => {
                // TODO: check nonce of whitelist update;
                // for this, we need to store the nonce of
                // whitelist updates somewhere
            }
            // consider other ethereum event kinds valid
            _ => {}
        }
        Ok(())
    }

    /// Checks the channel from the Ethereum oracle monitoring
    /// the fullnode and retrieves all seen Ethereum events.
    pub fn new_ethereum_events(&mut self) -> Vec<EthereumEvent> {
        match &mut self.mode {
            ShellMode::Validator {
                eth_oracle:
                    Some(EthereumOracleChannels {
                        ethereum_receiver, ..
                    }),
                ..
            } => {
                ethereum_receiver.fill_queue();
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
        #[cfg(not(feature = "abcipp"))]
        #[allow(clippy::question_mark)]
        if self.wl_storage.storage.last_block.is_none() {
            return None;
        }

        #[cfg(feature = "abcipp")]
        let vexts_epoch = self
            .wl_storage
            .pos_queries()
            .get_epoch(self.wl_storage.storage.get_last_block_height())
            .expect(
                "The epoch of the last block height should always be known",
            );

        #[cfg(feature = "abcipp")]
        let total_voting_power = u64::from(
            self.wl_storage
                .pos_queries()
                .get_total_voting_power(Some(vexts_epoch)),
        );
        #[cfg(feature = "abcipp")]
        let mut voting_power = FractionalVotingPower::default();

        let mut event_observers = BTreeMap::new();
        let mut signatures = HashMap::new();

        for (_validator_voting_power, vote_extension) in
            self.filter_invalid_eth_events_vexts(vote_extensions)
        {
            let validator_addr = vote_extension.data.validator_addr;
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
    use borsh::BorshDeserialize;
    use borsh::BorshSerialize;
    use namada::core::ledger::storage_api::collections::lazy_map::{
        NestedSubKey, SubKey,
    };
    use namada::eth_bridge::storage::bridge_pool;
    use namada::ledger::pos::PosQueries;
    use namada::proof_of_stake::consensus_validator_set_handle;
    #[cfg(feature = "abcipp")]
    use namada::proto::{SignableEthMessage, Signed};
    use namada::types::address::testing::gen_established_address;
    #[cfg(feature = "abcipp")]
    use namada::types::eth_abi::Encode;
    use namada::types::ethereum_events::{
        EthAddress, EthereumEvent, TransferToEthereum, TransferToEthereumKind,
        Uint,
    };
    #[cfg(feature = "abcipp")]
    use namada::types::keccak::keccak_hash;
    #[cfg(feature = "abcipp")]
    use namada::types::keccak::KeccakHash;
    use namada::types::key::*;
    use namada::types::storage::{Epoch, InnerEthEventsQueue};
    #[cfg(feature = "abcipp")]
    use namada::types::vote_extensions::bridge_pool_roots;
    use namada::types::vote_extensions::ethereum_events;
    #[cfg(feature = "abcipp")]
    use namada::types::vote_extensions::VoteExtension;

    #[cfg(feature = "abcipp")]
    use crate::facade::tendermint_proto::abci::response_verify_vote_extension::VerifyStatus;
    #[cfg(feature = "abcipp")]
    use crate::facade::tower_abci::request;
    use crate::node::ledger::shell::test_utils::*;

    /// Test validating Ethereum events.
    #[test]
    fn test_eth_event_validate() {
        let (mut shell, _, _, _) = setup();
        let nonce: Uint = 10u64.into();

        // write bp nonce to storage
        shell
            .wl_storage
            .storage
            .write(&bridge_pool::get_nonce_key(), nonce.try_to_vec().unwrap())
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
            .validate_eth_event(&EthereumEvent::TransfersToEthereum {
                nonce,
                transfers: vec![],
                valid_transfers_map: vec![],
                relayer: gen_established_address(),
            })
            .expect("Test failed");

        // eth transfers with different nonces are invalid
        shell
            .validate_eth_event(&EthereumEvent::TransfersToEthereum {
                nonce: nonce + 1,
                transfers: vec![],
                valid_transfers_map: vec![],
                relayer: gen_established_address(),
            })
            .expect_err("Test failed");
        shell
            .validate_eth_event(&EthereumEvent::TransfersToEthereum {
                nonce: nonce - 1,
                transfers: vec![],
                valid_transfers_map: vec![],
                relayer: gen_established_address(),
            })
            .expect_err("Test failed");

        // nam transfers with nonces >= the nonce in storage are valid
        shell
            .validate_eth_event(&EthereumEvent::TransfersToNamada {
                nonce,
                transfers: vec![],
                valid_transfers_map: vec![],
            })
            .expect("Test failed");
        shell
            .validate_eth_event(&EthereumEvent::TransfersToNamada {
                nonce: nonce + 5,
                transfers: vec![],
                valid_transfers_map: vec![],
            })
            .expect("Test failed");

        // nam transfers with lower nonces are invalid
        shell
            .validate_eth_event(&EthereumEvent::TransfersToNamada {
                nonce: nonce - 1,
                transfers: vec![],
                valid_transfers_map: vec![],
            })
            .expect_err("Test failed");
        shell
            .validate_eth_event(&EthereumEvent::TransfersToNamada {
                nonce: nonce - 2,
                transfers: vec![],
                valid_transfers_map: vec![],
            })
            .expect_err("Test failed");

        // either kind of transfer with different validity map and transfer
        // array length are invalid
        shell
            .validate_eth_event(&EthereumEvent::TransfersToEthereum {
                nonce,
                transfers: vec![],
                valid_transfers_map: vec![true, true],
                relayer: gen_established_address(),
            })
            .expect_err("Test failed");
        shell
            .validate_eth_event(&EthereumEvent::TransfersToNamada {
                nonce,
                transfers: vec![],
                valid_transfers_map: vec![true, true],
            })
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
                kind: TransferToEthereumKind::Erc20,
                amount: 100.into(),
                asset: EthAddress([1; 20]),
                sender: gen_established_address(),
                receiver: EthAddress([2; 20]),
                gas_amount: 10.into(),
                gas_payer: gen_established_address(),
            }],
            valid_transfers_map: vec![true],
            relayer: gen_established_address(),
        };
        let event_2 = EthereumEvent::TransfersToEthereum {
            nonce: 1.into(),
            transfers: vec![TransferToEthereum {
                kind: TransferToEthereumKind::Erc20,
                amount: 100.into(),
                asset: EthAddress([1; 20]),
                sender: gen_established_address(),
                receiver: EthAddress([2; 20]),
                gas_amount: 10.into(),
                gas_payer: gen_established_address(),
            }],
            valid_transfers_map: vec![true],
            relayer: gen_established_address(),
        };
        let event_3 = EthereumEvent::NewContract {
            name: "Test".to_string(),
            address: EthAddress([0; 20]),
        };

        tokio_test::block_on(oracle.send(event_1.clone()))
            .expect("Test failed");
        tokio_test::block_on(oracle.send(event_3.clone()))
            .expect("Test failed");
        let [event_first, event_second]: [EthereumEvent; 2] =
            shell.new_ethereum_events().try_into().expect("Test failed");

        assert_eq!(event_first, event_1);
        assert_eq!(event_second, event_3);
        // check that we queue and de-duplicate events
        tokio_test::block_on(oracle.send(event_2.clone()))
            .expect("Test failed");
        tokio_test::block_on(oracle.send(event_3.clone()))
            .expect("Test failed");
        let [event_first, event_second, event_third]: [EthereumEvent; 3] =
            shell.new_ethereum_events().try_into().expect("Test failed");

        assert_eq!(event_first, event_1);
        assert_eq!(event_second, event_2);
        assert_eq!(event_third, event_3);
    }

    /// Test that ethereum events are added to vote extensions.
    /// Check that vote extensions pass verification.
    #[cfg(feature = "abcipp")]
    #[tokio::test]
    async fn test_eth_events_vote_extension() {
        let (mut shell, _, oracle, _) = setup_at_height(1);
        let address = shell
            .mode
            .get_validator_address()
            .expect("Test failed")
            .clone();
        let event_1 = EthereumEvent::TransfersToEthereum {
            nonce: 0.into(),
            transfers: vec![TransferToEthereum {
                kind: TransferToEthereumKind::Erc20,
                amount: 100.into(),
                asset: EthAddress([1; 20]),
                sender: gen_established_address(),
                receiver: EthAddress([2; 20]),
                gas_amount: 10.into(),
                gas_payer: gen_established_address(),
            }],
            valid_transfers_map: vec![true],
            relayer: gen_established_address(),
        };
        let event_2 = EthereumEvent::NewContract {
            name: "Test".to_string(),
            address: EthAddress([0; 20]),
        };
        oracle.send(event_1.clone()).await.expect("Test failed");
        oracle.send(event_2.clone()).await.expect("Test failed");
        let vote_extension =
            <VoteExtension as BorshDeserialize>::try_from_slice(
                &shell.extend_vote(Default::default()).vote_extension[..],
            )
            .expect("Test failed");

        let [event_first, event_second]: [EthereumEvent; 2] = vote_extension
            .ethereum_events
            .clone()
            .expect("Test failed")
            .data
            .ethereum_events
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
            height: 1,
            vote_extension: vote_extension.try_to_vec().expect("Test failed"),
        };
        let res = shell.verify_vote_extension(req);
        assert_eq!(res.status, i32::from(VerifyStatus::Accept));
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
                    kind: TransferToEthereumKind::Erc20,
                    amount: 100.into(),
                    sender: gen_established_address(),
                    asset: EthAddress([1; 20]),
                    receiver: EthAddress([2; 20]),
                    gas_amount: 10.into(),
                    gas_payer: gen_established_address(),
                }],
                valid_transfers_map: vec![true],
                relayer: gen_established_address(),
            }],
            block_height: shell
                .wl_storage
                .pos_queries()
                .get_current_decision_height(),
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
                ethereum_events: Some(ethereum_events.clone()),
                bridge_pool_root: {
                    let to_sign = keccak_hash(
                        [
                            KeccakHash([0; 32]).encode().into_inner(),
                            Uint::from(0).encode().into_inner(),
                        ]
                        .concat(),
                    );
                    let sig = Signed::<_, SignableEthMessage>::new(
                        shell
                            .mode
                            .get_eth_bridge_keypair()
                            .expect("Test failed"),
                        to_sign,
                    )
                    .sig;
                    Some(
                        bridge_pool_roots::Vext {
                            block_height: shell
                                .wl_storage
                                .storage
                                .get_last_block_height(),
                            validator_addr: address,
                            sig,
                        }
                        .sign(
                            shell.mode.get_protocol_key().expect("Test failed"),
                        ),
                    )
                },
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
                    kind: TransferToEthereumKind::Erc20,
                    amount: 100.into(),
                    sender: gen_established_address(),
                    asset: EthAddress([1; 20]),
                    receiver: EthAddress([2; 20]),
                    gas_amount: 10.into(),
                    gas_payer: gen_established_address(),
                }],
                valid_transfers_map: vec![true],
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
        assert_eq!(shell.start_new_epoch().0, 1);
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
                    kind: TransferToEthereumKind::Erc20,
                    amount: 100.into(),
                    sender: gen_established_address(),
                    asset: EthAddress([1; 20]),
                    receiver: EthAddress([2; 20]),
                    gas_amount: 10.into(),
                    gas_payer: gen_established_address(),
                }],
                valid_transfers_map: vec![true],
                relayer: gen_established_address(),
            }],
            block_height: shell.wl_storage.storage.get_last_block_height(),
            validator_addr: address.clone(),
        };

        #[cfg(feature = "abcipp")]
        {
            let signed_vext = ethereum_events
                .clone()
                .sign(shell.mode.get_protocol_key().expect("Test failed"));
            let bp_root = {
                let to_sign = keccak_hash(
                    [
                        KeccakHash([0; 32]).encode().into_inner(),
                        Uint::from(0).encode().into_inner(),
                    ]
                    .concat(),
                );
                let sig = Signed::<_, SignableEthMessage>::new(
                    shell.mode.get_eth_bridge_keypair().expect("Test failed"),
                    to_sign,
                )
                .sig;
                bridge_pool_roots::Vext {
                    block_height: shell
                        .wl_storage
                        .storage
                        .get_last_block_height(),
                    validator_addr: address.clone(),
                    sig,
                }
                .sign(shell.mode.get_protocol_key().expect("Test failed"))
            };
            let req = request::VerifyVoteExtension {
                hash: vec![],
                validator_address: address.try_to_vec().expect("Test failed"),
                height: 0,
                vote_extension: VoteExtension {
                    ethereum_events: Some(signed_vext),
                    bridge_pool_root: Some(bp_root),
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
                    kind: TransferToEthereumKind::Erc20,
                    amount: 100.into(),
                    sender: gen_established_address(),
                    asset: EthAddress([1; 20]),
                    receiver: EthAddress([2; 20]),
                    gas_amount: 10.into(),
                    gas_payer: gen_established_address(),
                }],
                valid_transfers_map: vec![true],
                relayer: gen_established_address(),
            }],
            block_height: shell.wl_storage.storage.get_last_block_height(),
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
        assert!(!shell.validate_eth_events_vext(
            vote_ext,
            shell.wl_storage.storage.get_last_block_height()
        ))
    }
}
