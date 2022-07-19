//! Extend Tendermint votes with Ethereum bridge logic.

#[cfg(not(feature = "ABCI"))]
pub mod ethereum_events;

#[cfg(not(feature = "ABCI"))]
pub mod validator_set_update;

#[cfg(not(feature = "ABCI"))]
mod extend_votes {
    use borsh::BorshDeserialize;
    use namada::proto::Signed;
    use namada::types::transaction::protocol::ProtocolTxType;
    use namada::types::vote_extensions::{
        ethereum_events, validator_set_update, VoteExtension,
        VoteExtensionDigest,
    };
    use tendermint_proto::abci::ExtendedVoteInfo;

    use super::super::*;
    use crate::node::ledger::shell::queries::{QueriesExt, SendValsetUpd};

    /// Message to be passed to `.expect()` calls in this module.
    const VALIDATOR_EXPECT_MSG: &str =
        "Only validators receive this method call.";

    /// The error yielded from validating faulty vote extensions in the shell
    #[derive(Error, Debug)]
    pub enum VoteExtensionError {
        #[error("The vote extension was issued at block height 0.")]
        IssuedAtGenesis,
        #[error(
            "The vote extension has an unexpected sequence number (e.g. block \
             height)."
        )]
        UnexpectedSequenceNumber,
        #[error(
            "The vote extension contains duplicate or non-sorted Ethereum \
             events."
        )]
        HaveDupesOrNonSorted,
        #[error(
            "The public key of the vote extension's associated validator \
             could not be found in storage."
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
        pub fn extend_vote(
            &mut self,
            _req: request::ExtendVote,
        ) -> response::ExtendVote {
            let vote_extension = VoteExtension {
                ethereum_events: self.extend_vote_with_ethereum_events(),
                validator_set_update: self.extend_vote_with_valset_update(),
            }
            .try_to_vec()
            .unwrap();

            response::ExtendVote { vote_extension }
        }

        /// Extend PreCommit votes with [`ethereum_events::Vext`] instances.
        pub fn extend_vote_with_ethereum_events(
            &mut self,
        ) -> Signed<ethereum_events::Vext> {
            let validator_addr = self
                .mode
                .get_validator_address()
                .expect(VALIDATOR_EXPECT_MSG)
                .to_owned();

            let ext = ethereum_events::Vext {
                block_height: self.storage.get_current_decision_height(),
                ethereum_events: self.new_ethereum_events(),
                validator_addr,
            };
            if !ext.ethereum_events.is_empty() {
                tracing::info!(
                    new_ethereum_events.len = ext.ethereum_events.len(),
                    ?ext.block_height,
                    "Voting for new Ethereum events"
                );
                tracing::debug!(
                    "New Ethereum events - {:#?}",
                    ext.ethereum_events
                );
            }

            let protocol_key = match &self.mode {
                ShellMode::Validator { data, .. } => {
                    &data.keys.protocol_keypair
                }
                _ => unreachable!("{VALIDATOR_EXPECT_MSG}"),
            };

            ext.sign(protocol_key)
        }

        /// Extend PreCommit votes with [`validator_set_update::Vext`]
        /// instances.
        pub fn extend_vote_with_valset_update(
            &mut self,
        ) -> Option<validator_set_update::SignedVext> {
            let validator_addr = self
                .mode
                .get_validator_address()
                .expect(VALIDATOR_EXPECT_MSG)
                .to_owned();

            self.storage
                .can_send_validator_set_update(SendValsetUpd::Now)
                .then(|| {
                    let next_epoch = self.storage.get_current_epoch().0.next();
                    let _validator_set =
                        self.storage.get_active_validators(Some(next_epoch));

                    let ext = validator_set_update::Vext {
                        validator_addr,
                        // TODO: we need a way to map ethereum addresses to
                        // namada validator addresses
                        voting_powers: std::collections::HashMap::new(),
                        epoch: next_epoch,
                    };

                    let protocol_key = match &self.mode {
                        ShellMode::Validator { data, .. } => {
                            &data.keys.protocol_keypair
                        }
                        _ => unreachable!("{VALIDATOR_EXPECT_MSG}"),
                    };

                    // TODO: sign validator set update with secp key instead
                    ext.sign(protocol_key)
                })
        }

        /// This checks that the vote extension:
        /// * Correctly deserializes.
        /// * The Ethereum events vote extension within was correctly signed by
        ///   an active validator.
        /// * The validator set update vote extension within was correctly
        ///   signed by an active validator, in case it could have been sent at
        ///   the current block height.
        /// * The Ethereum events vote extension block height signed over is
        ///   correct (for replay protection).
        /// * The validator set update vote extension epoch signed over is
        ///   correct (for replay protection).
        ///
        /// INVARIANT: This method must be stateless.
        pub fn verify_vote_extension(
            &self,
            req: request::VerifyVoteExtension,
        ) -> response::VerifyVoteExtension {
            let ext =
                match VoteExtension::try_from_slice(&req.vote_extension[..]) {
                    Ok(ext) => ext,
                    Err(err) => {
                        tracing::warn!(
                            ?err,
                            ?req.validator_address,
                            ?req.hash,
                            req.height,
                            "Received undeserializable vote extension"
                        );
                        return response::VerifyVoteExtension {
                            status: VerifyStatus::Reject.into(),
                        };
                    }
                };

            let validated_eth_events =
                self.verify_ethereum_events(&req, ext.ethereum_events);
            let validated_valset_upd =
                self.verify_valset_update(&req, ext.validator_set_update);

            response::VerifyVoteExtension {
                status: if validated_eth_events && validated_valset_upd {
                    VerifyStatus::Accept.into()
                } else {
                    VerifyStatus::Reject.into()
                },
            }
        }

        /// Check if [`ethereum_events::Vext`] instances are valid.
        pub fn verify_ethereum_events(
            &self,
            req: &request::VerifyVoteExtension,
            ext: Signed<ethereum_events::Vext>,
        ) -> bool {
            self.validate_eth_events_vext(ext, self.storage.get_current_decision_height())
                .then(|| true)
                .unwrap_or_else(|| {
                    tracing::warn!(
                        ?req.validator_address,
                        ?req.hash,
                        req.height,
                        "Received Ethereum events vote extension that didn't validate"
                    );
                    false
                })
        }

        /// Check if [`validator_set_update::Vext`] instances are valid.
        pub fn verify_valset_update(
            &self,
            req: &request::VerifyVoteExtension,
            ext: Option<validator_set_update::SignedVext>,
        ) -> bool {
            self.storage.can_send_validator_set_update(SendValsetUpd::Now).then(|| {
                ext
                    .and_then(|ext| {
                        // we have a valset update vext when we're expecting one, cool,
                        // let's validate it
                        self.validate_valset_upd_vext(ext, self.storage.get_current_epoch().0.next())
                            .then(|| true)
                    })
                    .unwrap_or_else(|| {
                        // either validation failed, or we were expecting a valset update
                        // vext and got none
                        tracing::warn!(
                            ?req.validator_address,
                            ?req.hash,
                            req.height,
                            "Missing or invalid validator set update vote extension"
                        );
                        false
                    })
            }).unwrap_or({
                // NOTE: if we're not supposed to send a validator set update
                // vote extension at a particular block height, we will
                // just return true as the validation result
                true
            })
        }
    }

    /// Given a `Vec` of [`ExtendedVoteInfo`], return an iterator over the
    /// ones we could deserialize to [`VoteExtension`]
    /// instances.
    pub fn deserialize_vote_extensions(
        vote_extensions: Vec<ExtendedVoteInfo>,
    ) -> impl Iterator<Item = VoteExtension> + 'static {
        vote_extensions.into_iter().filter_map(|vote| {
            VoteExtension::try_from_slice(&vote.vote_extension[..])
                .map_err(|err| {
                    tracing::error!(
                        ?err,
                        "Failed to deserialize data as a VoteExtension",
                    );
                })
                .ok()
        })
    }

    /// Yields an iterator over the [`ProtocolTxType`] transactions
    /// in a [`VoteExtensionDigest`].
    pub fn iter_protocol_txs(
        digest: VoteExtensionDigest,
    ) -> impl Iterator<Item = ProtocolTxType> {
        [
            Some(ProtocolTxType::EthereumEvents(digest.ethereum_events)),
            digest
                .validator_set_update
                .map(ProtocolTxType::ValidatorSetUpdate),
        ]
        .into_iter()
        .flatten()
    }

    /// Deserializes `vote_extensions` as [`VoteExtension`] instances, filtering
    /// out invalid data, and splits these into [`ethereum_events::Vext`]
    /// and [`validator_set_update::Vext`] instances.
    pub fn split_vote_extensions(
        vote_extensions: Vec<ExtendedVoteInfo>,
    ) -> (
        Vec<Signed<ethereum_events::Vext>>,
        Vec<validator_set_update::SignedVext>,
    ) {
        let mut eth_evs = vec![];
        let mut valset_upds = vec![];

        for ext in deserialize_vote_extensions(vote_extensions) {
            if let Some(validator_set_update) = ext.validator_set_update {
                valset_upds.push(validator_set_update);
            }
            eth_evs.push(ext.ethereum_events);
        }

        (eth_evs, valset_upds)
    }
}

#[cfg(not(feature = "ABCI"))]
pub use extend_votes::*;
