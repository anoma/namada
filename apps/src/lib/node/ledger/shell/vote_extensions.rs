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
    use crate::node::ledger::shell::queries::QueriesExt;

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
            let addr = self
                .mode
                .get_validator_address()
                .expect("only validators should receive this method call")
                .to_owned();

            let curr_height = self.storage.last_height + 1;

            let validator_addr = addr.clone();
            let eth_evs = ethereum_events::Vext {
                block_height: curr_height,
                ethereum_events: self.new_ethereum_events(),
                validator_addr,
            };

            // TODO: should we move this inside the if block below?
            // non-validator nodes don't need to perform these checks;
            // similarly, the ethereum events stuff above could be moved
            // to the if block below
            let validator_addr = addr;
            let vset_upd = self
                .storage
                .can_send_validator_set_update(curr_height)
                .then(|| {
                    let next_epoch = self.storage.get_current_epoch().0.next();
                    let _validator_set =
                        self.storage.get_active_validators(Some(next_epoch));

                    validator_set_update::Vext {
                        validator_addr,
                        // TODO: we need a way to map ethereum addresses to
                        // namada validator addresses
                        voting_powers: std::collections::HashMap::new(),
                        epoch: next_epoch,
                    }
                });

            if let ShellMode::Validator { data, .. } = &self.mode {
                let protocol_key = &data.keys.protocol_keypair;

                let vset_upd = vset_upd.map(|ext| {
                    // TODO: sign validator set update with secp key instead
                    ext.sign(protocol_key)
                });

                let eth_evs = eth_evs.sign(protocol_key);

                let vote_extension = VoteExtension {
                    ethereum_events: eth_evs,
                    validator_set_update: vset_upd,
                }
                .try_to_vec()
                .unwrap();

                response::ExtendVote { vote_extension }
            } else {
                Default::default()
            }
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
            let curr_height = self.storage.last_height + 1;
            let validated_eth_events = self.validate_eth_events_vext(ext.ethereum_events, curr_height)
                .then(|| true)
                .unwrap_or_else(|| {
                    tracing::warn!(
                        ?req.validator_address,
                        ?req.hash,
                        req.height,
                        "Received Ethereum events vote extension that didn't validate"
                    );
                    false
                });
            let validated_valset_upd = self.storage.can_send_validator_set_update(curr_height).then(|| {
                ext.validator_set_update
                    .and_then(|ext| {
                        self.validate_valset_upd_vext(ext, self.storage.get_current_epoch().0.next())
                            .then(|| true)
                    })
                    .unwrap_or_else(|| {
                        tracing::warn!(
                            ?req.validator_address,
                            ?req.hash,
                            req.height,
                            "Received validator set update vote extension that didn't validate"
                        );
                        false
                    })
            }).unwrap_or({
                // NOTE: if we're not supposed to send a validator set update
                // vote extension at a particular block height, we will
                // just return true as the validation result
                true
            });
            response::VerifyVoteExtension {
                status: if validated_eth_events && validated_valset_upd {
                    VerifyStatus::Accept.into()
                } else {
                    VerifyStatus::Reject.into()
                },
            }
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
        .flat_map(|tx| tx)
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
