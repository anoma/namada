//! Extend Tendermint votes with Ethereum bridge logic.

#[cfg(not(feature = "ABCI"))]
pub mod ethereum_events;

#[cfg(not(feature = "ABCI"))]
pub mod validator_set_update;

#[cfg(not(feature = "ABCI"))]
mod extend_votes {
    use borsh::BorshDeserialize;
    use namada::proto::Signed;
    use namada::types::storage::Epoch;
    use namada::types::vote_extensions::{
        ethereum_events, validator_set_update, VoteExtension,
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

            let validator_addr = addr.clone();
            let eth_evs = ethereum_events::Vext {
                block_height: self.storage.last_height + 1,
                ethereum_events: self.new_ethereum_events(),
                validator_addr,
            };

            let validator_addr = addr;
            let vset_upd = if self.storage.can_send_validator_set_update() {
                let (Epoch(current_epoch), _) =
                    self.storage.get_current_epoch();
                let next_epoch = Epoch(current_epoch + 1);
                let _validator_set =
                    self.storage.get_active_validators(Some(next_epoch));

                Some(validator_set_update::Vext {
                    validator_addr,
                    // TODO: we need a way to map ethereum addresses to
                    // namada validator addresses
                    voting_powers: todo!(),
                    epoch: next_epoch,
                })
            } else {
                None
            };

            if let ShellMode::Validator { data, .. } = &self.mode {
                let protocol_key = &data.keys.protocol_keypair;

                let vset_upd =
                    vset_upd.map(|ext: validator_set_update::Vext| {
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
        /// * Correctly deserializes
        /// * Was correctly signed by an active validator.
        /// * The block height signed over is correct (replay protection)
        ///
        /// INVARIANT: This method must be stateless.
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
                    status: if self.validate_eth_events_vext(
                        signed,
                        self.storage.last_height + 1,
                    ) {
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
}

#[cfg(not(feature = "ABCI"))]
pub use extend_votes::*;
