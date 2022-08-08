//! Extend Tendermint votes with Ethereum bridge logic.

#[cfg(not(feature = "ABCI"))]
pub mod ethereum_events;

#[cfg(not(feature = "ABCI"))]
mod extend_votes {
    use borsh::BorshDeserialize;
    use namada::ledger::pos::namada_proof_of_stake::types::VotingPower;
    use namada::proto::Signed;
    use namada::types::vote_extensions::{ethereum_events, VoteExtension};
    use tendermint_proto::abci::ExtendedVoteInfo;

    use super::super::queries::QueriesExt;
    use super::super::*;

    /// The error yielded from validating faulty vote extensions in the shell
    #[derive(Error, Debug)]
    pub enum VoteExtensionError {
        #[error("The vote extension was issued at block height 0.")]
        IssuedAtGenesis,
        #[error("The vote extension has an unexpected block height.")]
        UnexpectedBlockHeight,
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
