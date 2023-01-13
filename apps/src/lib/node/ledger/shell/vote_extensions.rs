//! Extend Tendermint votes with Ethereum bridge logic.

pub mod eth_events;
pub mod val_set_update;

#[cfg(feature = "abcipp")]
use borsh::BorshDeserialize;
#[cfg(not(feature = "abcipp"))]
use index_set::vec::VecIndexSet;
use namada::ledger::eth_bridge::{EthBridgeQueries, SendValsetUpd};
#[cfg(feature = "abcipp")]
use namada::ledger::pos::PosQueries;
use namada::proto::Signed;
#[cfg(not(feature = "abcipp"))]
use namada::types::storage::Epoch;
use namada::types::transaction::protocol::ProtocolTxType;
#[cfg(feature = "abcipp")]
use namada::types::vote_extensions::VoteExtensionDigest;
use namada::types::vote_extensions::{
    ethereum_events, validator_set_update, VoteExtension,
};

use super::*;
#[cfg(feature = "abcipp")]
use crate::facade::tendermint_proto::abci::ExtendedVoteInfo;
#[cfg(not(feature = "abcipp"))]
use crate::node::ledger::shims::abcipp_shim_types::shim::TxBytes;

/// Message to be passed to `.expect()` calls in this module.
const VALIDATOR_EXPECT_MSG: &str = "Only validators receive this method call.";

/// The error yielded from validating faulty vote extensions in the shell
#[derive(Error, Debug)]
pub enum VoteExtensionError {
    #[error("The vote extension was issued at block height 0.")]
    IssuedAtGenesis,
    #[error("The vote extension was issued for an unexpected block height.")]
    UnexpectedBlockHeight,
    #[error("The vote extension was issued for an unexpected epoch.")]
    UnexpectedEpoch,
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
    #[error(
        "Validator is missing from an expected field in the vote extension."
    )]
    ValidatorMissingFromExtension,
    #[error(
        "Found value for a field in the vote extension diverging from the \
         equivalent field in storage."
    )]
    DivergesFromStorage,
}

impl<D, H> Shell<D, H>
where
    D: DB + for<'iter> DBIter<'iter> + Sync + 'static,
    H: StorageHasher + Sync + 'static,
{
    /// The ExtendVote ABCI++ method implementation.
    ///
    /// INVARIANT: This method must be stateless.
    #[cfg(feature = "abcipp")]
    #[inline]
    pub fn extend_vote(
        &mut self,
        _req: request::ExtendVote,
    ) -> response::ExtendVote {
        response::ExtendVote {
            vote_extension: self.craft_extension().try_to_vec().unwrap(),
        }
    }

    /// Creates the data to be added to a vote extension.
    ///
    /// INVARIANT: This method must be stateless.
    #[inline]
    pub fn craft_extension(&mut self) -> VoteExtension {
        VoteExtension {
            ethereum_events: self.extend_vote_with_ethereum_events(),
            validator_set_update: self.extend_vote_with_valset_update(),
        }
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
            #[cfg(feature = "abcipp")]
            block_height: self.storage.get_current_decision_height(),
            #[cfg(not(feature = "abcipp"))]
            block_height: self.storage.last_height,
            ethereum_events: self.new_ethereum_events(),
            validator_addr,
        };
        if !ext.ethereum_events.is_empty() {
            tracing::info!(
                new_ethereum_events.len = ext.ethereum_events.len(),
                ?ext.block_height,
                "Voting for new Ethereum events"
            );
            tracing::debug!("New Ethereum events - {:#?}", ext.ethereum_events);
        }

        let protocol_key = match &self.mode {
            ShellMode::Validator { data, .. } => &data.keys.protocol_keypair,
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
                let voting_powers = self
                    .storage
                    .get_active_eth_addresses(Some(next_epoch))
                    .map(|(eth_addr_book, _, voting_power)| {
                        (eth_addr_book, voting_power)
                    })
                    .collect();

                let ext = validator_set_update::Vext {
                    validator_addr,
                    voting_powers,
                    #[cfg(feature = "abcipp")]
                    block_height: self.storage.get_current_decision_height(),
                    #[cfg(not(feature = "abcipp"))]
                    block_height: self.storage.last_height,
                };

                let eth_key = match &self.mode {
                    ShellMode::Validator { data, .. } => {
                        &data.keys.eth_bridge_keypair
                    }
                    _ => unreachable!("{VALIDATOR_EXPECT_MSG}"),
                };

                ext.sign(eth_key)
            })
    }

    /// The VerifyVoteExtension ABCI++ method.
    ///
    /// This checks that the vote extension:
    /// * Correctly deserializes.
    /// * The Ethereum events vote extension within was correctly signed by an
    ///   active validator.
    /// * The validator set update vote extension within was correctly signed by
    ///   an active validator, in case it could have been sent at the current
    ///   block height.
    /// * The Ethereum events vote extension block height signed over is correct
    ///   (for replay protection).
    /// * The validator set update vote extension block height signed over is
    ///   correct (for replay protection).
    ///
    /// INVARIANT: This method must be stateless.
    #[cfg(feature = "abcipp")]
    pub fn verify_vote_extension(
        &self,
        req: request::VerifyVoteExtension,
    ) -> response::VerifyVoteExtension {
        use crate::facade::tendermint_proto::abci::response_verify_vote_extension::VerifyStatus;

        let ext = match VoteExtension::try_from_slice(&req.vote_extension[..]) {
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
    #[cfg(feature = "abcipp")]
    pub fn verify_ethereum_events(
        &self,
        req: &request::VerifyVoteExtension,
        ext: Signed<ethereum_events::Vext>,
    ) -> bool {
        self.validate_eth_events_vext(
            ext,
            self.storage.get_current_decision_height(),
        )
        .then_some(true)
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
    #[cfg(feature = "abcipp")]
    pub fn verify_valset_update(
        &self,
        req: &request::VerifyVoteExtension,
        ext: Option<validator_set_update::SignedVext>,
    ) -> bool {
        if let Some(ext) = ext {
            self.storage
                .can_send_validator_set_update(SendValsetUpd::Now)
                .then(|| {
                    // we have a valset update vext when we're expecting one,
                    // cool, let's validate it
                    self.validate_valset_upd_vext(
                        ext,
                        self.storage.get_current_decision_height(),
                    )
                })
                .unwrap_or_else(|| {
                    // either validation failed, or we were expecting a valset
                    // update vext and got none
                    tracing::warn!(
                        ?req.validator_address,
                        ?req.hash,
                        req.height,
                        "Missing or invalid validator set update vote extension"
                    );
                    false
                })
        } else {
            // NOTE: if we're not supposed to send a validator set update
            // vote extension at a particular block height, we will
            // just return true as the validation result
            true
        }
    }
}

/// Given a `Vec` of [`ExtendedVoteInfo`], return an iterator over the
/// ones we could deserialize to [`VoteExtension`]
/// instances.
#[cfg(feature = "abcipp")]
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

/// Given a slice of [`TxBytes`], return an iterator over the
/// ones we could deserialize to vote extension protocol txs.
#[cfg(not(feature = "abcipp"))]
pub fn deserialize_vote_extensions<'shell>(
    txs: &'shell [TxBytes],
    protocol_tx_indices: &'shell mut VecIndexSet<u128>,
    current_epoch: Epoch,
) -> impl Iterator<Item = TxBytes> + 'shell {
    use namada::types::transaction::protocol::ProtocolTx;

    txs.iter().enumerate().filter_map(|(index, tx_bytes)| {
        let tx = match Tx::try_from(tx_bytes.as_slice()) {
            Ok(tx) => tx,
            Err(err) => {
                tracing::warn!(
                    ?err,
                    "Failed to deserialize tx in deserialize_vote_extensions"
                );
                return None;
            }
        };
        match process_tx(tx).ok()? {
            TxType::Protocol(ProtocolTx {
                tx: ProtocolTxType::EthEventsVext(_),
                ..
            }) => {
                // mark tx for inclusion
                protocol_tx_indices.insert(index);
                Some(tx_bytes.clone())
            }
            TxType::Protocol(ProtocolTx {
                tx: ProtocolTxType::ValSetUpdateVext(ext),
                ..
            }) => {
                // mark tx, so it's skipped when
                // building the batch of remaining txs
                protocol_tx_indices.insert(index);

                // only include non-stale validator set updates
                // in block proposals. it might be sitting long
                // enough in the mempool for it to no longer be
                // relevant to propose (e.g. the new epoch was
                // installed before this validator set update got
                // a chance to be decided). unfortunately, we won't
                // be able to remove it from the mempool this way,
                // but it will eventually be evicted, getting replaced
                // by newer txs.
                (ext.data.signing_epoch == current_epoch)
                    .then(|| tx_bytes.clone())
            }
            _ => None,
        }
    })
}

/// Yields an iterator over the [`ProtocolTxType`] transactions
/// in a [`VoteExtensionDigest`].
#[cfg(feature = "abcipp")]
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

/// Yields an iterator over the [`ProtocolTxType`] transactions
/// in a [`VoteExtension`].
#[cfg(not(feature = "abcipp"))]
pub fn iter_protocol_txs(
    ext: VoteExtension,
) -> impl Iterator<Item = ProtocolTxType> {
    [
        Some(ProtocolTxType::EthEventsVext(ext.ethereum_events)),
        ext.validator_set_update
            .map(ProtocolTxType::ValSetUpdateVext),
    ]
    .into_iter()
    .flatten()
}

/// Deserializes `vote_extensions` as [`VoteExtension`] instances, filtering
/// out invalid data, and splits these into [`ethereum_events::Vext`]
/// and [`validator_set_update::Vext`] instances.
#[cfg(feature = "abcipp")]
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
