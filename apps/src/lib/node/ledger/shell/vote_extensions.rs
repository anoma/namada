//! Extend Tendermint votes with Ethereum bridge logic.

pub mod bridge_pool_vext;
pub mod eth_events;
pub mod val_set_update;

#[cfg(not(feature = "abcipp"))]
use index_set::vec::VecIndexSet;
use namada::ledger::eth_bridge::{EthBridgeQueries, SendValsetUpd};
#[cfg(feature = "abcipp")]
use namada::ledger::pos::PosQueries;
use namada::proto::{SignableEthBytes, Signed};
use namada::types::transaction::protocol::ProtocolTxType;
#[cfg(feature = "abcipp")]
use namada::types::vote_extensions::VoteExtensionDigest;
use namada::types::vote_extensions::{
    bridge_pool_roots, ethereum_events, validator_set_update, VoteExtension,
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
    #[error("The signature of the Bridge pool root is invalid")]
    InvalidBPRootSig,
    #[error(
        "Received a vote extension for the Ethereum bridge which is currently \
         not active"
    )]
    EthereumBridgeInactive,
    #[error("A vote extension for the Ethereum bridge is missing.")]
    MissingBridgeVext,
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
            bridge_pool_root: self.extend_vote_with_bp_roots(),
            validator_set_update: self.extend_vote_with_valset_update(),
        }
    }

    /// Extend PreCommit votes with [`ethereum_events::Vext`] instances.
    pub fn extend_vote_with_ethereum_events(
        &mut self,
    ) -> Option<Signed<ethereum_events::Vext>> {
        if !self.storage.is_bridge_active() {
            return None;
        }
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

        Some(ext.sign(protocol_key))
    }

    /// Extend PreCommit votes with [`bridge_pool_roots::Vext`] instances.
    pub fn extend_vote_with_bp_roots(
        &self,
    ) -> Option<Signed<bridge_pool_roots::Vext>> {
        if !self.storage.is_bridge_active() {
            return None;
        }
        let validator_addr = self
            .mode
            .get_validator_address()
            .expect(VALIDATOR_EXPECT_MSG)
            .to_owned();
        let bp_root = self.storage.get_bridge_pool_root().0;
        let nonce = self.storage.get_bridge_pool_nonce().to_bytes();
        let to_sign = [bp_root.as_slice(), nonce.as_slice()].concat();
        let eth_key = self
            .mode
            .get_eth_bridge_keypair()
            .expect(VALIDATOR_EXPECT_MSG);
        let signed = Signed::<Vec<u8>, SignableEthBytes>::new(eth_key, to_sign);

        let ext = bridge_pool_roots::Vext {
            block_height: self.storage.last_height,
            validator_addr,
            sig: signed.sig,
        };
        let protocol_key =
            self.mode.get_protocol_key().expect(VALIDATOR_EXPECT_MSG);
        Some(ext.sign(protocol_key))
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
            .must_send_valset_upd(SendValsetUpd::Now)
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
                    signing_epoch: self.storage.get_current_epoch().0,
                };

                let eth_key = self
                    .mode
                    .get_eth_bridge_keypair()
                    .expect("{VALIDATOR_EXPECT_MSG}");
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
        let validated_bp_roots =
            self.verify_bridge_pool_root(&req, ext.bridge_pool_root);
        let validated_valset_upd =
            self.verify_valset_update(&req, ext.validator_set_update);

        response::VerifyVoteExtension {
            status: if validated_eth_events
                && validated_bp_roots
                && validated_valset_upd
            {
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
        ext: Option<Signed<ethereum_events::Vext>>,
    ) -> bool {
        if !self.storage.is_bridge_active() {
            ext.is_none()
        } else {
            if ext.is_none() {
                return false;
            }
            self.validate_eth_events_vext(
                ext.unwrap(),
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
    }

    /// Check if [`bridge_pool_roots::Vext`] instances are valid.
    #[cfg(feature = "abcipp")]
    pub fn verify_bridge_pool_root(
        &self,
        req: &request::VerifyVoteExtension,
        ext: Option<bridge_pool_roots::SignedVext>,
    ) -> bool {
        if self.storage.is_bridge_active() {
            if ext.is_none() {
                return false;
            }
            self.validate_bp_roots_vext(
                ext.unwrap(),
                self.storage.last_height,
            )
            .then_some(true)
            .unwrap_or_else(|| {
                tracing::warn!(
                    ?req.validator_address,
                    ?req.hash,
                    req.height,
                    "Received Bridge pool root vote extension that didn't validate"
                );
                    false
                })
        } else {
            ext.is_none()
        }
    }

    /// Check if [`validator_set_update::Vext`] instances are valid.
    #[cfg(feature = "abcipp")]
    pub fn verify_valset_update(
        &self,
        req: &request::VerifyVoteExtension,
        ext: Option<validator_set_update::SignedVext>,
    ) -> bool {
        let Some(ext) = ext else {
            // if no validator set update was provided,
            // we must check if we are not supposed to
            // send one at the current block height.
            // remember, we need to gather a quorum of
            // votes, so this check is quite important!
            //
            // can send = true -> verify = false
            // can send = false -> verify = true
            //
            // (we simply invert the can send logic)
            let verify_passes = !self.storage
                .must_send_valset_upd(SendValsetUpd::Now);
            if !verify_passes {
                tracing::warn!(
                    ?req.validator_address,
                    ?req.hash,
                    req.height,
                    "Expected validator set update, but got none"
                );
            }
            return verify_passes;
        };
        self.storage
            .must_send_valset_upd(SendValsetUpd::Now)
            .then(|| {
                // we have a valset update vext when we're expecting one,
                // cool, let's validate it
                self.validate_valset_upd_vext(
                    ext,
                    self.storage.get_current_epoch().0,
                )
            })
            .unwrap_or_else(|| {
                // oh no, validation failed
                tracing::warn!(
                    ?req.validator_address,
                    ?req.hash,
                    req.height,
                    "Invalid validator set update vote extension"
                );
                false
            })
    }

    /// Given a slice of [`TxBytes`], return an iterator over the
    /// ones we could deserialize to vote extension protocol txs.
    #[cfg(not(feature = "abcipp"))]
    pub fn deserialize_vote_extensions<'shell>(
        &'shell self,
        txs: &'shell [TxBytes],
        protocol_tx_indices: &'shell mut VecIndexSet<u128>,
    ) -> impl Iterator<Item = TxBytes> + 'shell {
        use namada::types::transaction::protocol::ProtocolTx;
        let current_epoch = self.storage.get_current_epoch().0;

        txs.iter().enumerate().filter_map(move |(index, tx_bytes)| {
            let tx = match Tx::try_from(tx_bytes.as_slice()) {
                Ok(tx) => tx,
                Err(err) => {
                    tracing::warn!(
                        ?err,
                        "Failed to deserialize tx in \
                         deserialize_vote_extensions"
                    );
                    return None;
                }
            };
            match process_tx(tx).ok()? {
                TxType::Protocol(ProtocolTx {
                    tx:
                        ProtocolTxType::EthEventsVext(_)
                        | ProtocolTxType::BridgePoolVext(_),
                    ..
                }) => {
                    // mark tx for inclusion or it is skipped
                    // if the bridge is inactive
                    protocol_tx_indices.insert(index);
                    self.storage.is_bridge_active().then_some(tx_bytes.clone())
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

    /// Deserializes `vote_extensions` as [`VoteExtension`] instances, filtering
    /// out invalid data, and splits these into [`ethereum_events::Vext`]
    /// and [`validator_set_update::Vext`] instances.
    #[cfg(feature = "abcipp")]
    #[allow(clippy::type_complexity)]
    pub fn split_vote_extensions(
        &self,
        vote_extensions: Vec<ExtendedVoteInfo>,
    ) -> (
        Option<Vec<Signed<ethereum_events::Vext>>>,
        Option<Vec<Signed<bridge_pool_roots::Vext>>>,
        Vec<validator_set_update::SignedVext>,
    ) {
        let mut eth_evs = vec![];
        let mut bp_roots = vec![];
        let mut valset_upds = vec![];
        let bridge_active = self.storage.is_bridge_active();

        for ext in deserialize_vote_extensions(vote_extensions) {
            if let Some(validator_set_update) = ext.validator_set_update {
                valset_upds.push(validator_set_update);
            }
            if bridge_active {
                if let Some(events) = ext.ethereum_events {
                    eth_evs.push(events);
                }
                if let Some(roots) = ext.bridge_pool_root {
                    bp_roots.push(roots);
                }
            }
        }
        if bridge_active {
            (Some(eth_evs), Some(bp_roots), valset_upds)
        } else {
            (None, None, valset_upds)
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

/// Yields an iterator over the [`ProtocolTxType`] transactions
/// in a [`VoteExtensionDigest`].
#[cfg(feature = "abcipp")]
pub fn iter_protocol_txs(
    digest: VoteExtensionDigest,
) -> impl Iterator<Item = ProtocolTxType> {
    [
        digest.ethereum_events.map(ProtocolTxType::EthereumEvents),
        digest.bridge_pool_roots.map(ProtocolTxType::BridgePool),
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
    let VoteExtension {
        ethereum_events,
        bridge_pool_root,
        validator_set_update,
    } = ext;
    [
        ethereum_events.map(ProtocolTxType::EthEventsVext),
        bridge_pool_root.map(ProtocolTxType::BridgePoolVext),
        validator_set_update.map(ProtocolTxType::ValSetUpdateVext),
    ]
    .into_iter()
    .flatten()
}
