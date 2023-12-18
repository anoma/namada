//! Extend Tendermint votes with Ethereum bridge logic.

pub mod bridge_pool_vext;
pub mod eth_events;
pub mod val_set_update;

pub use namada::eth_bridge::protocol::validation::VoteExtensionError;
use namada::proto::{SignableEthMessage, Signed};
use namada::types::keccak::keccak_hash;
use namada::types::transaction::protocol::EthereumTxData;
use namada::types::vote_extensions::{
    bridge_pool_roots, ethereum_events, validator_set_update, VoteExtension,
};
use namada_sdk::eth_bridge::{EthBridgeQueries, SendValsetUpd};

use super::*;
use crate::node::ledger::shims::abcipp_shim_types::shim::TxBytes;

/// Message to be passed to `.expect()` calls in this module.
const VALIDATOR_EXPECT_MSG: &str = "Only validators receive this method call.";

impl<D, H> Shell<D, H>
where
    D: DB + for<'iter> DBIter<'iter> + Sync + 'static,
    H: StorageHasher + Sync + 'static,
{
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
    #[inline]
    pub fn extend_vote_with_ethereum_events(
        &mut self,
    ) -> Option<Signed<ethereum_events::Vext>> {
        let events = self.new_ethereum_events();
        self.sign_ethereum_events(events)
    }

    /// Sign the given Ethereum events, and return the associated
    /// vote extension protocol transaction.
    pub fn sign_ethereum_events(
        &mut self,
        ethereum_events: Vec<EthereumEvent>,
    ) -> Option<Signed<ethereum_events::Vext>> {
        if !self.wl_storage.ethbridge_queries().is_bridge_active() {
            return None;
        }
        let validator_addr = self
            .mode
            .get_validator_address()
            .expect(VALIDATOR_EXPECT_MSG)
            .to_owned();

        let ext = ethereum_events::Vext {
            block_height: self.wl_storage.storage.get_last_block_height(),
            ethereum_events,
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
        if !self.wl_storage.ethbridge_queries().is_bridge_active() {
            return None;
        }
        let validator_addr = self
            .mode
            .get_validator_address()
            .expect(VALIDATOR_EXPECT_MSG)
            .to_owned();
        let bp_root =
            self.wl_storage.ethbridge_queries().get_bridge_pool_root().0;
        let nonce = self
            .wl_storage
            .ethbridge_queries()
            .get_bridge_pool_nonce()
            .to_bytes();
        let to_sign =
            keccak_hash([bp_root.as_slice(), nonce.as_slice()].concat());
        let eth_key = self
            .mode
            .get_eth_bridge_keypair()
            .expect(VALIDATOR_EXPECT_MSG);
        let signed = Signed::<_, SignableEthMessage>::new(eth_key, to_sign);
        let ext = bridge_pool_roots::Vext {
            block_height: self.wl_storage.storage.get_last_block_height(),
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
        self.wl_storage
            .ethbridge_queries()
            .must_send_valset_upd(SendValsetUpd::Now)
            .then(|| {
                let next_epoch =
                    self.wl_storage.storage.get_current_epoch().0.next();

                let validator_addr = self
                    .mode
                    .get_validator_address()
                    .expect(VALIDATOR_EXPECT_MSG)
                    .to_owned();

                let voting_powers = self
                    .wl_storage
                    .ethbridge_queries()
                    .get_consensus_eth_addresses(Some(next_epoch))
                    .iter()
                    .map(|(eth_addr_book, _, voting_power)| {
                        (eth_addr_book, voting_power)
                    })
                    .collect();

                let ext = validator_set_update::Vext {
                    validator_addr,
                    voting_powers,
                    signing_epoch: self
                        .wl_storage
                        .storage
                        .get_current_epoch()
                        .0,
                };

                let eth_key = self
                    .mode
                    .get_eth_bridge_keypair()
                    .expect("{VALIDATOR_EXPECT_MSG}");
                ext.sign(eth_key)
            })
    }

    /// Given a slice of [`TxBytes`], return an iterator over the
    /// ones we could deserialize to vote extension protocol txs.
    pub fn deserialize_vote_extensions<'shell>(
        &'shell self,
        txs: &'shell [TxBytes],
    ) -> impl Iterator<Item = TxBytes> + 'shell {
        txs.iter().filter_map(move |tx_bytes| {
            let tx = match Tx::try_from(tx_bytes.as_ref()) {
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
            match (&tx).try_into().ok()? {
                EthereumTxData::BridgePoolVext(_) => Some(tx_bytes.clone()),
                EthereumTxData::EthEventsVext(ext) => {
                    // NB: only propose events with at least
                    // one valid nonce
                    ext.data
                        .ethereum_events
                        .iter()
                        .any(|event| {
                            self.wl_storage
                                .ethbridge_queries()
                                .validate_eth_event_nonce(event)
                        })
                        .then(|| tx_bytes.clone())
                }
                EthereumTxData::ValSetUpdateVext(ext) => {
                    // only include non-stale validator set updates
                    // in block proposals. it might be sitting long
                    // enough in the mempool for it to no longer be
                    // relevant to propose (e.g. a proof was constructed
                    // before this validator set update got a chance
                    // to be decided). unfortunately, we won't be able
                    // to remove it from the mempool this way, but it
                    // will eventually be evicted, getting replaced
                    // by newer txs.
                    (!self
                        .wl_storage
                        .ethbridge_queries()
                        .valset_upd_seen(ext.data.signing_epoch.next()))
                    .then(|| tx_bytes.clone())
                }
                _ => None,
            }
        })
    }
}

/// Yields an iterator over the protocol transactions
/// in a [`VoteExtension`].
pub fn iter_protocol_txs(
    ext: VoteExtension,
) -> impl Iterator<Item = EthereumTxData> {
    let VoteExtension {
        ethereum_events,
        bridge_pool_root,
        validator_set_update,
    } = ext;
    [
        ethereum_events.map(EthereumTxData::EthEventsVext),
        bridge_pool_root.map(EthereumTxData::BridgePoolVext),
        validator_set_update.map(EthereumTxData::ValSetUpdateVext),
    ]
    .into_iter()
    .flatten()
}
