//! This module contains types necessary for processing vote extensions.

pub mod ethereum_events;
pub mod validator_set_update;

use crate::proto::Signed;
use crate::types::transaction::protocol::ProtocolTxType;

/// This type represents the data we pass to the extension of
/// a vote at the PreCommit phase of Tendermint.
pub struct VoteExtension {
    /// Vote extension data related with Ethereum events.
    pub ethereum_events: Signed<ethereum_events::Vext>,
    /// Vote extension data related with validator set updates.
    pub validator_set_update: Option<validator_set_update::SignedVext>,
}

/// The digest of the signatures from different validators
/// in [`VoteExtension`] instances.
///
/// From a [`VoteExtensionDigest`] we yield two signed
/// [`ProtocolTxType`] transactions:
///   - A `ProtocolTxType::EthereumEvents` tx, and
///   - A `ProtocolTxType::ValidatorSetUpdate` tx
pub struct VoteExtensionDigest {
    /// The digest of Ethereum events vote extension signatures.
    pub ethereum_events: ethereum_events::VextDigest,
    /// The digest of validator set updates vote extension signatures.
    pub validator_set_update: Option<validator_set_update::VextDigest>,
}

impl VoteExtensionDigest {
    /// Yields an iterator over the [`ProtocolTxType`] transactions
    /// in this [`VoteExtensionDigest`].
    pub fn into_protocol_txs(self) -> impl Iterator<Item = ProtocolTxType> {
        [
            Some(ProtocolTxType::EthereumEvents(self.ethereum_events)),
            self.validator_set_update
                .map(ProtocolTxType::ValidatorSetUpdate),
        ]
        .into_iter()
        .flat_map(|tx| tx)
    }
}
