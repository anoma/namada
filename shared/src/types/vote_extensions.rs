//! This module contains types necessary for processing vote extensions.

pub mod ethereum_events;
pub mod validator_set_update;

/// This type represents the data we pass to the extension of
/// a vote at the PreCommit phase of Tendermint.
pub struct VoteExtension {
    /// Vote extension data related with Ethereum events.
    pub ethereum_events: Signed<ethereum_events::Vext>,
    /// Vote extension data related with validator set updates.
    pub validator_set_update: Option<validator_set_update::SignedVext>,
}

// TODO: add a `VoteExtensionDigest` type; this will contain
// the values to be proposed, for a quorum of Ethereum events
// vote extensions, and a separate quorum of validator set update
// vote extensions
//
// ```ignore
// pub struct VoteExtensionDigest {
//     pub ethereum_events: ethereum_events::VextDigest,
//     pub validator_set_update: Option<validator_set_update::VextDigest>,
// }
// ```
//
// from a `VoteExtensionDigest` we yield two signed `ProtocolTxType` values,
// one of `ProtocolTxType::EthereumEvents` and the other of
// `ProtocolTxType::ValidatorSetUpdate`
