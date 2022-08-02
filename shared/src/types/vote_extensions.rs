//! This module contains types necessary for processing vote extensions.

pub mod ethereum_events;

// TODO: add a `VoteExtension` type
//
// ```ignore
// pub struct VoteExtension {
//     pub ethereum_events: SignedEthEventsVext,
//     pub validator_set_update: Option<SignedValidatorSetUpdateVext>,
// }
// ```

// TODO: add a `VoteExtensionDigest` type; this will contain
// the values to be proposed, for a quorum of Ethereum events
// vote extensions, and a separate quorum of validator set update
// vote extensions
//
// ```ignore
// pub struct VoteExtensionDigest {
//     pub ethereum_events: EthEventsVextDigest,
//     pub validator_set_update: Option<ValidatorSetUpdateVextDigest>,
// }
// ```
//
// from a `VoteExtensionDigest` we yield two signed `ProtocolTxType` values,
// one of `ProtocolTxType::EthereumEvents` and the other of
// `ProtocolTxType::ValidatorSetUpdate`
