//! Contains types necessary for processing validator set updates
//! in vote extensions.

// TODO: finish signed vote extension
// ```ignore
// struct Vext {
//     ...?
// }
// struct SignedVext {
//     signature: EthereumSignature,
//     data: Vext,
// }
// ```
// we derive a keccak hash from the `Vext` data
// in `SignedVext`, which we can sign with an
// Ethereum key. that is the content of `signature`
