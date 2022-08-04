//! Contains types necessary for processing validator set updates
//! in vote extensions.

use std::collections::HashMap;

use tiny_keccak::{Hasher, Keccak};
use ethabi::ethereum_types as ethereum;

use crate::types::ethereum_events::KeccakHash;
use crate::ledger::pos::types::{Epoch, VotingPower};

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

/// Represents a validator set update, for some new [`Epoch`].
pub struct Vext {
    /// The addresses of the validators in the new [`Epoch`],
    /// and their respective voting power.
    ///
    /// When signing a [`Vext`], this [`HashMap`] is converted
    /// into two arrays: one for its keys, and another for its
    /// values. The arrays are sorted in descending order based
    /// on the voting power of each validator.
    pub voting_powers: HashMap<ethereum::Address, VotingPower>,
    /// The new [`Epoch`].
    ///
    /// Since this is a monotonically growing sequence number,
    /// it is signed together with the rest of the data to
    /// prevent replay attacks on validator set updates.
    pub epoch: Epoch,
}

impl Vext {
    /// TODO
    pub fn get_keccak_hash(&self) -> KeccakHash {
        let state = Keccak::v256();
        let mut output = [0u8; 32];
        // state.update(&[...]);
        state.finalize(&mut output);
        todo!()
    }
}
