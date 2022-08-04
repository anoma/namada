//! Contains types necessary for processing validator set updates
//! in vote extensions.

pub mod encoding;

use std::collections::HashMap;

use encoding::{AbiEncode, Encode, Token};
use ethabi::ethereum_types as ethereum;
use num_rational::Ratio;

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
    pub fn get_keccak_hash(&self) -> [u8; 32] {
        // TODO: we need to get this value from `Storage`
        // related issue: https://github.com/anoma/namada/issues/249
        const GOVERNANCE_CONTRACT_VERSION: u8 = 1;

        AbiEncode::keccak256(&[
            // the version of the governance smart contract
            //
            // TODO: in the Ethereum bridge smart contracts, the version
            // fields are of type `uint8`. we might need to adjust this
            // line accordingly
            Token::Uint(ethereum::U256::from(GOVERNANCE_CONTRACT_VERSION)),
            // TODO: add the other fields
        ])
    }

    /// Returns the list of Ethereum validator addresses and their respective
    /// voting power.
    #[allow(dead_code)]
    fn get_validators_and_addresses(
        &self,
    ) -> (Vec<ethereum::Address>, Vec<ethereum::U256>) {
        // get addresses and voting powers all into one vec
        let mut unsorted: Vec<_> = self.voting_powers.iter().collect();

        // sort it by voting power, in descending order
        unsorted.sort_by(|&(_, ref power_1), &(_, ref power_2)| {
            power_2.cmp(power_1)
        });

        let sorted = unsorted;
        let total_voting_power: u64 = sorted
            .iter()
            .map(|&(_, &voting_power)| u64::from(voting_power))
            .sum();

        // split the vec into two
        sorted
            .into_iter()
            .map(|(&addr, &voting_power)| {
                let voting_power: u64 = voting_power.into();

                // normalize the voting power
                // https://github.com/anoma/ethereum-bridge/blob/main/test/utils/utilities.js#L29
                const NORMALIZED_VOTING_POWER: u64 = 1 << 32;

                let voting_power = Ratio::new(voting_power, total_voting_power)
                    * NORMALIZED_VOTING_POWER;
                let voting_power = voting_power.round().to_integer();

                let voting_power: ethereum::U256 = voting_power.into();
                (addr, voting_power)
            })
            .unzip()
    }
}
