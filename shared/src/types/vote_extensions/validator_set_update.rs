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
    /// Returns the keccak hash of this [`Vext`] to be signed
    /// by an Ethereum validator key.
    pub fn get_bridge_hash(&self) -> [u8; 32] {
        // TODO: we need to get this value from `Storage`
        // related issue: https://github.com/anoma/namada/issues/249
        const BRIDGE_CONTRACT_VERSION: u8 = 1;

        const BRIDGE_CONTRACT_NAMESPACE: &str = "bridge";

        let (validators, voting_powers) =
            self.get_validators_and_voting_powers();

        self.compute_hash(
            BRIDGE_CONTRACT_VERSION,
            BRIDGE_CONTRACT_NAMESPACE,
            validators,
            voting_powers,
        )
    }

    /// Returns the keccak hash of this [`Vext`] to be signed
    /// by an Ethereum governance key.
    pub fn get_governance_hash(&self) -> [u8; 32] {
        // TODO: we need to get this value from `Storage`
        // related issue: https://github.com/anoma/namada/issues/249
        const GOVERNANCE_CONTRACT_VERSION: u8 = 1;

        const GOVERNANCE_CONTRACT_NAMESPACE: &str = "governance";

        self.compute_hash(
            GOVERNANCE_CONTRACT_VERSION,
            GOVERNANCE_CONTRACT_NAMESPACE,
            // TODO: get governance validators
            vec![],
            // TODO: get governance voting powers
            vec![],
        )
    }

    /// Compute the keccak hash of this [`Vext`].
    ///
    /// For more information, check the Ethereum bridge smart contracts:
    //    - <https://github.com/anoma/ethereum-bridge/blob/main/contracts/contract/Governance.sol#L232>
    //    - <https://github.com/anoma/ethereum-bridge/blob/main/contracts/contract/Bridge.sol#L201>
    #[inline]
    fn compute_hash(
        &self,
        version: u8,
        namespace: &str,
        validators: Vec<Token>,
        voting_powers: Vec<Token>,
    ) -> [u8; 32] {
        let nonce = u64::from(self.epoch).into();
        AbiEncode::keccak256(&[
            // TODO: in the Ethereum bridge smart contracts, the version
            // fields are of type `uint8`. we need to adjust this
            // line accordingly, since packed serialization yields
            // a different result from `uint256` for `uint8` values
            Token::Uint(ethereum::U256::from(version)),
            Token::String(namespace.into()),
            Token::Array(validators),
            Token::Array(voting_powers),
            Token::Uint(nonce),
        ])
    }

    /// Returns the list of Ethereum validator addresses and their respective
    /// voting power.
    #[allow(dead_code)]
    fn get_validators_and_voting_powers(&self) -> (Vec<Token>, Vec<Token>) {
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

                (Token::Address(addr), Token::Uint(voting_power))
            })
            .unzip()
    }
}
