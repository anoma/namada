//! Contains types necessary for processing validator set updates
//! in vote extensions.
use std::collections::HashMap;

use borsh::{BorshDeserialize, BorshSchema, BorshSerialize};
use ethabi::ethereum_types as ethereum;
use num_rational::Ratio;

use crate::ledger::pos::types::VotingPower;
use crate::proto::Signed;
use crate::types::address::Address;
use crate::types::ethereum_events::EthAddress;
use crate::types::keccak::encode::{AbiEncode, Encode, Token};
use crate::types::keccak::KeccakHash;
use crate::types::key::common::{self, Signature};
use crate::types::storage::BlockHeight;
#[allow(unused_imports)]
use crate::types::storage::Epoch;

// the namespace strings plugged into validator set hashes
const BRIDGE_CONTRACT_NAMESPACE: &str = "bridge";
const GOVERNANCE_CONTRACT_NAMESPACE: &str = "governance";

/// Type alias for a [`ValidatorSetUpdateVextDigest`].
pub type VextDigest = ValidatorSetUpdateVextDigest;

/// Contains the digest of all signatures from a quorum of
/// validators for a [`Vext`].
#[derive(
    Clone, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize, BorshSchema,
)]
pub struct ValidatorSetUpdateVextDigest {
    #[cfg(feature = "abcipp")]
    /// A mapping from a validator address to a [`Signature`].
    pub signatures: HashMap<Address, Signature>,
    #[cfg(not(feature = "abcipp"))]
    /// A mapping from a validator address to a [`Signature`].
    ///
    /// The key includes the block height at which a validator
    /// set was signed by a given validator.
    pub signatures: HashMap<(Address, BlockHeight), Signature>,
    /// The addresses of the validators in the new [`Epoch`],
    /// and their respective voting power.
    pub voting_powers: VotingPowersMap,
}

impl VextDigest {
    /// Decompresses a set of signed [`Vext`] instances.
    pub fn decompress(self, block_height: BlockHeight) -> Vec<SignedVext> {
        #[cfg(not(feature = "abcipp"))]
        {
            #[allow(clippy::drop_copy)]
            drop(block_height);
        }

        let VextDigest {
            signatures,
            voting_powers,
        } = self;

        let mut extensions = vec![];

        for (validator_addr, signature) in signatures.into_iter() {
            #[cfg(not(feature = "abcipp"))]
            let (validator_addr, block_height) = validator_addr;
            let voting_powers = voting_powers.clone();
            let data = Vext {
                validator_addr,
                voting_powers,
                block_height,
            };
            extensions.push(SignedVext::new_from(data, signature));
        }
        extensions
    }

    /// Returns an Ethereum ABI encoded string with the
    /// params to feed to the Ethereum bridge smart contracts.
    pub fn abi_params(&self) -> String {
        todo!()
    }
}

/// Represents a [`Vext`] signed by some validator, with
/// an Ethereum key.
pub type SignedVext = Signed<Vext, SerializeWithAbiEncode>;

/// Type alias for a [`ValidatorSetUpdateVext`].
pub type Vext = ValidatorSetUpdateVext;

/// Represents a validator set update, for some new [`Epoch`].
#[derive(
    Eq, PartialEq, Clone, Debug, BorshSerialize, BorshDeserialize, BorshSchema,
)]
pub struct ValidatorSetUpdateVext {
    /// The addresses of the validators in the new [`Epoch`],
    /// and their respective voting power.
    ///
    /// When signing a [`Vext`], this [`VotingPowersMap`] is converted
    /// into two arrays: one for its keys, and another for its
    /// values. The arrays are sorted in descending order based
    /// on the voting power of each validator.
    pub voting_powers: VotingPowersMap,
    /// TODO: the validator's address is temporarily being included
    /// until we're able to map a Tendermint address to a validator
    /// address (see <https://github.com/anoma/namada/issues/200>)
    pub validator_addr: Address,
    /// The value of the Namada [`BlockHeight`] at the creation of this
    /// [`Vext`].
    ///
    /// An important invariant is that this [`BlockHeight`] will always
    /// correspond to an epoch before the new validator set is installed.
    ///
    /// Since this is a monotonically growing sequence number,
    /// it is signed together with the rest of the data to
    /// prevent replay attacks on validator set updates.
    ///
    /// Additionally, we can use this [`BlockHeight`] value to query the
    /// epoch with the appropriate validator set to verify signatures with
    /// (i.e. the previous validator set).
    pub block_height: BlockHeight,
}

impl Vext {
    /// Creates a new signed [`Vext`].
    ///
    /// For more information, read the docs of [`SignedVext::new`].
    #[inline]
    pub fn sign(&self, sk: &common::SecretKey) -> SignedVext {
        SignedVext::new(sk, self.clone())
    }
}

/// Container type for both kinds of Ethereum bridge addresses:
///
///   - An address derived from a hot key.
///   - An address derived from a cold key.
#[derive(
    Clone,
    Debug,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
    BorshSerialize,
    BorshDeserialize,
    BorshSchema,
)]
pub struct EthAddrBook {
    /// Ethereum address derived from a hot key.
    pub hot_key_addr: EthAddress,
    /// Ethereum address derived from a cold key.
    pub cold_key_addr: EthAddress,
}

/// Provides a mapping between [`EthAddress`] and [`VotingPower`] instances.
pub type VotingPowersMap = HashMap<EthAddrBook, VotingPower>;

/// This trait contains additional methods for a [`HashMap`], related
/// with validator set update vote extensions logic.
pub trait VotingPowersMapExt {
    /// Returns the list of Ethereum validator hot and cold addresses and their
    /// respective voting power (in this order), with an Ethereum ABI
    /// compatible encoding.
    fn get_abi_encoded(&self) -> (Vec<Token>, Vec<Token>, Vec<Token>);

    /// Returns the keccak hashes of this [`VotingPowersMap`],
    /// to be signed by an Ethereum hot and cold key, respectively.
    fn get_bridge_and_gov_hashes(
        &self,
        block_height: BlockHeight,
    ) -> (KeccakHash, KeccakHash) {
        let (hot_key_addrs, cold_key_addrs, voting_powers) =
            self.get_abi_encoded();

        let bridge_hash = compute_hash(
            block_height,
            BRIDGE_CONTRACT_NAMESPACE,
            hot_key_addrs,
            voting_powers.clone(),
        );

        let governance_hash = compute_hash(
            block_height,
            GOVERNANCE_CONTRACT_NAMESPACE,
            cold_key_addrs,
            voting_powers,
        );

        (bridge_hash, governance_hash)
    }
}

impl VotingPowersMapExt for VotingPowersMap {
    fn get_abi_encoded(&self) -> (Vec<Token>, Vec<Token>, Vec<Token>) {
        // get addresses and voting powers all into one vec
        let mut unsorted: Vec<_> = self.iter().collect();

        // sort it by voting power, in descending order
        unsorted.sort_by(|&(_, ref power_1), &(_, ref power_2)| {
            power_2.cmp(power_1)
        });

        let sorted = unsorted;
        let total_voting_power: u64 = sorted
            .iter()
            .map(|&(_, &voting_power)| u64::from(voting_power))
            .sum();

        // split the vec into three portions
        sorted.into_iter().fold(
            Default::default(),
            |accum, (addr_book, &voting_power)| {
                let voting_power: u64 = voting_power.into();

                // normalize the voting power
                // https://github.com/anoma/ethereum-bridge/blob/fe93d2e95ddb193a759811a79c8464ad4d709c12/test/utils/utilities.js#L29
                const NORMALIZED_VOTING_POWER: u64 = 1 << 32;

                let voting_power = Ratio::new(voting_power, total_voting_power)
                    * NORMALIZED_VOTING_POWER;
                let voting_power = voting_power.round().to_integer();
                let voting_power: ethereum::U256 = voting_power.into();

                let (mut hot_key_addrs, mut cold_key_addrs, mut voting_powers) =
                    accum;
                let &EthAddrBook {
                    hot_key_addr: EthAddress(hot_key_addr),
                    cold_key_addr: EthAddress(cold_key_addr),
                } = addr_book;

                hot_key_addrs
                    .push(Token::Address(ethereum::H160(hot_key_addr)));
                cold_key_addrs
                    .push(Token::Address(ethereum::H160(cold_key_addr)));
                voting_powers.push(Token::Uint(voting_power));

                (hot_key_addrs, cold_key_addrs, voting_powers)
            },
        )
    }
}

/// Convert a [`BlockHeight`] to a [`Token`].
#[inline]
fn bheight_to_token(BlockHeight(h): BlockHeight) -> Token {
    Token::Uint(h.into())
}

/// Compute the keccak hash of a validator set update.
///
/// For more information, check the Ethereum bridge smart contracts:
//    - <https://github.com/anoma/ethereum-bridge/blob/main/contracts/contract/Governance.sol#L232>
//    - <https://github.com/anoma/ethereum-bridge/blob/main/contracts/contract/Bridge.sol#L201>
#[inline]
fn compute_hash(
    block_height: BlockHeight,
    namespace: &str,
    validators: Vec<Token>,
    voting_powers: Vec<Token>,
) -> KeccakHash {
    AbiEncode::keccak256(&[
        Token::String(namespace.into()),
        Token::Array(validators),
        Token::Array(voting_powers),
        bheight_to_token(block_height),
    ])
}

// this is only here so we don't pollute the
// outer namespace with serde traits
mod tag {
    use serde::{Deserialize, Serialize};

    use super::{bheight_to_token, Vext, VotingPowersMapExt};
    use crate::proto::SignedSerialize;
    use crate::types::keccak::encode::{AbiEncode, Encode, Token};
    use crate::types::keccak::KeccakHash;

    /// Tag type that indicates we should use [`AbiEncode`]
    /// to sign data in a [`crate::proto::Signed`] wrapper.
    #[derive(Eq, PartialEq, Clone, Debug, Serialize, Deserialize)]
    pub struct SerializeWithAbiEncode;

    impl SignedSerialize<Vext> for SerializeWithAbiEncode {
        type Output = [u8; 32];

        fn serialize(ext: &Vext) -> Self::Output {
            let (KeccakHash(bridge_hash), KeccakHash(gov_hash)) = ext
                .voting_powers
                .get_bridge_and_gov_hashes(ext.block_height);
            let KeccakHash(output) = AbiEncode::signed_keccak256(&[
                Token::String("updateValidatorsSet".into()),
                Token::FixedBytes(bridge_hash.to_vec()),
                Token::FixedBytes(gov_hash.to_vec()),
                bheight_to_token(ext.block_height),
            ]);
            output
        }
    }
}

#[doc(inline)]
pub use tag::SerializeWithAbiEncode;

#[cfg(test)]
mod tests {
    use super::*;

    /// Test the keccak hash of a validator set update
    #[test]
    fn test_validator_set_update_keccak_hash() {
        // ```js
        // const ethers = require('ethers');
        // const keccak256 = require('keccak256')
        //
        // const abiEncoder = new ethers.utils.AbiCoder();
        //
        // const output = abiEncoder.encode(
        //     ['string', 'address[]', 'uint256[]', 'uint256'],
        //     ['bridge', [], [], 1],
        // );
        //
        // const hash = keccak256(output).toString('hex');
        //
        // console.log(hash);
        // ```
        const EXPECTED: &str =
            "694d9bc27d5da7444e5742b13394b2c8a7e73b43d6acd52b6e23b26b612f7c86";

        let KeccakHash(got) = compute_hash(
            1u64.into(),
            BRIDGE_CONTRACT_NAMESPACE,
            vec![],
            vec![],
        );

        assert_eq!(&hex::encode(got), EXPECTED);
    }
}
