//! Contains types necessary for processing validator set updates
//! in vote extensions.
use std::cmp::Ordering;
use std::collections::HashMap;
use std::ops::Deref;

use namada_core::borsh::{BorshDeserialize, BorshSchema, BorshSerialize};
use namada_core::types::address::Address;
use namada_core::types::eth_abi::{AbiEncode, Encode, Token};
use namada_core::types::ethereum_events::EthAddress;
use namada_core::types::keccak::KeccakHash;
use namada_core::types::key::common::{self, Signature};
use namada_core::types::storage::Epoch;
use namada_core::types::voting_power::{
    EthBridgeVotingPower, FractionalVotingPower,
};
use namada_core::types::{ethereum_structs, token};
use namada_tx::Signed;

// the contract versions and namespaces plugged into validator set hashes
// TODO: ideally, these values should not be hardcoded
const BRIDGE_CONTRACT_VERSION: u8 = 1;
const BRIDGE_CONTRACT_NAMESPACE: &str = "bridge";
const GOVERNANCE_CONTRACT_VERSION: u8 = 1;
const GOVERNANCE_CONTRACT_NAMESPACE: &str = "governance";

/// Type alias for a [`ValidatorSetUpdateVextDigest`].
pub type VextDigest = ValidatorSetUpdateVextDigest;

/// Contains the digest of all signatures from a quorum of
/// validators for a [`Vext`].
#[derive(
    Clone, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize, BorshSchema,
)]
pub struct ValidatorSetUpdateVextDigest {
    /// A mapping from a consensus validator address to a [`Signature`].
    pub signatures: HashMap<Address, Signature>,
    /// The addresses of the validators in the new [`Epoch`],
    /// and their respective voting power.
    pub voting_powers: VotingPowersMap,
}

impl VextDigest {
    /// Build a singleton [`VextDigest`], from the provided [`Vext`].
    #[inline]
    pub fn singleton(SignedVext(ext): SignedVext) -> VextDigest {
        VextDigest {
            signatures: HashMap::from([(
                ext.data.validator_addr.clone(),
                ext.sig,
            )]),
            voting_powers: ext.data.voting_powers,
        }
    }

    /// Decompresses a set of signed [`Vext`] instances.
    pub fn decompress(self, signing_epoch: Epoch) -> Vec<SignedVext> {
        let VextDigest {
            signatures,
            voting_powers,
        } = self;

        let mut extensions = vec![];

        for (validator_addr, signature) in signatures.into_iter() {
            let voting_powers = voting_powers.clone();
            let data = Vext {
                validator_addr,
                voting_powers,
                signing_epoch,
            };
            extensions.push(SignedVext(Signed::new_from(data, signature)));
        }
        extensions
    }
}

/// Represents a [`Vext`] signed by some validator, with
/// an Ethereum key.
#[derive(
    Clone, Debug, BorshSerialize, BorshDeserialize, BorshSchema, PartialEq, Eq,
)]
pub struct SignedVext(pub Signed<Vext, SerializeWithAbiEncode>);

impl Deref for SignedVext {
    type Target = Signed<Vext, SerializeWithAbiEncode>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

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
    /// The value of Namada's [`Epoch`] at the creation of this
    /// [`Vext`].
    ///
    /// An important invariant is that this [`Epoch`] will always
    /// correspond to an [`Epoch`] before the new validator set
    /// is installed.
    ///
    /// Since this is a monotonically growing sequence number,
    /// it is signed together with the rest of the data to
    /// prevent replay attacks on validator set updates.
    ///
    /// Additionally, we can use this [`Epoch`] value to query
    /// the appropriate validator set to verify signatures with
    /// (i.e. the previous validator set).
    pub signing_epoch: Epoch,
}

impl Vext {
    /// Creates a new signed [`Vext`].
    ///
    /// For more information, read the docs of [`SignedVext`].
    #[inline]
    pub fn sign(&self, sk: &common::SecretKey) -> SignedVext {
        SignedVext(Signed::new(sk, self.clone()))
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

/// Provides a mapping between [`EthAddress`] and [`token::Amount`] instances.
pub type VotingPowersMap = HashMap<EthAddrBook, token::Amount>;

/// This trait contains additional methods for a [`VotingPowersMap`], related
/// with validator set update vote extensions logic.
pub trait VotingPowersMapExt {
    /// Returns a [`Vec`] of pairs of validator addresses and voting powers,
    /// sorted in descending order by voting power.
    fn get_sorted(&self) -> Vec<(&EthAddrBook, &token::Amount)>;

    /// Returns the list of Ethereum validator hot and cold addresses and their
    /// respective voting powers (in this order), with an Ethereum ABI
    /// compatible encoding. Implementations of this method must be
    /// deterministic based on `self`. In addition, the returned `Vec`s must be
    /// sorted in descending order by voting power, as this is more efficient to
    /// deal with on the Ethereum side when working out if there is enough
    /// voting power for a given validator set update.
    fn get_abi_encoded(&self) -> (Vec<Token>, Vec<Token>) {
        let sorted = self.get_sorted();

        let total_voting_power: token::Amount =
            sorted.iter().map(|&(_, &voting_power)| voting_power).sum();

        // split the vec into two portions
        sorted
            .into_iter()
            .map(|(addr_book, &voting_power)| {
                let voting_power: EthBridgeVotingPower =
                    FractionalVotingPower::new(
                        voting_power.into(),
                        total_voting_power.into(),
                    )
                    .expect(
                        "Voting power in map can't be larger than the total \
                         voting power",
                    )
                    .into();

                let &EthAddrBook {
                    hot_key_addr,
                    cold_key_addr,
                } = addr_book;

                (
                    Token::FixedBytes(
                        encode_validator_data(hot_key_addr, voting_power)
                            .into(),
                    ),
                    Token::FixedBytes(
                        encode_validator_data(cold_key_addr, voting_power)
                            .into(),
                    ),
                )
            })
            .unzip()
    }

    /// Returns the bridge and governance keccak hashes of
    /// this [`VotingPowersMap`].
    #[inline]
    fn get_bridge_and_gov_hashes(
        &self,
        next_epoch: Epoch,
    ) -> (KeccakHash, KeccakHash) {
        let (bridge_validators, governance_validators) = self.get_abi_encoded();
        valset_upd_toks_to_hashes(
            next_epoch,
            bridge_validators,
            governance_validators,
        )
    }
}

/// Returns the bridge and governance keccak hashes calculated from
/// the given hot and cold key addresses, and their respective validator's
/// voting powers, normalized to `2^32`.
pub fn valset_upd_toks_to_hashes(
    next_epoch: Epoch,
    bridge_validators: Vec<Token>,
    governance_validators: Vec<Token>,
) -> (KeccakHash, KeccakHash) {
    let bridge_hash = compute_hash(
        next_epoch,
        BRIDGE_CONTRACT_VERSION,
        BRIDGE_CONTRACT_NAMESPACE,
        bridge_validators,
    );
    let governance_hash = compute_hash(
        next_epoch,
        GOVERNANCE_CONTRACT_VERSION,
        GOVERNANCE_CONTRACT_NAMESPACE,
        governance_validators,
    );
    (bridge_hash, governance_hash)
}

/// Compare two items of [`VotingPowersMap`]. This comparison operation must
/// match the equivalent comparison operation in Ethereum bridge code.
fn compare_voting_powers_map_items(
    first: &(&EthAddrBook, &token::Amount),
    second: &(&EthAddrBook, &token::Amount),
) -> Ordering {
    let (first_power, second_power) = (first.1, second.1);
    let (first_addr, second_addr) = (first.0, second.0);
    match second_power.cmp(first_power) {
        Ordering::Equal => first_addr.cmp(second_addr),
        ordering => ordering,
    }
}

impl VotingPowersMapExt for VotingPowersMap {
    fn get_sorted(&self) -> Vec<(&EthAddrBook, &token::Amount)> {
        let mut pairs: Vec<_> = self.iter().collect();
        pairs.sort_by(compare_voting_powers_map_items);
        pairs
    }
}

/// Convert an [`Epoch`] to a [`Token`].
#[inline]
fn epoch_to_token(Epoch(e): Epoch) -> Token {
    Token::Uint(e.into())
}

/// Compute the keccak hash of a validator set update.
///
/// For more information, check the specs of the Ethereum bridge smart
/// contracts.
#[inline]
fn compute_hash(
    next_epoch: Epoch,
    contract_version: u8,
    contract_namespace: &str,
    validators: Vec<Token>,
) -> KeccakHash {
    AbiEncode::keccak256(&[
        Token::Uint(contract_version.into()),
        Token::String(contract_namespace.into()),
        Token::Array(validators),
        epoch_to_token(next_epoch),
    ])
}

/// Given a validator's [`EthAddress`] and its respective
/// [`EthBridgeVotingPower`], return an encoded representation
/// of this data, understood by the smart contract.
#[inline]
fn encode_validator_data(
    address: EthAddress,
    voting_power: EthBridgeVotingPower,
) -> [u8; 32] {
    let address = address.0;
    let voting_power = u128::from(voting_power).to_be_bytes();

    let mut buffer = [0u8; 32];
    buffer[..20].copy_from_slice(&address);
    buffer[20..].copy_from_slice(&voting_power[4..]);

    buffer
}

/// Struct for serializing validator set
/// arguments with ABI for Ethereum smart
/// contracts.
#[derive(
    Debug,
    Clone,
    Default,
    Eq,
    PartialEq,
    BorshSerialize,
    BorshDeserialize,
    BorshSchema,
)]
// TODO: find a new home for this type
pub struct ValidatorSetArgs {
    /// Ethereum addresses of the validators.
    pub validators: Vec<EthAddress>,
    /// The voting powers of the validators.
    pub voting_powers: Vec<EthBridgeVotingPower>,
    /// The epoch when the validators were part of
    /// the consensus set of validators.
    ///
    /// Serves as a nonce.
    pub epoch: Epoch,
}

impl From<ValidatorSetArgs> for ethereum_structs::ValidatorSetArgs {
    fn from(valset: ValidatorSetArgs) -> Self {
        let ValidatorSetArgs {
            validators,
            voting_powers,
            epoch,
        } = valset;
        ethereum_structs::ValidatorSetArgs {
            validator_set: validators
                .into_iter()
                .zip(voting_powers.into_iter())
                .map(|(addr, power)| encode_validator_data(addr, power))
                .collect(),
            nonce: epoch.0.into(),
        }
    }
}

impl Encode<1> for ValidatorSetArgs {
    fn tokenize(&self) -> [Token; 1] {
        let validator_set = Token::Array(
            self.validators
                .iter()
                .zip(self.voting_powers.iter())
                .map(|(&addr, &power)| {
                    Token::FixedBytes(encode_validator_data(addr, power).into())
                })
                .collect(),
        );
        let nonce = Token::Uint(self.epoch.0.into());
        [Token::Tuple(vec![validator_set, nonce])]
    }
}

// this is only here so we don't pollute the
// outer namespace with serde traits
mod tag {
    use namada_core::types::eth_abi::{AbiEncode, Encode, Token};
    use namada_core::types::hash::KeccakHasher;
    use namada_core::types::keccak::KeccakHash;
    use namada_core::types::key::Signable;
    use serde::{Deserialize, Serialize};

    use super::{
        epoch_to_token, Vext, VotingPowersMapExt, GOVERNANCE_CONTRACT_VERSION,
    };

    /// Tag type that indicates we should use [`AbiEncode`]
    /// to sign data in a [`namada_tx::Signed`] wrapper.
    #[derive(Eq, PartialEq, Clone, Debug, Serialize, Deserialize)]
    pub struct SerializeWithAbiEncode;

    impl Signable<Vext> for SerializeWithAbiEncode {
        type Hasher = KeccakHasher;
        type Output = KeccakHash;

        fn as_signable(ext: &Vext) -> Self::Output {
            // NOTE: the smart contract expects us to sign
            // against the next nonce (i.e. the new epoch)
            let next_epoch = ext.signing_epoch.next();
            let (KeccakHash(bridge_hash), KeccakHash(gov_hash)) =
                ext.voting_powers.get_bridge_and_gov_hashes(next_epoch);
            AbiEncode::signable_keccak256(&[
                Token::Uint(GOVERNANCE_CONTRACT_VERSION.into()),
                Token::String("updateValidatorSet".into()),
                Token::FixedBytes(bridge_hash.to_vec()),
                Token::FixedBytes(gov_hash.to_vec()),
                epoch_to_token(next_epoch),
            ])
        }
    }
}

#[doc(inline)]
pub use tag::SerializeWithAbiEncode;

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use data_encoding::HEXLOWER;
    use namada_core::types::ethereum_events::EthAddress;

    use super::*;

    /// Test the keccak hash of a validator set update
    #[test]
    fn test_validator_set_update_keccak_hash() {
        // ```js
        // const ethers = require('ethers');
        // const keccak256 = require('keccak256')
        //
        // const abiEncoder = new ethers.AbiCoder();
        //
        // const output = abiEncoder.encode(
        //     ['uint256', 'string', 'bytes32[]', 'uint256'],
        //     [1, 'bridge', [], 1],
        // );
        //
        // const hash = keccak256(output).toString('hex');
        //
        // console.log(hash);
        // ```
        const EXPECTED: &str =
            "b97454f4c266c0d223651a52a705d76f3be337ace04be4590d9aedab9818dabc";

        let KeccakHash(got) = compute_hash(
            1u64.into(),
            BRIDGE_CONTRACT_VERSION,
            BRIDGE_CONTRACT_NAMESPACE,
            vec![],
        );

        assert_eq!(&HEXLOWER.encode(&got[..]), EXPECTED);
    }

    /// Checks that comparing two [`VotingPowersMap`] items which have the same
    /// voting powers but different [`EthAddrBook`]s does not result in them
    /// being regarded as equal.
    #[test]
    fn test_compare_voting_powers_map_items_identical_voting_powers() {
        let same_voting_power = 200.into();

        let validator_a = EthAddrBook {
            hot_key_addr: EthAddress([0; 20]),
            cold_key_addr: EthAddress([0; 20]),
        };
        let validator_b = EthAddrBook {
            hot_key_addr: EthAddress([1; 20]),
            cold_key_addr: EthAddress([1; 20]),
        };

        assert_eq!(
            compare_voting_powers_map_items(
                &(&validator_a, &same_voting_power),
                &(&validator_b, &same_voting_power),
            ),
            Ordering::Less
        );
    }

    /// Checks that comparing two [`VotingPowersMap`] items with different
    /// voting powers results in the item with the lesser voting power being
    /// regarded as "greater".
    #[test]
    fn test_compare_voting_powers_map_items_different_voting_powers() {
        let validator_a = EthAddrBook {
            hot_key_addr: EthAddress([0; 20]),
            cold_key_addr: EthAddress([0; 20]),
        };
        let validator_a_voting_power = 200.into();
        let validator_b = EthAddrBook {
            hot_key_addr: EthAddress([1; 20]),
            cold_key_addr: EthAddress([1; 20]),
        };
        let validator_b_voting_power = 100.into();

        assert_eq!(
            compare_voting_powers_map_items(
                &(&validator_a, &validator_a_voting_power),
                &(&validator_b, &validator_b_voting_power),
            ),
            Ordering::Less
        );
    }

    /// Checks that [`VotingPowersMapExt::get_abi_encoded`] gives a
    /// deterministic result in the case where there are multiple validators
    /// with the same voting power.
    ///
    /// NB: this test may pass even if the implementation is not
    /// deterministic unless the test is run with the `--release` profile, as it
    /// is implicitly relying on how iterating over a [`HashMap`] seems to
    /// return items in the order in which they were inserted, at least for this
    /// very small 2-item example.
    #[test]
    fn test_voting_powers_map_get_abi_encoded_deterministic_with_identical_voting_powers()
     {
        let validator_a = EthAddrBook {
            hot_key_addr: EthAddress([0; 20]),
            cold_key_addr: EthAddress([0; 20]),
        };
        let validator_b = EthAddrBook {
            hot_key_addr: EthAddress([1; 20]),
            cold_key_addr: EthAddress([1; 20]),
        };
        let same_voting_power = 200.into();

        let mut voting_powers_1 = VotingPowersMap::default();
        voting_powers_1.insert(validator_a.clone(), same_voting_power);
        voting_powers_1.insert(validator_b.clone(), same_voting_power);

        let mut voting_powers_2 = VotingPowersMap::default();
        voting_powers_2.insert(validator_b, same_voting_power);
        voting_powers_2.insert(validator_a, same_voting_power);

        let x = voting_powers_1.get_abi_encoded();
        let y = voting_powers_2.get_abi_encoded();
        assert_eq!(x, y);
    }

    #[test]
    fn test_abi_encode_valset_args() {
        let valset_update = ValidatorSetArgs {
            validators: vec![
                EthAddress::from_str(
                    "0x241D37B7Cf5233b3b0b204321420A86e8f7bfdb5",
                )
                .expect("Test failed"),
            ],
            voting_powers: vec![8828299u64.into()],
            epoch: 0.into(),
        };
        let encoded = valset_update.encode().into_inner();
        let encoded = HEXLOWER.encode(&encoded);
        let expected = "000000000000000000000000000000000000000000000000000000000000002\
                        000000000000000000000000000000000000000000000000000000000000000\
                        400000000000000000000000000000000000000000000000000000000000000\
                        000000000000000000000000000000000000000000000000000000000000000\
                        0001241d37b7cf5233b3b0b204321420a86e8f7bfdb50000000000000000008\
                        6b58b";
        assert_eq!(expected, encoded);
    }
}
