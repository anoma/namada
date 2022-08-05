//! Contains types necessary for processing validator set updates
//! in vote extensions.

pub mod encoding;

use std::collections::HashMap;

use borsh::{BorshDeserialize, BorshSchema, BorshSerialize};
use encoding::{AbiEncode, Encode, Token};
use ethabi::ethereum_types as ethereum;
use num_rational::Ratio;

use crate::ledger::pos::types::{Epoch, VotingPower};
use crate::proto::Signed;
use crate::types::address::Address;
use crate::types::key::common::{self, Signature};

// TODO: we need to get these values from `Storage`
// related issue: https://github.com/anoma/namada/issues/249
const BRIDGE_CONTRACT_VERSION: u8 = 1;
const GOVERNANCE_CONTRACT_VERSION: u8 = 1;

// the namespace strings plugged into validator set hashes
const BRIDGE_CONTRACT_NAMESPACE: &str = "bridge";
const GOVERNANCE_CONTRACT_NAMESPACE: &str = "governance";

/// Wrapper type for [`ethereum::Address`]
#[derive(Copy, Clone, Debug, Hash, PartialEq, Eq, PartialOrd, Ord)]
pub struct EthAddr(pub ethereum::Address);

impl BorshSerialize for EthAddr {
    fn serialize<W: ark_serialize::Write>(
        &self,
        writer: &mut W,
    ) -> std::io::Result<()> {
        let EthAddr(ethereum::H160(inner_array)) = self;
        inner_array.serialize(writer)
    }
}

impl BorshDeserialize for EthAddr {
    fn deserialize(buf: &mut &[u8]) -> std::io::Result<Self> {
        let inner = <[u8; 20]>::deserialize(buf)?;
        Ok(EthAddr(ethereum::H160(inner)))
    }
}

impl BorshSchema for EthAddr {
    fn add_definitions_recursively(
        definitions: &mut std::collections::HashMap<
            borsh::schema::Declaration,
            borsh::schema::Definition,
        >,
    ) {
        let fields =
            borsh::schema::Fields::UnnamedFields(borsh::maybestd::vec![
                <[u8; 20]>::declaration()
            ]);
        let definition = borsh::schema::Definition::Struct { fields };
        Self::add_definition(Self::declaration(), definition, definitions);
    }

    fn declaration() -> borsh::schema::Declaration {
        "validator_set_update::EthAddr".into()
    }
}

/// Contains the digest of all signatures from a quorum of
/// validators for a [`Vext`].
#[derive(Clone, Debug, BorshSerialize, BorshDeserialize, BorshSchema)]
pub struct VextDigest {
    /// A mapping from a validator address to a [`Signature`].
    pub signatures: HashMap<Address, Signature>,
    /// The addresses of the validators in the new [`Epoch`],
    /// and their respective voting power.
    pub voting_powers: HashMap<EthAddr, VotingPower>,
}

impl VextDigest {
    /// Decompresses a set of signed [`Vext`] instances.
    pub fn decompress(self, epoch: Epoch) -> Vec<SignedVext> {
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
                epoch,
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

impl SignedVext {
    /// Sign this [`Vext`] with an Ethereum key.
    ///
    /// For more information, check the Ethereum bridge smart contract code:
    ///   - <https://github.com/anoma/ethereum-bridge/blob/main/contracts/contract/Bridge.sol#L186>
    pub fn new_abi_encoded(
        _keypair: &common::SecretKey,
        _vote_extension: Vext,
    ) -> Self {
        todo!()
    }

    // TODO: verify
}

/// Represents a validator set update, for some new [`Epoch`].
#[derive(
    Eq, PartialEq, Clone, Debug, BorshSerialize, BorshDeserialize, BorshSchema,
)]
pub struct Vext {
    /// The addresses of the validators in the new [`Epoch`],
    /// and their respective voting power.
    ///
    /// When signing a [`Vext`], this [`HashMap`] is converted
    /// into two arrays: one for its keys, and another for its
    /// values. The arrays are sorted in descending order based
    /// on the voting power of each validator.
    pub voting_powers: HashMap<EthAddr, VotingPower>,
    /// TODO: the validator's address is temporarily being included
    /// until we're able to map a Tendermint address to a validator
    /// address (see https://github.com/anoma/namada/issues/200)
    pub validator_addr: Address,
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
    #[inline]
    pub fn get_bridge_hash(&self) -> [u8; 32] {
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
    #[inline]
    pub fn get_governance_hash(&self) -> [u8; 32] {
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
            Token::Uint(ethereum::U256::from(version)),
            Token::String(namespace.into()),
            Token::Array(validators),
            Token::Array(voting_powers),
            Token::Uint(nonce),
        ])
    }

    /// Returns the list of Ethereum validator addresses and their respective
    /// voting power.
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
            .map(|(&EthAddr(addr), &voting_power)| {
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

    /// Creates a new signed [`Vext`].
    ///
    /// For more information, read the docs of [`SignedVext::new`].
    #[inline]
    pub fn sign(&self, sk: &common::SecretKey) -> SignedVext {
        SignedVext::new_abi_encoded(sk, self.clone())
    }
}

// this is only here so we don't pollute the
// outer namespace with serde traits
mod tag {
    use serde::{Deserialize, Serialize};

    /// Tag type that indicates we should use [`super::encoding::AbiEncode`]
    /// to sign data in a [`crate::proto::Signed`] wrapper.
    #[derive(Eq, PartialEq, Clone, Debug, Serialize, Deserialize)]
    pub enum SerializeWithAbiEncode {}
}

#[doc(inline)]
pub use tag::SerializeWithAbiEncode;
