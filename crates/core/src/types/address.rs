//! Implements transparent addresses as described in [Accounts
//! Addresses](docs/src/explore/design/ledger/accounts.md#addresses).

mod raw;

use std::collections::HashMap;
use std::fmt::{Debug, Display};
use std::hash::Hash;
use std::str::FromStr;

use borsh::{BorshDeserialize, BorshSchema, BorshSerialize};
use borsh_ext::BorshSerializeExt;
use data_encoding::HEXUPPER;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::ibc::primitives::Signer;
use crate::impl_display_and_from_str_via_format;
use crate::types::ethereum_events::EthAddress;
use crate::types::ibc::IbcTokenHash;
use crate::types::key::PublicKeyHash;
use crate::types::token::Denomination;
use crate::types::{key, string_encoding};

/// The length of an established [`Address`] encoded with Borsh.
pub const ESTABLISHED_ADDRESS_BYTES_LEN: usize = 21;

/// The length of [`Address`] encoded with Bech32m.
// NOTE: This must be kept in sync with the bech32 HRP.
// Uppercase prefixes might result in a different length,
// so tread carefully when changing this value.
pub const ADDRESS_LEN: usize =
    string_encoding::hrp_len::<Address>() + 1 + HASH_HEX_LEN;

/// Length of a hash of an address as a hexadecimal string
pub const HASH_HEX_LEN: usize = 40;

/// Length of a trimmed hash of an address.
pub const HASH_LEN: usize = 20;

/// SHA-256 hash len
///
/// ```
/// use sha2::Digest;
/// assert_eq!(
///     sha2::Sha256::output_size(),
///     namada_core::types::address::SHA_HASH_LEN
/// );
/// ```
pub const SHA_HASH_LEN: usize = 32;

/// Internal IBC address
pub const IBC: Address = Address::Internal(InternalAddress::Ibc);
/// Internal ledger parameters address
pub const PARAMETERS: Address = Address::Internal(InternalAddress::Parameters);
/// Internal PoS address
pub const POS: Address = Address::Internal(InternalAddress::PoS);
/// Internal PoS slash pool address
pub const POS_SLASH_POOL: Address =
    Address::Internal(InternalAddress::PosSlashPool);
/// Internal Governance address
pub const GOV: Address = Address::Internal(InternalAddress::Governance);
/// Internal MASP address
pub const MASP: Address = Address::Internal(InternalAddress::Masp);
/// Internal Multitoken address
pub const MULTITOKEN: Address = Address::Internal(InternalAddress::Multitoken);

/// Error from decoding address from string
pub type DecodeError = string_encoding::DecodeError;

/// Result of decoding address from string
pub type Result<T> = std::result::Result<T, DecodeError>;

/// An account's address
#[derive(
    Clone, BorshSerialize, BorshDeserialize, BorshSchema, PartialEq, Eq, Hash,
)]
pub enum Address {
    /// An established address is generated on-chain
    Established(EstablishedAddress),
    /// An implicit address is derived from a cryptographic key
    Implicit(ImplicitAddress),
    /// An internal address represents a module with a native VP
    Internal(InternalAddress),
}

impl From<raw::Address<'_, raw::Validated>> for Address {
    fn from(raw_addr: raw::Address<'_, raw::Validated>) -> Self {
        match raw_addr.discriminant() {
            raw::Discriminant::Implicit => Address::Implicit(ImplicitAddress(
                PublicKeyHash(*raw_addr.data()),
            )),
            raw::Discriminant::Established => {
                Address::Established(EstablishedAddress {
                    hash: *raw_addr.data(),
                })
            }
            raw::Discriminant::Pos => Address::Internal(InternalAddress::PoS),
            raw::Discriminant::SlashPool => {
                Address::Internal(InternalAddress::PosSlashPool)
            }
            raw::Discriminant::Parameters => {
                Address::Internal(InternalAddress::Parameters)
            }
            raw::Discriminant::Governance => {
                Address::Internal(InternalAddress::Governance)
            }
            raw::Discriminant::Ibc => Address::Internal(InternalAddress::Ibc),
            raw::Discriminant::EthBridge => {
                Address::Internal(InternalAddress::EthBridge)
            }
            raw::Discriminant::BridgePool => {
                Address::Internal(InternalAddress::EthBridgePool)
            }
            raw::Discriminant::Multitoken => {
                Address::Internal(InternalAddress::Multitoken)
            }
            raw::Discriminant::Pgf => Address::Internal(InternalAddress::Pgf),
            raw::Discriminant::Erc20 => Address::Internal(
                InternalAddress::Erc20(EthAddress(*raw_addr.data())),
            ),
            raw::Discriminant::Nut => Address::Internal(InternalAddress::Nut(
                EthAddress(*raw_addr.data()),
            )),
            raw::Discriminant::IbcToken => Address::Internal(
                InternalAddress::IbcToken(IbcTokenHash(*raw_addr.data())),
            ),
            raw::Discriminant::Masp => Address::Internal(InternalAddress::Masp),
        }
    }
}

impl From<Address> for raw::Address<'static, raw::Validated> {
    #[inline]
    fn from(address: Address) -> Self {
        raw::Address::from(&address).to_owned()
    }
}

impl<'addr> From<&'addr Address> for raw::Address<'addr, raw::Validated> {
    fn from(address: &'addr Address) -> Self {
        match address {
            Address::Established(EstablishedAddress { hash }) => {
                raw::Address::from_discriminant(raw::Discriminant::Established)
                    .with_data_array_ref(hash)
                    .validate()
                    .expect("This raw address is valid")
            }
            Address::Implicit(ImplicitAddress(key::PublicKeyHash(pkh))) => {
                raw::Address::from_discriminant(raw::Discriminant::Implicit)
                    .with_data_array_ref(pkh)
                    .validate()
                    .expect("This raw address is valid")
            }
            Address::Internal(InternalAddress::PoS) => {
                raw::Address::from_discriminant(raw::Discriminant::Pos)
                    .validate()
                    .expect("This raw address is valid")
            }
            Address::Internal(InternalAddress::PosSlashPool) => {
                raw::Address::from_discriminant(raw::Discriminant::SlashPool)
                    .validate()
                    .expect("This raw address is valid")
            }
            Address::Internal(InternalAddress::Parameters) => {
                raw::Address::from_discriminant(raw::Discriminant::Parameters)
                    .validate()
                    .expect("This raw address is valid")
            }
            Address::Internal(InternalAddress::Governance) => {
                raw::Address::from_discriminant(raw::Discriminant::Governance)
                    .validate()
                    .expect("This raw address is valid")
            }
            Address::Internal(InternalAddress::Ibc) => {
                raw::Address::from_discriminant(raw::Discriminant::Ibc)
                    .validate()
                    .expect("This raw address is valid")
            }
            Address::Internal(InternalAddress::IbcToken(IbcTokenHash(
                hash,
            ))) => raw::Address::from_discriminant(raw::Discriminant::IbcToken)
                .with_data_array_ref(hash)
                .validate()
                .expect("This raw address is valid"),
            Address::Internal(InternalAddress::EthBridge) => {
                raw::Address::from_discriminant(raw::Discriminant::EthBridge)
                    .validate()
                    .expect("This raw address is valid")
            }
            Address::Internal(InternalAddress::EthBridgePool) => {
                raw::Address::from_discriminant(raw::Discriminant::BridgePool)
                    .validate()
                    .expect("This raw address is valid")
            }
            Address::Internal(InternalAddress::Erc20(EthAddress(eth_addr))) => {
                raw::Address::from_discriminant(raw::Discriminant::Erc20)
                    .with_data_array_ref(eth_addr)
                    .validate()
                    .expect("This raw address is valid")
            }
            Address::Internal(InternalAddress::Nut(EthAddress(eth_addr))) => {
                raw::Address::from_discriminant(raw::Discriminant::Nut)
                    .with_data_array_ref(eth_addr)
                    .validate()
                    .expect("This raw address is valid")
            }
            Address::Internal(InternalAddress::Multitoken) => {
                raw::Address::from_discriminant(raw::Discriminant::Multitoken)
                    .validate()
                    .expect("This raw address is valid")
            }
            Address::Internal(InternalAddress::Pgf) => {
                raw::Address::from_discriminant(raw::Discriminant::Pgf)
                    .validate()
                    .expect("This raw address is valid")
            }
            Address::Internal(InternalAddress::Masp) => {
                raw::Address::from_discriminant(raw::Discriminant::Masp)
                    .validate()
                    .expect("This raw address is valid")
            }
        }
    }
}

// We're using the string format of addresses (bech32m) for ordering to ensure
// that addresses as strings, storage keys and storage keys as strings preserve
// the order.
impl PartialOrd for Address {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        self.encode().partial_cmp(&other.encode())
    }
}

impl Ord for Address {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.encode().cmp(&other.encode())
    }
}

impl Address {
    /// Encode an address with Bech32m encoding
    pub fn encode(&self) -> String {
        string_encoding::Format::encode(self)
    }

    /// Decode an address from Bech32m encoding
    pub fn decode(string: impl AsRef<str>) -> Result<Self> {
        string_encoding::Format::decode(string)
    }

    /// Try to get a raw hash of an address, only defined for established and
    /// implicit addresses.
    pub fn raw_hash(&self) -> Option<String> {
        match self {
            Address::Established(established) => {
                let hash_hex = HEXUPPER.encode(&established.hash);
                Some(hash_hex)
            }
            Address::Implicit(ImplicitAddress(implicit)) => {
                let hash_hex = HEXUPPER.encode(&implicit.0);
                Some(hash_hex)
            }
            Address::Internal(_) => None,
        }
    }

    fn pretty_fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.to_pretty_string())
    }

    /// Print the type of the address and its bech32m encoded value
    pub fn to_pretty_string(&self) -> String {
        match self {
            Address::Established(_) => {
                format!("Established: {}", self.encode())
            }
            Address::Implicit(_) => {
                format!("Implicit: {}", self.encode())
            }
            Address::Internal(kind) => {
                format!("Internal {}: {}", kind, self.encode())
            }
        }
    }

    /// If the address established?
    pub fn is_established(&self) -> bool {
        matches!(self, Address::Established(_))
    }

    /// If the address implicit?
    pub fn is_implicit(&self) -> bool {
        matches!(self, Address::Implicit(_))
    }
}

impl string_encoding::Format for Address {
    type EncodedBytes<'a> = [u8; raw::ADDR_ENCODING_LEN];

    const HRP: &'static str = string_encoding::ADDRESS_HRP;

    fn to_bytes(&self) -> [u8; raw::ADDR_ENCODING_LEN] {
        let raw_addr: raw::Address<'_, _> = self.into();
        raw_addr.to_bytes()
    }

    fn decode_bytes(bytes: &[u8]) -> Result<Self> {
        let unvalidated_raw_addr = raw::Address::try_from_slice(bytes)
            .ok_or_else(|| {
                DecodeError::InvalidInnerEncoding(
                    "Invalid raw address length".to_string(),
                )
            })?;
        let validated_raw_addr =
            unvalidated_raw_addr.validate().ok_or_else(|| {
                DecodeError::InvalidInnerEncoding(
                    "Invalid address discriminant and data pair".to_string(),
                )
            })?;
        Ok(validated_raw_addr.into())
    }
}

impl_display_and_from_str_via_format!(Address);

impl serde::Serialize for Address {
    fn serialize<S>(
        &self,
        serializer: S,
    ) -> std::result::Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let encoded = self.encode();
        serde::Serialize::serialize(&encoded, serializer)
    }
}

impl<'de> serde::Deserialize<'de> for Address {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        use serde::de::Error;
        let encoded: String = serde::Deserialize::deserialize(deserializer)?;
        Self::decode(encoded).map_err(D::Error::custom)
    }
}

impl Debug for Address {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.pretty_fmt(f)
    }
}

// compute an Address from an IBC signer
impl TryFrom<Signer> for Address {
    type Error = DecodeError;

    fn try_from(signer: Signer) -> Result<Self> {
        // The given address should be an address or payment address. When
        // sending a token from a spending key, it has been already
        // replaced with the MASP address.
        Address::decode(signer.as_ref()).or(
            match crate::types::masp::PaymentAddress::from_str(signer.as_ref())
            {
                Ok(_) => Ok(MASP),
                Err(_) => Err(DecodeError::InvalidInnerEncoding(format!(
                    "Invalid address for IBC transfer: {signer}"
                ))),
            },
        )
    }
}

/// An established address is generated on-chain
#[derive(
    Debug,
    Clone,
    BorshSerialize,
    BorshDeserialize,
    BorshSchema,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
    Serialize,
    Deserialize,
)]
pub struct EstablishedAddress {
    hash: [u8; HASH_LEN],
}

impl From<[u8; HASH_LEN]> for EstablishedAddress {
    fn from(hash: [u8; HASH_LEN]) -> Self {
        Self { hash }
    }
}

impl From<[u8; SHA_HASH_LEN]> for EstablishedAddress {
    fn from(input_hash: [u8; SHA_HASH_LEN]) -> Self {
        let mut hash = [0; HASH_LEN];
        hash.copy_from_slice(&input_hash[..HASH_LEN]);
        Self { hash }
    }
}

impl string_encoding::Format for EstablishedAddress {
    type EncodedBytes<'a> = [u8; raw::ADDR_ENCODING_LEN];

    const HRP: &'static str = string_encoding::ADDRESS_HRP;

    #[inline]
    fn to_bytes(&self) -> [u8; raw::ADDR_ENCODING_LEN] {
        Address::Established(self.hash.into()).to_bytes()
    }

    #[inline]
    fn decode_bytes(bytes: &[u8]) -> Result<Self> {
        match Address::decode_bytes(bytes)? {
            Address::Established(established) => Ok(established),
            address => Err(DecodeError::InvalidInnerEncoding(format!(
                "Expected established address, got {address:?}"
            ))),
        }
    }
}

impl_display_and_from_str_via_format!(EstablishedAddress);

/// A generator of established addresses
#[derive(
    Debug,
    Default,
    Clone,
    PartialEq,
    Eq,
    BorshSerialize,
    BorshDeserialize,
    Serialize,
    Deserialize,
)]
pub struct EstablishedAddressGen {
    last_hash: [u8; SHA_HASH_LEN],
}

impl EstablishedAddressGen {
    /// Initialize a new address generator with a given randomness seed.
    pub fn new(seed: impl AsRef<str>) -> Self {
        Self {
            last_hash: Sha256::digest(seed.as_ref().as_bytes()).into(),
        }
    }

    /// Generate a new established address. Requires a source of randomness as
    /// arbitrary bytes. In the ledger, this could be some unpredictable value,
    /// such as hash of the transaction that has initialized the new address.
    pub fn generate_address(
        &mut self,
        rng_source: impl AsRef<[u8]>,
    ) -> Address {
        let gen_bytes = self.serialize_to_vec();
        let bytes = [&gen_bytes, rng_source.as_ref()].concat();
        let full_hash = Sha256::digest(&bytes);
        // take first 20 bytes of the hash
        let mut hash: [u8; HASH_LEN] = Default::default();
        hash.copy_from_slice(&full_hash[..HASH_LEN]);
        self.last_hash = full_hash.into();
        Address::Established(EstablishedAddress { hash })
    }
}

/// An implicit address is derived from a cryptographic key
#[derive(
    Debug,
    Clone,
    Default,
    BorshSerialize,
    BorshDeserialize,
    BorshSchema,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
    Serialize,
    Deserialize,
)]
pub struct ImplicitAddress(pub key::PublicKeyHash);

impl From<&key::common::PublicKey> for ImplicitAddress {
    fn from(pk: &key::common::PublicKey) -> Self {
        ImplicitAddress(pk.into())
    }
}

impl From<&key::common::PublicKey> for Address {
    fn from(pk: &key::common::PublicKey) -> Self {
        Self::Implicit(pk.into())
    }
}

/// An internal address represents a module with a native VP
#[derive(
    Debug,
    Clone,
    BorshSerialize,
    BorshDeserialize,
    BorshSchema,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
    Serialize,
    Deserialize,
)]
pub enum InternalAddress {
    /// Proof-of-stake
    PoS,
    /// Proof-of-stake slash pool contains slashed tokens
    PosSlashPool,
    /// Protocol parameters
    Parameters,
    /// Inter-blockchain communication
    Ibc,
    /// IBC-related token
    IbcToken(IbcTokenHash),
    /// Governance address
    Governance,
    /// Bridge to Ethereum
    EthBridge,
    /// The pool of transactions to be relayed to Ethereum
    EthBridgePool,
    /// ERC20 token for Ethereum bridge
    Erc20(EthAddress),
    /// Non-usable ERC20 tokens
    Nut(EthAddress),
    /// Multitoken
    Multitoken,
    /// Pgf
    Pgf,
    /// Masp
    Masp,
}

impl Display for InternalAddress {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}",
            match self {
                Self::PoS => "PoS".to_string(),
                Self::PosSlashPool => "PosSlashPool".to_string(),
                Self::Parameters => "Parameters".to_string(),
                Self::Governance => "Governance".to_string(),
                Self::Ibc => "IBC".to_string(),
                Self::IbcToken(hash) => format!("IbcToken: {}", hash),
                Self::EthBridge => "EthBridge".to_string(),
                Self::EthBridgePool => "EthBridgePool".to_string(),
                Self::Erc20(eth_addr) => format!("Erc20: {}", eth_addr),
                Self::Nut(eth_addr) => format!("Non-usable token: {eth_addr}"),
                Self::Multitoken => "Multitoken".to_string(),
                Self::Pgf => "PublicGoodFundings".to_string(),
                Self::Masp => "MASP".to_string(),
            }
        )
    }
}

impl InternalAddress {
    /// Certain internal addresses have reserved aliases.
    pub fn try_from_alias(alias: &str) -> Option<Self> {
        match alias {
            "pos" => Some(InternalAddress::PoS),
            "ibc" => Some(InternalAddress::Ibc),
            "ethbridge" => Some(InternalAddress::EthBridge),
            "bridgepool" => Some(InternalAddress::EthBridgePool),
            "governance" => Some(InternalAddress::Governance),
            "masp" => Some(InternalAddress::Masp),
            _ => None,
        }
    }
}

/// Temporary helper for testing
pub fn nam() -> Address {
    Address::decode("tnam1q99c37u38grkdcc2qze0hz4zjjd8zr3yucd3mzgz")
        .expect("The token address decoding shouldn't fail")
}

/// Temporary helper for testing
pub fn btc() -> Address {
    Address::decode("tnam1qy7jxng788scr4fdqxqxtc2ze2guq5478cml9cd9")
        .expect("The token address decoding shouldn't fail")
}

/// Temporary helper for testing
pub fn eth() -> Address {
    Address::decode("tnam1qyr9vd8ltunq72qc7pk58v7jdsedt4mggqqpxs03")
        .expect("The token address decoding shouldn't fail")
}

/// Temporary helper for testing
pub fn dot() -> Address {
    Address::decode("tnam1qx6k4wau5t6m8g2hjq55fje2ynpvh5t27s8p3p0l")
        .expect("The token address decoding shouldn't fail")
}

/// Temporary helper for testing
pub fn schnitzel() -> Address {
    Address::decode("tnam1q9euzsu2qfv4y6p0dqaga20n0u0yp8c3ec006yg2")
        .expect("The token address decoding shouldn't fail")
}

/// Temporary helper for testing
pub fn apfel() -> Address {
    Address::decode("tnam1qxlmdmw2y6hzvjg34zca8r6d4s6zmtkhty8myzu4")
        .expect("The token address decoding shouldn't fail")
}

/// Temporary helper for testing
pub fn kartoffel() -> Address {
    Address::decode("tnam1q87teqzjytwa9xd9qk8u558xxnrwuzdjzs7zvhzr")
        .expect("The token address decoding shouldn't fail")
}

/// Sentinel secret key to indicate a MASP source
pub fn masp_tx_key() -> crate::types::key::common::SecretKey {
    use crate::types::key::common;
    let bytes = [
        0, 27, 238, 157, 32, 131, 242, 184, 142, 146, 189, 24, 249, 68, 165,
        205, 71, 213, 158, 25, 253, 52, 217, 87, 52, 171, 225, 110, 131, 238,
        58, 94, 56,
    ];
    common::SecretKey::try_from_slice(bytes.as_ref()).unwrap()
}

/// Temporary helper for testing
pub const fn wnam() -> EthAddress {
    // TODO: Replace this with the real wNam ERC20 address once it exists
    // "DEADBEEF DEADBEEF DEADBEEF DEADBEEF DEADBEEF"
    EthAddress([
        222, 173, 190, 239, 222, 173, 190, 239, 222, 173, 190, 239, 222, 173,
        190, 239, 222, 173, 190, 239,
    ])
}

/// Temporary helper for testing, a hash map of tokens addresses with their
/// informal currency codes and number of decimal places.
pub fn tokens() -> HashMap<&'static str, Denomination> {
    vec![
        ("nam", 6.into()),
        ("btc", 8.into()),
        ("eth", 18.into()),
        ("dot", 10.into()),
        ("schnitzel", 6.into()),
        ("apfel", 6.into()),
        ("kartoffel", 6.into()),
    ]
    .into_iter()
    .collect()
}

#[cfg(test)]
pub mod tests {
    use proptest::prelude::*;

    use super::*;

    /// Run `cargo test gen_established_address -- --nocapture` to generate a
    /// new established address.
    #[test]
    pub fn gen_established_address() {
        for _ in 0..10 {
            let address = testing::gen_established_address();
            println!("address {}", address);
        }
    }

    /// Run `cargo test gen_implicit_address -- --nocapture` to generate a
    /// new established address.
    #[test]
    pub fn gen_implicit_address() {
        for _ in 0..10 {
            let address = testing::gen_implicit_address();
            println!("address {}", address);
        }
    }

    #[test]
    fn test_address_serde_serialize() {
        let original_address =
            Address::decode("tnam1q8j5s6xp55p05yznwnftkv3kr9gjtsw3nq7x6tw5")
                .unwrap();
        let expect = "\"tnam1q8j5s6xp55p05yznwnftkv3kr9gjtsw3nq7x6tw5\"";
        let decoded_address: Address =
            serde_json::from_str(expect).expect("could not read JSON");
        assert_eq!(original_address, decoded_address);

        let encoded_address = serde_json::to_string(&original_address).unwrap();
        assert_eq!(encoded_address, expect);
    }

    proptest! {
        #[test]
        /// Check that all the address types are of the same length
        /// `ADDRESS_LEN` when bech32m encoded, and that that decoding them
        /// yields back the same value.
        fn test_encoded_address_length(address in testing::arb_address()) {
            let encoded: String = address.encode();
            assert_eq!(encoded.len(), ADDRESS_LEN);
            // Also roundtrip check that we decode back the same value
            let decoded = Address::decode(&encoded).unwrap();
            assert_eq!(address, decoded);
        }

        #[test]
        fn test_established_address_bytes_length(address in testing::arb_established_address()) {
            let address = Address::Established(address);
            let bytes = address.serialize_to_vec();
            assert_eq!(bytes.len(), ESTABLISHED_ADDRESS_BYTES_LEN);
        }
    }
}

/// Generate a new established address.
#[cfg(any(test, feature = "rand"))]
pub fn gen_established_address(seed: impl AsRef<str>) -> Address {
    use rand::prelude::ThreadRng;
    use rand::{thread_rng, RngCore};

    let mut key_gen = EstablishedAddressGen::new(seed);

    let mut rng: ThreadRng = thread_rng();
    let mut rng_bytes = vec![0u8; 32];
    rng.fill_bytes(&mut rng_bytes[..]);
    let rng_source = rng_bytes
        .iter()
        .map(|b| format!("{:02X}", b))
        .collect::<Vec<String>>()
        .join("");
    key_gen.generate_address(rng_source)
}

/// Generate a new established address. Unlike `gen_established_address`, this
/// will give the same address for the same `seed`.
pub fn gen_deterministic_established_address(seed: impl AsRef<str>) -> Address {
    let mut key_gen = EstablishedAddressGen::new(seed);
    key_gen.generate_address("")
}

/// Helpers for testing with addresses.
#[cfg(any(test, feature = "testing"))]
pub mod testing {
    use proptest::prelude::*;

    use super::*;
    use crate::types::key::*;

    /// Generate a new established address.
    pub fn gen_established_address() -> Address {
        let seed = "such randomness, much wow";
        super::gen_established_address(seed)
    }

    /// Derive an established address from a simple seed (`u64`).
    pub fn address_from_simple_seed(seed: u64) -> Address {
        super::gen_deterministic_established_address(seed.to_string())
    }

    /// Generate a new implicit address.
    pub fn gen_implicit_address() -> Address {
        let keypair: common::SecretKey =
            key::testing::gen_keypair::<ed25519::SigScheme>()
                .try_to_sk()
                .unwrap();
        let pkh = PublicKeyHash::from(&keypair.ref_to());
        Address::Implicit(ImplicitAddress(pkh))
    }

    /// A sampled established address for tests
    pub fn established_address_1() -> Address {
        Address::decode("tnam1q8j5s6xp55p05yznwnftkv3kr9gjtsw3nq7x6tw5")
            .expect("The token address decoding shouldn't fail")
    }

    /// A sampled established address for tests
    pub fn established_address_2() -> Address {
        Address::decode("tnam1q9k6y928edsh3wsw6xu9d92vwfhjcf8n2qn3g5y8")
            .expect("The token address decoding shouldn't fail")
    }

    /// A sampled established address for tests
    pub fn established_address_3() -> Address {
        Address::decode("tnam1q93zjrvl48w798ena2cg3lhg6s6gzhpssc766yvs")
            .expect("The token address decoding shouldn't fail")
    }

    /// A sampled established address for tests
    pub fn established_address_4() -> Address {
        Address::decode("tnam1q8g8780290hs6p6qtuqaknlc62akwgyn4cj48tkq")
            .expect("The token address decoding shouldn't fail")
    }

    /// Generate an arbitrary [`Address`] (established or implicit).
    pub fn arb_non_internal_address() -> impl Strategy<Value = Address> {
        prop_oneof![
            arb_established_address().prop_map(Address::Established),
            arb_implicit_address().prop_map(Address::Implicit),
        ]
    }

    /// Generate an arbitrary [`Address`] (established, implicit or internal).
    pub fn arb_address() -> impl Strategy<Value = Address> {
        prop_oneof![
            arb_established_address().prop_map(Address::Established),
            arb_implicit_address().prop_map(Address::Implicit),
            arb_internal_address().prop_map(Address::Internal),
        ]
    }

    /// Generate an arbitrary [`EstablishedAddress`].
    pub fn arb_established_address() -> impl Strategy<Value = EstablishedAddress>
    {
        any::<Vec<u8>>().prop_map(|rng_source| {
            let mut key_gen = EstablishedAddressGen::new("seed");
            match key_gen.generate_address(rng_source) {
                Address::Established(addr) => addr,
                _ => {
                    panic!(
                        "Assuming key gen to only generated established \
                         addresses"
                    )
                }
            }
        })
    }

    /// Generate an arbitrary [`ImplicitAddress`].
    pub fn arb_implicit_address() -> impl Strategy<Value = ImplicitAddress> {
        key::testing::arb_keypair::<ed25519::SigScheme>().prop_map(|keypair| {
            let keypair: common::SecretKey = keypair.try_to_sk().unwrap();
            let pkh = PublicKeyHash::from(&keypair.ref_to());
            ImplicitAddress(pkh)
        })
    }

    /// Generate an arbitrary [`InternalAddress`].
    pub fn arb_internal_address() -> impl Strategy<Value = InternalAddress> {
        // This is here for match exhaustion check to remind to add any new
        // internal addresses below.
        match InternalAddress::PoS {
            InternalAddress::PoS => {}
            InternalAddress::PosSlashPool => {}
            InternalAddress::Governance => {}
            InternalAddress::Parameters => {}
            InternalAddress::Ibc => {}
            InternalAddress::IbcToken(_) => {}
            InternalAddress::EthBridge => {}
            InternalAddress::EthBridgePool => {}
            InternalAddress::Erc20(_) => {}
            InternalAddress::Nut(_) => {}
            InternalAddress::Pgf => {}
            InternalAddress::Masp => {}
            InternalAddress::Multitoken => {} /* Add new addresses in the
                                               * `prop_oneof` below. */
        };
        prop_oneof![
            Just(InternalAddress::PoS),
            Just(InternalAddress::PosSlashPool),
            Just(InternalAddress::Ibc),
            Just(InternalAddress::Parameters),
            arb_ibc_token(),
            Just(InternalAddress::Governance),
            Just(InternalAddress::EthBridge),
            Just(InternalAddress::EthBridgePool),
            Just(arb_erc20()),
            Just(arb_nut()),
            Just(InternalAddress::Multitoken),
            Just(InternalAddress::Pgf),
            Just(InternalAddress::Masp),
        ]
    }

    fn arb_ibc_token() -> impl Strategy<Value = InternalAddress> {
        ("[a-zA-Z0-9_]{2,128}", any::<u64>()).prop_map(|(id, counter)| {
            let mut hasher = sha2::Sha256::new();
            let s = format!(
                "{}/{}/{}",
                id,
                format_args!("channel-{}", counter),
                &nam()
            );
            hasher.update(&s);
            let hash = hasher.finalize();
            let hash = IbcTokenHash({
                let input: &[u8; SHA_HASH_LEN] = hash.as_ref();
                let mut output = [0; HASH_LEN];
                output.copy_from_slice(&input[..HASH_LEN]);
                output
            });
            InternalAddress::IbcToken(hash)
        })
    }

    fn arb_erc20() -> InternalAddress {
        use crate::types::ethereum_events::testing::arbitrary_eth_address;
        // TODO: generate random erc20 addr data
        InternalAddress::Erc20(arbitrary_eth_address())
    }

    fn arb_nut() -> InternalAddress {
        use crate::types::ethereum_events::testing::arbitrary_eth_address;
        // TODO: generate random erc20 addr data
        InternalAddress::Nut(arbitrary_eth_address())
    }
}
