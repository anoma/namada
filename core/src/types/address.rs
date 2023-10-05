//! Implements transparent addresses as described in [Accounts
//! Addresses](docs/src/explore/design/ledger/accounts.md#addresses).

use std::collections::HashMap;
use std::fmt::{Debug, Display};
use std::hash::Hash;
use std::io::ErrorKind;
use std::str::FromStr;

use bech32::{self, FromBase32, ToBase32, Variant};
use borsh::{BorshDeserialize, BorshSchema, BorshSerialize};
use data_encoding::HEXUPPER;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::ibc::Signer;
use crate::types::ethereum_events::EthAddress;
use crate::types::key;
use crate::types::key::PublicKeyHash;
use crate::types::token::Denomination;

/// The length of an established [`Address`] encoded with Borsh.
pub const ESTABLISHED_ADDRESS_BYTES_LEN: usize = 21;

/// The length of [`Address`] encoded with Bech32m.
pub const ADDRESS_LEN: usize = 79 + ADDRESS_HRP.len();

/// human-readable part of Bech32m encoded address
// TODO use "a" for live network
const ADDRESS_HRP: &str = "atest";
/// We're using "Bech32m" variant
pub const BECH32M_VARIANT: bech32::Variant = Variant::Bech32m;

/// Length of a hash of an address as a hexadecimal string
pub(crate) const HASH_HEX_LEN: usize = 40;

/// Length of a trimmed hash of an address.
pub(crate) const HASH_LEN: usize = 20;

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

/// An address string before bech32m encoding must be this size.
pub const FIXED_LEN_STRING_BYTES: usize = 45;

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

/// Raw strings used to produce internal addresses. All the strings must begin
/// with `PREFIX_INTERNAL` and be `FIXED_LEN_STRING_BYTES` characters long.
#[rustfmt::skip]
mod internal {
    pub const POS: &str = 
        "ano::Proof of Stake                          ";
    pub const POS_SLASH_POOL: &str =
        "ano::Proof of Stake Slash Pool               ";
    pub const PARAMETERS: &str =
        "ano::Protocol Parameters                     ";
    pub const GOVERNANCE: &str =
        "ano::Governance                              ";
    pub const IBC: &str =
        "ibc::Inter-Blockchain Communication          ";
    pub const ETH_BRIDGE: &str =
        "ano::ETH Bridge Address                      ";
    pub const ETH_BRIDGE_POOL: &str =
        "ano::ETH Bridge Pool Address                 ";
    pub const MULTITOKEN: &str =
        "ano::Multitoken                              ";
    pub const PGF: &str =
        "ano::Pgf                                     ";
}

/// Fixed-length address strings prefix for established addresses.
const PREFIX_ESTABLISHED: &str = "est";
/// Fixed-length address strings prefix for implicit addresses.
const PREFIX_IMPLICIT: &str = "imp";
/// Fixed-length address strings prefix for internal addresses.
const PREFIX_INTERNAL: &str = "ano";
/// Fixed-length address strings prefix for IBC addresses.
const PREFIX_IBC: &str = "ibc";
/// Fixed-length address strings prefix for Ethereum addresses.
const PREFIX_ETH: &str = "eth";
/// Fixed-length address strings prefix for Non-Usable-Token addresses.
const PREFIX_NUT: &str = "nut";

#[allow(missing_docs)]
#[derive(Error, Debug, PartialEq, Eq, Clone)]
pub enum DecodeError {
    #[error("Error decoding address from Bech32m: {0}")]
    DecodeBech32(bech32::Error),
    #[error("Error decoding address from base32: {0}")]
    DecodeBase32(bech32::Error),
    #[error("Unexpected Bech32m human-readable part {0}, expected {1}")]
    UnexpectedBech32Prefix(String, String),
    #[error("Unexpected Bech32m variant {0:?}, expected {BECH32M_VARIANT:?}")]
    UnexpectedBech32Variant(bech32::Variant),
    #[error("Invalid address encoding: {0}, {1}")]
    InvalidInnerEncoding(ErrorKind, String),
    #[error("Invalid address encoding")]
    InvalidInnerEncodingStr(String),
}

/// Result of a function that may fail
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
        let bytes = self.to_fixed_len_string();
        bech32::encode(ADDRESS_HRP, bytes.to_base32(), BECH32M_VARIANT)
            .unwrap_or_else(|_| {
                panic!(
                    "The human-readable part {} should never cause a failure",
                    ADDRESS_HRP
                )
            })
    }

    /// Decode an address from Bech32m encoding
    pub fn decode(string: impl AsRef<str>) -> Result<Self> {
        let (prefix, hash_base32, variant) = bech32::decode(string.as_ref())
            .map_err(DecodeError::DecodeBech32)?;
        if prefix != ADDRESS_HRP {
            return Err(DecodeError::UnexpectedBech32Prefix(
                prefix,
                ADDRESS_HRP.into(),
            ));
        }
        match variant {
            BECH32M_VARIANT => {}
            _ => return Err(DecodeError::UnexpectedBech32Variant(variant)),
        }
        let bytes: Vec<u8> = FromBase32::from_base32(&hash_base32)
            .map_err(DecodeError::DecodeBase32)?;
        Self::try_from_fixed_len_string(&mut &bytes[..])
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

    /// Convert an address to a fixed length 7-bit ascii string bytes
    fn to_fixed_len_string(&self) -> Vec<u8> {
        let mut string = match self {
            Address::Established(EstablishedAddress { hash }) => {
                // The bech32m's data is a hex of the first 40 chars of the hash
                let hash_hex = HEXUPPER.encode(hash);
                debug_assert_eq!(hash_hex.len(), HASH_HEX_LEN);
                format!("{}::{}", PREFIX_ESTABLISHED, hash_hex)
            }
            Address::Implicit(ImplicitAddress(pkh)) => {
                format!("{}::{}", PREFIX_IMPLICIT, pkh)
            }
            Address::Internal(internal) => {
                let string = match internal {
                    InternalAddress::PoS => internal::POS.to_string(),
                    InternalAddress::PosSlashPool => {
                        internal::POS_SLASH_POOL.to_string()
                    }
                    InternalAddress::Parameters => {
                        internal::PARAMETERS.to_string()
                    }
                    InternalAddress::Governance => {
                        internal::GOVERNANCE.to_string()
                    }
                    InternalAddress::Ibc => internal::IBC.to_string(),
                    InternalAddress::IbcToken(hash) => {
                        format!("{}::{}", PREFIX_IBC, hash)
                    }
                    InternalAddress::EthBridge => {
                        internal::ETH_BRIDGE.to_string()
                    }
                    InternalAddress::EthBridgePool => {
                        internal::ETH_BRIDGE_POOL.to_string()
                    }
                    InternalAddress::Erc20(eth_addr) => {
                        let eth_addr =
                            eth_addr.to_canonical().replace("0x", "");
                        format!("{}::{}", PREFIX_ETH, eth_addr)
                    }
                    InternalAddress::Nut(eth_addr) => {
                        let eth_addr =
                            eth_addr.to_canonical().replace("0x", "");
                        format!("{PREFIX_NUT}::{eth_addr}")
                    }
                    InternalAddress::Multitoken => {
                        internal::MULTITOKEN.to_string()
                    }
                    InternalAddress::Pgf => internal::PGF.to_string(),
                };
                debug_assert_eq!(string.len(), FIXED_LEN_STRING_BYTES);
                string
            }
        }
        .into_bytes();
        string.resize(FIXED_LEN_STRING_BYTES, b' ');
        string
    }

    /// Try to parse an address from fixed-length utf-8 encoded address string.
    fn try_from_fixed_len_string(buf: &mut &[u8]) -> Result<Self> {
        let string = std::str::from_utf8(buf).map_err(|err| {
            DecodeError::InvalidInnerEncoding(
                ErrorKind::InvalidData,
                err.to_string(),
            )
        })?;
        if string.len() != FIXED_LEN_STRING_BYTES {
            return Err(DecodeError::InvalidInnerEncoding(
                ErrorKind::InvalidData,
                "Invalid length".to_string(),
            ));
        }
        match string.split_once("::") {
            Some((PREFIX_ESTABLISHED, hash)) => {
                if hash.len() == HASH_HEX_LEN {
                    let raw =
                        HEXUPPER.decode(hash.as_bytes()).map_err(|e| {
                            DecodeError::InvalidInnerEncoding(
                                std::io::ErrorKind::InvalidInput,
                                e.to_string(),
                            )
                        })?;
                    if raw.len() != HASH_LEN {
                        return Err(DecodeError::InvalidInnerEncoding(
                            ErrorKind::InvalidData,
                            "Established address hash must be 40 characters \
                             long"
                                .to_string(),
                        ));
                    }
                    let mut hash: [u8; HASH_LEN] = Default::default();
                    hash.copy_from_slice(&raw);
                    Ok(Address::Established(EstablishedAddress { hash }))
                } else {
                    Err(DecodeError::InvalidInnerEncoding(
                        ErrorKind::InvalidData,
                        "Established address hash must be 40 characters long"
                            .to_string(),
                    ))
                }
            }
            Some((PREFIX_IMPLICIT, pkh)) => {
                let pkh = PublicKeyHash::from_str(pkh).map_err(|err| {
                    DecodeError::InvalidInnerEncoding(
                        ErrorKind::InvalidData,
                        err.to_string(),
                    )
                })?;
                Ok(Address::Implicit(ImplicitAddress(pkh)))
            }
            Some((PREFIX_INTERNAL, _)) => match string {
                internal::POS => Ok(Address::Internal(InternalAddress::PoS)),
                internal::POS_SLASH_POOL => {
                    Ok(Address::Internal(InternalAddress::PosSlashPool))
                }
                internal::PARAMETERS => {
                    Ok(Address::Internal(InternalAddress::Parameters))
                }
                internal::GOVERNANCE => {
                    Ok(Address::Internal(InternalAddress::Governance))
                }
                internal::ETH_BRIDGE => {
                    Ok(Address::Internal(InternalAddress::EthBridge))
                }
                internal::ETH_BRIDGE_POOL => {
                    Ok(Address::Internal(InternalAddress::EthBridgePool))
                }
                internal::MULTITOKEN => {
                    Ok(Address::Internal(InternalAddress::Multitoken))
                }
                internal::PGF => Ok(Address::Internal(InternalAddress::Pgf)),
                _ => Err(DecodeError::InvalidInnerEncoding(
                    ErrorKind::InvalidData,
                    "Invalid internal address".to_string(),
                )),
            },
            Some((PREFIX_IBC, raw)) => match string {
                internal::IBC => Ok(Address::Internal(InternalAddress::Ibc)),
                _ if raw.len() == HASH_HEX_LEN => Ok(Address::Internal(
                    InternalAddress::IbcToken(raw.to_string()),
                )),
                _ => Err(DecodeError::InvalidInnerEncoding(
                    ErrorKind::InvalidData,
                    "Invalid IBC internal address".to_string(),
                )),
            },
            Some((prefix @ (PREFIX_ETH | PREFIX_NUT), raw)) => match string {
                _ if raw.len() == HASH_HEX_LEN => {
                    match EthAddress::from_str(&format!("0x{}", raw)) {
                        Ok(eth_addr) => Ok(match prefix {
                            PREFIX_ETH => Address::Internal(
                                InternalAddress::Erc20(eth_addr),
                            ),
                            PREFIX_NUT => Address::Internal(
                                InternalAddress::Nut(eth_addr),
                            ),
                            _ => unreachable!(),
                        }),
                        Err(e) => Err(DecodeError::InvalidInnerEncoding(
                            ErrorKind::InvalidData,
                            e.to_string(),
                        )),
                    }
                }
                _ => Err(DecodeError::InvalidInnerEncoding(
                    ErrorKind::InvalidData,
                    "Invalid ERC20 internal address".to_string(),
                )),
            },
            _ => Err(DecodeError::InvalidInnerEncoding(
                ErrorKind::InvalidData,
                "Invalid address prefix".to_string(),
            )),
        }
    }

    fn pretty_fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.to_pretty_string())
    }

    /// Print the type of the address and its bech32m encoded value
    pub fn to_pretty_string(&self) -> String {
        match self {
            Address::Established(_) => {
                format!("Established: {}", self.encode(),)
            }
            Address::Implicit(_) => {
                format!("Implicit: {}", self.encode(),)
            }
            Address::Internal(kind) => {
                format!("Internal {}: {}", kind, self.encode())
            }
        }
    }
}

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

impl Display for Address {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.encode())
    }
}

impl Debug for Address {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.pretty_fmt(f)
    }
}

impl FromStr for Address {
    type Err = DecodeError;

    fn from_str(s: &str) -> Result<Self> {
        Address::decode(s)
    }
}

/// for IBC signer
impl TryFrom<Signer> for Address {
    type Error = DecodeError;

    fn try_from(signer: Signer) -> Result<Self> {
        Address::decode(signer.as_ref())
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

/// A generator of established addresses
#[derive(Debug, Clone, PartialEq, BorshSerialize, BorshDeserialize)]
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
        let gen_bytes = self
            .try_to_vec()
            .expect("Encoding established addresses generator shouldn't fail");
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
    IbcToken(String),
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
            }
        )
    }
}

/// Temporary helper for testing
pub fn nam() -> Address {
    Address::decode("atest1v4ehgw36x3prswzxggunzv6pxqmnvdj9xvcyzvpsggeyvs3cg9qnywf589qnwvfsg5erg3fkl09rg5").expect("The token address decoding shouldn't fail")
}

/// Temporary helper for testing
pub fn btc() -> Address {
    Address::decode("atest1v4ehgw36xdzryve5gsc52veeg5cnsv2yx5eygvp38qcrvd29xy6rys6p8yc5xvp4xfpy2v694wgwcp").expect("The token address decoding shouldn't fail")
}

/// Temporary helper for testing
pub fn eth() -> Address {
    Address::decode("atest1v4ehgw36xqmr2d3nx3ryvd2xxgmrq33j8qcns33sxezrgv6zxdzrydjrxveygd2yxumrsdpsf9jc2p").expect("The token address decoding shouldn't fail")
}

/// Temporary helper for testing
pub fn dot() -> Address {
    Address::decode("atest1v4ehgw36gg6nvs2zgfpyxsfjgc65yv6pxy6nwwfsxgungdzrggeyzv35gveyxsjyxymyz335hur2jn").expect("The token address decoding shouldn't fail")
}

/// Temporary helper for testing
pub fn schnitzel() -> Address {
    Address::decode("atest1v4ehgw36xue5xvf5xvuyzvpjx5un2v3k8qeyvd3cxdqns32p89rrxd6xx9zngvpegccnzs699rdnnt").expect("The token address decoding shouldn't fail")
}

/// Temporary helper for testing
pub fn apfel() -> Address {
    Address::decode("atest1v4ehgw36gfryydj9g3p5zv3kg9znyd358ycnzsfcggc5gvecgc6ygs2rxv6ry3zpg4zrwdfeumqcz9").expect("The token address decoding shouldn't fail")
}

/// Temporary helper for testing
pub fn kartoffel() -> Address {
    Address::decode("atest1v4ehgw36gep5ysecxq6nyv3jg3zygv3e89qn2vp48pryxsf4xpznvve5gvmy23fs89pryvf5a6ht90").expect("The token address decoding shouldn't fail")
}

/// Temporary helper for testing
pub fn masp() -> Address {
    Address::decode("atest1v4ehgw36xaryysfsx5unvve4g5my2vjz89p52sjxxgenzd348yuyyv3hg3pnjs35g5unvde4ca36y5").expect("The token address decoding shouldn't fail")
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
pub fn tokens() -> HashMap<Address, (&'static str, Denomination)> {
    vec![
        (nam(), ("NAM", 6.into())),
        (btc(), ("BTC", 8.into())),
        (eth(), ("ETH", 18.into())),
        (dot(), ("DOT", 10.into())),
        (schnitzel(), ("Schnitzel", 6.into())),
        (apfel(), ("Apfel", 6.into())),
        (kartoffel(), ("Kartoffel", 6.into())),
    ]
    .into_iter()
    .collect()
}

/// Temporary helper for testing, a hash map of tokens addresses with their
/// MASP XAN incentive schedules. If the reward is (a, b) then a rewarded tokens
/// are dispensed for every b possessed tokens.
pub fn masp_rewards() -> HashMap<Address, (u32, u32)> {
    vec![
        (nam(), (0, 100)),
        (btc(), (1, 100)),
        (eth(), (2, 100)),
        (dot(), (3, 100)),
        (schnitzel(), (4, 100)),
        (apfel(), (5, 100)),
        (kartoffel(), (6, 100)),
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
        let original_address = Address::decode("atest1v4ehgw36g56ngwpk8ppnzsf4xqeyvsf3xq6nxde5gseyys3nxgenvvfex5cnyd2rx9zrzwfctgx7sp").unwrap();
        let expect =
            "\"atest1v4ehgw36g56ngwpk8ppnzsf4xqeyvsf3xq6nxde5gseyys3nxgenvvfex5cnyd2rx9zrzwfctgx7sp\"";
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
            let bytes = address.try_to_vec().unwrap();
            assert_eq!(bytes.len(), ESTABLISHED_ADDRESS_BYTES_LEN);
        }
    }
}

/// Generate a new established address.
#[cfg(feature = "rand")]
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
        Address::decode("atest1v4ehgw36g56ngwpk8ppnzsf4xqeyvsf3xq6nxde5gseyys3nxgenvvfex5cnyd2rx9zrzwfctgx7sp").expect("The token address decoding shouldn't fail")
    }

    /// A sampled established address for tests
    pub fn established_address_2() -> Address {
        Address::decode("atest1v4ehgw36xezyzv33x56rws6zxccnwwzzgycy23p3ggur2d3ex56yxdejxerrysejx3rrxdfs44s9wu").expect("The token address decoding shouldn't fail")
    }

    /// A sampled established address for tests
    pub fn established_address_3() -> Address {
        Address::decode("atest1v4ehgw36xcerywfsgsu5vsfeg3zy2v3egcenx32pggcrswzxg4zns3p5xv6rsvf4gvenqwpkdnnqsy").expect("The token address decoding shouldn't fail")
    }

    /// A sampled established address for tests
    pub fn established_address_4() -> Address {
        Address::decode("atest1v4ehgw36gscrw333g3z5zvjzg4rrq3psxu6rqd2xxqc5gs35gerrs3pjgfprvdejxqunxs29t6p5s9").expect("The token address decoding shouldn't fail")
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
            let hash =
                format!("{:.width$x}", hasher.finalize(), width = HASH_HEX_LEN);
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
