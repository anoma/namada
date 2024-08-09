//! Types representing data intended for Namada via Ethereum events

use std::cmp::Ordering;
use std::fmt::{Display, Formatter};
use std::str::FromStr;

use borsh::{BorshDeserialize, BorshSchema, BorshSerialize};
use borsh_ext::BorshSerializeExt;
use ethabi::ethereum_types::{H160, U256 as ethUint};
use ethabi::Token;
use eyre::{eyre, Context};
use namada_macros::BorshDeserializer;
#[cfg(feature = "migrations")]
use namada_migrations::*;
use serde::{Deserialize, Serialize};

use crate::address::Address;
use crate::eth_abi::Encode;
use crate::ethereum_structs::Erc20Transfer;
use crate::hash::Hash;
use crate::keccak::KeccakHash;
use crate::storage::{DbKeySeg, KeySeg};
use crate::token::Amount;

/// Namada native type to replace the ethabi::Uint type
#[derive(
    Copy,
    Clone,
    Debug,
    Default,
    Hash,
    PartialEq,
    Eq,
    Serialize,
    Deserialize,
    BorshSerialize,
    BorshDeserialize,
    BorshDeserializer,
    BorshSchema,
)]
#[repr(align(32))]
pub struct Uint(pub [u64; 4]);

impl PartialOrd for Uint {
    #[inline]
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for Uint {
    #[inline]
    fn cmp(&self, other: &Self) -> Ordering {
        ethUint(self.0).cmp(&ethUint(other.0))
    }
}

impl Uint {
    /// Convert to an Ethereum-compatible byte representation.
    ///
    /// The Ethereum virtual machine employs big-endian integers
    /// (Wood, 2014), therefore the returned byte array has the
    /// same endianness.
    pub fn to_bytes(self) -> [u8; 32] {
        let mut bytes = [0; 32];
        ethUint(self.0).to_big_endian(&mut bytes);
        bytes
    }

    /// Try to increment this [`Uint`], whilst checking
    /// for overflows.
    pub fn checked_increment(self) -> Option<Self> {
        ethUint::from(self).checked_add(1.into()).map(Self::from)
    }
}

impl Display for Uint {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        ethUint(self.0).fmt(f)
    }
}

impl Encode<1> for Uint {
    fn tokenize(&self) -> [Token; 1] {
        [Token::Uint(self.into())]
    }
}

impl From<ethUint> for Uint {
    fn from(value: ethUint) -> Self {
        Self(value.0)
    }
}

impl From<Uint> for ethUint {
    fn from(value: Uint) -> Self {
        Self(value.0)
    }
}

impl From<&Uint> for ethUint {
    fn from(value: &Uint) -> Self {
        Self(value.0)
    }
}

impl From<u64> for Uint {
    fn from(value: u64) -> Self {
        ethUint::from(value).into()
    }
}

/// Representation of address on Ethereum. The inner value is the last 20 bytes
/// of the public key that controls the account.
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
#[derive(
    Copy,
    Clone,
    Debug,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
    Serialize,
    Deserialize,
    BorshSerialize,
    BorshDeserialize,
    BorshDeserializer,
    BorshSchema,
)]
#[serde(try_from = "String")]
#[serde(into = "String")]
pub struct EthAddress(pub [u8; 20]);

impl EthAddress {
    /// The canonical way we represent an [`EthAddress`] in storage keys. A
    /// 40-character lower case hexadecimal address prefixed by '0x'.
    /// e.g. "0x6b175474e89094c44da98b954eedeac495271d0f"
    pub fn to_canonical(&self) -> String {
        format!("{:?}", ethabi::ethereum_types::Address::from(&self.0))
    }
}

impl From<H160> for EthAddress {
    fn from(H160(addr): H160) -> Self {
        Self(addr)
    }
}

impl From<EthAddress> for H160 {
    fn from(EthAddress(addr): EthAddress) -> Self {
        Self(addr)
    }
}

impl Display for EthAddress {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.to_canonical())
    }
}

impl FromStr for EthAddress {
    type Err = eyre::Error;

    /// Parses an [`EthAddress`] from a standard hex-encoded Ethereum address
    /// string. e.g. "0x6B175474E89094C44Da98b954EedeAC495271d0F"
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let h160 = ethabi::ethereum_types::Address::from_str(s)
            .wrap_err_with(|| eyre!("couldn't parse Ethereum address {}", s))?;
        Ok(Self(h160.into()))
    }
}

impl TryFrom<String> for EthAddress {
    type Error = eyre::Error;

    fn try_from(string: String) -> Result<Self, eyre::Error> {
        Self::from_str(string.as_ref())
    }
}

impl From<EthAddress> for String {
    fn from(addr: EthAddress) -> Self {
        addr.to_string()
    }
}

impl KeySeg for EthAddress {
    fn parse(string: String) -> crate::storage::Result<Self> {
        Self::from_str(string.as_str())
            .map_err(|_| crate::storage::Error::ParseKeySeg(string))
    }

    fn raw(&self) -> String {
        self.to_canonical()
    }

    fn to_db_key(&self) -> DbKeySeg {
        DbKeySeg::StringSeg(self.raw())
    }
}

/// Nonces of Ethereum events.
pub trait GetEventNonce {
    /// Returns the nonce of an Ethereum event.
    fn get_event_nonce(&self) -> Uint;
}

/// Event transferring batches of ether or Ethereum based ERC20 tokens
/// from Ethereum to wrapped assets on Namada
#[derive(
    PartialEq,
    Eq,
    PartialOrd,
    Hash,
    Ord,
    Clone,
    Debug,
    BorshSerialize,
    BorshDeserialize,
    BorshDeserializer,
    BorshSchema,
)]
pub struct TransfersToNamada {
    /// Monotonically increasing nonce
    pub nonce: Uint,
    /// The batch of transfers
    pub transfers: Vec<TransferToNamada>,
}

impl GetEventNonce for TransfersToNamada {
    #[inline]
    fn get_event_nonce(&self) -> Uint {
        self.nonce
    }
}

impl From<TransfersToNamada> for EthereumEvent {
    #[inline]
    fn from(event: TransfersToNamada) -> Self {
        let TransfersToNamada { nonce, transfers } = event;
        Self::TransfersToNamada { nonce, transfers }
    }
}

/// An Ethereum event to be processed by the Namada ledger
#[derive(
    PartialEq,
    Eq,
    PartialOrd,
    Hash,
    Ord,
    Clone,
    Debug,
    BorshSerialize,
    BorshDeserialize,
    BorshDeserializer,
    BorshSchema,
)]
// NOTE: Avoid changing the order of the elements in this struct,
// to maintain compatibility between Namada versions.
pub enum EthereumEvent {
    /// Event transferring batches of ether or Ethereum based ERC20 tokens
    /// from Ethereum to wrapped assets on Namada
    TransfersToNamada {
        /// Monotonically increasing nonce
        nonce: Uint,
        /// The batch of transfers
        transfers: Vec<TransferToNamada>,
    },
    /// A confirmation event that a batch of transfers have been made
    /// from Namada to Ethereum
    TransfersToEthereum {
        /// Monotonically increasing nonce
        nonce: Uint,
        /// The batch of transfers
        transfers: Vec<TransferToEthereum>,
        /// The Namada address that receives the gas fees
        /// for relaying a batch of transfers
        relayer: Address,
    },
    /// Event indication that the validator set has been updated
    /// in the governance contract
    ValidatorSetUpdate {
        /// Monotonically increasing nonce
        nonce: Uint,
        /// Hash of the validators in the bridge contract
        bridge_validator_hash: KeccakHash,
        /// Hash of the validators in the governance contract
        governance_validator_hash: KeccakHash,
    },
}

impl EthereumEvent {
    /// SHA256 of the Borsh serialization of the [`EthereumEvent`].
    pub fn hash(&self) -> Result<Hash, std::io::Error> {
        let bytes = self.serialize_to_vec();
        Ok(Hash::sha256(bytes))
    }
}

/// An event transferring some kind of value from Ethereum to Namada
#[derive(
    Clone,
    Debug,
    PartialEq,
    Eq,
    PartialOrd,
    Hash,
    Ord,
    BorshSerialize,
    BorshDeserialize,
    BorshDeserializer,
    BorshSchema,
)]
pub struct TransferToNamada {
    /// Quantity of the ERC20 token in the transfer
    pub amount: Amount,
    /// Address of the smart contract issuing the token
    pub asset: EthAddress,
    /// The address receiving wrapped assets on Namada
    pub receiver: Address,
}

/// An event transferring some kind of value from Namada to Ethereum
#[derive(
    Clone,
    Debug,
    PartialEq,
    Eq,
    Hash,
    PartialOrd,
    Ord,
    BorshSerialize,
    BorshDeserialize,
    BorshDeserializer,
    BorshSchema,
    Serialize,
    Deserialize,
)]
pub struct TransferToEthereum {
    /// Quantity of wrapped Asset in the transfer
    pub amount: Amount,
    /// Address of the smart contract issuing the token
    pub asset: EthAddress,
    /// The address receiving assets on Ethereum
    pub receiver: EthAddress,
    /// Checksum of all Namada specific fields, including,
    /// but not limited to, whether it is a NUT transfer,
    /// the address of the sender, etc
    ///
    /// It serves to uniquely identify an event stored under
    /// the Bridge pool, in Namada
    pub checksum: Hash,
}

impl From<Erc20Transfer> for TransferToEthereum {
    #[inline]
    fn from(transfer: Erc20Transfer) -> Self {
        Self {
            amount: {
                let uint = {
                    use crate::uint::Uint as NamadaUint;
                    let mut num_buf = [0; 32];
                    transfer.amount.to_little_endian(&mut num_buf);
                    NamadaUint::from_little_endian(&num_buf)
                };
                // this is infallible for a denom of 0
                Amount::from_uint(uint, 0).unwrap()
            },
            asset: EthAddress(transfer.from.0),
            receiver: EthAddress(transfer.to.0),
            checksum: Hash(transfer.data_digest),
        }
    }
}

#[cfg(test)]
pub mod tests {

    use super::*;

    #[test]
    fn test_eth_address_to_canonical() {
        let canonical = testing::DAI_ERC20_ETH_ADDRESS.to_canonical();

        assert_eq!(
            testing::DAI_ERC20_ETH_ADDRESS_CHECKSUMMED.to_ascii_lowercase(),
            canonical,
        );
    }

    #[test]
    fn test_eth_address_from_str() {
        let addr =
            EthAddress::from_str(testing::DAI_ERC20_ETH_ADDRESS_CHECKSUMMED)
                .unwrap();

        assert_eq!(testing::DAI_ERC20_ETH_ADDRESS, addr);
    }

    #[test]
    fn test_eth_address_from_str_error() {
        let result = EthAddress::from_str(
            "arbitrary string which isn't an Ethereum address",
        );

        assert!(result.is_err());
    }

    /// Test that serde correct serializes EthAddress types to/from lowercase
    /// hex encodings
    #[test]
    fn test_eth_address_serde_roundtrip() {
        let addr =
            EthAddress::from_str(testing::DAI_ERC20_ETH_ADDRESS_CHECKSUMMED)
                .unwrap();
        let serialized = serde_json::to_string(&addr).expect("Test failed");
        assert_eq!(
            serialized,
            format!(
                r#""{}""#,
                testing::DAI_ERC20_ETH_ADDRESS_CHECKSUMMED.to_lowercase()
            )
        );
        let deserialized: EthAddress =
            serde_json::from_str(&serialized).expect("Test failed");
        assert_eq!(addr, deserialized);
    }
}

#[allow(missing_docs)]
#[allow(clippy::arithmetic_side_effects)]
/// Test helpers
#[cfg(any(test, feature = "testing", feature = "benches"))]
pub mod testing {
    use proptest::prop_compose;

    use super::*;
    use crate::token;

    pub const DAI_ERC20_ETH_ADDRESS_CHECKSUMMED: &str =
        "0x6B175474E89094C44Da98b954EedeAC495271d0F";
    pub const DAI_ERC20_ETH_ADDRESS: EthAddress = EthAddress([
        107, 23, 84, 116, 232, 144, 148, 196, 77, 169, 139, 149, 78, 237, 234,
        196, 149, 39, 29, 15,
    ]);
    pub const USDC_ERC20_ETH_ADDRESS_CHECKSUMMED: &str =
        "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48";
    pub const USDC_ERC20_ETH_ADDRESS: EthAddress = EthAddress([
        160, 184, 105, 145, 198, 33, 139, 54, 193, 209, 157, 74, 46, 158, 176,
        206, 54, 6, 235, 72,
    ]);

    impl std::ops::Add<u64> for Uint {
        type Output = Self;

        fn add(self, rhs: u64) -> Self::Output {
            (ethUint(self.0) + rhs).into()
        }
    }

    impl std::ops::Sub<u64> for Uint {
        type Output = Self;

        fn sub(self, rhs: u64) -> Self::Output {
            (ethUint(self.0) - rhs).into()
        }
    }

    pub fn arbitrary_eth_address() -> EthAddress {
        DAI_ERC20_ETH_ADDRESS
    }

    pub fn arbitrary_nonce() -> Uint {
        0.into()
    }

    pub fn arbitrary_keccak_hash() -> KeccakHash {
        KeccakHash([0; 32])
    }

    pub fn arbitrary_amount() -> Amount {
        Amount::from(1_000)
    }

    pub fn arbitrary_bonded_stake() -> token::Amount {
        token::Amount::from(1_000)
    }

    /// A [`EthereumEvent::TransfersToNamada`] containing a single transfer of
    /// some arbitrary ERC20
    pub fn arbitrary_single_transfer(
        nonce: Uint,
        receiver: Address,
    ) -> EthereumEvent {
        EthereumEvent::TransfersToNamada {
            nonce,
            transfers: vec![TransferToNamada {
                amount: arbitrary_amount(),
                asset: arbitrary_eth_address(),
                receiver,
            }],
        }
    }

    prop_compose! {
        // Generate an arbitrary Ethereum address
        pub fn arb_eth_address()(bytes: [u8; 20]) -> EthAddress {
            EthAddress(bytes)
        }
    }
}
