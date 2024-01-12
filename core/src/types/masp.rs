//! MASP types

use std::fmt::Display;
use std::str::FromStr;

use borsh::{BorshDeserialize, BorshSerialize};
use borsh_ext::BorshSerializeExt;
use masp_primitives::asset_type::AssetType;
use sha2::{Digest, Sha256};

use crate::impl_display_and_from_str_via_format;
use crate::types::address::{Address, DecodeError, HASH_HEX_LEN, MASP};
use crate::types::storage::Epoch;
use crate::types::string_encoding::{
    self, MASP_EXT_FULL_VIEWING_KEY_HRP, MASP_EXT_SPENDING_KEY_HRP,
    MASP_PAYMENT_ADDRESS_HRP,
};
use crate::types::token::MaspDenom;

/// Make asset type corresponding to given address and epoch
pub fn encode_asset_type(
    epoch: Option<Epoch>,
    token: &Address,
    denom: MaspDenom,
) -> Result<AssetType, std::io::Error> {
    // Timestamp the chosen token with the current epoch
    let token_bytes = (token, denom, epoch).serialize_to_vec();
    // Generate the unique asset identifier from the unique token address
    AssetType::new(token_bytes.as_ref()).map_err(|_| {
        std::io::Error::new(
            std::io::ErrorKind::Other,
            "unable to create asset type".to_string(),
        )
    })
}

// enough capacity to store the payment address
// plus the pinned/unpinned discriminant
const PAYMENT_ADDRESS_SIZE: usize = 43 + 1;

/// Wrapper for masp_primitive's FullViewingKey
#[derive(
    Clone,
    Debug,
    Copy,
    Hash,
    BorshSerialize,
    BorshDeserialize,
    Eq,
    PartialEq,
    PartialOrd,
    Ord,
)]
pub struct ExtendedViewingKey(masp_primitives::zip32::ExtendedFullViewingKey);

impl ExtendedViewingKey {
    /// Encode `Self` to bytes
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = [0; 169];
        self.0
            .write(&mut bytes[..])
            .expect("should be able to serialize an ExtendedFullViewingKey");
        bytes.to_vec()
    }

    /// Try to decode `Self` from bytes
    pub fn decode_bytes(bytes: &[u8]) -> Result<Self, std::io::Error> {
        masp_primitives::zip32::ExtendedFullViewingKey::read(&mut &bytes[..])
            .map(Self)
    }
}

impl string_encoding::Format for ExtendedViewingKey {
    type EncodedBytes<'a> = Vec<u8>;

    const HRP: &'static str = MASP_EXT_FULL_VIEWING_KEY_HRP;

    fn to_bytes(&self) -> Vec<u8> {
        self.to_bytes()
    }

    fn decode_bytes(
        bytes: &[u8],
    ) -> Result<Self, string_encoding::DecodeError> {
        Self::decode_bytes(bytes).map_err(DecodeError::InvalidBytes)
    }
}

impl_display_and_from_str_via_format!(ExtendedViewingKey);

impl string_encoding::Format for PaymentAddress {
    type EncodedBytes<'a> = Vec<u8>;

    const HRP: &'static str = MASP_PAYMENT_ADDRESS_HRP;

    fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(PAYMENT_ADDRESS_SIZE);
        bytes.push(self.is_pinned() as u8);
        bytes.extend_from_slice(self.0.to_bytes().as_slice());
        bytes
    }

    fn decode_bytes(
        bytes: &[u8],
    ) -> Result<Self, string_encoding::DecodeError> {
        if bytes.len() != PAYMENT_ADDRESS_SIZE {
            return Err(DecodeError::InvalidInnerEncoding(format!(
                "expected {PAYMENT_ADDRESS_SIZE} bytes for the payment address"
            )));
        }
        let pinned = match bytes[0] {
            0 => false,
            1 => true,
            k => return Err(DecodeError::UnexpectedDiscriminant(k)),
        };
        let payment_addr =
            masp_primitives::sapling::PaymentAddress::from_bytes(&{
                // NB: the first byte is the pinned/unpinned discriminant
                let mut payment_addr = [0u8; PAYMENT_ADDRESS_SIZE - 1];
                payment_addr.copy_from_slice(&bytes[1..]);
                payment_addr
            })
            .ok_or_else(|| {
                DecodeError::InvalidInnerEncoding(
                    "invalid payment address provided".to_string(),
                )
            })?;
        Ok(Self(payment_addr, pinned))
    }
}

impl_display_and_from_str_via_format!(PaymentAddress);

impl From<ExtendedViewingKey>
    for masp_primitives::zip32::ExtendedFullViewingKey
{
    fn from(key: ExtendedViewingKey) -> Self {
        key.0
    }
}

impl From<masp_primitives::zip32::ExtendedFullViewingKey>
    for ExtendedViewingKey
{
    fn from(key: masp_primitives::zip32::ExtendedFullViewingKey) -> Self {
        Self(key)
    }
}

impl serde::Serialize for ExtendedViewingKey {
    fn serialize<S>(
        &self,
        serializer: S,
    ) -> std::result::Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let encoded = self.to_string();
        serde::Serialize::serialize(&encoded, serializer)
    }
}

impl<'de> serde::Deserialize<'de> for ExtendedViewingKey {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        use serde::de::Error;
        let encoded: String = serde::Deserialize::deserialize(deserializer)?;
        Self::from_str(&encoded).map_err(D::Error::custom)
    }
}

/// Wrapper for masp_primitive's PaymentAddress
#[derive(
    Clone,
    Debug,
    Copy,
    PartialOrd,
    Ord,
    Eq,
    PartialEq,
    Hash,
    BorshSerialize,
    BorshDeserialize,
)]
pub struct PaymentAddress(masp_primitives::sapling::PaymentAddress, bool);

impl PaymentAddress {
    /// Turn this PaymentAddress into a pinned/unpinned one
    pub fn pinned(self, pin: bool) -> PaymentAddress {
        PaymentAddress(self.0, pin)
    }

    /// Determine whether this PaymentAddress is pinned
    pub fn is_pinned(&self) -> bool {
        self.1
    }

    /// Hash this payment address
    pub fn hash(&self) -> String {
        let bytes = (self.0, self.1).serialize_to_vec();
        let mut hasher = Sha256::new();
        hasher.update(bytes);
        // hex of the first 40 chars of the hash
        format!("{:.width$X}", hasher.finalize(), width = HASH_HEX_LEN)
    }
}

impl From<PaymentAddress> for masp_primitives::sapling::PaymentAddress {
    fn from(addr: PaymentAddress) -> Self {
        addr.0
    }
}

impl From<masp_primitives::sapling::PaymentAddress> for PaymentAddress {
    fn from(addr: masp_primitives::sapling::PaymentAddress) -> Self {
        Self(addr, false)
    }
}

impl serde::Serialize for PaymentAddress {
    fn serialize<S>(
        &self,
        serializer: S,
    ) -> std::result::Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let encoded = self.to_string();
        serde::Serialize::serialize(&encoded, serializer)
    }
}

impl<'de> serde::Deserialize<'de> for PaymentAddress {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        use serde::de::Error;
        let encoded: String = serde::Deserialize::deserialize(deserializer)?;
        Self::from_str(&encoded).map_err(D::Error::custom)
    }
}

/// Wrapper for masp_primitive's ExtendedSpendingKey
#[derive(Clone, Debug, Copy, BorshSerialize, BorshDeserialize)]
pub struct ExtendedSpendingKey(masp_primitives::zip32::ExtendedSpendingKey);

impl string_encoding::Format for ExtendedSpendingKey {
    type EncodedBytes<'a> = Vec<u8>;

    const HRP: &'static str = MASP_EXT_SPENDING_KEY_HRP;

    fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = [0; 169];
        self.0
            .write(&mut &mut bytes[..])
            .expect("should be able to serialize an ExtendedSpendingKey");
        bytes.to_vec()
    }

    fn decode_bytes(
        bytes: &[u8],
    ) -> Result<Self, string_encoding::DecodeError> {
        masp_primitives::zip32::ExtendedSpendingKey::read(&mut &bytes[..])
            .map_err(|op| DecodeError::InvalidInnerEncoding(op.to_string()))
            .map(Self)
    }
}

impl_display_and_from_str_via_format!(ExtendedSpendingKey);

impl From<ExtendedSpendingKey> for masp_primitives::zip32::ExtendedSpendingKey {
    fn from(key: ExtendedSpendingKey) -> Self {
        key.0
    }
}

impl From<masp_primitives::zip32::ExtendedSpendingKey> for ExtendedSpendingKey {
    fn from(key: masp_primitives::zip32::ExtendedSpendingKey) -> Self {
        Self(key)
    }
}

impl serde::Serialize for ExtendedSpendingKey {
    fn serialize<S>(
        &self,
        serializer: S,
    ) -> std::result::Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let encoded = self.to_string();
        serde::Serialize::serialize(&encoded, serializer)
    }
}

impl<'de> serde::Deserialize<'de> for ExtendedSpendingKey {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        use serde::de::Error;
        let encoded: String = serde::Deserialize::deserialize(deserializer)?;
        Self::from_str(&encoded).map_err(D::Error::custom)
    }
}

/// Represents a source of funds for a transfer
#[derive(Debug, Clone)]
pub enum TransferSource {
    /// A transfer coming from a transparent address
    Address(Address),
    /// A transfer coming from a shielded address
    ExtendedSpendingKey(ExtendedSpendingKey),
}

impl TransferSource {
    /// Get the transparent address that this source would effectively draw from
    pub fn effective_address(&self) -> Address {
        match self {
            Self::Address(x) => x.clone(),
            // An ExtendedSpendingKey for a source effectively means that
            // assets will be drawn from the MASP
            Self::ExtendedSpendingKey(_) => MASP,
        }
    }

    /// Get the contained ExtendedSpendingKey contained, if any
    pub fn spending_key(&self) -> Option<ExtendedSpendingKey> {
        match self {
            Self::ExtendedSpendingKey(x) => Some(*x),
            _ => None,
        }
    }

    /// Get the contained Address, if any
    pub fn address(&self) -> Option<Address> {
        match self {
            Self::Address(x) => Some(x.clone()),
            _ => None,
        }
    }
}

impl Display for TransferSource {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Address(x) => x.fmt(f),
            Self::ExtendedSpendingKey(x) => x.fmt(f),
        }
    }
}

/// Represents a target for the funds of a transfer
#[derive(Debug, Clone)]
pub enum TransferTarget {
    /// A transfer going to a transparent address
    Address(Address),
    /// A transfer going to a shielded address
    PaymentAddress(PaymentAddress),
}

impl TransferTarget {
    /// Get the transparent address that this target would effectively go to
    pub fn effective_address(&self) -> Address {
        match self {
            Self::Address(x) => x.clone(),
            // An ExtendedSpendingKey for a source effectively means that
            // assets will be drawn from the MASP
            Self::PaymentAddress(_) => MASP,
        }
    }

    /// Get the contained PaymentAddress, if any
    pub fn payment_address(&self) -> Option<PaymentAddress> {
        match self {
            Self::PaymentAddress(address) => Some(*address),
            _ => None,
        }
    }

    /// Get the contained Address, if any
    pub fn address(&self) -> Option<Address> {
        match self {
            Self::Address(x) => Some(x.clone()),
            _ => None,
        }
    }
}

impl Display for TransferTarget {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Address(x) => x.fmt(f),
            Self::PaymentAddress(address) => address.fmt(f),
        }
    }
}

/// Represents the owner of arbitrary funds
#[allow(clippy::large_enum_variant)]
#[derive(
    Debug,
    Clone,
    Hash,
    BorshSerialize,
    BorshDeserialize,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
)]
pub enum BalanceOwner {
    /// A balance stored at a transparent address
    Address(Address),
    /// A balance stored at a shielded address
    FullViewingKey(ExtendedViewingKey),
    /// A balance stored at a payment address
    PaymentAddress(PaymentAddress),
}

impl BalanceOwner {
    /// Get the contained Address, if any
    pub fn address(&self) -> Option<Address> {
        match self {
            Self::Address(x) => Some(x.clone()),
            _ => None,
        }
    }

    /// Get the contained FullViewingKey, if any
    pub fn full_viewing_key(&self) -> Option<ExtendedViewingKey> {
        match self {
            Self::FullViewingKey(x) => Some(*x),
            _ => None,
        }
    }

    /// Get the contained PaymentAddress, if any
    pub fn payment_address(&self) -> Option<PaymentAddress> {
        match self {
            Self::PaymentAddress(x) => Some(*x),
            _ => None,
        }
    }
}

impl Display for BalanceOwner {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            BalanceOwner::Address(addr) => addr.fmt(f),
            BalanceOwner::FullViewingKey(fvk) => fvk.fmt(f),
            BalanceOwner::PaymentAddress(pa) => pa.fmt(f),
        }
    }
}

/// Represents any MASP value
#[allow(clippy::large_enum_variant)]
#[derive(Debug, Clone)]
pub enum MaspValue {
    /// A MASP PaymentAddress
    PaymentAddress(PaymentAddress),
    /// A MASP ExtendedSpendingKey
    ExtendedSpendingKey(ExtendedSpendingKey),
    /// A MASP FullViewingKey
    FullViewingKey(ExtendedViewingKey),
}

impl FromStr for MaspValue {
    type Err = DecodeError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        // Try to decode this value first as a PaymentAddress, then as an
        // ExtendedSpendingKey, then as FullViewingKey
        PaymentAddress::from_str(s)
            .map(Self::PaymentAddress)
            .or_else(|_err| {
                ExtendedSpendingKey::from_str(s).map(Self::ExtendedSpendingKey)
            })
            .or_else(|_err| {
                ExtendedViewingKey::from_str(s).map(Self::FullViewingKey)
            })
    }
}
