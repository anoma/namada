//! MASP types

use std::collections::BTreeMap;
use std::fmt::Display;
use std::num::ParseIntError;
use std::str::FromStr;

use borsh::{BorshDeserialize, BorshSchema, BorshSerialize};
use borsh_ext::BorshSerializeExt;
use masp_primitives::asset_type::AssetType;
use masp_primitives::transaction::TransparentAddress;
use namada_macros::BorshDeserializer;
#[cfg(feature = "migrations")]
use namada_migrations::*;
use ripemd::Digest as RipemdDigest;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use sha2::{Digest, Sha256};

use crate::address::{Address, DecodeError, HASH_HEX_LEN, IBC, MASP};
use crate::impl_display_and_from_str_via_format;
use crate::storage::Epoch;
use crate::string_encoding::{
    self, MASP_EXT_FULL_VIEWING_KEY_HRP, MASP_EXT_SPENDING_KEY_HRP,
    MASP_PAYMENT_ADDRESS_HRP,
};
use crate::token::{Denomination, MaspDigitPos};

/// Serialize the given TxId
pub fn serialize_txid<S>(
    txid: &masp_primitives::transaction::TxId,
    s: S,
) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    s.serialize_bytes(txid.as_ref())
}

/// Deserialize the given TxId
pub fn deserialize_txid<'de, D>(
    deserializer: D,
) -> Result<masp_primitives::transaction::TxId, D::Error>
where
    D: Deserializer<'de>,
{
    Ok(masp_primitives::transaction::TxId::from_bytes(
        Deserialize::deserialize(deserializer)?,
    ))
}

/// Wrapper for masp_primitive's TxId
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
#[derive(
    Serialize,
    Deserialize,
    Clone,
    BorshSerialize,
    BorshDeserialize,
    BorshSchema,
    Debug,
    Eq,
    PartialEq,
    Copy,
    Ord,
    PartialOrd,
    Hash,
)]
pub struct MaspTxId(
    #[serde(
        serialize_with = "serialize_txid",
        deserialize_with = "deserialize_txid"
    )]
    masp_primitives::transaction::TxId,
);

impl From<masp_primitives::transaction::TxId> for MaspTxId {
    fn from(txid: masp_primitives::transaction::TxId) -> Self {
        Self(txid)
    }
}

/// Wrapper for masp_primitive's TxId
pub type TxId = MaspTxId;

/// Wrapper type around `Epoch` for type safe operations involving the masp
/// epoch
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
#[derive(
    BorshSerialize,
    BorshDeserialize,
    BorshDeserializer,
    BorshSchema,
    Clone,
    Copy,
    Debug,
    PartialOrd,
    Ord,
    PartialEq,
    Eq,
    Hash,
    Serialize,
    Deserialize,
)]
pub struct MaspEpoch(Epoch);

impl Display for MaspEpoch {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl FromStr for MaspEpoch {
    type Err = ParseIntError;

    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        let raw: u64 = u64::from_str(s)?;
        Ok(Self(Epoch(raw)))
    }
}

impl MaspEpoch {
    /// Converts and `Epoch` into a `MaspEpoch` based on the provided conversion
    /// rate
    pub fn try_from_epoch(
        epoch: Epoch,
        masp_epoch_multiplier: u64,
    ) -> Result<Self, &'static str> {
        Ok(Self(
            epoch
                .checked_div(masp_epoch_multiplier)
                .ok_or("Masp epoch multiplier cannot be 0")?,
        ))
    }

    /// Returns a 0 masp epoch
    pub const fn zero() -> Self {
        Self(Epoch(0))
    }

    /// Change to the previous masp epoch.
    pub fn prev(&self) -> Option<Self> {
        Some(Self(self.0.checked_sub(1)?))
    }

    /// Initialize a new masp epoch from the provided one
    #[cfg(any(test, feature = "testing"))]
    pub const fn new(epoch: u64) -> Self {
        Self(Epoch(epoch))
    }
}

/// The plain representation of a MASP aaset
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
#[derive(
    BorshSerialize,
    BorshDeserialize,
    BorshDeserializer,
    BorshSchema,
    Clone,
    Debug,
    PartialOrd,
    Ord,
    PartialEq,
    Eq,
    Hash,
    Serialize,
    Deserialize,
)]
pub struct AssetData {
    /// The token associated with this asset type
    pub token: Address,
    /// The denomination associated with the above toke
    pub denom: Denomination,
    /// The digit position covered by this asset type
    pub position: MaspDigitPos,
    /// The epoch of the asset type, if any
    pub epoch: Option<MaspEpoch>,
}

impl AssetData {
    /// Make asset type corresponding to given address and epoch
    pub fn encode(&self) -> Result<AssetType, std::io::Error> {
        // Timestamp the chosen token with the current epoch
        let token_bytes = self.serialize_to_vec();
        // Generate the unique asset identifier from the unique token address
        AssetType::new(token_bytes.as_ref()).map_err(|_| {
            std::io::Error::new(
                std::io::ErrorKind::Other,
                "unable to create asset type".to_string(),
            )
        })
    }

    /// Give this pre-asset type the given epoch if already has an epoch. Return
    /// the replaced value.
    pub fn redate(&mut self, to: MaspEpoch) -> Option<MaspEpoch> {
        if self.epoch.is_some() {
            self.epoch.replace(to)
        } else {
            None
        }
    }

    /// Remove the epoch associated with this pre-asset type
    pub fn undate(&mut self) {
        self.epoch = None;
    }
}

/// Make asset type corresponding to given address and epoch
pub fn encode_asset_type(
    token: Address,
    denom: Denomination,
    position: MaspDigitPos,
    epoch: Option<MaspEpoch>,
) -> Result<AssetType, std::io::Error> {
    AssetData {
        token,
        denom,
        position,
        epoch,
    }
    .encode()
}

/// MASP token map
pub type TokenMap = BTreeMap<String, Address>;

// enough capacity to store the payment address
const PAYMENT_ADDRESS_SIZE: usize = 43;

/// Wrapper for masp_primitive's FullViewingKey
#[derive(
    Clone,
    Debug,
    Copy,
    Hash,
    BorshSerialize,
    BorshDeserialize,
    BorshDeserializer,
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
        let payment_addr =
            masp_primitives::sapling::PaymentAddress::from_bytes(&{
                let mut payment_addr = [0u8; PAYMENT_ADDRESS_SIZE];
                payment_addr.copy_from_slice(&bytes[0..]);
                payment_addr
            })
            .ok_or_else(|| {
                DecodeError::InvalidInnerEncoding(
                    "invalid payment address provided".to_string(),
                )
            })?;
        Ok(Self(payment_addr))
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

impl From<ExtendedViewingKey> for masp_primitives::sapling::ViewingKey {
    fn from(value: ExtendedViewingKey) -> Self {
        let fvk = masp_primitives::zip32::ExtendedFullViewingKey::from(value);
        fvk.fvk.vk
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
    BorshDeserializer,
)]
pub struct PaymentAddress(masp_primitives::sapling::PaymentAddress);

impl PaymentAddress {
    /// Hash this payment address
    pub fn hash(&self) -> String {
        let bytes = self.0.serialize_to_vec();
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
        Self(addr)
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
#[derive(
    Clone,
    Debug,
    Copy,
    BorshSerialize,
    BorshDeserialize,
    BorshDeserializer,
    Hash,
    Eq,
    PartialEq,
)]
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
#[derive(Debug, Clone, Hash, Eq, PartialEq)]
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

    /// Get the contained transparent address data, if any
    pub fn t_addr_data(&self) -> Option<TAddrData> {
        match self {
            Self::Address(x) => Some(TAddrData::Addr(x.clone())),
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

/// Represents the pre-image to a TransparentAddress
#[derive(Debug, Clone, BorshDeserialize, BorshSerialize, BorshDeserializer)]
pub enum TAddrData {
    /// A transparent address within Namada
    Addr(Address),
    /// An IBC address
    Ibc(String),
}

impl TAddrData {
    /// Get the transparent address that this target would effectively go to
    pub fn effective_address(&self) -> Address {
        match self {
            Self::Addr(x) => x.clone(),
            // An IBC signer address effectively means that assets are
            // associated with the IBC internal address
            Self::Ibc(_) => IBC,
        }
    }

    /// Get the contained IBC receiver, if any
    pub fn ibc_receiver_address(&self) -> Option<String> {
        match self {
            Self::Ibc(address) => Some(address.clone()),
            _ => None,
        }
    }

    /// Get the contained Address, if any
    pub fn address(&self) -> Option<Address> {
        match self {
            Self::Addr(x) => Some(x.clone()),
            _ => None,
        }
    }

    /// Convert transparent address data into a transparent address
    pub fn taddress(&self) -> TransparentAddress {
        TransparentAddress(<[u8; 20]>::from(ripemd::Ripemd160::digest(
            sha2::Sha256::digest(&self.serialize_to_vec()),
        )))
    }
}

/// Convert a receiver string to a TransparentAddress
pub fn ibc_taddr(receiver: String) -> TransparentAddress {
    TAddrData::Ibc(receiver).taddress()
}

/// Convert a Namada Address to a TransparentAddress
pub fn addr_taddr(addr: Address) -> TransparentAddress {
    TAddrData::Addr(addr).taddress()
}

/// Represents a target for the funds of a transfer
#[derive(
    Debug,
    Clone,
    BorshDeserialize,
    BorshSerialize,
    BorshDeserializer,
    Hash,
    Eq,
    PartialEq,
)]
pub enum TransferTarget {
    /// A transfer going to a transparent address
    Address(Address),
    /// A transfer going to a shielded address
    PaymentAddress(PaymentAddress),
    /// A transfer going to an IBC address
    Ibc(String),
}

impl TransferTarget {
    /// Get the transparent address that this target would effectively go to
    pub fn effective_address(&self) -> Address {
        match self {
            Self::Address(x) => x.clone(),
            // A PaymentAddress for a target effectively means that assets will
            // be sent to the MASP
            Self::PaymentAddress(_) => MASP,
            // An IBC signer address for a target effectively means that assets
            // will be sent to the IBC internal address
            Self::Ibc(_) => IBC,
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

    /// Get the contained TAddrData, if any
    pub fn t_addr_data(&self) -> Option<TAddrData> {
        match self {
            Self::Address(x) => Some(TAddrData::Addr(x.clone())),
            Self::Ibc(x) => Some(TAddrData::Ibc(x.clone())),
            _ => None,
        }
    }
}

impl Display for TransferTarget {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Address(x) => x.fmt(f),
            Self::PaymentAddress(address) => address.fmt(f),
            Self::Ibc(x) => x.fmt(f),
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
    BorshDeserializer,
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
}

impl Display for BalanceOwner {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            BalanceOwner::Address(addr) => addr.fmt(f),
            BalanceOwner::FullViewingKey(fvk) => fvk.fmt(f),
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

/// The masp transactions' references of a given batch
#[derive(Default, Clone, Serialize, Deserialize)]
pub struct MaspTxRefs(pub Vec<TxId>);

impl Display for MaspTxRefs {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", serde_json::to_string(self).unwrap())
    }
}

impl FromStr for MaspTxRefs {
    type Err = serde_json::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        serde_json::from_str(s)
    }
}
