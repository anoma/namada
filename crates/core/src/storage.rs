//! Storage types
use std::collections::VecDeque;
use std::fmt::Display;
use std::io::{Read, Write};
use std::num::ParseIntError;
use std::ops::Deref;
use std::str::FromStr;

use arse_merkle_tree::InternalKey;
use borsh::{BorshDeserialize, BorshSchema, BorshSerialize};
use borsh_ext::BorshSerializeExt;
use data_encoding::{BASE32HEX_NOPAD, HEXUPPER};
use index_set::vec::VecIndexSet;
use namada_macros::BorshDeserializer;
#[cfg(feature = "migrations")]
use namada_migrations::*;
use serde::{Deserialize, Serialize};
use thiserror::Error;

use super::key::common;
use crate::address::{self, Address, PARAMETERS};
use crate::bytes::ByteBuf;
use crate::ethereum_events::{GetEventNonce, TransfersToNamada, Uint};
use crate::hash::Hash;
use crate::hints;
use crate::keccak::{KeccakHash, TryFromError};
use crate::time::DateTimeUtc;

/// The maximum size of an IBC key (in bytes) allowed in merkle-ized storage
pub const IBC_KEY_LIMIT: usize = 240;

#[allow(missing_docs)]
#[derive(Error, Debug)]
pub enum Error {
    #[error("Error parsing address: {0}")]
    ParseAddress(address::DecodeError),
    #[error("Error parsing address from a storage key")]
    ParseAddressFromKey,
    #[error("Reserved prefix or string is specified: {0}")]
    InvalidKeySeg(String),
    #[error("Error parsing key segment: {0}")]
    ParseKeySeg(String),
    #[error("Error parsing block hash: {0}")]
    ParseBlockHash(String),
    #[error("Error parsing tx index: {0}")]
    ParseTxIndex(String),
    #[error("The key is empty")]
    EmptyKey,
    #[error("The key is missing sub-key segments: {0}")]
    MissingSegments(String),
    #[error(
        "The following input could not be interpreted as a DB column family: \
         {0}"
    )]
    DbColFamily(String),
}

/// Result for functions that may fail
pub type Result<T> = std::result::Result<T, Error>;

/// The length of the block's hash string
pub const BLOCK_HASH_LENGTH: usize = 32;
/// The length of the transaction index
pub const TX_INDEX_LENGTH: usize = 4;
/// The length of the block height
pub const BLOCK_HEIGHT_LENGTH: usize = 8;
/// The length of the epoch type
pub const EPOCH_TYPE_LENGTH: usize = 8;

/// The separator of storage key segments
pub const KEY_SEGMENT_SEPARATOR: char = '/';
/// The reserved storage key prefix for addresses
pub const RESERVED_ADDRESS_PREFIX: char = '#';
/// The reserved storage key prefix for validity predicates
pub const VP_KEY_PREFIX: char = '?';
/// The reserved storage key for validity predicates
pub const RESERVED_VP_KEY: &str = "?";
/// The reserved storage key prefix for wasm codes
pub const WASM_KEY_PREFIX: &str = "wasm";
/// The reserved storage key prefix for wasm codes
pub const WASM_CODE_PREFIX: &str = "code";
/// The reserved storage key prefix for wasm codes' name
pub const WASM_CODE_NAME_PREFIX: &str = "name";
/// The reserved storage key prefix for wasm codes' length
pub const WASM_CODE_LEN_PREFIX: &str = "len";
/// The reserved storage key prefix for wasm code hashes
pub const WASM_HASH_PREFIX: &str = "hash";

#[derive(Debug, Copy, Clone, Serialize, Deserialize, PartialEq)]
/// Storage column families
pub enum DbColFam {
    /// Subspace
    SUBSPACE,
    /// Block
    BLOCK,
    /// State
    STATE,
    /// Diffs
    DIFFS,
    /// Diffs for rollback (only kept for 1 block)
    ROLLBACK,
    /// Replay protection
    REPLAYPROT,
}

/// Subspace column family name
pub const SUBSPACE_CF: &str = "subspace";
/// Diffs column family name
pub const DIFFS_CF: &str = "diffs";
/// Diffs for rollback (only kept for 1 block) column family name
pub const ROLLBACK_CF: &str = "rollback";
/// State column family name
pub const STATE_CF: &str = "state";
/// Block column family name
pub const BLOCK_CF: &str = "block";
/// Replay protection column family name
pub const REPLAY_PROTECTION_CF: &str = "replay_protection";

impl DbColFam {
    /// Get the name of the column family
    pub fn to_str(&self) -> &str {
        match self {
            DbColFam::SUBSPACE => SUBSPACE_CF,
            DbColFam::BLOCK => BLOCK_CF,
            DbColFam::STATE => STATE_CF,
            DbColFam::DIFFS => DIFFS_CF,
            DbColFam::ROLLBACK => ROLLBACK_CF,
            DbColFam::REPLAYPROT => REPLAY_PROTECTION_CF,
        }
    }

    /// Return an array of all column families
    pub fn all() -> [&'static str; 6] {
        [
            SUBSPACE_CF,
            BLOCK_CF,
            STATE_CF,
            DIFFS_CF,
            ROLLBACK_CF,
            REPLAY_PROTECTION_CF,
        ]
    }
}

impl FromStr for DbColFam {
    type Err = Error;

    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            SUBSPACE_CF => Ok(Self::SUBSPACE),
            DIFFS_CF => Ok(Self::DIFFS),
            ROLLBACK_CF => Ok(Self::ROLLBACK),
            STATE_CF => Ok(Self::STATE),
            REPLAY_PROTECTION_CF => Ok(Self::REPLAYPROT),
            BLOCK_CF => Ok(Self::BLOCK),
            _ => Err(Error::DbColFamily(s.to_string())),
        }
    }
}

/// Transaction index within block.
#[derive(
    Default,
    Clone,
    Copy,
    BorshSerialize,
    BorshDeserialize,
    BorshDeserializer,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
    Debug,
    Serialize,
    Deserialize,
)]
pub struct TxIndex(pub u32);

impl TxIndex {
    /// Convert from a [`usize`] or panic.
    pub fn must_from_usize(tx_index: usize) -> Self {
        Self(
            tx_index
                .try_into()
                .expect("Transaction index out of bounds"),
        )
    }
}

impl FromStr for TxIndex {
    type Err = Error;

    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        let tx_index = u32::from_str(s)
            .map_err(|err| Error::ParseTxIndex(err.to_string()))?;
        Ok(TxIndex(tx_index))
    }
}

impl Display for TxIndex {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl From<TxIndex> for u32 {
    fn from(index: TxIndex) -> Self {
        index.0
    }
}

impl From<u32> for TxIndex {
    fn from(value: u32) -> Self {
        Self(value)
    }
}

impl TxIndex {
    /// Checked index addition.
    #[must_use = "this returns the result of the operation, without modifying \
                  the original"]
    pub fn checked_add(self, rhs: impl Into<TxIndex>) -> Option<Self> {
        let TxIndex(rhs) = rhs.into();
        Some(Self(self.0.checked_add(rhs)?))
    }
}

/// Represents the indices of the accepted transactions
/// in a block.
#[derive(
    Clone,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
    Debug,
    Serialize,
    Deserialize,
    BorshSerialize,
    BorshDeserialize,
    BorshDeserializer,
    Default,
)]
pub struct BlockResults(VecIndexSet<u128>);

impl BlockResults {
    /// Accept the tx at the given position.
    #[inline]
    pub fn accept(&mut self, index: usize) {
        self.0.remove(index)
    }

    /// Reject the tx at the given position.
    #[inline]
    pub fn reject(&mut self, index: usize) {
        self.0.insert(index)
    }

    /// Check if the tx at the given position is accepted.
    #[inline]
    pub fn is_accepted(&self, index: usize) -> bool {
        !self.0.contains(index)
    }

    /// Return an iterator over the removed txs
    /// in this [`BlockResults`] instance.
    #[inline]
    pub fn iter_removed(&self) -> impl Iterator<Item = usize> + '_ {
        self.0.iter()
    }
}

/// Height of a block, i.e. the level. The `default` is the
/// [`BlockHeight::sentinel`] value, which doesn't correspond to any block.
#[derive(
    Clone,
    Copy,
    BorshSerialize,
    BorshDeserialize,
    BorshDeserializer,
    BorshSchema,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
    Debug,
    Serialize,
    Deserialize,
)]
pub struct BlockHeight(pub u64);

impl Default for BlockHeight {
    fn default() -> Self {
        Self::sentinel()
    }
}

impl Display for BlockHeight {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl From<BlockHeight> for u64 {
    fn from(height: BlockHeight) -> Self {
        height.0
    }
}

impl FromStr for BlockHeight {
    type Err = ParseIntError;

    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        Ok(Self(s.parse::<u64>()?))
    }
}

/// Hash of a block as fixed-size byte array
#[derive(
    Clone,
    Default,
    BorshSerialize,
    BorshDeserialize,
    BorshDeserializer,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
    Serialize,
    Deserialize,
)]
pub struct BlockHash(pub [u8; BLOCK_HASH_LENGTH]);

impl Display for BlockHash {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", HEXUPPER.encode(&self.0))
    }
}

impl From<Hash> for BlockHash {
    fn from(hash: Hash) -> Self {
        BlockHash(hash.0)
    }
}

impl From<u64> for BlockHeight {
    fn from(height: u64) -> Self {
        BlockHeight(height)
    }
}

impl From<tendermint::block::Height> for BlockHeight {
    fn from(height: tendermint::block::Height) -> Self {
        Self(u64::from(height))
    }
}

impl TryFrom<BlockHeight> for tendermint::block::Height {
    type Error = tendermint::Error;

    fn try_from(height: BlockHeight) -> std::result::Result<Self, Self::Error> {
        Self::try_from(height.0)
    }
}

impl TryFrom<i64> for BlockHeight {
    type Error = String;

    fn try_from(value: i64) -> std::result::Result<Self, Self::Error> {
        value
            .try_into()
            .map(BlockHeight)
            .map_err(|e| format!("Unexpected height value {}, {}", value, e))
    }
}
impl BlockHeight {
    /// The first block height 1.
    pub const fn first() -> Self {
        Self(1)
    }

    /// A sentinel value block height 0 may be used before any block is
    /// committed or in queries to read from the latest committed block.
    pub const fn sentinel() -> Self {
        Self(0)
    }

    /// Get the height of the next block
    pub fn next_height(&self) -> BlockHeight {
        BlockHeight(
            self.0
                .checked_add(1)
                .expect("Block height must not overflow"),
        )
    }

    /// Get the height of the previous block
    pub fn prev_height(&self) -> Option<BlockHeight> {
        Some(BlockHeight(self.0.checked_sub(1)?))
    }

    /// Checked block height addition.
    #[must_use = "this returns the result of the operation, without modifying \
                  the original"]
    pub fn checked_add(self, rhs: impl Into<BlockHeight>) -> Option<Self> {
        let BlockHeight(rhs) = rhs.into();
        Some(Self(self.0.checked_add(rhs)?))
    }

    /// Checked block height subtraction.
    #[must_use = "this returns the result of the operation, without modifying \
                  the original"]
    pub fn checked_sub(self, rhs: impl Into<BlockHeight>) -> Option<Self> {
        let BlockHeight(rhs) = rhs.into();
        Some(Self(self.0.checked_sub(rhs)?))
    }
}

impl TryFrom<&[u8]> for BlockHash {
    type Error = self::Error;

    fn try_from(value: &[u8]) -> Result<Self> {
        if value.len() != BLOCK_HASH_LENGTH {
            return Err(Error::ParseBlockHash(format!(
                "Unexpected block hash length {}, expected {}",
                value.len(),
                BLOCK_HASH_LENGTH
            )));
        }
        let mut hash = [0; 32];
        hash.copy_from_slice(value);
        Ok(BlockHash(hash))
    }
}

impl TryFrom<Vec<u8>> for BlockHash {
    type Error = self::Error;

    fn try_from(value: Vec<u8>) -> Result<Self> {
        value.as_slice().try_into()
    }
}

impl core::fmt::Debug for BlockHash {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let hash = format!("{}", ByteBuf(&self.0));
        f.debug_tuple("BlockHash").field(&hash).finish()
    }
}

/// The data from Tendermint header
/// relevant for Namada storage
#[derive(
    Clone, Debug, BorshSerialize, BorshDeserialize, BorshDeserializer, Default,
)]
pub struct Header {
    /// Merkle root hash of block
    pub hash: Hash,
    /// Timestamp associated to block
    pub time: DateTimeUtc,
    /// Hash of the addresses of the next validator set
    pub next_validators_hash: Hash,
}

impl Header {
    /// The number of bytes when this header is encoded
    pub fn encoded_len(&self) -> usize {
        self.serialize_to_vec().len()
    }
}

/// A storage key is made of storage key segments [`DbKeySeg`], separated by
/// [`KEY_SEGMENT_SEPARATOR`].
#[derive(
    Clone,
    BorshSerialize,
    BorshDeserialize,
    BorshDeserializer,
    BorshSchema,
    Debug,
    Default,
    Eq,
    PartialEq,
    Ord,
    PartialOrd,
    Hash,
    Serialize,
    Deserialize,
)]
pub struct Key {
    /// The segments of the key in the original (left-to-right) order.
    pub segments: Vec<DbKeySeg>,
}

/// A [`Key`] made of borrowed key segments [`DbKeySeg`].
#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct KeyRef<'a> {
    /// Reference of key segments
    pub segments: &'a [DbKeySeg],
}

impl From<DbKeySeg> for Key {
    fn from(seg: DbKeySeg) -> Self {
        Self {
            segments: vec![seg],
        }
    }
}

impl FromStr for Key {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self> {
        Key::parse(s)
    }
}

/// Storage keys that are utf8 encoded strings
#[derive(Eq, Debug, PartialEq, Copy, Clone, Hash, BorshDeserializer)]
pub struct StringKey {
    /// The original key string, in bytes
    pub original: [u8; IBC_KEY_LIMIT],
    /// The utf8 bytes representation of the key to be
    /// used internally in the merkle tree
    pub tree_key: InternalKey<IBC_KEY_LIMIT>,
    /// The length of the input (without the padding)
    pub length: usize,
}

#[allow(missing_docs)]
#[derive(Error, Debug)]
pub enum TreeKeyError {
    #[error("Invalid key for merkle tree: {0}")]
    InvalidMerkleKey(String),
}

impl Deref for StringKey {
    type Target = InternalKey<IBC_KEY_LIMIT>;

    fn deref(&self) -> &Self::Target {
        &self.tree_key
    }
}

impl BorshSerialize for StringKey {
    fn serialize<W: Write>(&self, writer: &mut W) -> std::io::Result<()> {
        let to_serialize = (self.original.to_vec(), self.tree_key, self.length);
        BorshSerialize::serialize(&to_serialize, writer)
    }
}

impl BorshDeserialize for StringKey {
    fn deserialize_reader<R: Read>(reader: &mut R) -> std::io::Result<Self> {
        use std::io::ErrorKind;
        let (original, tree_key, length): (
            Vec<u8>,
            InternalKey<IBC_KEY_LIMIT>,
            usize,
        ) = BorshDeserialize::deserialize_reader(reader)?;
        let original: [u8; IBC_KEY_LIMIT] =
            original.try_into().map_err(|_| {
                std::io::Error::new(
                    ErrorKind::InvalidData,
                    "Input byte vector is too large",
                )
            })?;
        Ok(Self {
            original,
            tree_key,
            length,
        })
    }
}

impl arse_merkle_tree::Key<IBC_KEY_LIMIT> for StringKey {
    type Error = TreeKeyError;

    fn as_slice(&self) -> &[u8] {
        &self.original.as_slice()[..self.length]
    }

    fn try_from_bytes(bytes: &[u8]) -> std::result::Result<Self, Self::Error> {
        let mut tree_key = [0u8; IBC_KEY_LIMIT];
        let mut original = [0u8; IBC_KEY_LIMIT];
        let mut length = 0;
        for (i, byte) in bytes.iter().enumerate() {
            if i >= IBC_KEY_LIMIT {
                return Err(TreeKeyError::InvalidMerkleKey(
                    "Input IBC key is too large".into(),
                ));
            }
            original[i] = *byte;
            tree_key[i] = byte.wrapping_add(1);
            // There is no way the bytes.len() > u64::max
            #[allow(clippy::arithmetic_side_effects)]
            {
                length += 1;
            }
        }
        Ok(Self {
            original,
            tree_key: tree_key.into(),
            length,
        })
    }
}

/// A wrapper around raw bytes to be stored as values
/// in a merkle tree
#[derive(
    Clone,
    Debug,
    PartialEq,
    Eq,
    BorshSerialize,
    BorshDeserialize,
    BorshDeserializer,
)]
pub struct TreeBytes(pub Vec<u8>);

impl arse_merkle_tree::traits::Value for TreeBytes {
    fn as_slice(&self) -> &[u8] {
        self.0.as_slice()
    }

    fn zero() -> Self {
        TreeBytes::zero()
    }
}

impl TreeBytes {
    /// The value indicating that a leaf should be deleted
    pub fn zero() -> Self {
        Self(vec![])
    }

    /// Check if an instance is the zero value
    pub fn is_zero(&self) -> bool {
        self.0.is_empty()
    }
}

impl From<Vec<u8>> for TreeBytes {
    fn from(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }
}

impl From<TreeBytes> for Vec<u8> {
    fn from(bytes: TreeBytes) -> Self {
        bytes.0
    }
}

impl Key {
    /// Parses string and returns a key
    pub fn parse(string: impl AsRef<str>) -> Result<Self> {
        let string = string.as_ref();
        if string.is_empty() {
            Err(Error::ParseKeySeg(string.to_string()))
        } else {
            let mut segments = Vec::new();
            for s in string.split(KEY_SEGMENT_SEPARATOR) {
                segments.push(DbKeySeg::parse(s.to_owned())?);
            }
            Ok(Key { segments })
        }
    }

    /// Returns a new key with segments of `Self` and the given segment
    pub fn push<T: KeySeg>(&self, other: &T) -> Result<Self> {
        let mut segments = self.segments.clone();
        segments.push(DbKeySeg::parse(other.raw())?);
        Ok(Key { segments })
    }

    /// Takes ownership of the key, appends a new segment to it,
    /// and returns the modified key.
    #[must_use]
    pub fn with_segment<T: KeySeg>(mut self, other: T) -> Self {
        self.segments.push(other.to_db_key());
        self
    }

    /// Returns a new key with segments of `Self` and the given key
    pub fn join(&self, other: &Key) -> Self {
        let mut segments = self.segments.clone();
        let mut added = other.segments.clone();
        segments.append(&mut added);
        Key { segments }
    }

    /// Returns the addresses from the key segments
    pub fn find_addresses(&self) -> Vec<Address> {
        self.iter_addresses().cloned().collect()
    }

    /// Returns the address from the first key segment if it's an address.
    pub fn fst_address(&self) -> Option<&Address> {
        self.segments.first().and_then(|s| match s {
            DbKeySeg::AddressSeg(addr) => Some(addr),
            DbKeySeg::StringSeg(_) => None,
        })
    }

    /// Iterates over all addresses in the key segments
    pub fn iter_addresses<'k, 'this: 'k>(
        &'this self,
    ) -> impl Iterator<Item = &'_ Address> + 'k {
        self.segments.iter().filter_map(|s| match s {
            DbKeySeg::AddressSeg(addr) => Some(addr),
            _ => None,
        })
    }

    /// Return the segment at the index parameter
    pub fn get_at(&self, index: usize) -> Option<&DbKeySeg> {
        self.segments.get(index)
    }

    /// Returns the length
    pub fn len(&self) -> usize {
        self.to_string().len()
    }

    /// Returns `true` if the key is empty
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Returns the first segment of the key, or `None` if it is empty.
    pub fn first(&self) -> Option<&DbKeySeg> {
        self.segments.first()
    }

    /// Returns the last segment of the key, or `None` if it is empty.
    pub fn last(&self) -> Option<&DbKeySeg> {
        self.segments.last()
    }

    /// Returns the prefix before the last segment and last segment of the key,
    /// or `None` if it is empty.
    pub fn split_last(&self) -> Option<(KeyRef<'_>, &DbKeySeg)> {
        let (last, prefix) = self.segments.split_last()?;
        Some((KeyRef { segments: prefix }, last))
    }

    /// Returns a key of the wasm code of the given hash
    pub fn wasm_code(code_hash: &Hash) -> Self {
        let mut segments =
            Self::from(PARAMETERS.to_owned().to_db_key()).segments;
        segments.push(DbKeySeg::StringSeg(WASM_KEY_PREFIX.to_owned()));
        segments.push(DbKeySeg::StringSeg(WASM_CODE_PREFIX.to_owned()));
        segments.push(DbKeySeg::StringSeg(code_hash.to_string()));
        Key { segments }
    }

    /// Returns a key of wasm code's hash of the given name
    pub fn wasm_code_name(code_name: String) -> Self {
        let mut segments =
            Self::from(PARAMETERS.to_owned().to_db_key()).segments;
        segments.push(DbKeySeg::StringSeg(WASM_KEY_PREFIX.to_owned()));
        segments.push(DbKeySeg::StringSeg(WASM_CODE_NAME_PREFIX.to_owned()));
        segments.push(DbKeySeg::StringSeg(code_name));
        Key { segments }
    }

    /// Returns a key of the wasm code's length of the given hash
    pub fn wasm_code_len(code_hash: &Hash) -> Self {
        let mut segments =
            Self::from(PARAMETERS.to_owned().to_db_key()).segments;
        segments.push(DbKeySeg::StringSeg(WASM_KEY_PREFIX.to_owned()));
        segments.push(DbKeySeg::StringSeg(WASM_CODE_LEN_PREFIX.to_owned()));
        segments.push(DbKeySeg::StringSeg(code_hash.to_string()));
        Key { segments }
    }

    /// Returns a key of the wasm code hash of the given code path
    pub fn wasm_hash(code_path: impl AsRef<str>) -> Self {
        let mut segments =
            Self::from(PARAMETERS.to_owned().to_db_key()).segments;
        segments.push(DbKeySeg::StringSeg(WASM_KEY_PREFIX.to_owned()));
        segments.push(DbKeySeg::StringSeg(WASM_HASH_PREFIX.to_owned()));
        segments.push(DbKeySeg::StringSeg(code_path.as_ref().to_string()));
        Key { segments }
    }

    /// Returns a key of the validity predicate of the given address
    /// Only this function can push "?" segment for validity predicate
    pub fn validity_predicate(addr: &Address) -> Self {
        let mut segments = Self::from(addr.to_db_key()).segments;
        segments.push(DbKeySeg::StringSeg(RESERVED_VP_KEY.to_owned()));
        Key { segments }
    }

    /// Check if the given key is a key to a validity predicate. If it is,
    /// returns the address of the account.
    pub fn is_validity_predicate(&self) -> Option<&Address> {
        match &self.segments[..] {
            [DbKeySeg::AddressSeg(address), DbKeySeg::StringSeg(sub_key)]
                if sub_key == RESERVED_VP_KEY =>
            {
                Some(address)
            }
            _ => None,
        }
    }

    /// Returns a key from the given DB key path that has the height and
    /// the space type
    pub fn parse_db_key(db_key: &str) -> Result<Self> {
        let mut segments: Vec<&str> =
            db_key.split(KEY_SEGMENT_SEPARATOR).collect();
        let key = match segments.get(3) {
            Some(seg) if *seg == RESERVED_VP_KEY => {
                // the path of a validity predicate should be
                // height/subspace/{address}/?
                let mut addr_str =
                    (*segments.get(2).expect("the address not found"))
                        .to_owned();
                let _ = addr_str.remove(0);
                let addr = Address::decode(&addr_str)
                    .expect("cannot decode the address");
                Self::validity_predicate(&addr)
            }
            _ => Self::parse(
                segments
                    .split_off(2)
                    .join(&KEY_SEGMENT_SEPARATOR.to_string()),
            )
            .map_err(|e| {
                Error::ParseKeySeg(format!(
                    "Cannot parse key segments {}: {}",
                    db_key, e
                ))
            })?,
        };
        Ok(key)
    }

    /// Returns a sub key without the first segment
    pub fn sub_key(&self) -> Result<Self> {
        match self.segments.split_first() {
            Some((_, rest)) => {
                if rest.is_empty() {
                    Err(Error::MissingSegments(format!("{self}")))
                } else {
                    Ok(Self {
                        segments: rest.to_vec(),
                    })
                }
            }
            None => Err(Error::EmptyKey),
        }
    }

    /// Check if the key begins with the given prefix and returns:
    ///   - `Some(Some(suffix))` the suffix after the match with, if any, or
    ///   - `Some(None)` if the prefix is matched, but it has no suffix, or
    ///   - `None` if it doesn't match
    pub fn split_prefix(&self, prefix: &Self) -> Option<Option<Self>> {
        if self.segments.len() < prefix.segments.len() {
            return None;
        } else if self == prefix {
            return Some(None);
        }
        // This is safe, because we check that the length of segments in self >=
        // in prefix above
        let (self_prefix, rest) = self.segments.split_at(prefix.segments.len());
        if self_prefix == prefix.segments {
            Some(Some(Key {
                segments: rest.to_vec(),
            }))
        } else {
            None
        }
    }
}

impl Display for Key {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let key = self
            .segments
            .iter()
            .map(DbKeySeg::raw)
            .collect::<Vec<String>>()
            .join(&KEY_SEGMENT_SEPARATOR.to_string());
        f.write_str(&key)
    }
}

impl KeyRef<'_> {
    /// Check if [`KeyRef`] is equal to a [`Key`].
    pub fn eq_owned(&self, other: &Key) -> bool {
        self.segments == other.segments
    }

    /// Returns the prefix before the last segment and last segment of the key,
    /// or `None` if it is empty.
    pub fn split_last(&self) -> Option<(KeyRef<'_>, &DbKeySeg)> {
        let (last, prefix) = self.segments.split_last()?;
        Some((KeyRef { segments: prefix }, last))
    }
}

// TODO use std::convert::{TryFrom, Into}?
/// Represents a segment in a path that may be used as a database key
pub trait KeySeg {
    /// Reverse of `into_string`. Convert key segment to `Self`.
    fn parse(string: String) -> Result<Self>
    where
        Self: Sized;

    /// Convert `Self` to a string.
    fn raw(&self) -> String;

    /// Convert `Self` to a key segment. This mapping should preserve the
    /// ordering of `Self`
    fn to_db_key(&self) -> DbKeySeg;
}

/// A storage key segment
#[derive(
    Clone,
    BorshSerialize,
    BorshDeserialize,
    BorshDeserializer,
    BorshSchema,
    Debug,
    Eq,
    PartialEq,
    Ord,
    PartialOrd,
    Hash,
    Serialize,
    Deserialize,
)]
pub enum DbKeySeg {
    /// A segment made of an address
    AddressSeg(Address),
    /// Any other key segment
    StringSeg(String),
}

impl KeySeg for DbKeySeg {
    fn parse(mut string: String) -> Result<Self> {
        // a separator should not be included
        if string.contains(KEY_SEGMENT_SEPARATOR) {
            return Err(Error::InvalidKeySeg(string));
        }
        match string.chars().next() {
            // address hashes are prefixed with `'#'`
            Some(c) if c == RESERVED_ADDRESS_PREFIX => {
                let _ = string.remove(0);
                Address::decode(&string)
                    .map_err(Error::ParseAddress)
                    .map(DbKeySeg::AddressSeg)
            }
            _ => Ok(DbKeySeg::StringSeg(string)),
        }
    }

    fn raw(&self) -> String {
        match self {
            DbKeySeg::AddressSeg(addr) => {
                format!("{}{}", RESERVED_ADDRESS_PREFIX, addr.encode())
            }
            DbKeySeg::StringSeg(seg) => seg.to_owned(),
        }
    }

    fn to_db_key(&self) -> DbKeySeg {
        self.clone()
    }
}

impl KeySeg for String {
    fn parse(string: String) -> Result<Self> {
        Ok(string)
    }

    fn raw(&self) -> String {
        self.to_owned()
    }

    fn to_db_key(&self) -> DbKeySeg {
        DbKeySeg::StringSeg(self.clone())
    }
}

impl KeySeg for BlockHeight {
    fn parse(string: String) -> Result<Self> {
        let h = string.parse::<u64>().map_err(|e| {
            Error::ParseKeySeg(format!(
                "Unexpected height value {}, {}",
                string, e
            ))
        })?;
        Ok(BlockHeight(h))
    }

    fn raw(&self) -> String {
        self.0.raw()
    }

    fn to_db_key(&self) -> DbKeySeg {
        DbKeySeg::StringSeg(self.raw())
    }
}

impl KeySeg for Address {
    fn parse(mut seg: String) -> Result<Self> {
        match seg.chars().next() {
            Some(c) if c == RESERVED_ADDRESS_PREFIX => {
                let _ = seg.remove(0);
                Address::decode(seg).map_err(Error::ParseAddress)
            }
            _ => Err(Error::ParseAddressFromKey),
        }
    }

    fn raw(&self) -> String {
        format!("{}{}", RESERVED_ADDRESS_PREFIX, self.encode())
    }

    fn to_db_key(&self) -> DbKeySeg {
        DbKeySeg::AddressSeg(self.clone())
    }
}

impl KeySeg for Hash {
    fn parse(seg: String) -> Result<Self> {
        seg.try_into()
            .map_err(|e: crate::hash::Error| Error::ParseKeySeg(e.to_string()))
    }

    fn raw(&self) -> String {
        self.to_string()
    }

    fn to_db_key(&self) -> DbKeySeg {
        DbKeySeg::StringSeg(self.raw())
    }
}

impl KeySeg for KeccakHash {
    fn parse(seg: String) -> Result<Self> {
        seg.try_into()
            .map_err(|e: TryFromError| Error::ParseKeySeg(e.to_string()))
    }

    fn raw(&self) -> String {
        self.to_string()
    }

    fn to_db_key(&self) -> DbKeySeg {
        DbKeySeg::StringSeg(self.raw())
    }
}

/// Implement [`KeySeg`] for a type via base32hex of its BE bytes (using
/// `to_le_bytes()` and `from_le_bytes` methods) that maintains sort order of
/// the original data.
// TODO this could be a bit more efficient without the string conversion (atm
// with base32hex), if we can use bytes for storage key directly (which we can
// with rockDB, but atm, we're calling `to_string()` using the custom `Display`
// impl from here)
macro_rules! impl_int_key_seg {
    ($unsigned:ty, $signed:ty, $len:literal) => {
        impl KeySeg for $unsigned {
            fn parse(string: String) -> Result<Self> {
                let bytes =
                    BASE32HEX_NOPAD.decode(string.as_ref()).map_err(|err| {
                        Error::ParseKeySeg(format!(
                            "Failed parsing {} with {}",
                            string, err
                        ))
                    })?;
                let mut fixed_bytes = [0; $len];
                fixed_bytes.copy_from_slice(&bytes);
                Ok(<$unsigned>::from_be_bytes(fixed_bytes))
            }

            fn raw(&self) -> String {
                BASE32HEX_NOPAD.encode(&self.to_be_bytes())
            }

            fn to_db_key(&self) -> DbKeySeg {
                DbKeySeg::StringSeg(self.raw())
            }
        }

        impl KeySeg for $signed {
            fn parse(string: String) -> Result<Self> {
                // get signed int from a unsigned int complemented with a max
                // value
                let complemented = <$unsigned>::parse(string)?;
                #[allow(clippy::cast_possible_wrap)]
                let signed = (complemented as $signed) ^ <$signed>::MIN;
                Ok(signed)
            }

            fn raw(&self) -> String {
                // signed int is converted to unsigned int that preserves the
                // order by complementing it with a max value
                #[allow(clippy::cast_sign_loss)]
                let complemented = (*self ^ <$signed>::MIN) as $unsigned;
                complemented.raw()
            }

            fn to_db_key(&self) -> DbKeySeg {
                DbKeySeg::StringSeg(self.raw())
            }
        }
    };
}

impl_int_key_seg!(u8, i8, 1);
impl_int_key_seg!(u16, i16, 2);
impl_int_key_seg!(u32, i32, 4);
impl_int_key_seg!(u64, i64, 8);
impl_int_key_seg!(u128, i128, 16);

impl KeySeg for Epoch {
    fn parse(string: String) -> Result<Self>
    where
        Self: Sized,
    {
        let raw = u64::parse(string)?;
        Ok(Epoch(raw))
    }

    fn raw(&self) -> String {
        self.to_string()
    }

    fn to_db_key(&self) -> DbKeySeg {
        self.0.to_db_key()
    }
}

impl KeySeg for common::PublicKey {
    fn parse(string: String) -> Result<Self>
    where
        Self: Sized,
    {
        let raw = common::PublicKey::from_str(&string)
            .map_err(|err| Error::ParseKeySeg(err.to_string()))?;
        Ok(raw)
    }

    fn raw(&self) -> String {
        self.to_string()
    }

    fn to_db_key(&self) -> DbKeySeg {
        DbKeySeg::StringSeg(self.raw())
    }
}

/// Epoch identifier. Epochs are identified by consecutive numbers.
#[derive(
    Clone,
    Copy,
    Default,
    Debug,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
    BorshSerialize,
    BorshDeserialize,
    BorshDeserializer,
    BorshSchema,
    Serialize,
    Deserialize,
)]
pub struct Epoch(pub u64);

impl Display for Epoch {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl FromStr for Epoch {
    type Err = ParseIntError;

    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        let raw: u64 = u64::from_str(s)?;
        Ok(Self(raw))
    }
}

impl Epoch {
    /// Change to the next epoch
    pub fn next(&self) -> Self {
        Self(self.0.checked_add(1).expect("Epoch shouldn't overflow"))
    }

    /// Change to the previous epoch.
    pub fn prev(&self) -> Option<Self> {
        Some(Self(self.0.checked_sub(1)?))
    }

    /// Iterate a range of consecutive epochs starting from `self` of a given
    /// length. Work-around for `Step` implementation pending on stabilization of <https://github.com/rust-lang/rust/issues/42168>.
    pub fn iter_range(self, len: u64) -> impl Iterator<Item = Epoch> + Clone {
        let start_ix: u64 = self.into();
        let end_ix: u64 = start_ix.checked_add(len).unwrap_or(u64::MAX);
        (start_ix..end_ix).map(Epoch::from)
    }

    /// Iterate a range of epochs, inclusive of the start and end.
    pub fn iter_bounds_inclusive(
        start: Self,
        end: Self,
    ) -> impl Iterator<Item = Epoch> + Clone {
        let start_ix = start.0;
        let end_ix = end.0;
        (start_ix..=end_ix).map(Epoch::from)
    }

    /// Checked epoch addition.
    #[must_use = "this returns the result of the operation, without modifying \
                  the original"]
    pub fn checked_add(self, rhs: impl Into<Epoch>) -> Option<Self> {
        let Epoch(rhs) = rhs.into();
        Some(Self(self.0.checked_add(rhs)?))
    }

    /// Unchecked epoch addition.
    ///
    /// # Panic
    ///
    /// Panics on overflow. Care must be taken to only use this with trusted
    /// values that are known to be in a limited range (e.g. system parameters
    /// but not e.g. transaction variables).
    pub fn unchecked_add(self, rhs: impl Into<Epoch>) -> Self {
        self.checked_add(rhs)
            .expect("Epoch addition shouldn't overflow")
    }

    /// Checked epoch subtraction. Computes self - rhs, returning None if
    /// overflow occurred.
    #[must_use = "this returns the result of the operation, without modifying \
                  the original"]
    pub fn checked_sub(self, rhs: impl Into<Epoch>) -> Option<Self> {
        let Epoch(rhs) = rhs.into();
        Some(Self(self.0.checked_sub(rhs)?))
    }

    /// Checked epoch division.
    #[must_use = "this returns the result of the operation, without modifying \
                  the original"]
    pub fn checked_div(self, rhs: impl Into<Epoch>) -> Option<Self> {
        let Epoch(rhs) = rhs.into();
        Some(Self(self.0.checked_div(rhs)?))
    }

    /// Checked epoch multiplication.
    #[must_use = "this returns the result of the operation, without modifying \
                  the original"]
    pub fn checked_mul(self, rhs: impl Into<Epoch>) -> Option<Self> {
        let Epoch(rhs) = rhs.into();
        Some(Self(self.0.checked_mul(rhs)?))
    }

    /// Checked epoch integral reminder.
    #[must_use = "this returns the result of the operation, without modifying \
                  the original"]
    pub fn checked_rem(self, rhs: impl Into<Epoch>) -> Option<Self> {
        let Epoch(rhs) = rhs.into();
        Some(Self(self.0.checked_rem(rhs)?))
    }

    /// Checked epoch subtraction. Computes self - rhs, returning default
    /// `Epoch(0)` if overflow occurred.
    #[must_use = "this returns the result of the operation, without modifying \
                  the original"]
    pub fn sub_or_default(self, rhs: Epoch) -> Self {
        self.checked_sub(rhs).unwrap_or_default()
    }
}

impl From<u64> for Epoch {
    fn from(epoch: u64) -> Self {
        Epoch(epoch)
    }
}

impl From<Epoch> for u64 {
    fn from(epoch: Epoch) -> Self {
        epoch.0
    }
}

/// Predecessor block epochs
#[derive(
    Clone,
    Debug,
    Default,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
    BorshSerialize,
    BorshDeserialize,
    BorshDeserializer,
)]
pub struct Epochs {
    /// The block heights of the first block of each known epoch.
    /// Invariant: the values must be sorted in ascending order.
    pub first_block_heights: Vec<BlockHeight>,
}

impl Epochs {
    /// Record start of a new epoch at the given block height
    pub fn new_epoch(&mut self, block_height: BlockHeight) {
        self.first_block_heights.push(block_height);
    }

    /// Look up the epoch of a given block height. If the given height is
    /// greater than the current height, the current epoch will be returned even
    /// though an epoch for a future block cannot be determined.
    pub fn get_epoch(&self, block_height: BlockHeight) -> Option<Epoch> {
        if let Some((_first_known_epoch_height, rest)) =
            self.first_block_heights.split_first()
        {
            let mut epoch = Epoch::default();
            for next_block_height in rest {
                if block_height < *next_block_height {
                    return Some(epoch);
                } else {
                    epoch = epoch.next();
                }
            }
            return Some(epoch);
        }
        None
    }

    /// Look up the starting block height of an epoch at or before a given
    /// height.
    pub fn get_epoch_start_height(
        &self,
        height: BlockHeight,
    ) -> Option<BlockHeight> {
        for start_height in self.first_block_heights.iter().rev() {
            if *start_height <= height {
                return Some(*start_height);
            }
        }
        None
    }

    /// Look up the starting block height of the given epoch
    pub fn get_start_height_of_epoch(
        &self,
        epoch: Epoch,
    ) -> Option<BlockHeight> {
        if epoch.0 > self.first_block_heights.len() as u64 {
            return None;
        }
        let idx = usize::try_from(epoch.0).ok()?;
        self.first_block_heights.get(idx).copied()
    }

    /// Return all starting block heights for each successive Epoch.
    ///
    /// __INVARIANT:__ The returned values are sorted in ascending order.
    pub fn first_block_heights(&self) -> &[BlockHeight] {
        &self.first_block_heights
    }
}

/// A value of a storage prefix iterator.
#[derive(
    Debug,
    Clone,
    BorshSerialize,
    BorshDeserialize,
    BorshDeserializer,
    BorshSchema,
)]
pub struct PrefixValue {
    /// Storage key
    pub key: Key,
    /// Raw value bytes
    pub value: Vec<u8>,
}

/// Container of all Ethereum event queues.
#[derive(
    Default, Debug, BorshSerialize, BorshDeserialize, BorshDeserializer,
)]
pub struct EthEventsQueue {
    /// Queue of transfer to Namada events.
    pub transfers_to_namada: InnerEthEventsQueue<TransfersToNamada>,
}

/// A queue of confirmed Ethereum events of type `E`.
///
/// __INVARIANT:__ At any given moment, the queue holds the nonce `N`
/// of the next confirmed event to be processed by the ledger, and any
/// number of events that have been confirmed with a nonce greater than
/// or equal to `N`. Events in the queue must be returned in ascending
/// order of their nonce.
#[derive(Debug, BorshSerialize, BorshDeserialize)]
pub struct InnerEthEventsQueue<E> {
    next_nonce_to_process: Uint,
    inner: VecDeque<E>,
}

impl<E: GetEventNonce> InnerEthEventsQueue<E> {
    /// Return an Ethereum events queue starting at the specified nonce.
    pub fn new_at(next_nonce_to_process: Uint) -> Self {
        Self {
            next_nonce_to_process,
            ..Default::default()
        }
    }
}

impl<E: GetEventNonce> Default for InnerEthEventsQueue<E> {
    fn default() -> Self {
        Self {
            next_nonce_to_process: 0u64.into(),
            inner: Default::default(),
        }
    }
}

/// Draining iterator over a queue of Ethereum events,
///
/// At each iteration step, we peek into the head of the
/// queue, and if an event is present with a nonce equal
/// to the local nonce maintained by the iterator object,
/// we pop it and increment the local nonce. Otherwise,
/// iteration stops.
///
/// Upon being dropped, the iterator object updates the
/// nonce of the next event of type `E` to be processed
/// by the ledger (stored in an [`InnerEthEventsQueue`]),
/// if the iterator's nonce was incremented.
pub struct EthEventsQueueIter<'queue, E> {
    current_nonce: Uint,
    queue: &'queue mut InnerEthEventsQueue<E>,
}

impl<E> Drop for EthEventsQueueIter<'_, E> {
    fn drop(&mut self) {
        // on drop, we commit the nonce of the next event to process
        if self.queue.next_nonce_to_process < self.current_nonce {
            self.queue.next_nonce_to_process = self.current_nonce;
        }
    }
}

impl<E: GetEventNonce> Iterator for EthEventsQueueIter<'_, E> {
    type Item = E;

    fn next(&mut self) -> Option<E> {
        let nonce_in_queue = self.queue.peek_event_nonce()?;
        if nonce_in_queue == self.current_nonce {
            self.current_nonce = self
                .current_nonce
                .checked_increment()
                .expect("Nonce overflow");
            self.queue.pop_event()
        } else {
            None
        }
    }
}

impl<E: GetEventNonce> InnerEthEventsQueue<E> {
    /// Push a new Ethereum event of type `E` into the queue,
    /// and return a draining iterator over the next events to
    /// be processed, if any.
    pub fn push_and_iter(
        &mut self,
        latest_event: E,
    ) -> EthEventsQueueIter<'_, E>
    where
        E: std::fmt::Debug,
    {
        let event_nonce = latest_event.get_event_nonce();
        if hints::unlikely(self.next_nonce_to_process > event_nonce) {
            unreachable!(
                "Attempted to replay an Ethereum event: {latest_event:#?}"
            );
        }

        self.try_push_event(latest_event);

        EthEventsQueueIter {
            current_nonce: self.next_nonce_to_process,
            queue: self,
        }
    }

    /// Provide a reference to the earliest event stored in the queue.
    #[inline]
    fn peek_event_nonce(&self) -> Option<Uint> {
        self.inner.front().map(GetEventNonce::get_event_nonce)
    }

    /// Attempt to push a new Ethereum event to the queue.
    ///
    /// This operation may panic if a confirmed event is
    /// already present in the queue.
    #[inline]
    fn try_push_event(&mut self, new_event: E)
    where
        E: std::fmt::Debug,
    {
        self.inner
            .binary_search_by_key(
                &new_event.get_event_nonce(),
                |event_in_queue| event_in_queue.get_event_nonce(),
            )
            .map_or_else(
                |insert_at| {
                    tracing::debug!(?new_event, "Queueing Ethereum event");
                    self.inner.insert(insert_at, new_event)
                },
                // the event is already present in the queue... this is
                // certainly a protocol error
                |_| {
                    hints::cold();
                    unreachable!(
                        "An event with an identical nonce was already present \
                         in the EthEventsQueue"
                    )
                },
            )
    }

    /// Pop a transfer to Namada event from the queue.
    #[inline]
    fn pop_event(&mut self) -> Option<E> {
        self.inner.pop_front()
    }
}

impl<E> GetEventNonce for InnerEthEventsQueue<E> {
    fn get_event_nonce(&self) -> Uint {
        self.next_nonce_to_process
    }
}

#[cfg(test)]
/// Tests and strategies for storage
pub mod tests {
    use proptest::prelude::*;

    use super::*;
    use crate::address::testing::arb_address;

    proptest! {
        /// Tests that any key that doesn't contain reserved prefixes is valid.
        /// This test excludes key segments starting with `#` or `?`
        /// because they are reserved for `Address` or a validity predicate.
        #[test]
        fn test_key_parse(s in "[^#?/][^/]*/[^#?/][^/]*/[^#?/][^/]*") {
            let key = Key::parse(s.clone()).expect("cannot parse the string");
            assert_eq!(key.to_string(), s);
        }

        /// Tests that any key that doesn't contain reserved prefixes and
        /// separators is valid. This test excludes key segments including `/`
        /// or starting with `#` or `?` because they are reserved for separator,
        /// `Address` or validity predicate.
        #[test]
        fn test_key_push(s in "[^#?/][^/]*") {
            let addr = address::testing::established_address_1();
            let key = Key::from(addr.to_db_key()).push(&s).expect("cannot push the segment");
            assert_eq!(key.segments[1].raw(), s);
        }

        /// Test roundtrip parsing of key segments derived from [`Epoch`]
        /// values.
        #[test]
        fn test_parse_epoch_key_segment(e in 0..=u64::MAX) {
            let original_epoch = Epoch(e);
            let key_seg = match original_epoch.to_db_key() {
                DbKeySeg::StringSeg(s) => s,
                _ => panic!("Test failed"),
            };
            let parsed_epoch: Epoch = KeySeg::parse(key_seg).expect("Test failed");
            assert_eq!(original_epoch, parsed_epoch);
        }
    }

    /// Test that providing an [`EthEventsQueue`] with an event containing
    /// a nonce identical to the next expected nonce in Namada yields the
    /// event itself.
    #[test]
    fn test_eth_events_queue_equal_nonces() {
        let mut queue = EthEventsQueue::default();
        queue.transfers_to_namada.next_nonce_to_process = 2u64.into();
        let new_event = TransfersToNamada {
            transfers: vec![],
            nonce: 2u64.into(),
        };
        let next_event = queue
            .transfers_to_namada
            .push_and_iter(new_event.clone())
            .next();
        assert_eq!(next_event, Some(new_event));
    }

    /// Test that providing an [`EthEventsQueue`] with an event containing
    /// a nonce lower than the next expected nonce in Namada results in a
    /// panic.
    #[test]
    #[should_panic = "Attempted to replay an Ethereum event"]
    fn test_eth_events_queue_panic_on_invalid_nonce() {
        let mut queue = EthEventsQueue::default();
        queue.transfers_to_namada.next_nonce_to_process = 3u64.into();
        let new_event = TransfersToNamada {
            transfers: vec![],
            nonce: 2u64.into(),
        };
        _ = queue.transfers_to_namada.push_and_iter(new_event);
    }

    /// Test enqueueing transfer to Namada events to
    /// an [`EthEventsQueue`].
    #[test]
    fn test_eth_events_queue_enqueue() {
        let mut queue = EthEventsQueue::default();
        queue.transfers_to_namada.next_nonce_to_process = 1u64.into();

        let new_event_1 = TransfersToNamada {
            transfers: vec![],
            nonce: 1u64.into(),
        };
        let new_event_2 = TransfersToNamada {
            transfers: vec![],
            nonce: 2u64.into(),
        };
        let new_event_3 = TransfersToNamada {
            transfers: vec![],
            nonce: 3u64.into(),
        };
        let new_event_4 = TransfersToNamada {
            transfers: vec![],
            nonce: 4u64.into(),
        };
        let new_event_7 = TransfersToNamada {
            transfers: vec![],
            nonce: 7u64.into(),
        };

        // enqueue events
        assert!(
            queue
                .transfers_to_namada
                .push_and_iter(new_event_4.clone())
                .next()
                .is_none()
        );
        assert!(
            queue
                .transfers_to_namada
                .push_and_iter(new_event_2.clone())
                .next()
                .is_none()
        );
        assert!(
            queue
                .transfers_to_namada
                .push_and_iter(new_event_3.clone())
                .next()
                .is_none()
        );
        assert!(
            queue
                .transfers_to_namada
                .push_and_iter(new_event_7.clone())
                .next()
                .is_none()
        );
        assert_eq!(
            &queue.transfers_to_namada.inner,
            &[
                new_event_2.clone(),
                new_event_3.clone(),
                new_event_4.clone(),
                new_event_7.clone()
            ]
        );

        // start dequeueing events
        assert_eq!(
            vec![new_event_1.clone(), new_event_2, new_event_3, new_event_4],
            queue
                .transfers_to_namada
                .push_and_iter(new_event_1)
                .collect::<Vec<_>>()
        );

        // check the next nonce to process
        assert_eq!(queue.transfers_to_namada.get_event_nonce(), 5u64.into());

        // one remaining event with nonce 7
        assert_eq!(
            queue.transfers_to_namada.pop_event().expect("Test failed"),
            new_event_7
        );
        assert!(queue.transfers_to_namada.pop_event().is_none());
    }

    #[test]
    fn test_key_parse_valid() {
        let addr = address::testing::established_address_1();
        let target = format!("{}/test", KeySeg::raw(&addr));
        let key = Key::parse(target.clone()).expect("cannot parse the string");
        assert_eq!(key.to_string(), target);

        let target = "?test/test@".to_owned();
        let key = Key::parse(target.clone()).expect("cannot parse the string");
        assert_eq!(key.to_string(), target);

        let target = "?/test".to_owned();
        let key = Key::parse(target.clone()).expect("cannot parse the string");
        assert_eq!(key.to_string(), target);
    }

    #[test]
    fn test_key_push_valid() {
        let addr = address::testing::established_address_1();
        let other = address::testing::established_address_2();
        let target = KeySeg::raw(&other);
        let key = Key::from(addr.to_db_key())
            .push(&target)
            .expect("cannot push the segment");
        assert_eq!(key.segments[1].raw(), target);

        let target = "?test".to_owned();
        let key = Key::from(addr.to_db_key())
            .push(&target)
            .expect("cannot push the segment");
        assert_eq!(key.segments[1].raw(), target);

        let target = "?".to_owned();
        let key = Key::from(addr.to_db_key())
            .push(&target)
            .expect("cannot push the segment");
        assert_eq!(key.segments[1].raw(), target);
    }

    #[test]
    fn test_key_push_invalid() {
        let addr = address::testing::established_address_1();
        let target = "/".to_owned();
        match Key::from(addr.to_db_key())
            .push(&target)
            .expect_err("unexpectedly succeeded")
        {
            Error::InvalidKeySeg(s) => assert_eq!(s, "/"),
            _ => panic!("unexpected error happens"),
        }
    }

    #[test]
    fn test_predecessor_epochs_and_heights() {
        let mut epochs = Epochs {
            first_block_heights: vec![BlockHeight::first()],
        };
        println!("epochs {:#?}", epochs);
        assert_eq!(
            epochs.get_start_height_of_epoch(Epoch(0)),
            Some(BlockHeight(1))
        );
        assert_eq!(epochs.get_epoch(BlockHeight(0)), Some(Epoch(0)));

        // epoch 1
        epochs.new_epoch(BlockHeight(10));
        println!("epochs {:#?}", epochs);
        assert_eq!(
            epochs.get_start_height_of_epoch(Epoch(1)),
            Some(BlockHeight(10))
        );
        assert_eq!(epochs.get_epoch(BlockHeight(0)), Some(Epoch(0)));
        assert_eq!(epochs.get_epoch_start_height(BlockHeight(0)), None);
        assert_eq!(
            epochs.get_epoch_start_height(BlockHeight(1)),
            Some(BlockHeight(1))
        );
        assert_eq!(epochs.get_epoch(BlockHeight(9)), Some(Epoch(0)));
        assert_eq!(
            epochs.get_epoch_start_height(BlockHeight(9)),
            Some(BlockHeight(1))
        );
        assert_eq!(epochs.get_epoch(BlockHeight(10)), Some(Epoch(1)));
        assert_eq!(
            epochs.get_epoch_start_height(BlockHeight(10)),
            Some(BlockHeight(10))
        );
        assert_eq!(epochs.get_epoch(BlockHeight(11)), Some(Epoch(1)));
        assert_eq!(
            epochs.get_epoch_start_height(BlockHeight(11)),
            Some(BlockHeight(10))
        );
        assert_eq!(epochs.get_epoch(BlockHeight(100)), Some(Epoch(1)));
        assert_eq!(
            epochs.get_epoch_start_height(BlockHeight(100)),
            Some(BlockHeight(10))
        );

        // epoch 2
        epochs.new_epoch(BlockHeight(20));
        println!("epochs {:#?}", epochs);
        assert_eq!(
            epochs.get_start_height_of_epoch(Epoch(2)),
            Some(BlockHeight(20))
        );
        assert_eq!(epochs.get_epoch(BlockHeight(0)), Some(Epoch(0)));
        assert_eq!(epochs.get_epoch(BlockHeight(9)), Some(Epoch(0)));
        assert_eq!(epochs.get_epoch(BlockHeight(10)), Some(Epoch(1)));
        assert_eq!(epochs.get_epoch(BlockHeight(11)), Some(Epoch(1)));
        assert_eq!(
            epochs.get_epoch_start_height(BlockHeight(11)),
            Some(BlockHeight(10))
        );
        assert_eq!(epochs.get_epoch(BlockHeight(20)), Some(Epoch(2)));
        assert_eq!(
            epochs.get_epoch_start_height(BlockHeight(20)),
            Some(BlockHeight(20))
        );
        assert_eq!(epochs.get_epoch(BlockHeight(100)), Some(Epoch(2)));
        assert_eq!(
            epochs.get_epoch_start_height(BlockHeight(100)),
            Some(BlockHeight(20))
        );

        // epoch 3
        epochs.new_epoch(BlockHeight(200));
        println!("epochs {:#?}", epochs);
        assert_eq!(
            epochs.get_start_height_of_epoch(Epoch(3)),
            Some(BlockHeight(200))
        );
        assert_eq!(epochs.get_epoch(BlockHeight(0)), Some(Epoch(0)));
        assert_eq!(epochs.get_epoch(BlockHeight(9)), Some(Epoch(0)));
        assert_eq!(epochs.get_epoch(BlockHeight(10)), Some(Epoch(1)));
        assert_eq!(epochs.get_epoch(BlockHeight(11)), Some(Epoch(1)));
        assert_eq!(epochs.get_epoch(BlockHeight(20)), Some(Epoch(2)));
        assert_eq!(epochs.get_epoch(BlockHeight(100)), Some(Epoch(2)));
        assert_eq!(
            epochs.get_epoch_start_height(BlockHeight(100)),
            Some(BlockHeight(20))
        );
        assert_eq!(epochs.get_epoch(BlockHeight(200)), Some(Epoch(3)));
        assert_eq!(
            epochs.get_epoch_start_height(BlockHeight(200)),
            Some(BlockHeight(200))
        );

        // epoch 4
        epochs.new_epoch(BlockHeight(300));
        println!("epochs {:#?}", epochs);
        assert_eq!(
            epochs.get_start_height_of_epoch(Epoch(4)),
            Some(BlockHeight(300))
        );
        assert_eq!(epochs.get_epoch(BlockHeight(20)), Some(Epoch(2)));
        assert_eq!(epochs.get_epoch(BlockHeight(100)), Some(Epoch(2)));
        assert_eq!(epochs.get_epoch(BlockHeight(200)), Some(Epoch(3)));
        assert_eq!(epochs.get_epoch(BlockHeight(300)), Some(Epoch(4)));

        // epoch 5
        epochs.new_epoch(BlockHeight(499));
        println!("epochs {:#?}", epochs);
        assert_eq!(
            epochs.get_start_height_of_epoch(Epoch(5)),
            Some(BlockHeight(499))
        );
        assert_eq!(epochs.get_epoch(BlockHeight(20)), Some(Epoch(2)));
        assert_eq!(epochs.get_epoch(BlockHeight(100)), Some(Epoch(2)));
        assert_eq!(epochs.get_epoch(BlockHeight(200)), Some(Epoch(3)));
        assert_eq!(epochs.get_epoch(BlockHeight(300)), Some(Epoch(4)));
        assert_eq!(epochs.get_epoch(BlockHeight(499)), Some(Epoch(5)));

        // epoch 6
        epochs.new_epoch(BlockHeight(500));
        println!("epochs {:#?}", epochs);
        assert_eq!(
            epochs.get_start_height_of_epoch(Epoch(6)),
            Some(BlockHeight(500))
        );
        assert_eq!(epochs.get_epoch(BlockHeight(200)), Some(Epoch(3)));
        assert_eq!(epochs.get_epoch(BlockHeight(300)), Some(Epoch(4)));
        assert_eq!(epochs.get_epoch(BlockHeight(499)), Some(Epoch(5)));
        assert_eq!(epochs.get_epoch(BlockHeight(500)), Some(Epoch(6)));

        // epoch 7
        epochs.new_epoch(BlockHeight(550));
        println!("epochs {:#?}", epochs);
        assert_eq!(
            epochs.get_start_height_of_epoch(Epoch(7)),
            Some(BlockHeight(550))
        );
        assert_eq!(epochs.get_epoch(BlockHeight(300)), Some(Epoch(4)));
        assert_eq!(epochs.get_epoch(BlockHeight(499)), Some(Epoch(5)));
        assert_eq!(epochs.get_epoch(BlockHeight(500)), Some(Epoch(6)));
        assert_eq!(epochs.get_epoch(BlockHeight(550)), Some(Epoch(7)));

        // epoch 8
        epochs.new_epoch(BlockHeight(600));
        println!("epochs {:#?}", epochs);
        assert_eq!(
            epochs.get_start_height_of_epoch(Epoch(7)),
            Some(BlockHeight(550))
        );
        assert_eq!(
            epochs.get_start_height_of_epoch(Epoch(8)),
            Some(BlockHeight(600))
        );
        assert_eq!(epochs.get_epoch(BlockHeight(500)), Some(Epoch(6)));
        assert_eq!(epochs.get_epoch(BlockHeight(550)), Some(Epoch(7)));
        assert_eq!(epochs.get_epoch(BlockHeight(600)), Some(Epoch(8)));

        // try to fetch height values out of range
        // at this point, the min known epoch is 7
        for e in [9, 10, 11, 12] {
            assert!(
                epochs.get_start_height_of_epoch(Epoch(e)).is_none(),
                "Epoch: {e}"
            );
        }
    }

    proptest! {
        /// Ensure that addresses in storage keys preserve the order of the
        /// addresses.
        #[test]
        fn test_address_in_storage_key_order(
            addr1 in arb_address(),
            addr2 in arb_address(),
        ) {
            test_address_in_storage_key_order_aux(addr1, addr2)
        }
    }

    #[cfg(test)]
    fn test_address_in_storage_key_order_aux(addr1: Address, addr2: Address) {
        println!("addr1 {addr1}");
        println!("addr2 {addr2}");
        let expected_order = addr1.cmp(&addr2);

        // Turn the addresses into strings
        let str1 = addr1.to_string();
        let str2 = addr2.to_string();
        println!("addr1 str {str1}");
        println!("addr1 str {str2}");
        let order = str1.cmp(&str2);
        assert_eq!(order, expected_order);

        // Turn the addresses into storage keys
        let key1 = Key::from(addr1.to_db_key());
        let key2 = Key::from(addr2.to_db_key());
        println!("addr1 key {key1}");
        println!("addr2 key {key2}");
        let order = key1.cmp(&key2);
        assert_eq!(order, expected_order);

        // Turn the addresses into raw storage keys (formatted to strings)
        let raw1 = addr1.raw();
        let raw2 = addr2.raw();
        println!("addr 1 raw {raw1}");
        println!("addr 2 raw {raw2}");
        let order = raw1.cmp(&raw2);
        assert_eq!(order, expected_order);
    }
}

/// Helpers for testing with storage types.
#[cfg(any(test, feature = "testing"))]
pub mod testing {
    use std::ops::{Add, AddAssign, Sub};

    use proptest::collection;
    use proptest::prelude::*;

    use super::*;
    use crate::address::testing::{arb_address, arb_non_internal_address};

    impl<T> Add<T> for BlockHeight
    where
        T: Into<BlockHeight>,
    {
        type Output = BlockHeight;

        fn add(self, rhs: T) -> Self::Output {
            self.checked_add(rhs.into()).unwrap()
        }
    }

    impl<T> AddAssign<T> for BlockHeight
    where
        T: Into<BlockHeight>,
    {
        fn add_assign(&mut self, rhs: T) {
            *self = self.checked_add(rhs.into()).unwrap()
        }
    }

    impl<T> Add<T> for Epoch
    where
        T: Into<Epoch>,
    {
        type Output = Epoch;

        fn add(self, rhs: T) -> Self::Output {
            self.checked_add(rhs.into()).unwrap()
        }
    }

    impl<T> Sub<T> for Epoch
    where
        T: Into<Epoch>,
    {
        type Output = Epoch;

        fn sub(self, rhs: T) -> Self::Output {
            self.checked_sub(rhs.into()).unwrap()
        }
    }

    prop_compose! {
        /// Generate an arbitrary epoch
        pub fn arb_epoch()(epoch: u64) -> Epoch {
            Epoch(epoch)
        }
    }

    /// Generate an arbitrary [`Key`].
    pub fn arb_key() -> impl Strategy<Value = Key> {
        prop_oneof![
            // a key for a validity predicate
            arb_non_internal_address()
                .prop_map(|addr| Key::validity_predicate(&addr)),
            // a key from key segments
            arb_key_no_vp(),
        ]
    }

    /// Generate an arbitrary [`Key`] other than a validity predicate key.
    pub fn arb_key_no_vp() -> impl Strategy<Value = Key> {
        // a key from key segments
        collection::vec(arb_key_seg(), 2..5)
            .prop_map(|segments| Key { segments })
            .prop_filter("Key length must be below IBC limit", |key| {
                let key_str = key.to_string();
                let bytes = key_str.as_bytes();
                bytes.len() <= IBC_KEY_LIMIT
            })
    }

    /// Generate an arbitrary [`Key`] for a given address storage sub-space.
    pub fn arb_account_storage_key(
        address: Address,
    ) -> impl Strategy<Value = Key> {
        prop_oneof![
            // a key for a validity predicate
            Just(Key::validity_predicate(&address)),
            // a key from key segments
            arb_account_storage_key_no_vp(address),
        ]
    }

    /// Generate an arbitrary [`Key`] other than a validity predicate key for a
    /// given address storage sub-space.
    pub fn arb_account_storage_key_no_vp(
        address: Address,
    ) -> impl Strategy<Value = Key> {
        collection::vec(arb_key_seg(), 1..5).prop_map(move |arb_segments| {
            let mut segments = vec![address.to_db_key()];
            segments.extend(arb_segments);
            Key { segments }
        })
    }

    /// Generate an arbitrary [`DbKeySeg`].
    pub fn arb_key_seg() -> impl Strategy<Value = DbKeySeg> {
        prop_oneof![
            // the string segment is 5 time more likely to be generated
            5 => "[a-zA-Z0-9_]{1,20}".prop_map(DbKeySeg::StringSeg),
            1 => arb_address().prop_map(DbKeySeg::AddressSeg),
        ]
    }

    /// A dummy header used for testing
    pub fn get_dummy_header() -> Header {
        use crate::time::DurationSecs;
        Header {
            hash: Hash([0; 32]),
            #[allow(
                clippy::disallowed_methods,
                clippy::arithmetic_side_effects
            )]
            time: DateTimeUtc::now() + DurationSecs(5),
            next_validators_hash: Hash([0; 32]),
        }
    }
}
