//! Storage types
use std::convert::{TryFrom, TryInto};
use std::fmt::Display;
use std::io::Write;
use std::num::ParseIntError;
use std::ops::{Add, Deref, Div, Mul, Rem, Sub};
use std::str::FromStr;

use arse_merkle_tree::InternalKey;
use borsh::{BorshDeserialize, BorshSchema, BorshSerialize};
use ics23::CommitmentProof;
use serde::{Deserialize, Serialize};
use thiserror::Error;

#[cfg(feature = "ferveo-tpke")]
use super::transaction::WrapperTx;
use crate::bytes::ByteBuf;
use crate::ledger::eth_bridge::storage::bridge_pool::BridgePoolProof;
use crate::ledger::storage::IBC_KEY_LIMIT;
use crate::types::address::{self, Address};
use crate::types::eth_bridge_pool::PendingTransfer;
use crate::types::hash::Hash;
use crate::types::keccak::{KeccakHash, TryFromError};
use crate::types::time::DateTimeUtc;

#[allow(missing_docs)]
#[derive(Error, Debug)]
pub enum Error {
    #[error("TEMPORARY error: {error}")]
    Temporary { error: String },
    #[error("Error parsing address: {0}")]
    ParseAddress(address::Error),
    #[error("Error parsing address from a storage key")]
    ParseAddressFromKey,
    #[error("Reserved prefix or string is specified: {0}")]
    InvalidKeySeg(String),
    #[error("Could not parse string into a key segment: {0}")]
    ParseError(String),
}

/// Result for functions that may fail
pub type Result<T> = std::result::Result<T, Error>;

/// The length of the block's hash string
pub const BLOCK_HASH_LENGTH: usize = 32;

/// The separator of storage key segments
pub const KEY_SEGMENT_SEPARATOR: char = '/';
/// The reserved storage key prefix for addresses
pub const RESERVED_ADDRESS_PREFIX: char = '#';
/// The reserved storage key prefix for validity predicates
pub const VP_KEY_PREFIX: char = '?';
/// The reserved storage key for validity predicates
pub const RESERVED_VP_KEY: &str = "?";

/// Height of a block, i.e. the level.
#[derive(
    Default,
    Clone,
    Copy,
    BorshSerialize,
    BorshDeserialize,
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

impl Display for BlockHeight {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl Add<u64> for BlockHeight {
    type Output = BlockHeight;

    fn add(self, rhs: u64) -> Self::Output {
        Self(self.0 + rhs)
    }
}

impl From<BlockHeight> for u64 {
    fn from(height: BlockHeight) -> Self {
        height.0
    }
}

/// Hash of a block as fixed-size byte array
#[derive(
    Clone,
    Default,
    BorshSerialize,
    BorshDeserialize,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
    Serialize,
    Deserialize,
)]
pub struct BlockHash(pub [u8; BLOCK_HASH_LENGTH]);

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
    /// Get the height of the next block
    pub fn next_height(&self) -> BlockHeight {
        BlockHeight(self.0 + 1)
    }
}

impl TryFrom<&[u8]> for BlockHash {
    type Error = self::Error;

    fn try_from(value: &[u8]) -> Result<Self> {
        if value.len() != BLOCK_HASH_LENGTH {
            return Err(Error::Temporary {
                error: format!(
                    "Unexpected block hash length {}, expected {}",
                    value.len(),
                    BLOCK_HASH_LENGTH
                ),
            });
        }
        let mut hash = [0; 32];
        hash.copy_from_slice(value);
        Ok(BlockHash(hash))
    }
}

impl TryFrom<Vec<u8>> for BlockHash {
    type Error = self::Error;

    fn try_from(value: Vec<u8>) -> Result<Self> {
        if value.len() != BLOCK_HASH_LENGTH {
            return Err(Error::Temporary {
                error: format!(
                    "Unexpected block hash length {}, expected {}",
                    value.len(),
                    BLOCK_HASH_LENGTH
                ),
            });
        }
        let mut hash = [0; 32];
        hash.copy_from_slice(&value);
        Ok(BlockHash(hash))
    }
}

impl core::fmt::Debug for BlockHash {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let hash = format!("{}", ByteBuf(&self.0));
        f.debug_tuple("BlockHash").field(&hash).finish()
    }
}

/// The data from Tendermint header
/// relevant for Anoma storage
#[derive(Clone, Debug, BorshSerialize, BorshDeserialize)]
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
        self.try_to_vec().unwrap().len()
    }
}

/// A storage key is made of storage key segments [`DbKeySeg`], separated by
/// [`KEY_SEGMENT_SEPARATOR`].
#[derive(
    Clone,
    BorshSerialize,
    BorshDeserialize,
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
pub struct Key {
    /// The segments of the key in the original (left-to-right) order.
    pub segments: Vec<DbKeySeg>,
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

/// An enum representing the different types of values
/// that can be passed into Anoma's storage.
///
/// This is a multi-store organized as
/// several Merkle trees, each of which is
/// responsible for understanding how to parse
/// this value.
#[derive(Debug, Clone)]
pub enum MerkleValue {
    /// raw bytes
    Bytes(Vec<u8>),
    /// A transfer to be put in the Ethereum bridge pool.
    BridgePoolTransfer(PendingTransfer),
}

impl<T> From<T> for MerkleValue
where
    T: AsRef<[u8]>,
{
    fn from(bytes: T) -> Self {
        Self::Bytes(bytes.as_ref().to_owned())
    }
}

impl From<PendingTransfer> for MerkleValue {
    fn from(transfer: PendingTransfer) -> Self {
        Self::BridgePoolTransfer(transfer)
    }
}

impl MerkleValue {
    /// Get the natural byte repesentation of the value
    pub fn to_bytes(self) -> Vec<u8> {
        match self {
            Self::Bytes(bytes) => bytes,
            Self::Transfer(transfer) => transfer.try_to_vec().unwrap(),
        }
    }
}

impl MerkleValue {
    /// Get the natural byte repesentation of the value
    pub fn to_bytes(self) -> Vec<u8> {
        match self {
            Self::Bytes(bytes) => bytes,
            Self::Transfer(transfer) => transfer.try_to_vec().unwrap(),
        }
    }
}

/// Storage keys that are utf8 encoded strings
#[derive(Eq, PartialEq, Copy, Clone, Hash)]
pub struct StringKey {
    /// The original key string, in bytes
    pub original: [u8; IBC_KEY_LIMIT],
    /// The utf8 bytes representation of the key to be
    /// used internally in the merkle tree
    pub tree_key: InternalKey<IBC_KEY_LIMIT>,
    /// The length of the input (without the padding)
    pub length: usize,
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
    fn deserialize(buf: &mut &[u8]) -> std::io::Result<Self> {
        use std::io::ErrorKind;
        let (original, tree_key, length): (
            Vec<u8>,
            InternalKey<IBC_KEY_LIMIT>,
            usize,
        ) = BorshDeserialize::deserialize(buf)?;
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

/// A wrapper around raw bytes to be stored as values
/// in a merkle tree
#[derive(Clone, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct TreeBytes(pub Vec<u8>);

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

/// Type of membership proof from a merkle tree
pub enum MembershipProof {
    /// ICS23 compliant membership proof
    ICS23(CommitmentProof),
    /// Bespoke membership proof for the Ethereum bridge pool
    BridgePool(BridgePoolProof),
}

impl From<CommitmentProof> for MembershipProof {
    fn from(proof: CommitmentProof) -> Self {
        Self::ICS23(proof)
    }
}

impl From<BridgePoolProof> for MembershipProof {
    fn from(proof: BridgePoolProof) -> Self {
        Self::BridgePool(proof)
    }
}

impl Key {
    /// Parses string and returns a key
    pub fn parse(string: impl AsRef<str>) -> Result<Self> {
        let mut segments = Vec::new();
        for s in string.as_ref().split(KEY_SEGMENT_SEPARATOR) {
            segments.push(DbKeySeg::parse(s.to_owned())?);
        }
        Ok(Key { segments })
    }

    /// Returns a new key with segments of `Self` and the given segment
    pub fn push<T: KeySeg>(&self, other: &T) -> Result<Self> {
        let mut segments = self.segments.clone();
        segments.push(DbKeySeg::parse(other.raw())?);
        Ok(Key { segments })
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
        let mut addresses = Vec::new();
        for s in &self.segments {
            match s {
                DbKeySeg::AddressSeg(addr) => addresses.push(addr.clone()),
                _ => continue,
            }
        }
        addresses
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
            .map_err(|e| Error::Temporary {
                error: format!("Cannot parse key segments {}: {}", db_key, e),
            })?,
        };
        Ok(key)
    }

    /// Returns a sub key without the first segment
    pub fn sub_key(&self) -> Result<Self> {
        match self.segments.split_first() {
            Some((_, rest)) => {
                if rest.is_empty() {
                    Err(Error::Temporary {
                        error: format!(
                            "The key doesn't have the sub segments: {}",
                            self
                        ),
                    })
                } else {
                    Ok(Self {
                        segments: rest.to_vec(),
                    })
                }
            }
            None => Err(Error::Temporary {
                error: "The key is empty".to_owned(),
            }),
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
        // a separator should not included
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
        let h = string.parse::<u64>().map_err(|e| Error::Temporary {
            error: format!("Unexpected height value {}, {}", string, e),
        })?;
        Ok(BlockHeight(h))
    }

    fn raw(&self) -> String {
        format!("{}", self.0)
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
        seg.try_into().map_err(|e: crate::types::hash::Error| {
            Error::ParseError(e.to_string())
        })
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
            .map_err(|e: TryFromError| Error::ParseError(e.to_string()))
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
        seg.clone()
            .try_into()
            .map_err(|_| Error::ParseError(seg, "Hash".into()))
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
        Self(self.0 + 1)
    }
}

impl Add<u64> for Epoch {
    type Output = Epoch;

    fn add(self, rhs: u64) -> Self::Output {
        Self(self.0 + rhs)
    }
}

impl Sub<u64> for Epoch {
    type Output = Epoch;

    fn sub(self, rhs: u64) -> Self::Output {
        Self(self.0 - rhs)
    }
}

impl Mul<u64> for Epoch {
    type Output = Epoch;

    fn mul(self, rhs: u64) -> Self::Output {
        Self(self.0 * rhs)
    }
}

impl Div<u64> for Epoch {
    type Output = Epoch;

    fn div(self, rhs: u64) -> Self::Output {
        Self(self.0 / rhs)
    }
}

impl Rem<u64> for Epoch {
    type Output = u64;

    fn rem(self, rhs: u64) -> Self::Output {
        Self(self.0 % rhs).0
    }
}

impl Sub for Epoch {
    type Output = Epoch;

    fn sub(self, rhs: Self) -> Self::Output {
        Self(self.0 - rhs.0)
    }
}

impl Add for Epoch {
    type Output = Epoch;

    fn add(self, rhs: Self) -> Self::Output {
        Self(self.0 + rhs.0)
    }
}

impl Mul for Epoch {
    type Output = Epoch;

    fn mul(self, rhs: Self) -> Self::Output {
        Self(self.0 * rhs.0)
    }
}

impl From<Epoch> for u64 {
    fn from(epoch: Epoch) -> Self {
        epoch.0
    }
}

impl From<u64> for Epoch {
    fn from(value: u64) -> Self {
        Self(value)
    }
}

/// Predecessor block epochs
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
)]
pub struct Epochs {
    /// The oldest epoch we can look-up.
    first_known_epoch: Epoch,
    /// The block heights of the first block of each known epoch.
    /// Invariant: the values must be sorted in ascending order.
    first_block_heights: Vec<BlockHeight>,
}

impl Default for Epochs {
    /// Initialize predecessor epochs, assuming starting on the epoch 0 and
    /// block height 0.
    fn default() -> Self {
        Self {
            first_known_epoch: Epoch::default(),
            first_block_heights: vec![BlockHeight::default()],
        }
    }
}

impl Epochs {
    /// Record start of a new epoch at the given block height and trim any
    /// epochs that ended more than `max_age_num_blocks` ago.
    pub fn new_epoch(
        &mut self,
        block_height: BlockHeight,
        max_age_num_blocks: u64,
    ) {
        let min_block_height_to_keep = (block_height.0 + 1)
            .checked_sub(max_age_num_blocks)
            .unwrap_or_default();
        // trim off any epochs whose last block is before the limit
        while let Some((_first_known_epoch_height, rest)) =
            self.first_block_heights.split_first()
        {
            if let Some(second_known_epoch_height) = rest.first() {
                if second_known_epoch_height.0 < min_block_height_to_keep {
                    self.first_known_epoch = self.first_known_epoch.next();
                    self.first_block_heights = rest.to_vec();
                    continue;
                }
            }
            break;
        }
        self.first_block_heights.push(block_height);
    }

    /// Look-up the epoch of a given block height.
    pub fn get_epoch(&self, block_height: BlockHeight) -> Option<Epoch> {
        if let Some((first_known_epoch_height, rest)) =
            self.first_block_heights.split_first()
        {
            if block_height < *first_known_epoch_height {
                return None;
            }
            let mut epoch = self.first_known_epoch;
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

    /// Return all starting block heights for each successive Epoch.
    ///
    /// __INVARIANT:__ The returned values are sorted in ascending order.
    pub fn first_block_heights(&self) -> &[BlockHeight] {
        &self.first_block_heights
    }
}

#[cfg(feature = "ferveo-tpke")]
#[derive(Default, Debug, Clone, BorshDeserialize, BorshSerialize)]
/// Wrapper txs to be decrypted in the next block proposal
pub struct TxQueue(std::collections::VecDeque<WrapperTx>);

#[cfg(feature = "ferveo-tpke")]
impl TxQueue {
    /// Add a new wrapper at the back of the queue
    pub fn push(&mut self, wrapper: WrapperTx) {
        self.0.push_back(wrapper);
    }

    /// Remove the wrapper at the head of the queue
    pub fn pop(&mut self) -> Option<WrapperTx> {
        self.0.pop_front()
    }

    /// Get an iterator over the queue
    pub fn iter(&self) -> impl std::iter::Iterator<Item = &WrapperTx> {
        self.0.iter()
    }

    /// Check if there are any txs in the queue
    #[allow(dead_code)]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

/// A value of a storage prefix iterator.
#[derive(Debug, Clone, BorshSerialize, BorshDeserialize, BorshSchema)]
pub struct PrefixValue {
    /// Storage key
    pub key: Key,
    /// Raw value bytes
    pub value: Vec<u8>,
}

#[cfg(test)]
mod tests {
    use proptest::prelude::*;

    use super::*;

    proptest! {
        /// Tests that any key that doesn't contain reserved prefixes is valid.
        /// This test excludes key segments starting with `#` or `?`
        /// because they are reserved for `Address` or a validity predicate.
        #[test]
        fn test_key_parse(s in "[^#?/][^/]*/[^#?/][^/]*/[^#?/][^/]*") {
            let key = Key::parse(s.clone()).expect("cannnot parse the string");
            assert_eq!(key.to_string(), s);
        }

        /// Tests that any key that doesn't contain reserved prefixes and
        /// separators is valid. This test excludes key segments including `/`
        /// or starting with `#` or `?` because they are reserved for separator,
        /// `Address` or validity predicate.
        #[test]
        fn test_key_push(s in "[^#?/][^/]*") {
            let addr = address::testing::established_address_1();
            let key = Key::from(addr.to_db_key()).push(&s).expect("cannnot push the segment");
            assert_eq!(key.segments[1].raw(), s);
        }
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
            .expect("cannnot push the segment");
        assert_eq!(key.segments[1].raw(), target);

        let target = "?test".to_owned();
        let key = Key::from(addr.to_db_key())
            .push(&target)
            .expect("cannnot push the segment");
        assert_eq!(key.segments[1].raw(), target);

        let target = "?".to_owned();
        let key = Key::from(addr.to_db_key())
            .push(&target)
            .expect("cannnot push the segment");
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
    fn test_predecessor_epochs() {
        let mut epochs = Epochs::default();
        assert_eq!(epochs.get_epoch(BlockHeight(0)), Some(Epoch(0)));
        let mut max_age_num_blocks = 100;

        // epoch 1
        epochs.new_epoch(BlockHeight(10), max_age_num_blocks);
        println!("epochs {:#?}", epochs);
        assert_eq!(epochs.get_epoch(BlockHeight(0)), Some(Epoch(0)));
        assert_eq!(epochs.get_epoch(BlockHeight(9)), Some(Epoch(0)));
        assert_eq!(epochs.get_epoch(BlockHeight(10)), Some(Epoch(1)));
        assert_eq!(epochs.get_epoch(BlockHeight(11)), Some(Epoch(1)));
        assert_eq!(epochs.get_epoch(BlockHeight(100)), Some(Epoch(1)));

        // epoch 2
        epochs.new_epoch(BlockHeight(20), max_age_num_blocks);
        println!("epochs {:#?}", epochs);
        assert_eq!(epochs.get_epoch(BlockHeight(0)), Some(Epoch(0)));
        assert_eq!(epochs.get_epoch(BlockHeight(9)), Some(Epoch(0)));
        assert_eq!(epochs.get_epoch(BlockHeight(10)), Some(Epoch(1)));
        assert_eq!(epochs.get_epoch(BlockHeight(11)), Some(Epoch(1)));
        assert_eq!(epochs.get_epoch(BlockHeight(20)), Some(Epoch(2)));
        assert_eq!(epochs.get_epoch(BlockHeight(100)), Some(Epoch(2)));

        // epoch 3, epoch 0 and 1 should be trimmed
        epochs.new_epoch(BlockHeight(200), max_age_num_blocks);
        println!("epochs {:#?}", epochs);
        assert_eq!(epochs.get_epoch(BlockHeight(0)), None);
        assert_eq!(epochs.get_epoch(BlockHeight(9)), None);
        assert_eq!(epochs.get_epoch(BlockHeight(10)), None);
        assert_eq!(epochs.get_epoch(BlockHeight(11)), None);
        assert_eq!(epochs.get_epoch(BlockHeight(20)), Some(Epoch(2)));
        assert_eq!(epochs.get_epoch(BlockHeight(100)), Some(Epoch(2)));
        assert_eq!(epochs.get_epoch(BlockHeight(200)), Some(Epoch(3)));

        // increase the limit
        max_age_num_blocks = 200;

        // epoch 4
        epochs.new_epoch(BlockHeight(300), max_age_num_blocks);
        println!("epochs {:#?}", epochs);
        assert_eq!(epochs.get_epoch(BlockHeight(20)), Some(Epoch(2)));
        assert_eq!(epochs.get_epoch(BlockHeight(100)), Some(Epoch(2)));
        assert_eq!(epochs.get_epoch(BlockHeight(200)), Some(Epoch(3)));
        assert_eq!(epochs.get_epoch(BlockHeight(300)), Some(Epoch(4)));

        // epoch 5, epoch 2 should be trimmed
        epochs.new_epoch(BlockHeight(499), max_age_num_blocks);
        println!("epochs {:#?}", epochs);
        assert_eq!(epochs.get_epoch(BlockHeight(20)), None);
        assert_eq!(epochs.get_epoch(BlockHeight(100)), None);
        assert_eq!(epochs.get_epoch(BlockHeight(200)), Some(Epoch(3)));
        assert_eq!(epochs.get_epoch(BlockHeight(300)), Some(Epoch(4)));
        assert_eq!(epochs.get_epoch(BlockHeight(499)), Some(Epoch(5)));

        // epoch 6, epoch 3 should be trimmed
        epochs.new_epoch(BlockHeight(500), max_age_num_blocks);
        println!("epochs {:#?}", epochs);
        assert_eq!(epochs.get_epoch(BlockHeight(200)), None);
        assert_eq!(epochs.get_epoch(BlockHeight(300)), Some(Epoch(4)));
        assert_eq!(epochs.get_epoch(BlockHeight(499)), Some(Epoch(5)));
        assert_eq!(epochs.get_epoch(BlockHeight(500)), Some(Epoch(6)));

        // decrease the limit
        max_age_num_blocks = 50;

        // epoch 7, epoch 4 and 5 should be trimmed
        epochs.new_epoch(BlockHeight(550), max_age_num_blocks);
        println!("epochs {:#?}", epochs);
        assert_eq!(epochs.get_epoch(BlockHeight(300)), None);
        assert_eq!(epochs.get_epoch(BlockHeight(499)), None);
        assert_eq!(epochs.get_epoch(BlockHeight(500)), Some(Epoch(6)));
        assert_eq!(epochs.get_epoch(BlockHeight(550)), Some(Epoch(7)));

        // epoch 8, epoch 6 should be trimmed
        epochs.new_epoch(BlockHeight(600), max_age_num_blocks);
        println!("epochs {:#?}", epochs);
        assert_eq!(epochs.get_epoch(BlockHeight(500)), None);
        assert_eq!(epochs.get_epoch(BlockHeight(550)), Some(Epoch(7)));
        assert_eq!(epochs.get_epoch(BlockHeight(600)), Some(Epoch(8)));
    }
}

/// Helpers for testing with storage types.
#[cfg(any(test, feature = "testing"))]
pub mod testing {
    use proptest::collection;
    use proptest::prelude::*;

    use super::*;
    use crate::types::address::testing::{
        arb_address, arb_non_internal_address,
    };

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
        collection::vec(arb_key_seg(), 1..5)
            .prop_map(|segments| Key { segments })
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
            5 => "[a-zA-Z0-9_]{1,100}".prop_map(DbKeySeg::StringSeg),
            1 => arb_address().prop_map(DbKeySeg::AddressSeg),
        ]
    }
}
