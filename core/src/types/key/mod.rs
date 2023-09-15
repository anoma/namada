//! Cryptographic keys

pub mod common;
/// Elliptic curve keys for the DKG
pub mod dkg_session_keys;
pub mod ed25519;
pub mod secp256k1;

use std::fmt::{Debug, Display};
use std::hash::Hash;
use std::str::FromStr;

use borsh::{BorshDeserialize, BorshSchema, BorshSerialize};
use borsh_ext::BorshSerializeExt;
use data_encoding::HEXUPPER;
use lazy_map::LazyMap;
use namada_macros::StorageKeys;
#[cfg(feature = "rand")]
use rand::{CryptoRng, RngCore};
use serde::Serialize;
use sha2::{Digest, Sha256};
use thiserror::Error;

use super::address::Address;
use super::storage::{self, DbKeySeg, Key};
use crate::ledger::storage::{Sha256Hasher, StorageHasher};
use crate::ledger::storage_api::collections::{lazy_map, LazyCollection};
use crate::types::address;

/// Storage keys for account.
#[derive(StorageKeys)]
struct Keys {
    public_keys: &'static str,
    threshold: &'static str,
    protocol_public_keys: &'static str,
}

/// Obtain a storage key for user's public key.
pub fn pks_key_prefix(owner: &Address) -> storage::Key {
    Key {
        segments: vec![
            DbKeySeg::AddressSeg(owner.to_owned()),
            DbKeySeg::StringSeg(Keys::VALUES.public_keys.to_string()),
        ],
    }
}

/// LazyMap handler for the user's public key subspace
pub fn pks_handle(owner: &Address) -> LazyMap<u8, common::PublicKey> {
    LazyMap::open(pks_key_prefix(owner))
}

/// Check if the given storage key is a public key. If it is, returns the owner.
pub fn is_pks_key(key: &Key) -> Option<&Address> {
    match &key.segments[..] {
        [
            DbKeySeg::AddressSeg(owner),
            DbKeySeg::StringSeg(prefix),
            DbKeySeg::StringSeg(data),
            DbKeySeg::StringSeg(index),
        ] if prefix.as_str() == Keys::VALUES.public_keys
            && data.as_str() == lazy_map::DATA_SUBKEY
            && index.parse::<u8>().is_ok() =>
        {
            Some(owner)
        }
        _ => None,
    }
}

/// Check if the given storage key is a threshol key.
pub fn is_threshold_key(key: &Key) -> Option<&Address> {
    match &key.segments[..] {
        [DbKeySeg::AddressSeg(owner), DbKeySeg::StringSeg(prefix)]
            if prefix.as_str() == Keys::VALUES.threshold =>
        {
            Some(owner)
        }
        _ => None,
    }
}

/// Obtain the storage key for a user threshold
pub fn threshold_key(owner: &Address) -> storage::Key {
    Key {
        segments: vec![
            DbKeySeg::AddressSeg(owner.to_owned()),
            DbKeySeg::StringSeg(Keys::VALUES.threshold.to_string()),
        ],
    }
}

/// Obtain a storage key for user's protocol public key.
pub fn protocol_pk_key(owner: &Address) -> storage::Key {
    Key {
        segments: vec![
            DbKeySeg::AddressSeg(owner.to_owned()),
            DbKeySeg::StringSeg(Keys::VALUES.protocol_public_keys.to_string()),
        ],
    }
}

/// Check if the given storage key is a public key. If it is, returns the owner.
pub fn is_protocol_pk_key(key: &Key) -> Option<&Address> {
    match &key.segments[..] {
        [DbKeySeg::AddressSeg(owner), DbKeySeg::StringSeg(key)]
            if key.as_str() == Keys::VALUES.protocol_public_keys =>
        {
            Some(owner)
        }
        _ => None,
    }
}

/// Represents an error in signature verification
#[allow(missing_docs)]
#[derive(Error, Debug)]
pub enum VerifySigError {
    #[error("Signature verification failed: {0}")]
    SigVerifyError(String),
    #[error("Signature verification failed to encode the data: {0}")]
    DataEncodingError(std::io::Error),
    #[error("Transaction doesn't have any data with a signature.")]
    MissingData,
    #[error("Signature belongs to a different scheme from the public key.")]
    MismatchedScheme,
}

#[allow(missing_docs)]
#[derive(Error, Debug)]
pub enum ParsePublicKeyError {
    #[error("Invalid public key hex: {0}")]
    InvalidHex(data_encoding::DecodeError),
    #[error("Invalid public key encoding: {0}")]
    InvalidEncoding(std::io::Error),
    #[error("Parsed public key does not belong to desired scheme")]
    MismatchedScheme,
}

#[allow(missing_docs)]
#[derive(Error, Debug)]
pub enum ParseSignatureError {
    #[error("Invalid signature hex: {0}")]
    InvalidHex(data_encoding::DecodeError),
    #[error("Invalid signature encoding: {0}")]
    InvalidEncoding(std::io::Error),
    #[error("Parsed signature does not belong to desired scheme")]
    MismatchedScheme,
}

#[allow(missing_docs)]
#[derive(Error, Debug)]
pub enum ParseSecretKeyError {
    #[error("Invalid secret key hex: {0}")]
    InvalidHex(data_encoding::DecodeError),
    #[error("Invalid secret key encoding: {0}")]
    InvalidEncoding(std::io::Error),
    #[error("Parsed secret key does not belong to desired scheme")]
    MismatchedScheme,
}

/// A value-to-value conversion that consumes the input value.

pub trait RefTo<T> {
    /// Performs the conversion.
    fn ref_to(&self) -> T;
}

/// Simple and safe type conversions that may fail in a controlled
/// way under some circumstances.

pub trait TryFromRef<T: ?Sized>: Sized {
    /// The type returned in the event of a conversion error.
    type Error;
    /// Performs the conversion.
    fn try_from_ref(value: &T) -> Result<Self, Self::Error>;
}

/// Type capturing signature scheme IDs
#[derive(PartialEq, Eq, Copy, Clone, Debug)]
pub enum SchemeType {
    /// Type identifier for Ed25519 scheme
    Ed25519,
    /// Type identifier for Secp256k1 scheme
    Secp256k1,
    /// Type identifier for Common
    Common,
}

impl FromStr for SchemeType {
    type Err = ();

    fn from_str(input: &str) -> Result<Self, Self::Err> {
        match input.to_lowercase().as_str() {
            "ed25519" => Ok(Self::Ed25519),
            "secp256k1" => Ok(Self::Secp256k1),
            "common" => Ok(Self::Common),
            _ => Err(()),
        }
    }
}

/// Represents a signature

pub trait Signature:
    Hash + PartialOrd + Serialize + BorshSerialize + BorshDeserialize + BorshSchema
{
    /// The scheme type of this implementation
    const TYPE: SchemeType;
    /// Convert from one Signature type to another
    fn try_from_sig<SIG: Signature>(
        sig: &SIG,
    ) -> Result<Self, ParseSignatureError> {
        if SIG::TYPE == Self::TYPE {
            let sig_arr = sig.serialize_to_vec();
            let res = Self::try_from_slice(sig_arr.as_ref());
            res.map_err(ParseSignatureError::InvalidEncoding)
        } else {
            Err(ParseSignatureError::MismatchedScheme)
        }
    }
    /// Convert from self to another SecretKey type
    fn try_to_sig<SIG: Signature>(&self) -> Result<SIG, ParseSignatureError> {
        SIG::try_from_sig(self)
    }
}

/// Represents a public key

pub trait PublicKey:
    BorshSerialize
    + BorshDeserialize
    + BorshSchema
    + Ord
    + Clone
    + Display
    + Debug
    + PartialOrd
    + FromStr<Err = ParsePublicKeyError>
    + Hash
    + Send
    + Sync
{
    /// The scheme type of this implementation
    const TYPE: SchemeType;
    /// Convert from one PublicKey type to another
    fn try_from_pk<PK: PublicKey>(
        pk: &PK,
    ) -> Result<Self, ParsePublicKeyError> {
        if Self::TYPE == PK::TYPE {
            let pk_arr = pk.serialize_to_vec();
            let res = Self::try_from_slice(pk_arr.as_ref());
            res.map_err(ParsePublicKeyError::InvalidEncoding)
        } else {
            Err(ParsePublicKeyError::MismatchedScheme)
        }
    }
    /// Convert from self to another PublicKey type
    fn try_to_pk<PK: PublicKey>(&self) -> Result<PK, ParsePublicKeyError> {
        PK::try_from_pk(self)
    }
}

/// Represents a secret key

pub trait SecretKey:
    BorshSerialize
    + BorshDeserialize
    + BorshSchema
    + Display
    + Debug
    + RefTo<Self::PublicKey>
    + FromStr<Err = ParseSecretKeyError>
    + Clone
    + Sync
    + Send
{
    /// The scheme type of this implementation
    const TYPE: SchemeType;
    /// Represents the public part of this keypair
    type PublicKey: PublicKey;
    /// Convert from one SecretKey type to self
    fn try_from_sk<SK: SecretKey>(
        sk: &SK,
    ) -> Result<Self, ParseSecretKeyError> {
        if SK::TYPE == Self::TYPE {
            let sk_vec = sk.serialize_to_vec();
            let res = Self::try_from_slice(sk_vec.as_ref());
            res.map_err(ParseSecretKeyError::InvalidEncoding)
        } else {
            Err(ParseSecretKeyError::MismatchedScheme)
        }
    }
    /// Convert from self to another SecretKey type
    fn try_to_sk<SK: SecretKey>(&self) -> Result<SK, ParseSecretKeyError> {
        SK::try_from_sk(self)
    }
}

/// Represents a digital signature scheme. More precisely this trait captures
/// the concepts of public keys, private keys, and signatures as well as
/// the algorithms over these concepts to generate keys, sign messages, and
/// verify signatures.

pub trait SigScheme: Eq + Ord + Debug + Serialize + Default {
    /// Represents the signature for this scheme
    type Signature: 'static + Signature;
    /// Represents the public key for this scheme
    type PublicKey: 'static + PublicKey;
    /// Represents the secret key for this scheme
    type SecretKey: 'static + SecretKey;
    /// The scheme type of this implementation
    const TYPE: SchemeType;

    /// Generate a keypair.
    #[cfg(feature = "rand")]
    fn generate<R>(csprng: &mut R) -> Self::SecretKey
    where
        R: CryptoRng + RngCore;

    /// Instantiate a secret key from the bytes.
    fn from_bytes(bytes: [u8; 32]) -> Self::SecretKey;

    /// Sign the data with a key.
    fn sign_with_hasher<H>(
        keypair: &Self::SecretKey,
        data: impl SignableBytes,
    ) -> Self::Signature
    where
        H: 'static + StorageHasher;

    /// Check that the public key matches the signature on the given data.
    fn verify_signature_with_hasher<H>(
        pk: &Self::PublicKey,
        data: &impl SignableBytes,
        sig: &Self::Signature,
    ) -> Result<(), VerifySigError>
    where
        H: 'static + StorageHasher;

    /// Sign the data with a key, using a SHA256 hasher.
    #[inline]
    fn sign(
        keypair: &Self::SecretKey,
        data: impl SignableBytes,
    ) -> Self::Signature {
        Self::sign_with_hasher::<Sha256Hasher>(keypair, data)
    }

    /// Check that the public key matches the signature on the given data,
    /// using a SHA256 hasher.
    #[inline]
    fn verify_signature(
        pk: &Self::PublicKey,
        data: &impl SignableBytes,
        sig: &Self::Signature,
    ) -> Result<(), VerifySigError> {
        Self::verify_signature_with_hasher::<Sha256Hasher>(pk, data, sig)
    }
}

/// Public key hash derived from `common::Key` borsh encoded bytes (hex string
/// of the first 40 chars of sha256 hash)
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
)]
pub struct PublicKeyHash(pub(crate) [u8; address::HASH_LEN]);

impl serde::Serialize for PublicKeyHash {
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

impl<'de> serde::Deserialize<'de> for PublicKeyHash {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        use serde::de::Error;
        let encoded: String = serde::Deserialize::deserialize(deserializer)?;
        Self::from_str(&encoded).map_err(D::Error::custom)
    }
}

const PKH_HEX_LEN: usize = address::HASH_HEX_LEN;
const PKH_LEN: usize = address::HASH_LEN;

impl From<PublicKeyHash> for String {
    fn from(pkh: PublicKeyHash) -> Self {
        pkh.to_string()
    }
}

impl Display for PublicKeyHash {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", HEXUPPER.encode(&self.0))
    }
}

impl FromStr for PublicKeyHash {
    type Err = PkhFromStringError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if s.len() != PKH_HEX_LEN {
            return Err(Self::Err::UnexpectedLen(s.len()));
        }
        let raw_bytes = HEXUPPER
            .decode(s.as_bytes())
            .map_err(Self::Err::DecodeUpperHex)?;
        let mut bytes: [u8; PKH_LEN] = Default::default();
        bytes.copy_from_slice(&raw_bytes);
        Ok(Self(bytes))
    }
}

#[allow(missing_docs)]
#[derive(Error, Debug)]
pub enum PkhFromStringError {
    #[error("Wrong PKH len. Expected {PKH_HEX_LEN}, got {0}")]
    UnexpectedLen(usize),
    #[error("Failed decoding upper hex with {0}")]
    DecodeUpperHex(data_encoding::DecodeError),
}

impl<PK: PublicKey> From<&PK> for PublicKeyHash {
    fn from(pk: &PK) -> Self {
        let pk_bytes = pk.serialize_to_vec();
        let full_hash = Sha256::digest(&pk_bytes);
        // take first 20 bytes of the hash
        let mut hash: [u8; PKH_LEN] = Default::default();
        hash.copy_from_slice(&full_hash[..PKH_LEN]);
        PublicKeyHash(hash)
    }
}

/// Derive Tendermint raw hash from the public key
pub trait PublicKeyTmRawHash {
    /// Derive Tendermint raw hash from the public key
    fn tm_raw_hash(&self) -> String;
}

impl PublicKeyTmRawHash for common::PublicKey {
    fn tm_raw_hash(&self) -> String {
        tm_consensus_key_raw_hash(self)
    }
}

/// Convert validator's consensus key into address raw hash that is compatible
/// with Tendermint
pub fn tm_consensus_key_raw_hash(pk: &common::PublicKey) -> String {
    let pkh = match pk {
        common::PublicKey::Ed25519(pk) => PublicKeyHash::from(pk),
        common::PublicKey::Secp256k1(pk) => PublicKeyHash::from(pk),
    };
    pkh.to_string()
}

/// Convert Tendermint validator's raw hash bytes to Namada raw hash string
pub fn tm_raw_hash_to_string(raw_hash: impl AsRef<[u8]>) -> String {
    HEXUPPER.encode(raw_hash.as_ref())
}

/// Helper trait to compress arbitrary bytes to a hash value,
/// which can be signed over.
pub trait SignableBytes: Sized + AsRef<[u8]> {
    /// Calculate a hash value to sign over.
    fn signable_hash<H: StorageHasher>(&self) -> [u8; 32] {
        H::hash(self.as_ref()).into()
    }
}

impl SignableBytes for Vec<u8> {}
impl SignableBytes for &Vec<u8> {}
impl SignableBytes for &[u8] {}
impl<const N: usize> SignableBytes for [u8; N] {}
impl<const N: usize> SignableBytes for &[u8; N] {}

impl SignableBytes for crate::types::hash::Hash {
    fn signable_hash<H: StorageHasher>(&self) -> [u8; 32] {
        self.0
    }
}

impl SignableBytes for &crate::types::hash::Hash {
    fn signable_hash<H: StorageHasher>(&self) -> [u8; 32] {
        self.0
    }
}

impl SignableBytes for crate::types::keccak::KeccakHash {
    fn signable_hash<H: StorageHasher>(&self) -> [u8; 32] {
        self.0
    }
}

impl SignableBytes for &crate::types::keccak::KeccakHash {
    fn signable_hash<H: StorageHasher>(&self) -> [u8; 32] {
        self.0
    }
}

/// Helpers for testing with keys.
#[cfg(any(test, feature = "testing"))]
pub mod testing {
    use borsh::BorshDeserialize;
    use proptest::prelude::*;
    use rand::prelude::{StdRng, ThreadRng};
    use rand::{thread_rng, SeedableRng};

    use super::SigScheme;
    use crate::types::key::*;

    /// A keypair for tests
    pub fn keypair_1() -> <common::SigScheme as SigScheme>::SecretKey {
        // generated from `cargo test gen_keypair -- --nocapture`
        let bytes = [
            33, 82, 91, 186, 100, 168, 220, 158, 185, 140, 63, 172, 3, 88, 52,
            113, 94, 30, 213, 84, 175, 184, 235, 169, 70, 175, 36, 252, 45,
            190, 138, 79,
        ];
        ed25519::SecretKey::try_from_slice(bytes.as_ref())
            .unwrap()
            .try_to_sk()
            .unwrap()
    }

    /// A keypair for tests
    pub fn keypair_2() -> <common::SigScheme as SigScheme>::SecretKey {
        // generated from `cargo test gen_keypair -- --nocapture`
        let bytes = [
            27, 238, 157, 32, 131, 242, 184, 142, 146, 189, 24, 249, 68, 165,
            205, 71, 213, 158, 25, 253, 52, 217, 87, 52, 171, 225, 110, 131,
            238, 58, 94, 56,
        ];
        ed25519::SecretKey::try_from_slice(bytes.as_ref())
            .unwrap()
            .try_to_sk()
            .unwrap()
    }

    /// An Ethereum keypair for tests
    pub fn keypair_3() -> <common::SigScheme as SigScheme>::SecretKey {
        let bytes = [
            0xf3, 0x78, 0x78, 0x80, 0xba, 0x85, 0x0b, 0xa4, 0xc5, 0x74, 0x50,
            0x5a, 0x23, 0x54, 0x6d, 0x46, 0x74, 0xa1, 0x3f, 0x09, 0x75, 0x0c,
            0xf4, 0xb5, 0xb8, 0x17, 0x69, 0x64, 0xf4, 0x08, 0xd4, 0x80,
        ];
        secp256k1::SecretKey::try_from_slice(bytes.as_ref())
            .unwrap()
            .try_to_sk()
            .unwrap()
    }

    /// An Ethereum keypair for tests
    pub fn keypair_4() -> <common::SigScheme as SigScheme>::SecretKey {
        let bytes = [
            0x68, 0xab, 0xce, 0x64, 0x54, 0x07, 0x7e, 0xf5, 0x1a, 0xb4, 0x31,
            0x7a, 0xb8, 0x8b, 0x98, 0x30, 0x27, 0x11, 0x4e, 0x58, 0x69, 0xd6,
            0x45, 0x94, 0xdc, 0x90, 0x8d, 0x94, 0xee, 0x58, 0x46, 0x91,
        ];
        secp256k1::SecretKey::try_from_slice(bytes.as_ref())
            .unwrap()
            .try_to_sk()
            .unwrap()
    }

    /// Generate an arbitrary [`super::SecretKey`].
    pub fn arb_keypair<S: SigScheme>() -> impl Strategy<Value = S::SecretKey> {
        any::<[u8; 32]>().prop_map(move |seed| {
            let mut rng = StdRng::from_seed(seed);
            S::generate(&mut rng)
        })
    }

    /// Generate an arbitrary `ed25519` [`common::SecretKey`].
    pub fn arb_common_keypair() -> impl Strategy<Value = common::SecretKey> {
        arb_keypair::<ed25519::SigScheme>()
            .prop_map(|keypair| keypair.try_to_sk().unwrap())
    }

    /// Generate an arbitrary `secp256k1` [`common::SecretKey`].
    pub fn arb_common_secp256k1_keypair()
    -> impl Strategy<Value = common::SecretKey> {
        arb_keypair::<secp256k1::SigScheme>()
            .prop_map(|keypair| keypair.try_to_sk().unwrap())
    }

    /// Derive an ed25519 [`common::SecretKey`] from a simple seed (`u64`).
    pub fn common_sk_from_simple_seed(seed: u64) -> common::SecretKey {
        let mut rng = StdRng::seed_from_u64(seed);
        common::SecretKey::Ed25519(ed25519::SigScheme::generate(&mut rng))
    }

    /// Generate a new random [`super::SecretKey`].
    pub fn gen_keypair<S: SigScheme>() -> S::SecretKey {
        let mut rng: ThreadRng = thread_rng();
        S::generate(&mut rng)
    }
}

#[cfg(test)]
macro_rules! sigscheme_test {
    ($name:ident, $type:ty) => {
        pub mod $name {
            use super::*;

            /// Run `cargo test gen_keypair -- --nocapture` to generate a
            /// keypair.
            #[test]
            fn gen_keypair0() {
                use rand::prelude::ThreadRng;
                use rand::thread_rng;

                let mut rng: ThreadRng = thread_rng();
                let keypair = <$type>::generate(&mut rng);
                println!("keypair {:?}", keypair.serialize_to_vec().as_slice());
            }
            /// Run `cargo test gen_keypair -- --nocapture` to generate a
            /// new keypair.
            #[test]
            fn gen_keypair1() {
                let secret_key = testing::gen_keypair::<$type>();
                let public_key = secret_key.ref_to();
                println!("Public key: {}", public_key);
                println!("Secret key: {}", secret_key);
            }

            /// Sign a simple message and verify the signature.
            #[test]
            fn gen_sign_verify() {
                use rand::prelude::ThreadRng;
                use rand::thread_rng;

                let mut rng: ThreadRng = thread_rng();
                let sk = <$type>::generate(&mut rng);
                let sig = <$type>::sign(&sk, b"hello");
                assert!(
                    <$type>::verify_signature(&sk.ref_to(), b"hello", &sig)
                        .is_ok()
                );
            }
        }
    };
}

#[cfg(test)]
sigscheme_test! {ed25519_test, ed25519::SigScheme}
#[cfg(test)]
sigscheme_test! {secp256k1_test, secp256k1::SigScheme}

#[cfg(test)]
mod more_tests {
    use super::*;

    #[test]
    fn zeroize_keypair_ed25519() {
        use rand::thread_rng;

        let sk = ed25519::SigScheme::generate(&mut thread_rng());
        let sk_bytes = sk.0.as_bytes();
        let len = sk_bytes.len();
        let ptr = sk_bytes.as_ptr();

        drop(sk);

        assert_eq!(&[0u8; 32], unsafe {
            core::slice::from_raw_parts(ptr, len)
        });
    }

    #[test]
    fn zeroize_keypair_secp256k1() {
        use rand::thread_rng;

        let mut sk = secp256k1::SigScheme::generate(&mut thread_rng());
        let sk_scalar = sk.0.to_scalar_ref();
        let len = sk_scalar.0.len();
        let ptr = sk_scalar.0.as_ref().as_ptr();

        let original_data = sk_scalar.0;

        drop(sk);

        assert_ne!(&original_data, unsafe {
            core::slice::from_raw_parts(ptr, len)
        });
    }
}
