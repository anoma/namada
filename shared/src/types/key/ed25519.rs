use std::convert::TryInto;
use std::fmt::Debug;
use std::io::{ErrorKind, Write};

use borsh::{BorshDeserialize, BorshSerialize};
use ed25519_dalek::Signer;
pub use ed25519_dalek::{Keypair, SecretKey, SignatureError};
use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::types::{address, Address, DbKeySeg, Key, KeySeg};

const SIGNATURE_LEN: usize = ed25519_dalek::SIGNATURE_LENGTH;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PublicKey(ed25519_dalek::PublicKey);

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Signature(ed25519_dalek::Signature);

#[derive(
    Debug,
    Clone,
    BorshSerialize,
    BorshDeserialize,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
)]
pub struct PublicKeyHash(pub(crate) String);

const PK_STORAGE_KEY: &str = "ed25519_pk";

/// Obtain a storage key for user's public key.
pub fn pk_key(owner: &Address) -> Key {
    Key::from(owner.to_db_key())
        .push(&PK_STORAGE_KEY.to_owned())
        .expect("Cannot obtain a storage key")
}

/// Check if the given storage key is a public key. If it is, returns the owner.
pub fn is_pk_key(key: &Key) -> Option<&Address> {
    match &key.segments[..] {
        [DbKeySeg::AddressSeg(owner), DbKeySeg::StringSeg(key)]
            if key == PK_STORAGE_KEY =>
        {
            Some(owner)
        }
        _ => None,
    }
}

/// Sign the data with a key.
pub fn sign(keypair: &Keypair, data: impl AsRef<[u8]>) -> Signature {
    Signature(keypair.sign(&data.as_ref()))
}

#[derive(Error, Debug)]
pub enum VerifySigError {
    #[error("Signature verification failed: {0}")]
    SigError(SignatureError),
    #[error("Signature verification failed to encode the data: {0}")]
    EncodingError(std::io::Error),
}

/// Check that the public key matches the signature on the given data.
pub fn verify_signature<T: BorshSerialize + BorshDeserialize>(
    pk: &PublicKey,
    data: &T,
    sig: &Signature,
) -> Result<(), VerifySigError> {
    let bytes = data.try_to_vec().map_err(VerifySigError::EncodingError)?;
    pk.0.verify_strict(&bytes, &sig.0)
        .map_err(VerifySigError::SigError)
}

/// Check that the public key matches the signature on the given raw data.
pub fn verify_signature_raw(
    pk: &PublicKey,
    data: &[u8],
    sig: &Signature,
) -> Result<(), VerifySigError> {
    pk.0.verify_strict(data, &sig.0)
        .map_err(VerifySigError::SigError)
}

/// This can be used to sign an arbitrary tx. The signature is produced and
/// verified on the tx data concatenated with the tx code, however the tx code
/// itself is not part of this structure.
///
/// Because the signature is not checked by the ledger, we don't inline it into
/// the `Tx` type directly. Instead, the signature is attached to the `tx.data`,
/// which is can then be checked by a validity predicate wasm.
#[derive(Clone, Debug, BorshSerialize, BorshDeserialize)]
pub struct SignedTxData {
    /// The tx data bytes
    pub data: Vec<u8>,
    /// The signature is produced on the tx data concatenated with the tx code.
    pub sig: Signature,
}

impl SignedTxData {
    pub fn new(
        keypair: &Keypair,
        data: Vec<u8>,
        tx_code: impl AsRef<[u8]>,
    ) -> Self {
        let to_sign = [&data[..], tx_code.as_ref()].concat();
        let sig = sign(keypair, &to_sign);
        Self { data, sig }
    }

    pub fn verify(
        &self,
        pk: &PublicKey,
        tx_code: impl AsRef<[u8]>,
    ) -> Result<(), VerifySigError> {
        let data = [&self.data, tx_code.as_ref()].concat();
        verify_signature_raw(pk, &data, &self.sig)
    }
}

/// A generic signed data wrapper for Borsh encode-able data.
#[derive(Clone, Debug, BorshSerialize, BorshDeserialize)]
pub struct Signed<T: BorshSerialize + BorshDeserialize> {
    pub data: T,
    pub sig: Signature,
}

impl<T> Signed<T>
where
    T: BorshSerialize + BorshDeserialize,
{
    pub fn new(keypair: &Keypair, data: T) -> Self {
        let to_sign = data
            .try_to_vec()
            .expect("Encoding data for signing shouldn't fail");
        let sig = sign(keypair, &to_sign);
        Self { data, sig }
    }

    pub fn verify(&self, pk: &PublicKey) -> Result<(), VerifySigError> {
        let bytes = self
            .data
            .try_to_vec()
            .expect("Encoding data for verifying signature shouldn't fail");
        verify_signature_raw(pk, &bytes, &self.sig)
    }
}

impl BorshDeserialize for PublicKey {
    fn deserialize(buf: &mut &[u8]) -> std::io::Result<Self> {
        // deserialize the bytes first
        let bytes: Vec<u8> =
            BorshDeserialize::deserialize(buf).map_err(|e| {
                std::io::Error::new(
                    ErrorKind::InvalidInput,
                    format!("Error decoding ed25519 public key: {}", e),
                )
            })?;
        ed25519_dalek::PublicKey::from_bytes(&bytes)
            .map(PublicKey)
            .map_err(|e| {
                std::io::Error::new(
                    ErrorKind::InvalidInput,
                    format!("Error decoding ed25519 public key: {}", e),
                )
            })
    }
}

impl BorshSerialize for PublicKey {
    fn serialize<W: Write>(&self, writer: &mut W) -> std::io::Result<()> {
        // We need to turn the signature to bytes first..
        let vec = self.0.as_bytes().to_vec();
        // .. and then encode them with Borsh
        let bytes = vec
            .try_to_vec()
            .expect("Public key bytes encoding shouldn't fail");
        writer.write_all(&bytes)
    }
}

impl BorshDeserialize for Signature {
    fn deserialize(buf: &mut &[u8]) -> std::io::Result<Self> {
        // deserialize the bytes first
        let bytes: Vec<u8> =
            BorshDeserialize::deserialize(buf).map_err(|e| {
                std::io::Error::new(
                    ErrorKind::InvalidInput,
                    format!("Error decoding ed25519 signature: {}", e),
                )
            })?;
        // convert them to an expected size array
        let bytes: [u8; SIGNATURE_LEN] = bytes[..].try_into().map_err(|e| {
            std::io::Error::new(
                ErrorKind::InvalidInput,
                format!("Error decoding ed25519 signature: {}", e),
            )
        })?;
        Ok(Signature(ed25519_dalek::Signature::new(bytes)))
    }
}

impl BorshSerialize for Signature {
    fn serialize<W: Write>(&self, writer: &mut W) -> std::io::Result<()> {
        // We need to turn the signature to bytes first..
        let vec = self.0.to_bytes().to_vec();
        // .. and then encode them with Borsh
        let bytes = vec
            .try_to_vec()
            .expect("Signature bytes encoding shouldn't fail");
        writer.write_all(&bytes)
    }
}

impl From<ed25519_dalek::PublicKey> for PublicKey {
    fn from(pk: ed25519_dalek::PublicKey) -> Self {
        Self(pk)
    }
}

impl From<PublicKey> for PublicKeyHash {
    fn from(pk: PublicKey) -> Self {
        let pk_bytes =
            pk.try_to_vec().expect("Public key encoding shouldn't fail");
        let mut hasher = Sha256::new();
        hasher.update(pk_bytes);
        // hex of the first 40 chars of the hash
        Self(format!(
            "{:.width$X}",
            hasher.finalize(),
            width = address::HASH_LEN
        ))
    }
}
