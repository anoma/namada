use std::convert::TryInto;
use std::fmt::Debug;
use std::io::{ErrorKind, Write};

use borsh::{BorshDeserialize, BorshSerialize};
use ed25519_dalek::Signer;
pub use ed25519_dalek::{Keypair, SecretKey, SignatureError};
use thiserror::Error;

use crate::types::{Address, DbKeySeg, Key, KeySeg};

const PUBLIC_KEY_LEN: usize = ed25519_dalek::PUBLIC_KEY_LENGTH;
const SIGNATURE_LEN: usize = ed25519_dalek::SIGNATURE_LENGTH;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PublicKey(ed25519_dalek::PublicKey);

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Signature(ed25519_dalek::Signature);

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

impl BorshDeserialize for PublicKey {
    fn deserialize(buf: &mut &[u8]) -> std::io::Result<Self> {
        ed25519_dalek::PublicKey::from_bytes(buf)
            .map(|pk| {
                // we have to clear the consumed bytes
                *buf = &buf[PUBLIC_KEY_LEN..];
                PublicKey(pk)
            })
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
        writer.write_all(self.0.as_bytes())
    }
}

impl BorshDeserialize for Signature {
    fn deserialize(buf: &mut &[u8]) -> std::io::Result<Self> {
        let bytes: [u8; SIGNATURE_LEN] = (*buf).try_into().map_err(|e| {
            std::io::Error::new(
                ErrorKind::InvalidInput,
                format!("Error decoding ed25519 signature: {}", e),
            )
        })?;
        // we have to clear the consumed bytes
        *buf = &buf[SIGNATURE_LEN..];
        Ok(Signature(ed25519_dalek::Signature::new(bytes)))
    }
}

impl BorshSerialize for Signature {
    fn serialize<W: Write>(&self, writer: &mut W) -> std::io::Result<()> {
        writer.write_all(&self.0.to_bytes())
    }
}

impl From<ed25519_dalek::PublicKey> for PublicKey {
    fn from(pk: ed25519_dalek::PublicKey) -> Self {
        Self(pk)
    }
}
