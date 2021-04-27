use ed25519_dalek;
pub use ed25519_dalek::{Keypair, SecretKey, SignatureError};

use crate::types::{Address, DbKeySeg, Key, KeySeg};
use borsh::{BorshDeserialize, BorshSerialize};
use std::io::{ErrorKind, Write};

pub struct PublicKey(ed25519_dalek::PublicKey);

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

/// Check that the public key matches the signature on the given data.
pub fn verify_signature(
    pk: &PublicKey,
    data: &[u8],
    sig: &Signature,
) -> Result<(), SignatureError> {
    pk.0.verify_strict(data, &sig.0)
}

impl BorshDeserialize for PublicKey {
    fn deserialize(buf: &mut &[u8]) -> std::io::Result<Self> {
        ed25519_dalek::PublicKey::from_bytes(buf)
            .map(PublicKey)
            .map_err(|e| std::io::Error::new(ErrorKind::InvalidData, e))
    }
}

impl BorshSerialize for PublicKey {
    fn serialize<W: Write>(&self, writer: &mut W) -> std::io::Result<()> {
        writer.write_all(self.0.as_bytes())
    }
}

impl From<ed25519_dalek::PublicKey> for PublicKey {
    fn from(pk: ed25519_dalek::PublicKey) -> Self {
        Self(pk)
    }
}
