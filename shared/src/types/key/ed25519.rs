pub use ed25519_dalek::{
    Keypair, PublicKey, SecretKey, Signature, SignatureError,
};

use crate::types::{Address, DbKeySeg, Key, KeySeg};

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
    pk.verify_strict(data, sig)
}
