//! Cryptographic keys for digital signatures support for the wallet.

use anoma::types::key::ed25519::Keypair;
use borsh::{BorshDeserialize, BorshSerialize};
use orion::{aead, kdf};
use thiserror::Error;

/// A keypair stored in a wallet
pub enum StoredKeypair {
    /// An encrypted keypair
    Encrypted(EncryptedKeypair),
    /// An raw (unencrypted) keypair
    Raw(Keypair),
}

/// An encrypted keypair stored in a wallet
pub struct EncryptedKeypair(Vec<u8>);

#[allow(missing_docs)]
#[derive(Debug, Error)]
pub enum DecryptionError {
    #[error("Unexpected encryption salt")]
    BadSalt,
    #[error("Unable to decrypt the keypair. Is the password correct?")]
    DecryptionError,
    #[error("Unable to deserialize the keypair")]
    DeserializingError,
    #[error("Password is required to decrypt the keypair")]
    PasswordRequired,
}

impl StoredKeypair {
    /// Construct a keypair for storage. If no password is provided, the keypair
    /// will be stored raw without encryption.
    pub fn new(keypair: Keypair, password: Option<String>) -> Self {
        match password {
            Some(password) => {
                Self::Encrypted(EncryptedKeypair::new(keypair, password))
            }
            None => Self::Raw(keypair),
        }
    }

    /// Get a raw keypair from a stored keypair. If the keypair is encrypted, a
    /// password must be provided, otherwise fails with
    /// [`DecryptionError::PasswordRequired`].
    pub fn get(
        self,
        password: Option<String>,
    ) -> Result<Keypair, DecryptionError> {
        match self {
            StoredKeypair::Encrypted(encrypted_keypair) => {
                let password =
                    password.ok_or(DecryptionError::PasswordRequired)?;
                encrypted_keypair.decrypt(password)
            }
            StoredKeypair::Raw(keypair) => Ok(keypair),
        }
    }
}

impl EncryptedKeypair {
    /// Encrypt a keypair
    pub fn new(keypair: Keypair, password: String) -> Self {
        let encryption_key = encryption_key(password);

        let data = keypair
            .try_to_vec()
            .expect("Serializing keypair shouldn't fail");

        let encrypted_data = aead::seal(&encryption_key, &data)
            .expect("Encryption of data shouldn't fail");
        Self(encrypted_data)
    }

    /// Decrypt an encrypted keypair
    pub fn decrypt(
        &self,
        password: String,
    ) -> Result<Keypair, DecryptionError> {
        let salt_len = encryption_salt().len();
        let (salt, cipher) = self.0.split_at(salt_len);

        let salt = kdf::Salt::from_slice(salt)
            .map_err(|_| DecryptionError::BadSalt)?;
        if salt != encryption_salt() {
            return Err(DecryptionError::BadSalt);
        }

        let encryption_key = encryption_key(password);

        let decrypted_data = aead::open(&encryption_key, cipher)
            .map_err(|_| DecryptionError::DecryptionError)?;

        Keypair::try_from_slice(&decrypted_data)
            .map_err(|_| DecryptionError::DeserializingError)
    }
}

/// Keypair encryption salt
fn encryption_salt() -> kdf::Salt {
    kdf::Salt::default()
}

/// Make encryption secret key from a password.
fn encryption_key(password: String) -> kdf::SecretKey {
    let salt = encryption_salt();
    kdf::Password::from_slice(password.as_bytes())
        .and_then(|password| kdf::derive_key(&password, &salt, 3, 1 << 16, 32))
        .expect("Generation of encryption secret key shouldn't fail")
}
