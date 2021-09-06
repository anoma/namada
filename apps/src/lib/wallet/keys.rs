//! Cryptographic keys for digital signatures support for the wallet.

use anoma::proto::Tx;
use anoma::types::key::ed25519::Keypair;
use borsh::{BorshDeserialize, BorshSerialize};
use itertools::Either;
use orion::{aead, kdf};
use thiserror::Error;

use super::read_password;

/// A keypair stored in a wallet
#[derive(Debug, BorshSerialize, BorshDeserialize)]
pub enum StoredKeypair {
    /// An encrypted keypair
    Encrypted(EncryptedKeypair),
    /// An raw (unencrypted) keypair
    Raw(Keypair),
}

/// An encrypted keypair stored in a wallet
#[derive(Debug, BorshSerialize, BorshDeserialize)]
pub struct EncryptedKeypair(Vec<u8>);

/// A key that has been read from the wallet. If the key has been encrypted,
/// It will be owned, otherwise it's borrowed. You can use its `get` method to
/// access the inner keypair.
#[derive(Debug)]
pub struct DecryptedKeypair<'a>(Either<Keypair, &'a Keypair>);

impl DecryptedKeypair<'_> {
    /// Sign a transaction using the decrypted keypair.
    pub fn sign_tx(&self, tx: Tx) -> Tx {
        let keypair = self.get();
        tx.sign(keypair)
    }

    /// Borrow the inner keypair.
    pub fn get(&self) -> &Keypair {
        match &self.0 {
            itertools::Either::Left(owned) => owned,
            itertools::Either::Right(borrowed) => *borrowed,
        }
    }
}

#[allow(missing_docs)]
#[derive(Debug, Error)]
pub enum DecryptionError {
    #[error("Unexpected encryption salt")]
    BadSalt,
    #[error("Unable to decrypt the keypair. Is the password correct?")]
    DecryptionError,
    #[error("Unable to deserialize the keypair")]
    DeserializingError,
    #[error("Asked not to decrypt")]
    NotDecrypting,
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
    /// password will be prompted from stdin.
    pub fn get(
        &self,
        decrypt: bool,
    ) -> Result<DecryptedKeypair, DecryptionError> {
        match self {
            StoredKeypair::Encrypted(encrypted_keypair) => {
                if decrypt {
                    let password = read_password("Enter decryption password: ");
                    let key = encrypted_keypair.decrypt(password)?;
                    Ok(DecryptedKeypair(Either::Left(key)))
                } else {
                    Err(DecryptionError::NotDecrypting)
                }
            }
            StoredKeypair::Raw(keypair) => {
                Ok(DecryptedKeypair(Either::Right(keypair)))
            }
        }
    }

    pub fn is_encrypted(&self) -> bool {
        match self {
            StoredKeypair::Encrypted(_) => true,
            StoredKeypair::Raw(_) => false,
        }
    }
}

impl EncryptedKeypair {
    /// Encrypt a keypair and store it with its salt.
    pub fn new(keypair: Keypair, password: String) -> Self {
        let salt = encryption_salt();
        let encryption_key = encryption_key(&salt, password);

        let data = keypair
            .try_to_vec()
            .expect("Serializing keypair shouldn't fail");

        let encrypted_keypair = aead::seal(&encryption_key, &data)
            .expect("Encryption of data shouldn't fail");

        let encrypted_data = [salt.as_ref(), &encrypted_keypair].concat();

        Self(encrypted_data)
    }

    /// Decrypt an encrypted keypair
    pub fn decrypt(
        &self,
        password: String,
    ) -> Result<Keypair, DecryptionError> {
        let salt_len = encryption_salt().len();
        let (raw_salt, cipher) = self.0.split_at(salt_len);

        let salt = kdf::Salt::from_slice(raw_salt)
            .map_err(|_| DecryptionError::BadSalt)?;

        let encryption_key = encryption_key(&salt, password);

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
fn encryption_key(salt: &kdf::Salt, password: String) -> kdf::SecretKey {
    kdf::Password::from_slice(password.as_bytes())
        .and_then(|password| kdf::derive_key(&password, salt, 3, 1 << 16, 32))
        .expect("Generation of encryption secret key shouldn't fail")
}
