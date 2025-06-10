//! Cryptographic keys for digital signatures support for the wallet.

use std::fmt::{Display, Error, Formatter};
use std::marker::PhantomData;
use std::str::FromStr;

use data_encoding::HEXLOWER;
use namada_core::borsh::{BorshDeserialize, BorshSerialize, BorshSerializeExt};
use namada_core::chain::BlockHeight;
use namada_core::masp::{ExtendedSpendingKey, ExtendedViewingKey};
use orion::{aead, kdf};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use zeroize::Zeroizing;

use crate::WalletIo;

const ENCRYPTED_KEY_PREFIX: &str = "encrypted:";
const UNENCRYPTED_KEY_PREFIX: &str = "unencrypted:";

/// Type alias for a viewing key with a birthday.
pub type DatedViewingKey = DatedKeypair<ExtendedViewingKey>;
/// Type alias for a spending key with a birthday.
pub type DatedSpendingKey = DatedKeypair<ExtendedSpendingKey>;

/// Extended spending key with Borsh serialization compatible with
/// DatedSpendingKey. This is necessary to facilitate reading the old Store
/// format.
#[derive(Clone, Debug)]
pub struct StoreSpendingKey(ExtendedSpendingKey);

impl FromStr for StoreSpendingKey {
    type Err = <ExtendedSpendingKey as FromStr>::Err;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        ExtendedSpendingKey::from_str(s).map(Self)
    }
}

impl Display for StoreSpendingKey {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result<(), Error> {
        self.0.fmt(f)
    }
}

impl BorshDeserialize for StoreSpendingKey {
    fn deserialize_reader<R: std::io::Read>(
        reader: &mut R,
    ) -> std::io::Result<Self> {
        DatedSpendingKey::deserialize_reader(reader).map(|x| Self(x.key))
    }
}

impl BorshSerialize for StoreSpendingKey {
    fn serialize<W: std::io::Write>(
        &self,
        writer: &mut W,
    ) -> std::io::Result<()> {
        BorshSerialize::serialize(&DatedSpendingKey::new(self.0, None), writer)
    }
}

impl From<ExtendedSpendingKey> for StoreSpendingKey {
    fn from(key: ExtendedSpendingKey) -> Self {
        Self(key)
    }
}

impl From<StoreSpendingKey> for ExtendedSpendingKey {
    fn from(key: StoreSpendingKey) -> Self {
        key.0
    }
}

/// A keypair stored in a wallet
#[derive(Debug)]
pub enum StoredKeypair<T: BorshSerialize + BorshDeserialize + Display + FromStr>
where
    <T as FromStr>::Err: Display,
{
    /// An encrypted keypair
    Encrypted(EncryptedKeypair<T>),
    /// An raw (unencrypted) keypair
    Raw(T),
}

impl<T: BorshSerialize + BorshDeserialize + Display + FromStr> Serialize
    for StoredKeypair<T>
where
    <T as FromStr>::Err: Display,
{
    fn serialize<S>(
        &self,
        serializer: S,
    ) -> std::result::Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        // String encoded, because toml doesn't support enums
        match self {
            StoredKeypair::Encrypted(encrypted) => {
                let keypair_string =
                    format!("{}{}", ENCRYPTED_KEY_PREFIX, encrypted);
                serde::Serialize::serialize(&keypair_string, serializer)
            }
            StoredKeypair::Raw(raw) => {
                let keypair_string =
                    format!("{}{}", UNENCRYPTED_KEY_PREFIX, raw);
                serde::Serialize::serialize(&keypair_string, serializer)
            }
        }
    }
}

impl<'de, T: BorshSerialize + BorshDeserialize + Display + FromStr>
    Deserialize<'de> for StoredKeypair<T>
where
    <T as FromStr>::Err: Display,
{
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        use serde::de::Error;

        let keypair_string: String =
            serde::Deserialize::deserialize(deserializer)
                .map_err(|err| {
                    DeserializeStoredKeypairError::InvalidStoredKeypairString(
                        err.to_string(),
                    )
                })
                .map_err(D::Error::custom)?;
        if let Some(raw) = keypair_string.strip_prefix(UNENCRYPTED_KEY_PREFIX) {
            FromStr::from_str(raw)
                .map(|keypair| Self::Raw(keypair))
                .map_err(|err| {
                    DeserializeStoredKeypairError::InvalidStoredKeypairString(
                        err.to_string(),
                    )
                })
                .map_err(D::Error::custom)
        } else if let Some(encrypted) =
            keypair_string.strip_prefix(ENCRYPTED_KEY_PREFIX)
        {
            FromStr::from_str(encrypted)
                .map(Self::Encrypted)
                .map_err(|err| {
                    DeserializeStoredKeypairError::InvalidStoredKeypairString(
                        err.to_string(),
                    )
                })
                .map_err(D::Error::custom)
        } else {
            Err(D::Error::custom(
                DeserializeStoredKeypairError::MissingPrefix,
            ))
        }
    }
}

#[allow(missing_docs)]
#[derive(Error, Debug)]
pub enum DeserializeStoredKeypairError {
    #[error("The stored keypair is not valid: {0}")]
    InvalidStoredKeypairString(String),
    #[error("The stored keypair is missing a prefix")]
    MissingPrefix,
}

#[allow(missing_docs)]
#[derive(Error, Debug)]
pub enum DeserializeDatedKeypairError {
    #[error("The stored keypair is not valid: {0}")]
    InvalidKeypairString(String),
    #[error("The stored keypair contains an invalid birthday: {0}")]
    InvalidBirthday(String),
}

/// A keypair with a block height after which it was created
#[derive(
    Debug,
    Serialize,
    Deserialize,
    BorshSerialize,
    BorshDeserialize,
    Ord,
    PartialOrd,
    Eq,
    PartialEq,
)]
pub struct DatedKeypair<T>
where
    T: BorshSerialize + BorshDeserialize,
{
    /// The keypair itself
    pub key: T,
    /// A blockheight that precedes the creation of the keypair
    pub birthday: BlockHeight,
}

impl<T> Copy for DatedKeypair<T> where
    T: Copy + BorshSerialize + BorshDeserialize
{
}

impl<T> Clone for DatedKeypair<T>
where
    T: Clone + BorshSerialize + BorshDeserialize,
{
    fn clone(&self) -> Self {
        Self {
            key: self.key.clone(),
            birthday: self.birthday,
        }
    }
}

impl<T> DatedKeypair<T>
where
    T: BorshSerialize + BorshDeserialize,
{
    /// Create a new dated keypair. If no birthday is provided,
    /// defaults to the first blockheight.
    pub fn new(key: T, birthday: Option<BlockHeight>) -> Self {
        Self {
            key,
            birthday: birthday.unwrap_or(BlockHeight(1)),
        }
    }

    /// Map the inner key type while maintaining the birthday.
    pub fn map<U, F>(self, func: F) -> DatedKeypair<U>
    where
        F: Fn(T) -> U,
        U: BorshSerialize + BorshDeserialize,
    {
        DatedKeypair {
            key: func(self.key),
            birthday: self.birthday,
        }
    }
}

impl<T> From<T> for DatedKeypair<T>
where
    T: BorshSerialize + BorshDeserialize,
{
    fn from(key: T) -> Self {
        Self::new(key, None)
    }
}

impl<T> Display for DatedKeypair<T>
where
    T: BorshSerialize + BorshDeserialize + Display,
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}<<{}", self.key, self.birthday,)
    }
}

impl<T> FromStr for DatedKeypair<T>
where
    T: Serialize + BorshSerialize + BorshDeserialize + FromStr,
    <T as FromStr>::Err: Display,
{
    type Err = DeserializeDatedKeypairError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let mut pieces = s.split("<<");
        let key_ser = pieces.next().ok_or(
            DeserializeDatedKeypairError::InvalidKeypairString(
                "Provided string was empty".to_string(),
            ),
        )?;
        let birthday = pieces
            .next()
            .map(|b| {
                BlockHeight::from_str(b).map_err(|_| {
                    DeserializeDatedKeypairError::InvalidBirthday(b.to_string())
                })
            })
            .transpose()?;
        Ok(Self::new(
            T::from_str(key_ser).map_err(|e| {
                DeserializeDatedKeypairError::InvalidKeypairString(
                    e.to_string(),
                )
            })?,
            birthday,
        ))
    }
}

/// An encrypted keypair stored in a wallet
#[derive(Debug)]
pub struct EncryptedKeypair<T: BorshSerialize + BorshDeserialize>(
    Vec<u8>,
    PhantomData<T>,
);

impl<T: BorshSerialize + BorshDeserialize> Display for EncryptedKeypair<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", HEXLOWER.encode(self.0.as_ref()))
    }
}

impl<T: BorshSerialize + BorshDeserialize> FromStr for EncryptedKeypair<T> {
    type Err = data_encoding::DecodeError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        HEXLOWER.decode(s.as_ref()).map(|x| Self(x, PhantomData))
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
    #[error("Empty password provided")]
    EmptyPassword,
}

impl<T: BorshSerialize + BorshDeserialize + Display + FromStr + Clone>
    StoredKeypair<T>
where
    <T as FromStr>::Err: Display,
{
    /// Construct a keypair for storage. If no password is provided, the keypair
    /// will be stored raw without encryption. Returns the key for storing and a
    /// reference-counting point to the raw key.
    pub fn new(keypair: T, password: Option<Zeroizing<String>>) -> (Self, T) {
        match password {
            Some(password) => (
                Self::Encrypted(EncryptedKeypair::new(&keypair, password)),
                keypair,
            ),
            None => (Self::Raw(keypair.clone()), keypair),
        }
    }

    /// Get a raw keypair from a stored keypair. If the keypair is encrypted and
    /// no password is provided in the argument, a password will be prompted
    /// from stdin.
    pub fn get<U: WalletIo>(
        &self,
        decrypt: bool,
        password: Option<Zeroizing<String>>,
        target_key: Option<&str>,
    ) -> Result<T, DecryptionError> {
        match self {
            StoredKeypair::Encrypted(encrypted_keypair) => {
                if decrypt {
                    let password = password
                        .unwrap_or_else(|| U::read_password(false, target_key));
                    let key = encrypted_keypair.decrypt(password)?;
                    Ok(key)
                } else {
                    Err(DecryptionError::NotDecrypting)
                }
            }
            StoredKeypair::Raw(keypair) => Ok(keypair.clone()),
        }
    }

    /// Indicates whether this key has been encrypted or not
    pub fn is_encrypted(&self) -> bool {
        match self {
            StoredKeypair::Encrypted(_) => true,
            StoredKeypair::Raw(_) => false,
        }
    }
}

impl<T: BorshSerialize + BorshDeserialize> EncryptedKeypair<T> {
    /// Encrypt a keypair and store it with its salt.
    pub fn new(keypair: &T, password: Zeroizing<String>) -> Self {
        let salt = encryption_salt();
        let encryption_key = encryption_key(&salt, &password);

        let data = keypair.serialize_to_vec();

        let encrypted_keypair = aead::seal(&encryption_key, &data)
            .expect("Encryption of data shouldn't fail");

        let encrypted_data = [salt.as_ref(), &encrypted_keypair].concat();

        Self(encrypted_data, PhantomData)
    }

    /// Decrypt an encrypted keypair
    pub fn decrypt(
        &self,
        password: Zeroizing<String>,
    ) -> Result<T, DecryptionError> {
        if password.is_empty() {
            return Err(DecryptionError::EmptyPassword);
        }

        let salt_len = encryption_salt().len();
        let (raw_salt, cipher) = self.0.split_at(salt_len);

        let salt = kdf::Salt::from_slice(raw_salt)
            .map_err(|_| DecryptionError::BadSalt)?;

        let encryption_key = encryption_key(&salt, &password);

        let decrypted_data = aead::open(&encryption_key, cipher)
            .map_err(|_| DecryptionError::DecryptionError)?;

        T::try_from_slice(&decrypted_data)
            .map_err(|_| DecryptionError::DeserializingError)
    }

    /// Change the type held by this encrypted key pair. This is only safe when
    /// the new and old types have the same Borsh serialization.
    pub fn map<U: BorshSerialize + BorshDeserialize>(
        self,
    ) -> EncryptedKeypair<U> {
        EncryptedKeypair(self.0, PhantomData)
    }
}

/// Keypair encryption salt
fn encryption_salt() -> kdf::Salt {
    kdf::Salt::default()
}

/// Make encryption secret key from a password.
fn encryption_key(salt: &kdf::Salt, password: &str) -> kdf::SecretKey {
    kdf::Password::from_slice(password.as_bytes())
        .and_then(|password| kdf::derive_key(&password, salt, 3, 1 << 17, 32))
        .expect("Generation of encryption secret key shouldn't fail")
}
