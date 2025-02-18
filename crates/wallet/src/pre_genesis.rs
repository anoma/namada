//! Provides functionality for managing validator keys
use namada_core::key::{common, SchemeType};
use rand::{CryptoRng, Rng};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use zeroize::Zeroizing;

use crate::StoredKeypair;

/// Ways in which wallet store operations can fail
#[derive(Error, Debug)]
pub enum ReadError {
    /// Failed decoding the wallet store
    #[error("Failed decoding the wallet store: {0}")]
    Decode(toml::de::Error),
    /// Failed to read the wallet store
    #[error("Failed to read the wallet store from {0}: {1}")]
    ReadWallet(String, String),
    /// Failed to write the wallet store
    #[error("Failed to write the wallet store: {0}")]
    StoreNewWallet(String),
    /// Failed to decode a key
    #[error("Failed to decode a key: {0}")]
    Decryption(crate::keys::DecryptionError),
}

/// Validator pre-genesis wallet includes all the required keys for genesis
/// setup and a cache of decrypted keys.
pub struct ValidatorWallet {
    /// The wallet store that can be written/read to/from TOML
    pub store: ValidatorStore,
    /// Cryptographic keypair for consensus key
    pub consensus_key: common::SecretKey,
    /// Cryptographic keypair for eth cold key
    pub eth_cold_key: common::SecretKey,
    /// Cryptographic keypair for eth hot key
    pub eth_hot_key: common::SecretKey,
    /// Cryptographic keypair for Tendermint node key
    pub tendermint_node_key: common::SecretKey,
}

/// Validator pre-genesis wallet store includes all the required keys for
/// genesis setup.
#[derive(Serialize, Deserialize, Debug)]
pub struct ValidatorStore {
    /// Cryptographic keypair for consensus key
    pub consensus_key: StoredKeypair<common::SecretKey>,
    /// Cryptographic keypair for eth cold key
    pub eth_cold_key: StoredKeypair<common::SecretKey>,
    /// Cryptographic keypair for Tendermint node key
    pub tendermint_node_key: StoredKeypair<common::SecretKey>,
    /// Special validator keys. Contains the ETH hot key.
    pub validator_keys: crate::ValidatorKeys,
}

impl ValidatorStore {
    /// Decode from TOML string
    pub fn decode(data: &str) -> Result<Self, toml::de::Error> {
        toml::from_str(data)
    }

    /// Encode in TOML string
    pub fn encode(&self) -> String {
        toml::to_string(self).expect(
            "Serializing of validator pre-genesis wallet shouldn't fail",
        )
    }
}

/// Generate a key and then encrypt it
pub fn gen_key_to_store(
    scheme: SchemeType,
    password: Option<Zeroizing<String>>,
    rng: &mut (impl CryptoRng + Rng),
) -> (StoredKeypair<common::SecretKey>, common::SecretKey) {
    let sk = crate::gen_secret_key(scheme, rng);
    StoredKeypair::new(sk, password)
}

impl From<crate::keys::DecryptionError> for ReadError {
    fn from(err: crate::keys::DecryptionError) -> Self {
        ReadError::Decryption(err)
    }
}
