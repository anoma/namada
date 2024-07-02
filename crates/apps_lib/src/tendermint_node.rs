use std::path::{Path, PathBuf};

use borsh_ext::BorshSerializeExt;
use namada_sdk::key::*;
use serde_json::json;
use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::facade::tendermint::node::Id as TendermintNodeId;
use crate::facade::tendermint_config::Error as TendermintError;

/// Env. var to output Tendermint log to stdout
pub const ENV_VAR_TM_STDOUT: &str = "NAMADA_CMT_STDOUT";

#[derive(Error, Debug)]
pub enum Error {
    #[error("Failed to initialize CometBFT: {0}")]
    Init(std::io::Error),
    #[error("Failed to load CometBFT config file: {0}")]
    LoadConfig(TendermintError),
    #[error("Failed to open CometBFT config for writing: {0}")]
    OpenWriteConfig(std::io::Error),
    #[error("Failed to serialize CometBFT config TOML to string: {0}")]
    ConfigSerializeToml(toml::ser::Error),
    #[error("Failed to write CometBFT config: {0}")]
    WriteConfig(std::io::Error),
    #[error("Failed to start up CometBFT node: {0}")]
    StartUp(std::io::Error),
    #[error("{0}")]
    Runtime(String),
    #[error("Failed to rollback CometBFT state: {0}")]
    RollBack(String),
    #[error("Failed to convert to String: {0:?}")]
    TendermintPath(std::ffi::OsString),
    #[error("Couldn't write {0}")]
    CantWrite(String),
    #[error("Couldn't create {0}")]
    CantCreate(String),
    #[error("Couldn't encode {0}")]
    CantEncode(&'static str),
}

pub type Result<T> = std::result::Result<T, Error>;

/// Convert a common signing scheme validator key into JSON for
/// Tendermint
pub fn validator_key_to_json(
    sk: &common::SecretKey,
) -> std::result::Result<serde_json::Value, ParseSecretKeyError> {
    let raw_hash = tm_consensus_key_raw_hash(&sk.ref_to());
    let (id_str, pk_arr, kp_arr) = match sk {
        common::SecretKey::Ed25519(_) => {
            let sk_ed: ed25519::SecretKey = sk.try_to_sk().unwrap();
            let keypair =
                [sk_ed.serialize_to_vec(), sk_ed.ref_to().serialize_to_vec()]
                    .concat();
            ("Ed25519", sk_ed.ref_to().serialize_to_vec(), keypair)
        }
        common::SecretKey::Secp256k1(_) => {
            let sk_sec: secp256k1::SecretKey = sk.try_to_sk().unwrap();
            (
                "Secp256k1",
                sk_sec.ref_to().serialize_to_vec(),
                sk_sec.serialize_to_vec(),
            )
        }
    };

    Ok(json!({
        "address": raw_hash,
        "pub_key": {
            "type": format!("tendermint/PubKey{}",id_str),
            "value": base64::encode(pk_arr),
        },
        "priv_key": {
            "type": format!("tendermint/PrivKey{}",id_str),
            "value": base64::encode(kp_arr),
        }
    }))
}

/// Initialize validator private key for Tendermint
pub fn write_validator_key(
    home_dir: impl AsRef<Path>,
    consensus_key: &common::SecretKey,
) -> Result<()> {
    let key = validator_key_to_json(consensus_key).unwrap();
    write_validator(validator_key(home_dir), KEY_DIR, KEY_FILE, key)
}

/// Initialize validator private state for Tendermint
pub fn write_validator_state(home_dir: impl AsRef<Path>) -> Result<()> {
    let state = json!({
       "height": "0",
       "round": 0,
       "step": 0
    });
    write_validator(validator_state(home_dir), STATE_DIR, STATE_FILE, state)
}

/// Abstract over the initialization of validator data for Tendermint
pub fn write_validator(
    path: PathBuf,
    err_dir: &'static str,
    err_file: &'static str,
    data: serde_json::Value,
) -> Result<()> {
    let parent_dir = path.parent().unwrap();
    // Make sure the dir exists
    std::fs::create_dir_all(parent_dir).map_err(|err| {
        Error::CantCreate(format!(
            "{} at {}. Caused by {err}",
            err_dir,
            parent_dir.to_string_lossy()
        ))
    })?;
    let file = ensure_empty(&path).map_err(|err| {
        Error::CantCreate(format!(
            "{} at {}. Caused by {err}",
            err_dir,
            path.to_string_lossy()
        ))
    })?;
    serde_json::to_writer_pretty(file, &data).map_err(|err| {
        Error::CantWrite(format!(
            "{} to {}. Caused by {err}",
            err_file,
            path.to_string_lossy()
        ))
    })
}

/// Length of a Tendermint Node ID in bytes
const TENDERMINT_NODE_ID_LENGTH: usize = 20;

/// Derive Tendermint node ID from public key
pub fn id_from_pk(pk: &common::PublicKey) -> TendermintNodeId {
    let mut bytes = [0u8; TENDERMINT_NODE_ID_LENGTH];

    match pk {
        common::PublicKey::Ed25519(_) => {
            let _pk: ed25519::PublicKey = pk.try_to_pk().unwrap();
            let digest = Sha256::digest(_pk.serialize_to_vec().as_slice());
            bytes.copy_from_slice(&digest[..TENDERMINT_NODE_ID_LENGTH]);
        }
        common::PublicKey::Secp256k1(_) => {
            let _pk: secp256k1::PublicKey = pk.try_to_pk().unwrap();
            let digest = Sha256::digest(_pk.serialize_to_vec().as_slice());
            bytes.copy_from_slice(&digest[..TENDERMINT_NODE_ID_LENGTH]);
        }
    }
    TendermintNodeId::new(bytes)
}

fn ensure_empty(path: &PathBuf) -> std::io::Result<std::fs::File> {
    std::fs::OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(true)
        .open(path)
}

fn validator_key(home_dir: impl AsRef<Path>) -> PathBuf {
    home_dir
        .as_ref()
        .join("config")
        .join("priv_validator_key.json")
}

fn validator_state(home_dir: impl AsRef<Path>) -> PathBuf {
    home_dir
        .as_ref()
        .join("data")
        .join("priv_validator_state.json")
}

// Constant strings to avoid repeating our magic words

const KEY_FILE: &str = "private validator key file";
const KEY_DIR: &str = "private validator key directory";

const STATE_FILE: &str = "private validator state file";
const STATE_DIR: &str = "private validator state directory";
