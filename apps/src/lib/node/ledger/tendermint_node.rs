use std::env;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::str::FromStr;

use borsh_ext::BorshSerializeExt;
use namada::types::chain::ChainId;
use namada::types::key::*;
use namada::types::storage::BlockHeight;
use namada::types::time::DateTimeUtc;
use serde_json::json;
#[cfg(feature = "abcipp")]
use tendermint_abcipp::Moniker;
use thiserror::Error;
use tokio::fs::{self, File, OpenOptions};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::process::Command;

use crate::cli::namada_version;
use crate::config;
#[cfg(feature = "abciplus")]
use crate::facade::tendermint::Moniker;
use crate::facade::tendermint::{block, Genesis};
use crate::facade::tendermint_config::{
    Error as TendermintError, TendermintConfig,
};
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
}

pub type Result<T> = std::result::Result<T, Error>;

/// Check if the COMET env var has been set and use that as the
/// location of the COMET binary. Otherwise, assume it is on path
///
/// Returns an error if the env var is defined but not a valid Unicode.
fn from_env_or_default() -> Result<String> {
    match std::env::var("COMETBFT") {
        Ok(path) => {
            tracing::info!("Using CometBFT path from env variable: {}", path);
            Ok(path)
        }
        Err(std::env::VarError::NotPresent) => Ok(String::from("cometbft")),
        Err(std::env::VarError::NotUnicode(msg)) => {
            Err(Error::TendermintPath(msg))
        }
    }
}

/// Run the tendermint node.
pub async fn run(
    home_dir: PathBuf,
    chain_id: ChainId,
    genesis_time: DateTimeUtc,
    proxy_app_address: String,
    config: config::Ledger,
    abort_recv: tokio::sync::oneshot::Receiver<
        tokio::sync::oneshot::Sender<()>,
    >,
) -> Result<()> {
    let home_dir_string = home_dir.to_string_lossy().to_string();
    let tendermint_path = from_env_or_default()?;
    let mode = config.shell.tendermint_mode.to_str().to_owned();

    #[cfg(feature = "dev")]
    // This has to be checked before we run tendermint init
    let has_validator_key = {
        let path = home_dir.join("config").join("priv_validator_key.json");
        Path::new(&path).exists()
    };

    // init and run a tendermint node child process
    let output = Command::new(&tendermint_path)
        .args(["init", &mode, "--home", &home_dir_string])
        .output()
        .await
        .map_err(Error::Init)?;
    if !output.status.success() {
        panic!("Tendermint failed to initialize with {:#?}", output);
    }

    #[cfg(feature = "dev")]
    {
        let consensus_key = crate::wallet::defaults::validator_keypair();
        // write the validator key file if it didn't already exist
        if !has_validator_key {
            write_validator_key_async(&home_dir, &consensus_key).await;
        }
    }
    #[cfg(feature = "abcipp")]
    write_tm_genesis(&home_dir, chain_id, genesis_time, &config).await;
    #[cfg(not(feature = "abcipp"))]
    write_tm_genesis(&home_dir, chain_id, genesis_time).await;

    update_tendermint_config(&home_dir, config.cometbft).await?;

    let mut tendermint_node = Command::new(&tendermint_path);
    tendermint_node.args([
        "start",
        "--proxy_app",
        &proxy_app_address,
        "--home",
        &home_dir_string,
    ]);

    let log_stdout = match env::var(ENV_VAR_TM_STDOUT) {
        Ok(val) => val.to_ascii_lowercase().trim() == "true",
        _ => false,
    };
    if !log_stdout {
        tendermint_node.stdout(Stdio::null());
    }

    let mut tendermint_node = tendermint_node
        .kill_on_drop(true)
        .spawn()
        .map_err(Error::StartUp)?;
    tracing::info!("CometBFT node started");

    tokio::select! {
        status = tendermint_node.wait() => {
            match status {
                Ok(status) => {
                    if status.success() {
                        Ok(())
                    } else {
                        Err(Error::Runtime(status.to_string()))
                    }
                },
                Err(err) => {
                    Err(Error::Runtime(err.to_string()))
                }
            }
        },
        resp_sender = abort_recv => {
            match resp_sender {
                Ok(resp_sender) => {
                    tracing::info!("Shutting down Tendermint node...");
                    tendermint_node.kill().await.unwrap();
                    resp_sender.send(()).unwrap();
                },
                Err(err) => {
                    tracing::error!("The Tendermint abort sender has unexpectedly dropped: {}", err);
                    tracing::info!("Shutting down Tendermint node...");
                    tendermint_node.kill().await.unwrap();
                }
            }
            Ok(())
        }
    }
}

pub fn reset(tendermint_dir: impl AsRef<Path>) -> Result<()> {
    let tendermint_path = from_env_or_default()?;
    let tendermint_dir = tendermint_dir.as_ref().to_string_lossy();
    // reset all the Tendermint state, if any
    std::process::Command::new(tendermint_path)
        .args([
            "reset-state",
            "unsafe-all",
            // NOTE: log config: https://docs.tendermint.com/master/nodes/logging.html#configuring-log-levels
            // "--log-level=\"*debug\"",
            "--home",
            &tendermint_dir,
        ])
        .output()
        .expect("Failed to reset tendermint node's data");
    std::fs::remove_dir_all(format!("{}/config", tendermint_dir,))
        .expect("Failed to reset tendermint node's config");
    Ok(())
}

pub fn rollback(tendermint_dir: impl AsRef<Path>) -> Result<BlockHeight> {
    let tendermint_path = from_env_or_default()?;
    let tendermint_dir = tendermint_dir.as_ref().to_string_lossy();

    // Rollback tendermint state, see https://github.com/tendermint/tendermint/blob/main/cmd/tendermint/commands/rollback.go for details
    // on how the tendermint rollback behaves
    let output = std::process::Command::new(tendermint_path)
        .args([
            "rollback",
            "unsafe-all",
            // NOTE: log config: https://docs.tendermint.com/master/nodes/logging.html#configuring-log-levels
            // "--log-level=\"*debug\"",
            "--home",
            &tendermint_dir,
        ])
        .output()
        .map_err(|e| Error::RollBack(e.to_string()))?;

    // Capture the block height from the output of tendermint rollback
    // Tendermint stdout message: "Rolled
    // back state to height %d and hash %v"
    let output_msg = String::from_utf8(output.stdout)
        .map_err(|e| Error::RollBack(e.to_string()))?;
    let (_, right) = output_msg
        .split_once("Rolled back state to height")
        .ok_or(Error::RollBack(
            "Missing expected block height in tendermint stdout message"
                .to_string(),
        ))?;

    let mut sub = right.split_ascii_whitespace();
    let height = sub.next().ok_or(Error::RollBack(
        "Missing expected block height in tendermint stdout message"
            .to_string(),
    ))?;

    Ok(height
        .parse::<u64>()
        .map_err(|e| Error::RollBack(e.to_string()))?
        .into())
}

/// Convert a common signing scheme validator key into JSON for
/// Tendermint
fn validator_key_to_json(
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
pub async fn write_validator_key_async(
    home_dir: impl AsRef<Path>,
    consensus_key: &common::SecretKey,
) {
    let home_dir = home_dir.as_ref();
    let path = home_dir.join("config").join("priv_validator_key.json");
    // Make sure the dir exists
    let wallet_dir = path.parent().unwrap();
    fs::create_dir_all(wallet_dir)
        .await
        .expect("Couldn't create private validator key directory");
    let mut file = OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(true)
        .open(&path)
        .await
        .expect("Couldn't create private validator key file");
    let key = validator_key_to_json(consensus_key).unwrap();
    let data = serde_json::to_vec_pretty(&key)
        .expect("Couldn't encode private validator key file");
    file.write_all(&data[..])
        .await
        .expect("Couldn't write private validator key file");
}

/// Initialize validator private key for Tendermint
pub fn write_validator_key(
    home_dir: impl AsRef<Path>,
    consensus_key: &common::SecretKey,
) {
    let home_dir = home_dir.as_ref();
    let path = home_dir.join("config").join("priv_validator_key.json");
    // Make sure the dir exists
    let wallet_dir = path.parent().unwrap();
    std::fs::create_dir_all(wallet_dir)
        .expect("Couldn't create private validator key directory");
    let file = std::fs::OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(true)
        .open(&path)
        .expect("Couldn't create private validator key file");
    let key = validator_key_to_json(consensus_key).unwrap();
    serde_json::to_writer_pretty(file, &key)
        .expect("Couldn't write private validator key file");
}

/// Initialize validator private state for Tendermint
pub fn write_validator_state(home_dir: impl AsRef<Path>) {
    let home_dir = home_dir.as_ref();
    let path = home_dir.join("data").join("priv_validator_state.json");
    // Make sure the dir exists
    let wallet_dir = path.parent().unwrap();
    std::fs::create_dir_all(wallet_dir)
        .expect("Couldn't create private validator state directory");
    let file = std::fs::OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(true)
        .open(&path)
        .expect("Couldn't create private validator state file");
    let state = json!({
       "height": "0",
       "round": 0,
       "step": 0
    });
    serde_json::to_writer_pretty(file, &state)
        .expect("Couldn't write private validator state file");
}

async fn update_tendermint_config(
    home_dir: impl AsRef<Path>,
    config: TendermintConfig,
) -> Result<()> {
    let home_dir = home_dir.as_ref();
    let path = home_dir.join("config").join("config.toml");
    let mut config = config.clone();

    config.moniker =
        Moniker::from_str(&format!("{}-{}", config.moniker, namada_version()))
            .expect("Invalid moniker");

    // In "dev", only produce blocks when there are txs or when the AppHash
    // changes
    config.consensus.create_empty_blocks = true; // !cfg!(feature = "dev");

    // We set this to true as we don't want any invalid tx be re-applied. This
    // also implies that it's not possible for an invalid tx to become valid
    // again in the future.
    config.mempool.keep_invalid_txs_in_cache = false;

    // Bumped from the default `1_000_000`, because some WASMs can be
    // quite large
    config.rpc.max_body_bytes = 2_000_000;

    let mut file = OpenOptions::new()
        .write(true)
        .truncate(true)
        .open(path)
        .await
        .map_err(Error::OpenWriteConfig)?;
    let config_str =
        toml::to_string(&config).map_err(Error::ConfigSerializeToml)?;
    file.write_all(config_str.as_bytes())
        .await
        .map_err(Error::WriteConfig)
}

async fn write_tm_genesis(
    home_dir: impl AsRef<Path>,
    chain_id: ChainId,
    genesis_time: DateTimeUtc,
    #[cfg(feature = "abcipp")] config: &config::Tendermint,
) {
    let home_dir = home_dir.as_ref();
    let path = home_dir.join("config").join("genesis.json");
    let mut file = File::open(&path).await.unwrap_or_else(|err| {
        panic!(
            "Couldn't open the genesis file at {:?}, error: {}",
            path, err
        )
    });
    let mut file_contents = vec![];
    file.read_to_end(&mut file_contents)
        .await
        .expect("Couldn't read Tendermint genesis file");
    let mut genesis: Genesis = serde_json::from_slice(&file_contents[..])
        .expect("Couldn't deserialize the genesis file");
    genesis.chain_id =
        FromStr::from_str(chain_id.as_str()).expect("Invalid chain ID");
    genesis.genesis_time = genesis_time
        .try_into()
        .expect("Couldn't convert DateTimeUtc to Tendermint Time");
    let size = block::Size {
        // maximum size of a serialized Tendermint block
        // cannot go over 100 MiB
        max_bytes: (100 << 20) - 1, /* unsure if we are dealing with an open
                                     * range, so it's better to subtract one,
                                     * here */
        // gas is metered app-side, so we disable it
        // at the Tendermint level
        max_gas: -1,
    };
    #[cfg(not(feature = "abcipp"))]
    let size = Some(size);
    genesis.consensus_params.block = size;
    #[cfg(feature = "abcipp")]
    {
        genesis.consensus_params.timeout.commit =
            config.consensus_timeout_commit.into();
    }

    let mut file = OpenOptions::new()
        .write(true)
        .truncate(true)
        .open(&path)
        .await
        .unwrap_or_else(|err| {
            panic!(
                "Couldn't open the genesis file at {:?} for writing, error: {}",
                path, err
            )
        });
    let data = serde_json::to_vec_pretty(&genesis)
        .expect("Couldn't encode the CometBFT genesis file");
    file.write_all(&data[..])
        .await
        .expect("Couldn't write the CometBFT genesis file");
}
