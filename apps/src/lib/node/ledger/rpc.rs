//! RPC endpoint is used for ledger state queries

use std::fmt::Display;
use std::str::FromStr;

use namada::types::address::Address;
use namada::types::hash::{self, Hash};
use namada::types::storage;
use thiserror::Error;

use crate::facade::tendermint::abci::Path as AbciPath;

/// RPC query path.
#[derive(Debug, Clone)]
pub enum Path {
    /// Dry run a transaction.
    DryRunTx,
    /// Epoch of the last committed block.
    Epoch,
    /// Read a storage value with exact storage key.
    Value(storage::Key),
    /// Read a range of storage values with a matching key prefix.
    Prefix(storage::Key),
    /// Check if the given storage key exists.
    HasKey(storage::Key),
    /// Check if a transaction was accepted.
    Accepted { tx_hash: Hash },
    /// Check if a transaction was applied.
    Applied { tx_hash: Hash },
}

#[derive(Debug, Clone)]
pub struct BalanceQuery {
    #[allow(dead_code)]
    owner: Option<Address>,
    #[allow(dead_code)]
    token: Option<Address>,
}

const DRY_RUN_TX_PATH: &str = "dry_run_tx";
const EPOCH_PATH: &str = "epoch";
const VALUE_PREFIX: &str = "value";
const PREFIX_PREFIX: &str = "prefix";
const HAS_KEY_PREFIX: &str = "has_key";
const ACCEPTED_PREFIX: &str = "accepted";
const APPLIED_PREFIX: &str = "applied";

impl Display for Path {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Path::DryRunTx => write!(f, "{}", DRY_RUN_TX_PATH),
            Path::Epoch => write!(f, "{}", EPOCH_PATH),
            Path::Value(storage_key) => {
                write!(f, "{}/{}", VALUE_PREFIX, storage_key)
            }
            Path::Prefix(storage_key) => {
                write!(f, "{}/{}", PREFIX_PREFIX, storage_key)
            }
            Path::HasKey(storage_key) => {
                write!(f, "{}/{}", HAS_KEY_PREFIX, storage_key)
            }
            Path::Accepted { tx_hash } => {
                write!(f, "{ACCEPTED_PREFIX}/{tx_hash}")
            }
            Path::Applied { tx_hash } => {
                write!(f, "{APPLIED_PREFIX}/{tx_hash}")
            }
        }
    }
}

impl FromStr for Path {
    type Err = PathParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            DRY_RUN_TX_PATH => Ok(Self::DryRunTx),
            EPOCH_PATH => Ok(Self::Epoch),
            _ => match s.split_once('/') {
                Some((VALUE_PREFIX, storage_key)) => {
                    let key = storage::Key::parse(storage_key)
                        .map_err(PathParseError::InvalidStorageKey)?;
                    Ok(Self::Value(key))
                }
                Some((PREFIX_PREFIX, storage_key)) => {
                    let key = storage::Key::parse(storage_key)
                        .map_err(PathParseError::InvalidStorageKey)?;
                    Ok(Self::Prefix(key))
                }
                Some((HAS_KEY_PREFIX, storage_key)) => {
                    let key = storage::Key::parse(storage_key)
                        .map_err(PathParseError::InvalidStorageKey)?;
                    Ok(Self::HasKey(key))
                }
                Some((ACCEPTED_PREFIX, tx_hash)) => {
                    let tx_hash = tx_hash
                        .try_into()
                        .map_err(PathParseError::InvalidTxHash)?;
                    Ok(Self::Accepted { tx_hash })
                }
                Some((APPLIED_PREFIX, tx_hash)) => {
                    let tx_hash = tx_hash
                        .try_into()
                        .map_err(PathParseError::InvalidTxHash)?;
                    Ok(Self::Applied { tx_hash })
                }
                _ => Err(PathParseError::InvalidPath(s.to_string())),
            },
        }
    }
}

impl From<Path> for AbciPath {
    fn from(path: Path) -> Self {
        let path = path.to_string();
        // TODO: update in tendermint-rs to allow to construct this from owned
        // string. It's what `from_str` does anyway
        AbciPath::from_str(&path).unwrap()
    }
}

#[allow(missing_docs)]
#[derive(Error, Debug)]
pub enum PathParseError {
    #[error("Unrecognized query path: {0}")]
    InvalidPath(String),
    #[error("Invalid storage key: {0}")]
    InvalidStorageKey(storage::Error),
    #[error("Invalid transaction hash: {0}")]
    InvalidTxHash(hash::Error),
}
