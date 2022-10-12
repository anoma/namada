//! RPC endpoint is used for ledger state queries

use std::fmt::Display;
use std::str::FromStr;

use namada::types::address::Address;
use namada::types::storage;
use thiserror::Error;

use crate::facade::tendermint::abci::Path as AbciPath;

/// RPC query path
#[derive(Debug, Clone)]
pub enum Path {
    /// Dry run a transaction
    DryRunTx,
    /// Epoch of the last committed block
    Epoch,
    /// The pool of transfers waiting to be
    /// relayed to Ethereum.
    EthereumBridgePool(BridgePoolSubpath),
    /// Read a storage value with exact storage key
    Value(storage::Key),
    /// Read a range of storage values with a matching key prefix
    Prefix(storage::Key),
    /// Check if the given storage key exists
    HasKey(storage::Key),
}

#[derive(Debug, Clone)]
pub enum BridgePoolSubpath {
    /// For queries that wish to see the contents of the
    /// Ethereum bridge pool.
    Contents,
    /// For queries that want to get a merkle proof of
    /// inclusion of transfers in the Ethereum bridge pool.
    Proof,
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
const ETH_BRIDGE_POOL_PATH: &str = "eth_bridge_pool";
const EBP_INFO_SUBPATH: &str = "contents";
const EBP_PROOF_SUBPATH: &str = "proof";
const VALUE_PREFIX: &str = "value";
const PREFIX_PREFIX: &str = "prefix";
const HAS_KEY_PREFIX: &str = "has_key";

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
            Path::EthereumBridgePool(subpath) => {
                let subpath = match subpath {
                    BridgePoolSubpath::Contents => EBP_INFO_SUBPATH,
                    BridgePoolSubpath::Proof => EBP_PROOF_SUBPATH,
                };
                write!(f, "{}/{}", ETH_BRIDGE_POOL_PATH, subpath)
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
                Some((ETH_BRIDGE_POOL_PATH, EBP_INFO_SUBPATH)) => {
                    Ok(Self::EthereumBridgePool(BridgePoolSubpath::Contents))
                }
                Some((ETH_BRIDGE_POOL_PATH, EBP_PROOF_SUBPATH)) => {
                    Ok(Self::EthereumBridgePool(BridgePoolSubpath::Proof))
                }
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
}
