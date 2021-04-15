//! Node and client configuration
use std::collections::HashSet;
use std::fs::{create_dir_all, File};
use std::io::Write;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::PathBuf;
use std::str::FromStr;

use libp2p::multiaddr::Multiaddr;
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::gossiper::Gossiper;
use crate::types::Topic;

#[derive(Error, Debug)]
pub enum Error {
    #[error("Error while reading config: {0}")]
    ReadError(config::ConfigError),
    #[error("Error while casting config: {0}")]
    CastError(config::ConfigError),
    #[error("Error while serializing to toml: {0}")]
    TomlError(toml::ser::Error),
    #[error("Error while writing config: {0}")]
    WriteError(std::io::Error),
    #[error("Error while creating config file: {0}")]
    FileError(std::io::Error),
}
pub const BASEDIR: &str = ".anoma";
pub const FILENAME: &str = "config.json";
pub const TENDERMINT: &str = "tendermint";
pub const DB: &str = "db";

pub type Result<T> = std::result::Result<T, Error>;
const VALUE_AFTER_TABLE_ERROR_MSG: &str = r#"
Error while serializing to toml. It means that some nested structure is followed
 by simple fields.
This fails:
    struct Nested{
       i:int
    }

    struct Broken{
       nested:Nested,
       simple:int
    }
And this is correct
    struct Nested{
       i:int
    }

    struct Correct{
       simple:int
       nested:Nested,
    }
"#;

#[derive(Debug, Serialize, Deserialize)]
pub struct Ledger {
    pub tendermint: PathBuf,
    pub db: PathBuf,
    pub address: SocketAddr,
    pub network: String,
}

impl Default for Ledger {
    fn default() -> Self {
        Self {
            // this two value are override when generating a default config in
            // config::generate(base_dir). There must be a better way ?
            tendermint: PathBuf::from(BASEDIR).join(TENDERMINT),
            db: PathBuf::from(BASEDIR).join(DB),
            address: SocketAddr::new(
                IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
                26658,
            ),
            network: String::from("mainnet"),
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Matchmaker {
    pub matchmaker: String,
    pub tx_template: String,
    pub ledger_address: SocketAddr,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct IntentGossip {
    pub matchmaker: Option<Matchmaker>,
}

impl Default for IntentGossip {
    fn default() -> Self {
        Self { matchmaker: None }
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Gossip {
    pub gossiper: Gossiper,
    // TODO instead use address type from libp2p ?
    pub address: Multiaddr,
    pub rpc: bool,
    pub intent_gossip: Option<IntentGossip>,
    // TODO instead use address type from libp2p ?
    pub peers: HashSet<String>,
    pub topics: HashSet<Topic>,
}

impl Default for Gossip {
    fn default() -> Self {
        Self {
            gossiper: Gossiper::new(),
            // TODO there must be a better option here
            address: Multiaddr::from_str("/ip4/127.0.0.1/tcp/20201").unwrap(),
            rpc: false,
            peers: HashSet::new(),
            topics: [Topic::Intent].iter().cloned().collect(),
            intent_gossip: Some(IntentGossip::default()),
        }
    }
}

impl Gossip {
    pub fn enable_dkg(&mut self, enable: bool) {
        if enable {
            self.topics.insert(Topic::Dkg);
        } else {
            self.topics.remove(&Topic::Dkg);
        }
    }

    pub fn enable_intent(&mut self, intent_gossip_cfg: Option<IntentGossip>) {
        self.intent_gossip = intent_gossip_cfg;
        if self.intent_gossip.is_some() {
            self.topics.insert(Topic::Intent);
        } else {
            self.topics.remove(&Topic::Intent);
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Config {
    pub ledger: Option<Ledger>,
    pub gossip: Option<Gossip>,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            ledger: Some(Ledger::default()),
            // TODO Should it be None by default
            gossip: Some(Gossip::default()),
        }
    }
}

impl Config {
    pub fn read(base_dir_path: String) -> Result<Self> {
        let file_path = PathBuf::from(base_dir_path).join(FILENAME);
        let mut config = config::Config::new();
        config
            .merge(config::File::with_name(
                file_path.to_str().expect("uncorrect file"),
            ))
            .map_err(Error::ReadError)?;
        config.try_into().map_err(Error::CastError)
    }

    pub fn generate(base_dir_path: String) -> Result<()> {
        let base_dir = PathBuf::from(base_dir_path);
        let mut config = Config::default();
        let mut ledger_cfg = config
            .ledger
            .as_mut()
            .expect("ledger cfg, safe because default has ledger");
        ledger_cfg.db = base_dir.join(DB);
        ledger_cfg.tendermint = base_dir.join(TENDERMINT);
        config.write(base_dir)
    }

    fn write(&self, base_dir: PathBuf) -> Result<()> {
        create_dir_all(&base_dir).map_err(Error::FileError)?;
        let file_path = base_dir.join(FILENAME);
        if file_path.exists() {
            Err(Error::AlreadyExistingConfig(file_path))
        } else {
            let mut file = File::create(file_path).map_err(Error::FileError)?;
            let toml = toml::ser::to_string(&self).map_err(|err| {
                if let toml::ser::Error::ValueAfterTable = err {
                    log::error!("{}", VALUE_AFTER_TABLE_ERROR_MSG);
                }
                Error::TomlError(err)
            })?;
            file.write_all(toml.as_bytes()).map_err(Error::WriteError)
        }
    }
}
