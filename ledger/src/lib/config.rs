//! Node and client configuration
use std::collections::HashSet;
use std::path::PathBuf;

use serde::{Deserialize, Serialize};

use crate::gossiper::Gossiper;
use crate::types::Topic;

const TENDERMINT: &str = "tendermint";
const DB: &str = "db";

#[derive(Debug, Serialize, Deserialize)]
pub struct Ledger {
    pub host: String,
    pub port: String,
    pub network: String,
}

impl Default for Ledger {
    fn default() -> Self {
        Self {
            host: String::from("127.0.0.1"),
            port: String::from("26658"),
            network: String::from("mainnet"),
        }
    }
}

#[derive(Debug, Serialize, Deserialize, Default)]
pub struct Matchmaker {
    pub matchmaker: String,
    pub tx_template: String,
    pub ledger_host: String,
    pub ledger_port: String,
}

impl Matchmaker {
    pub fn new(
        matchmaker: String,
        tx_template: String,
        ledger_host: String,
        ledger_port: String,
    ) -> Self {
        Self {
            matchmaker,
            tx_template,
            ledger_host,
            ledger_port,
        }
    }

    pub fn get_ledger_address(&self) -> String {
        format!("tcp://{}:{}", self.ledger_host, self.ledger_port)
    }

    pub fn set_ledger_address(&mut self, ledger_address: (String, String)) {
        self.ledger_host = ledger_address.0;
        self.ledger_port = ledger_address.1;
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Orderbook {
    pub matchmaker: Option<Matchmaker>,
}

impl Default for Orderbook {
    fn default() -> Self {
        Self { matchmaker: None }
    }
}

impl Orderbook {
    pub fn new(matchmaker: Option<Matchmaker>) -> Self {
        Self { matchmaker }
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Gossip {
    pub gossiper: Gossiper,
    pub host: String,
    pub port: String,
    pub rpc: bool,
    pub peers: HashSet<String>,
    pub topics: HashSet<Topic>,
    pub orderbook: Option<Orderbook>,
}

impl Default for Gossip {
    fn default() -> Self {
        Self {
            gossiper: Gossiper::new(),
            host: String::from("127.0.0.1"),
            port: String::from("20201"),
            rpc: false,
            peers: HashSet::new(),
            topics: HashSet::new(),
            orderbook: None,
        }
    }
}

impl Gossip {
    pub fn new(
        gossiper: Gossiper,
        host: String,
        port: String,
        rpc: bool,
        peers: HashSet<String>,
        topics: HashSet<Topic>,
        orderbook: Option<Orderbook>,
    ) -> Self {
        Self {
            gossiper,
            host,
            port,
            rpc,
            peers,
            topics,
            orderbook,
        }
    }

    // TODO here, and in set_address, we assumes a ip4+tcp address but it would
    // be nice to allow all accepted address by libp2p
    pub fn get_address(&self) -> String {
        format!("/ip4/{}/tcp/{}", self.host, self.port)
    }

    pub fn enable_dkg(&mut self, enable: bool) {
        if enable {
            self.topics.insert(Topic::Dkg);
        } else {
            self.topics.remove(&Topic::Dkg);
        }
    }

    pub fn enable_orderbook(&mut self, orderbook_cfg: Option<Orderbook>) {
        self.orderbook = orderbook_cfg;
        if self.orderbook.is_some() {
            self.topics.insert(Topic::Orderbook);
        } else {
            self.topics.remove(&Topic::Orderbook);
        }
    }

    pub fn set_address(&mut self, address: Option<(String, String)>) {
        if let Some(addr) = address {
            self.host = addr.0;
            self.port = addr.1;
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Config {
    pub home: PathBuf,
    pub ledger: Ledger,
    pub gossip: Gossip,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            home: PathBuf::from(".anoma"),
            ledger: Ledger::default(),
            gossip: Gossip::default(),
        }
    }
}

impl Config {
    pub fn read(home: String) -> Result<Self, config::ConfigError> {
        let mut config = config::Config::new();
        config.merge(config::File::with_name(&format!(
            "{}/{}",
            home, "settings.toml"
        )))?;

        config.try_into()
    }

    pub fn tendermint_home_dir(&self) -> PathBuf {
        self.home.join(TENDERMINT)
    }

    pub fn db_home_dir(&self) -> PathBuf {
        self.home.join(DB)
    }
}
