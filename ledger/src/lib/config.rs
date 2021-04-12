//! Node and client configuration settings

use std::collections::HashSet;
use std::fs;
use std::fs::{create_dir_all, File};
use std::io::Write;
use std::path::PathBuf;

use serde::Deserialize;

use crate::bookkeeper::Bookkeeper;
use crate::types::Topic;

const BOOKKEEPER_KEY_FILE: &str = "priv_bookkepeer_key.json";

#[derive(Debug, Deserialize)]
pub struct Node {
    home: PathBuf,
    tendermint_path: PathBuf,
    db_path: PathBuf,
    libp2p_path: PathBuf,
}

#[derive(Debug, Deserialize)]
pub struct Tendermint {
    pub host: String,
    pub port: String,
    pub network: String,
}

#[derive(Debug, Deserialize)]
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

#[derive(Debug, Deserialize)]
pub struct Orderbook {
    pub matchmaker: Option<Matchmaker>,
}

impl Orderbook {
    pub fn new(matchmaker: Option<Matchmaker>) -> Self {
        Self { matchmaker }
    }
}

#[derive(Debug, Deserialize)]
pub struct Gossip {
    pub host: String,
    pub port: String,
    pub rpc: bool,
    pub peers: HashSet<String>,
    pub topics: HashSet<Topic>,
    pub orderbook: Option<Orderbook>,
}

impl Gossip {
    pub fn new(
        host: String,
        port: String,
        rpc: bool,
        peers: HashSet<String>,
        topics: HashSet<Topic>,
        orderbook: Option<Orderbook>,
    ) -> Self {
        Self {
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

#[derive(Debug, Deserialize)]
pub struct Config {
    pub node: Node,
    pub tendermint: Tendermint,
    pub gossip: Gossip,
}

impl Config {
    pub fn new(home: String) -> Result<Self, config::ConfigError> {
        let mut config = config::Config::new();

        config.set_default("node.home", home.to_string())?;
        config.set_default("node.db_path", "db")?;
        config.set_default("node.libp2p_path", "libp2p")?;
        config.set_default("node.tendermint_path", "tendermint")?;

        config.set_default("tendermint.host", "127.0.0.1")?;
        config.set_default("tendermint.port", 26658)?;
        config.set_default("tendermint.network", "mainnet")?;

        config.set_default("p2p.host", "127.0.0.1")?;
        config.set_default("p2p.port", 20201)?;
        config.set_default("p2p.peers", Vec::<String>::new())?;
        config.set_default("p2p.topics", vec![Topic::Orderbook.to_string()])?;
        config.set_default("p2p.rpc", true)?;
        config.set_default::<Option<String>>("p2p.matchmaker", None)?;
        config.set_default::<Option<String>>("p2p.tx_template", None)?;
        config.set_default::<Option<String>>("p2p.ledger_host", None)?;
        config.set_default::<Option<String>>("p2p.ledger_port", None)?;

        config.merge(
            config::File::with_name(&format!("{}/{}", home, "settings.toml"))
                .required(false),
        )?;

        config.try_into()
    }

    pub fn tendermint_home_dir(&self) -> PathBuf {
        self.node.home.join(&self.node.tendermint_path)
    }

    pub fn gossip_home_dir(&self) -> PathBuf {
        self.node.home.join(&self.node.libp2p_path)
    }

    pub fn db_home_dir(&self) -> PathBuf {
        self.node.home.join(&self.node.db_path)
    }

    pub fn get_bookkeeper(&self) -> Result<Bookkeeper, std::io::Error> {
        if self.gossip_home_dir().join(BOOKKEEPER_KEY_FILE).exists() {
            let conf_file = self.gossip_home_dir().join(BOOKKEEPER_KEY_FILE);
            let json_string = fs::read_to_string(conf_file.as_path())?;
            let bookkeeper = serde_json::from_str::<Bookkeeper>(&json_string)?;
            Ok(bookkeeper)
        } else {
            let path = self.gossip_home_dir();
            create_dir_all(&path).unwrap();
            let path = path.join(BOOKKEEPER_KEY_FILE);
            let account: Bookkeeper = Bookkeeper::new();
            let mut file = File::create(path)?;
            let json = serde_json::to_string(&account)?;
            file.write_all(json.as_bytes()).map(|_| ()).unwrap();
            Ok(account)
        }
    }
}
