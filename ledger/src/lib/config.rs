//! Node and client configuration settings

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
pub struct Gossip {
    pub host: String,
    pub port: String,
    pub peers: Vec<String>,
    pub topics: Vec<Topic>,
}
#[derive(Debug, Deserialize)]
pub struct Config {
    pub node: Node,
    pub tendermint: Tendermint,
    pub p2p: Gossip,
}

impl Gossip {
    // TODO here, and in set_address, we assumes a ip4+tcp address but it would
    // be nice to allow all accepted address by libp2p
    pub fn get_address(&self) -> String {
        return format!("/ip4/{}/tcp/{}", self.host, self.port);
    }

    pub fn set_peers(&mut self, peers: Option<Vec<String>>) {
        if let Some(peers) = peers {
            self.peers = peers;
        }
    }

    pub fn set_dkg_topic(&mut self, enable: bool) {
        if enable {
            self.set_topic(Topic::Dkg);
        }
    }

    pub fn set_orderbook_topic(&mut self, enable: bool) {
        if enable {
            self.set_topic(Topic::Dkg);
        }
    }

    fn set_topic(&mut self, topic: Topic) {
        self.topics.push(topic);
    }

    pub fn set_address(&mut self, address: Option<String>) {
        match address {
            Some(address) => {
                let split_addresses: Vec<String> =
                    address.split("/").map(|s| s.to_string()).collect();
                self.host = split_addresses[2].clone();
                self.port = split_addresses[4].clone();
            }
            None => {}
        }
    }
}

impl Config {
    pub fn new(home: String) -> Result<Self, config::ConfigError> {
        let mut s = config::Config::new();

        let mut topics = Vec::<String>::with_capacity(2);
        topics.push(Topic::Orderbook.to_string());

        s.set_default("node.home", home.to_string())?;
        s.set_default("node.db_path", "db")?;
        s.set_default("node.libp2p_path", "libp2p")?;
        s.set_default("node.tendermint_path", "tendermint")?;

        s.set_default("tendermint.host", "127.0.0.1")?;
        s.set_default("tendermint.port", 26658)?;
        s.set_default("tendermint.network", "mainnet")?;

        s.set_default("p2p.host", "127.0.0.1")?;
        s.set_default("p2p.port", 20201)?;
        s.set_default("p2p.peers", Vec::<String>::new())?;
        s.set_default("p2p.topics", topics)?;

        s.merge(
            config::File::with_name(&format!("{}/{}", home, "settings.toml"))
                .required(false),
        )?;

        s.try_into()
    }

    pub fn tendermint_home_dir(&self) -> PathBuf {
        self.node.home.join(self.node.tendermint_path.clone())
    }

    pub fn gossip_home_dir(&self) -> PathBuf {
        self.node.home.join(self.node.libp2p_path.clone())
    }

    pub fn db_home_dir(&self) -> PathBuf {
        self.node.home.join(self.node.db_path.clone())
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
