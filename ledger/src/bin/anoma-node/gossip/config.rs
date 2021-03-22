use std::fs::{create_dir_all, File};
use std::io::{Result, Write};
use std::path::PathBuf;

use serde::Deserialize;
use serde_json::json;

#[derive(Debug, Deserialize)]
pub struct NetworkConfig {
    pub local_address: String,
    pub peers: Vec<String>,
    pub gossip: GossipConfig,
}

impl Default for NetworkConfig {
    fn default() -> Self {
        Self {
            local_address: String::from("/ip4/127.0.0.1/tcp/38153"),
            peers: Vec::new(),
            gossip: GossipConfig::default(),
        }
    }
}

#[derive(Debug, Deserialize)]
pub struct GossipConfig {
    pub orderbook: bool,
    pub dkg: bool,
}

impl Default for GossipConfig {
    fn default() -> Self {
        Self {
            orderbook: true,
            dkg: false,
        }
    }
}

const CONFIG_FILE: &str = "gossipsub.json";
impl NetworkConfig {
    pub fn read_or_generate(
        home_dir: &PathBuf,
        local_address: Option<String>,
        peers: Option<Vec<String>>,
        orderbook: bool,
        dkg: bool,
    ) -> Self {
        let config = if home_dir.join("config").join(CONFIG_FILE).exists() {
            Self::read_config(home_dir, peers, orderbook, dkg)
        } else {
            let config =
                Self::generate_config(local_address, peers, orderbook, dkg);
            let _written = config.write_config(home_dir);
            config
        };
        config
    }

    fn read_config(
        home_dir: &PathBuf,
        peers: Option<Vec<String>>,
        orderbook: bool,
        dkg: bool,
    ) -> Self {
        let path = home_dir.join("config").join(CONFIG_FILE);
        let file = File::open(path).unwrap();
        let config: Self =
            serde_json::from_reader(file).expect("JSON was not well-formatted");
        Self {
            local_address: config.local_address,
            peers: peers.unwrap_or(config.peers),
            gossip: GossipConfig {
                orderbook: orderbook || config.gossip.orderbook,
                dkg: dkg || config.gossip.dkg,
            },
        }
    }

    fn generate_config(
        local_address: Option<String>,
        peers: Option<Vec<String>>,
        orderbook: bool,
        dkg: bool,
    ) -> Self {
        let default_gossip_conf = GossipConfig::default();
        Self {
            local_address: local_address
                .unwrap_or(String::from("/ip4/127.0.0.1/tcp/38153")),
            peers: peers.unwrap_or_default(),
            gossip: GossipConfig {
                orderbook: orderbook || default_gossip_conf.orderbook,
                dkg: dkg || default_gossip_conf.dkg,
            },
        }
    }

    fn write_config(&self, home_dir: &PathBuf) -> Result<()> {
        let path = home_dir.join("config");
        create_dir_all(&path).unwrap();
        let path = path.join(CONFIG_FILE);
        let mut file = File::create(path)?;
        let config = json!({
            "local_address": self.local_address,
            "peers" : self.peers,
            "gossip": {
                "orderbook": self.gossip.orderbook,
                "dkg": self.gossip.dkg,
            },
        });
        file.write(config.to_string().as_bytes()).map(|_| ())
    }
}
