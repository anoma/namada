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

#[derive(Debug, Deserialize)]
pub struct GossipConfig {
    pub topics: Vec<String>,
}

const CONFIG_FILE: &str = "gossipsub.json";
impl NetworkConfig {
    pub fn read_or_generate(
        home_dir: &PathBuf,
        local_address: String,
        peers: Vec<String>,
        topics: Vec<String>,
    ) -> Self {
        let config = if home_dir.join("config").join(CONFIG_FILE).exists() {
            Self::read_config(home_dir, peers, topics)
        } else {
            let config = Self::generate_config(local_address, peers, topics);
            let _written = config.write_config(home_dir);
            config
        };
        config
    }

    fn read_config(
        home_dir: &PathBuf,
        peers: Vec<String>,
        topics: Vec<String>,
    ) -> Self {
        let path = home_dir.join("config").join(CONFIG_FILE);
        let file = File::open(path).unwrap();
        let config: Self =
            serde_json::from_reader(file).expect("JSON was not well-formatted");
        Self {
            local_address: config.local_address,
            peers: peers,
            gossip: GossipConfig {
                topics: topics,
            },
        }
    }

    fn generate_config(
        local_address: String,
        peers: Vec<String>,
        topics: Vec<String>,
    ) -> Self {
        Self {
            local_address: local_address,
            peers: peers,
            gossip: GossipConfig {
                topics: topics,
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
            "gossip": { "topics": self.gossip.topics},
        });
        file.write(config.to_string().as_bytes()).map(|_| ())
    }
}
