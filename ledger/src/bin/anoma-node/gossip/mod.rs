mod config;
mod dkg;
mod mempool;
mod network_behaviour;
mod orderbook;
mod p2p;
mod types;

use std::error::Error;
use std::fs::{create_dir_all, File};
use std::io::Write;
use std::path::PathBuf;
use std::{fs, thread};

// use self::Dkg::DKG;
use anoma::{bookkeeper::Bookkeeper, config::*};
use tokio::sync::mpsc;

use self::config::NetworkConfig;
use self::dkg::DKG;
use self::orderbook::Orderbook;
use crate::rpc;

// XXX TODO add type error and speficic Result type
pub fn run(
    config: AnomaConfig,
    rpc: bool,
    local_address: Option<String>,
    peers: Option<Vec<String>>,
    topics: Option<Vec<String>>,
) -> Result<(), Box<dyn Error>> {
    let base_dir: PathBuf = config.gossip_home_dir();
    let bookkeeper: Bookkeeper = read_or_generate_bookkeeper_key(&base_dir)?;

    let rpc_event_receiver = if rpc {
        let (tx, rx) = mpsc::channel(100);
        thread::spawn(|| rpc::rpc_server(tx).unwrap());
        Some(rx)
    } else {
        None
    };

    let network_config = NetworkConfig::read_or_generate(
        &base_dir,
        local_address,
        peers,
        topics,
    );

    let (mut swarm, event_receiver) = p2p::build_swarm(bookkeeper)?;
    p2p::prepare_swarm(&mut swarm, &network_config);
    p2p::dispatcher(
        swarm,
        event_receiver,
        rpc_event_receiver,
        Some(Orderbook::new()),
        Some(DKG::new()),
    )
}

const BOOKKEEPER_KEY_FILE: &str = "priv_bookkepeer_key.json";

fn read_or_generate_bookkeeper_key(
    home_dir: &PathBuf,
) -> Result<Bookkeeper, std::io::Error> {
    if home_dir.join("config").join(BOOKKEEPER_KEY_FILE).exists() {
        let conf_file = home_dir.join("config").join(BOOKKEEPER_KEY_FILE);
        let json_string = fs::read_to_string(conf_file.as_path())?;
        let bookkeeper = serde_json::from_str::<Bookkeeper>(&json_string)?;
        Ok(bookkeeper)
    } else {
        let path = home_dir.join("config");
        create_dir_all(&path).unwrap();
        let path = path.join(BOOKKEEPER_KEY_FILE);
        let account: Bookkeeper = Bookkeeper::new();
        let mut file = File::create(path)?;
        let json = serde_json::to_string(&account)?;
        file.write_all(json.as_bytes()).map(|_| ()).unwrap();
        Ok(account)
    }
}
