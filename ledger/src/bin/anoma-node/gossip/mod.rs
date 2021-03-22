mod config;
mod dkg;
mod matchmaker;
mod mempool;
mod network_behaviour;
mod orderbook;
mod p2p;
mod types;

use std::fs::{create_dir_all, File};
use std::io::Write;
use std::path::PathBuf;
use std::{fs, thread};

// use self::Dkg::DKG;
use anoma::{bookkeeper::Bookkeeper, config::*, protobuf::types::IntentMessage};
use tokio::sync::mpsc;

use self::{config::NetworkConfig, p2p::P2P};
use self::dkg::DKG;
use self::matchmaker::Matchmaker;
use self::orderbook::Orderbook;
use self::types::NetworkEvent;

use crate::rpc;

#[derive(Debug)]
pub enum Error {
    P2PError(p2p::Error),
}
type Result<T> = std::result::Result<T, Error>;

// XXX TODO add type error and speficic Result type
pub fn run(
    config: Config,
    rpc: bool,
    orderbook: bool,
    dkg: bool,
    matchmaker: bool,
    local_address: Option<String>,
    peers: Option<Vec<String>>,
) -> () {
    let base_dir: PathBuf = config.gossip_home_dir();
    let bookkeeper: Bookkeeper = read_or_generate_bookkeeper_key(&base_dir)
        .expect("TEMPORARY: Error reading or generating bookkeep file");

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
        orderbook,
        dkg,
    );
    let (mut p2p, event_receiver) =
        p2p::P2P::new(bookkeeper, orderbook, dkg, matchmaker)
            .expect("TEMPORARY: unable to build p2p swarm");
    p2p.prepare(&network_config);

    dispatcher(p2p, event_receiver, rpc_event_receiver)
        .expect("TEMPORARY: unable to start p2p dispatcher")
}

const BOOKKEEPER_KEY_FILE: &str = "priv_bookkepeer_key.json";

fn read_or_generate_bookkeeper_key(
    home_dir: &PathBuf,
) -> std::result::Result<Bookkeeper, std::io::Error> {
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

#[tokio::main]
pub async fn dispatcher(
    mut p2p: P2P,
    mut network_event_receiver: mpsc::Receiver<NetworkEvent>,
    rpc_event_receiver: Option<mpsc::Receiver<IntentMessage>>,
) -> Result<()> {
    // Here it should pass the option value to handle_network_event instead of
    // unwraping it
    match rpc_event_receiver {
        Some(mut rpc_event_receiver) => {
            loop {
                tokio::select! {
                    event = rpc_event_receiver.recv() =>
                    {p2p.handle_rpc_event(event)}
                    swarm_event = p2p.swarm.next() => {
                        // All events are handled by the
                        // `NetworkBehaviourEventProcess`es.  I.e. the
                        // `swarm.next()` future drives the `Swarm` without ever
                        // terminating.
                        panic!("Unexpected event: {:?}", swarm_event);
                    }
                    event = network_event_receiver.recv() =>
                        p2p.handle_network_event(event)
                };
            }
        }
        None => {
            loop {
                tokio::select! {
                    swarm_event = p2p.swarm.next() => {
                        // All events are handled by the
                        // `NetworkBehaviourEventProcess`es.  I.e. the
                        // `swarm.next()` future drives the `Swarm` without ever
                        // terminating.
                        panic!("Unexpected event: {:?}", swarm_event);
                    }
                    event = network_event_receiver.recv() =>
                        p2p.handle_network_event(event)
                }
            }
        }
    }
}
