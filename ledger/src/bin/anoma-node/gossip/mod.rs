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

use anoma::bookkeeper::Bookkeeper;
use anoma::config::Config;
use anoma::protobuf::types::{IntentMessage, Tx};
use mpsc::Receiver;
use prost::Message;
use tendermint_rpc::{Client, HttpClient};
use tokio::sync::mpsc;

use self::config::NetworkConfig;
use self::p2p::P2P;
use self::types::NetworkEvent;
use super::rpc;

#[derive(Debug)]
pub enum Error {}

type Result<T> = std::result::Result<T, Error>;

pub fn run(
    config: Config,
    rpc: bool,
    orderbook: bool,
    dkg: bool,
    address: Option<String>,
    peers: Option<Vec<String>>,
    matchmaker: Option<String>,
    ledger_address: Option<String>,
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

    let p2p_local_address = address
        .unwrap_or(format!("/ip4/{}/tcp/{}", config.p2p.host, config.p2p.port));
    let p2p_peers = peers.unwrap_or(config.p2p.peers);

    let network_config = NetworkConfig::read_or_generate(
        &base_dir,
        p2p_local_address,
        p2p_peers,
        orderbook,
        dkg,
    );
    let (mut p2p, event_receiver, matchmaker_event_receiver) =
        p2p::P2P::new(bookkeeper, orderbook, dkg, matchmaker, ledger_address)
            .expect("TEMPORARY: unable to build p2p layer");
    p2p.prepare(&network_config);

    dispatcher(
        p2p,
        event_receiver,
        rpc_event_receiver,
        matchmaker_event_receiver,
    )
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

// XXX TODO The protobuf encoding logic does not play well with asynchronous.
// see https://github.com/danburkert/prost/issues/108
// When this event handler is merged into the main handler of the dispatcher
// then it does not send the correct dota to the ledger and it fails to
// correctly decode the Tx.

// The problem comes from the line :
// https://github.com/informalsystems/tendermint-rs/blob/a0a59b3a3f8a50abdaa618ff00394eeeeb8b9a0f/abci/src/codec.rs#L151
// Ok(Some(M::decode(&mut result_bytes)?))

// This fix spawn a thread only to send the Tx to the ledger to prevent that.
#[tokio::main]
pub async fn matchmaker_dispatcher(
    mut matchmaker_event_receiver: Receiver<Tx>,
) {
    loop {
        // XXX todo, get rid of select because only 1 future
        tokio::select! {
            event = matchmaker_event_receiver.recv() =>
            {
                if let Some(tx) = event {
                    let mut tx_bytes = vec![];
                    tx.encode(&mut tx_bytes).unwrap();
                    let client =
                        HttpClient::new("tcp://127.0.0.1:26657".parse().unwrap()).unwrap();
                    let _response = client.broadcast_tx_commit(tx_bytes.into()).await;
                }
            }
        };
    }
}

#[tokio::main]
pub async fn dispatcher(
    mut p2p: P2P,
    mut network_event_receiver: Receiver<NetworkEvent>,
    rpc_event_receiver: Option<Receiver<IntentMessage>>,
    matchmaker_event_receiver: Option<Receiver<Tx>>,
) -> Result<()> {

    if let Some(matchmaker_event_receiver) = matchmaker_event_receiver {
        thread::spawn(|| matchmaker_dispatcher(matchmaker_event_receiver));
    }

    // XXX TODO find a way to factorize all that code
    match rpc_event_receiver {
        Some(mut rpc_event_receiver) => {
            loop {
                tokio::select! {
                    event = rpc_event_receiver.recv() =>
                        p2p.handle_rpc_event(event).await ,
                    swarm_event = p2p.swarm.next() => {
                        // All events are handled by the
                        // `NetworkBehaviourEventProcess`es.  I.e. the
                        // `swarm.next()` future drives the `Swarm` without ever
                        // terminating.
                        panic!("Unexpected event: {:?}", swarm_event);
                    },
                    event = network_event_receiver.recv() =>
                        p2p.handle_network_event(event).await
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
                    },
                    event = network_event_receiver.recv() =>
                        p2p.handle_network_event(event).await
                }
            }
        }
    }
}
