mod dkg;
mod matchmaker;
mod mempool;
mod network_behaviour;
mod orderbook;
mod p2p;
mod types;

use std::thread;

<<<<<<< HEAD
// use self::Dkg::DKG;
use anoma::{self, config::Config};
use tokio::sync::mpsc;

use self::dkg::DKG;
use self::orderbook::Orderbook;
use crate::rpc;

use thiserror::Error;

#[derive(Error, Debug)]
pub enum Error {
    #[error("Bad Bookkeeper file")]
    BadBookkeeper(std::io::Error),
    #[error("Error p2p swarm {0}")]
    P2pSwarmError(String),
    #[error("Error p2p dispatcher {0}")]
    P2pDispatcherError(String),
}

pub type Result<T> = std::result::Result<T, Error>;

=======
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

>>>>>>> 4d51412eba8e788912d42c8cd686c893f9df6a3b
pub fn run(
    mut config: Config,
    rpc: bool,
    orderbook: bool,
    dkg: bool,
    address: Option<String>,
    peers: Option<Vec<String>>,
<<<<<<< HEAD
) -> Result<()> {
    let bookkeeper = config
        .get_bookkeeper()
        .or_else(|e| Err(Error::BadBookkeeper(e)))?;
=======
    matchmaker: Option<String>,
    ledger_address: Option<String>,
) -> () {
    let base_dir: PathBuf = config.gossip_home_dir();
    let bookkeeper: Bookkeeper = read_or_generate_bookkeeper_key(&base_dir)
        .expect("TEMPORARY: Error reading or generating bookkeep file");
>>>>>>> 4d51412eba8e788912d42c8cd686c893f9df6a3b

    let rpc_event_receiver = if rpc {
        let (tx, rx) = mpsc::channel(100);
        thread::spawn(|| rpc::rpc_server(tx).unwrap());
        Some(rx)
    } else {
        None
    };

<<<<<<< HEAD
    config.p2p.set_address(local_address);
    config.p2p.set_peers(peers);
    // TODO: check for duplicates and push instead of set
    config.p2p.set_dkg_topic(dkg);
    config.p2p.set_orderbook_topic(orderbook);

    let (mut swarm, event_receiver) = p2p::build_swarm(bookkeeper)
        // .expect("msg");
        .map_err(|e| Error::P2pSwarmError(e.to_string()))?;
    p2p::prepare_swarm(&mut swarm, &config);
    p2p::dispatcher(
        swarm,
=======
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
    p2p.prepare(&network_config)
        .expect("p2p prepraration failed");

    dispatcher(
        p2p,
>>>>>>> 4d51412eba8e788912d42c8cd686c893f9df6a3b
        event_receiver,
        rpc_event_receiver,
        matchmaker_event_receiver,
    )
    .map_err(|e| Error::P2pDispatcherError(e.to_string()))
}

// XXX TODO The protobuf encoding logic does not play well with asynchronous.
// see https://github.com/danburkert/prost/issues/108
// When this event handler is merged into the main handler of the dispatcher
// then it does not send the correct data to the ledger and it fails to
// correctly decode the Tx.
//
// The problem comes from the line :
// https://github.com/informalsystems/tendermint-rs/blob/a0a59b3a3f8a50abdaa618ff00394eeeeb8b9a0f/abci/src/codec.rs#L151
// Ok(Some(M::decode(&mut result_bytes)?))
//
// As a work-around, we spawn a thread that sends [`Tx`]s to the ledger, which seems to prevent this issue.
#[tokio::main]
pub async fn matchmaker_dispatcher(
    mut matchmaker_event_receiver: Receiver<Tx>,
) {
    loop {
        if let Some(tx) = matchmaker_event_receiver.recv().await {
            let mut tx_bytes = vec![];
            tx.encode(&mut tx_bytes).unwrap();
            let client =
                HttpClient::new("tcp://127.0.0.1:26657".parse().unwrap())
                    .unwrap();
            let _response = client.broadcast_tx_commit(tx_bytes.into()).await;
        }
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
                    Some(event) = rpc_event_receiver.recv() =>
                        p2p.handle_rpc_event(event).await ,
                    swarm_event = p2p.swarm.next() => {
                        // All events are handled by the
                        // `NetworkBehaviourEventProcess`es.  I.e. the
                        // `swarm.next()` future drives the `Swarm` without ever
                        // terminating.
                        panic!("Unexpected event: {:?}", swarm_event);
                    },
                    Some(event) = network_event_receiver.recv() =>
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
                    Some(event) = network_event_receiver.recv() =>
                        p2p.handle_network_event(event).await
                }
            }
        }
    }
}
