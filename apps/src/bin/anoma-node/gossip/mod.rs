mod gossip_intent;
mod network_behaviour;
mod p2p;

use std::thread;

use anoma::protobuf::services::rpc_message;
use anoma::protobuf::types::Tx;
use mpsc::Receiver;
use prost::Message;
use tendermint_rpc::{Client, HttpClient};
use thiserror::Error;
use tokio::sync::mpsc;

use self::network_behaviour::IntentBroadcasterEvent;
use self::p2p::P2P;
use super::rpc;

#[derive(Error, Debug)]
pub enum Error {
    #[error("Error gossip dispatcher {0}")]
    P2pDispatcherError(String),
}

type Result<T> = std::result::Result<T, Error>;

pub fn run(config: anoma::config::Gossip) -> Result<()> {
    let rpc_event_receiver = if config.rpc {
        let (tx, rx) = mpsc::channel(100);
        thread::spawn(|| rpc::rpc_server(tx).unwrap());
        Some(rx)
    } else {
        None
    };

    let (gossip, network_event_receiver, matchmaker_event_receiver) =
        p2p::P2P::new(&config)
            .expect("TEMPORARY: unable to build gossip layer");
    dispatcher(
        gossip,
        network_event_receiver,
        rpc_event_receiver,
        matchmaker_event_receiver,
    )
    .map_err(|e| Error::P2pDispatcherError(e.to_string()))
}

// TODO The protobuf encoding logic does not play well with asynchronous.
// see https://github.com/danburkert/prost/issues/108
// When this event handler is merged into the main handler of the dispatcher
// then it does not send the correct data to the ledger and it fails to
// correctly decode the Tx.
//
// The problem comes from the line :
// https://github.com/informalsystems/tendermint-rs/blob/a0a59b3a3f8a50abdaa618ff00394eeeeb8b9a0f/abci/src/codec.rs#L151
// Ok(Some(M::decode(&mut result_bytes)?))
//
// As a work-around, we spawn a thread that sends [`Tx`]s to the ledger, which
// seems to prevent this issue.
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
    mut gossip: P2P,
    mut network_event_receiver: Receiver<IntentBroadcasterEvent>,
    rpc_event_receiver: Option<Receiver<rpc_message::Message>>,
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
                        gossip.handle_rpc_event(event).await ,
                    swarm_event = gossip.swarm.next() => {
                        // All events are handled by the
                        // `NetworkBehaviourEventProcess`es.  I.e. the
                        // `swarm.next()` future drives the `Swarm` without ever
                        // terminating.
                        panic!("Unexpected event: {:?}", swarm_event);
                    },
                    Some(event) = network_event_receiver.recv() =>
                        gossip.handle_network_event(event).await
                };
            }
        }
        None => {
            loop {
                tokio::select! {
                    swarm_event = gossip.swarm.next() => {
                        // All events are handled by the
                        // `NetworkBehaviourEventProcess`es.  I.e. the
                        // `swarm.next()` future drives the `Swarm` without ever
                        // terminating.
                        panic!("Unexpected event: {:?}", swarm_event);
                    },
                    Some(event) = network_event_receiver.recv() =>
                        gossip.handle_network_event(event).await
                }
            }
        }
    }
}
