mod intent_broadcaster;
mod network_behaviour;
mod p2p;
mod rpc;

use std::thread;

use anoma::protobuf::services::{rpc_message, RpcResponse};
use anoma::protobuf::types::Tx;
use mpsc::Receiver;
use prost::Message;
use tendermint_rpc::{Client, HttpClient};
use thiserror::Error;
use tokio::sync::mpsc;

use self::p2p::P2P;

#[derive(Error, Debug)]
pub enum Error {
    #[error("Error initializing p2p {0}")]
    P2pInit(p2p::Error),
}

type Result<T> = std::result::Result<T, Error>;

pub fn run(config: anoma::config::IntentBroadcaster) -> Result<()> {
    let rpc_event_receiver = if config.rpc {
        let (sender, receiver) = mpsc::channel(100);
        thread::spawn(|| rpc::rpc_server(sender).unwrap());
        Some(receiver)
    } else {
        None
    };

    let (gossip, matchmaker_event_receiver) =
        p2p::P2P::new(&config).map_err(Error::P2pInit)?;

    dispatcher(gossip, rpc_event_receiver, matchmaker_event_receiver)
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
    rpc_event_receiver: Option<
        Receiver<(
            rpc_message::Message,
            tokio::sync::oneshot::Sender<RpcResponse>,
        )>,
    >,
    matchmaker_event_receiver: Option<Receiver<Tx>>,
) -> Result<()> {
    if let Some(matchmaker_event_receiver) = matchmaker_event_receiver {
        thread::spawn(|| matchmaker_dispatcher(matchmaker_event_receiver));
    }
    match rpc_event_receiver {
        Some(mut rpc_event_receiver) => {
            loop {
                tokio::select! {
                    Some((event, inject_response)) = rpc_event_receiver.recv() =>
                    {
                        let response = gossip.handle_rpc_event(event).await;
                        inject_response.send(response).expect("failed to send response to rpc server")
                    },
                    swarm_event = gossip.swarm.next() => {
                        // All events are handled by the
                        // `NetworkBehaviourEventProcess`es.  I.e. the
                        // `swarm.next()` future drives the `Swarm` without ever
                        // terminating.
                        panic!("Unexpected event: {:?}", swarm_event);
                    },
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
                }
            }
        }
    }
}
