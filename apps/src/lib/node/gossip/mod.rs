mod intent_gossiper;
mod network_behaviour;
mod p2p;
mod rpc;

use thiserror::Error;
use tokio::sync::{mpsc, oneshot};

use self::p2p::P2P;
use crate::config::IntentGossiper;
use crate::proto::services::{rpc_message, RpcResponse};
use crate::types::MatchmakerMessage;

#[derive(Error, Debug)]
pub enum Error {
    #[error("Error initializing p2p: {0}")]
    P2pInit(p2p::Error),
}

type Result<T> = std::result::Result<T, Error>;

pub fn run(config: IntentGossiper) -> Result<()> {
    let rpc_event_receiver = config.rpc.as_ref().map(rpc::start_rpc_server);
    let (gossip, matchmaker_event_receiver) =
        p2p::P2P::new(&config).map_err(Error::P2pInit)?;

    dispatcher(gossip, rpc_event_receiver, matchmaker_event_receiver)
}

#[tokio::main]
pub async fn dispatcher(
    mut gossip: P2P,
    rpc_event_receiver: Option<
        mpsc::Receiver<(rpc_message::Message, oneshot::Sender<RpcResponse>)>,
    >,
    matchmaker_event_receiver: Option<mpsc::Receiver<MatchmakerMessage>>,
) -> Result<()> {
    match (rpc_event_receiver, matchmaker_event_receiver) {
        (Some(mut rpc_event_receiver), Some(mut matchmaker_event_receiver)) => {
            loop {
                tokio::select! {
                    Some(message) = matchmaker_event_receiver.recv() =>
                    {
                        gossip.handle_mm_message(message).await
                    },
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
        (Some(mut rpc_event_receiver), None) => {
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
        (None, Some(mut matchmaker_event_receiver)) => {
            loop {
                tokio::select! {
                    Some(message) = matchmaker_event_receiver.recv() =>
                    {
                        gossip.handle_mm_message(message).await
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
        (None, None) => {
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
