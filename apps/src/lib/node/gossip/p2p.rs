use libp2p::gossipsub::IdentTopic;
use libp2p::identity::Keypair;
use libp2p::identity::Keypair::Ed25519;
use libp2p::{PeerId, TransportError};
use prost::Message;
use thiserror::Error;
use tokio::sync::mpsc::Receiver;

use super::behaviour::Behaviour;
use crate::proto::services::{rpc_message, RpcResponse};
use crate::proto::types::{
    intent_broadcaster_message, IntentBroadcasterMessage,
};
use crate::types::MatchmakerMessage;

pub type Swarm = libp2p::Swarm<Behaviour>;

#[derive(Error, Debug)]
pub enum Error {
    #[error("Failed initializing the transport: {0}")]
    TransportError(std::io::Error),
    #[error("Error with the network behavior: {0}")]
    Behavior(super::behaviour::Error),
    #[error("Error while dialing: {0}")]
    Dialing(libp2p::swarm::DialError),
    #[error("Error while starting to listing: {0}")]
    Listening(TransportError<std::io::Error>),
}
type Result<T> = std::result::Result<T, Error>;

pub struct P2P {
    pub swarm: Swarm,
}

impl P2P {
    pub fn new(
        config: &crate::config::IntentBroadcaster,
    ) -> Result<(Self, Option<Receiver<MatchmakerMessage>>)> {
        let local_key: Keypair = Ed25519(config.gossiper.key.clone());
        let local_peer_id: PeerId = PeerId::from(local_key.public());

        println!("Local peer id: {:?}", local_peer_id);

        let transport = {
            let rt = tokio::runtime::Runtime::new().unwrap();
            rt.block_on(libp2p::development_transport(local_key.clone()))
                .map_err(Error::TransportError)?
        };

        let (gossipsub, matchmaker_event_receiver) =
            Behaviour::new(local_key, config).map_err(Error::Behavior)?;

        tracing::debug!("p2p.discover_peer -> {:?}", config.discover_peer);

        let mut swarm = libp2p::Swarm::new(transport, gossipsub, local_peer_id);

        Swarm::listen_on(&mut swarm, config.address.clone())
            .map_err(Error::Listening)?;

        Ok((Self { swarm }, matchmaker_event_receiver))
    }

    pub async fn handle_mm_message(&mut self, mm_message: MatchmakerMessage) {
        self.swarm
            .behaviour_mut()
            .intent_broadcaster_app
            .handle_mm_message(mm_message)
            .await
    }

    pub async fn handle_rpc_event(
        &mut self,
        event: rpc_message::Message,
    ) -> RpcResponse {
        match event {
            rpc_message::Message::Intent(
                crate::proto::services::IntentMesage {
                    intent: None,
                    topic: _,
                },
            ) => {
                let result = format!(
                    "rpc intent command for topic {:?} is empty",
                    event
                );
                tracing::error!("{}", result);
                RpcResponse { result }
            }
            rpc_message::Message::Intent(
                crate::proto::services::IntentMesage {
                    intent: Some(intent),
                    topic,
                },
            ) => {
                match self
                    .swarm
                    .behaviour_mut()
                    .intent_broadcaster_app
                    .apply_intent(intent.clone())
                {
                    Ok(true) => {
                        let mut intent_bytes = vec![];
                        let intent = IntentBroadcasterMessage {
                            msg: Some(intent_broadcaster_message::Msg::Intent(
                                intent,
                            )),
                        };
                        intent.encode(&mut intent_bytes).unwrap();
                        match self
                            .swarm
                            .behaviour_mut()
                            .intent_broadcaster_gossip
                            .publish(IdentTopic::new(topic), intent_bytes)
                        {
                            Ok(message_id) => {
                                tracing::info!(
                                    "publish intent with message_id {}",
                                    message_id
                                );
                                RpcResponse {
                                    result: String::from(
                                        "Intent sent correctly",
                                    ),
                                }
                            }
                            Err(err) => {
                                tracing::error!(
                                    "error while publishing intent {:?}",
                                    err
                                );
                                RpcResponse {
                                    result: format!(
                                        "Failed to publish_intent {:?}",
                                        err
                                    ),
                                }
                            }
                        }
                    }
                    Ok(false) => RpcResponse {
                        result: String::from("Failed to apply the intent"),
                    },
                    Err(err) => {
                        tracing::error!(
                            "error while applying the intent {:?}",
                            err
                        );
                        RpcResponse {
                            result: format!(
                                "Failed to apply the intent {:?}",
                                err
                            ),
                        }
                    }
                }
            }
            rpc_message::Message::Dkg(dkg_msg) => {
                tracing::debug!(
                    "dkg not yet
        implemented {:?}",
                    dkg_msg
                );
                RpcResponse {
                    result: String::from(
                        "DKG
        application not yet implemented",
                    ),
                }
            }
            rpc_message::Message::Topic(
                crate::proto::services::SubscribeTopicMessage {
                    topic: topic_str,
                },
            ) => {
                let topic = IdentTopic::new(&topic_str);
                match self
                    .swarm
                    .behaviour_mut()
                    .intent_broadcaster_gossip
                    .subscribe(&topic)
                {
                    Ok(true) => {
                        let result = format!("Node subscribed to {}", topic);
                        tracing::info!("{}", result);
                        RpcResponse { result }
                    }
                    Ok(false) => {
                        let result =
                            format!("Node already subscribed to {}", topic);
                        tracing::info!("{}", result);
                        RpcResponse { result }
                    }
                    Err(err) => {
                        let result = format!(
                            "failed to subscribe to {}: {:?}",
                            topic, err
                        );
                        tracing::error!("{}", result);
                        RpcResponse { result }
                    }
                }
            }
        }
    }
}
