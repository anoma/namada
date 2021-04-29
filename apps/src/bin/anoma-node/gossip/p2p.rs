use anoma::protobuf::services::rpc_message;
use anoma::protobuf::types::Tx;
use libp2p::gossipsub::IdentTopic;
use libp2p::identity::Keypair;
use libp2p::identity::Keypair::Ed25519;
use libp2p::PeerId;
use prost::Message;
use thiserror::Error;
use tokio::sync::mpsc::Receiver;

use super::network_behaviour::Behaviour;

pub type Swarm = libp2p::Swarm<Behaviour>;

#[derive(Error, Debug)]
pub enum Error {
    #[error("Failed initializing the transport: {0}")]
    TransportError(std::io::Error),
    #[error("Failed to subscribe")]
    FailedSubscribtion(libp2p::gossipsub::error::SubscriptionError),
    #[error("Failed to subscribe")]
    Behavior(super::network_behaviour::Error)
}
type Result<T> = std::result::Result<T, Error>;

pub struct P2P {
    pub swarm: Swarm,
}

impl P2P {
    pub fn new(
        config: &anoma::config::IntentBroadcaster,
    ) -> Result<(Self, Option<Receiver<Tx>>)>
    {
        let local_key: Keypair = Ed25519(config.gossiper.key.clone());
        let local_peer_id: PeerId = PeerId::from(local_key.public());

        // Set up an encrypted TCP Transport over the Mplex and Yamux protocols
        let transport = libp2p::build_development_transport(local_key.clone())
            .map_err(Error::TransportError)?;

        let (gossipsub, matchmaker_event_receiver) = Behaviour::new(local_key, config).map_err(Error::Behavior)?;
        let swarm = Swarm::new(transport, gossipsub, local_peer_id);

        let mut p2p = Self {
            swarm,
        };

        config
            .topics
            .iter()
            .try_for_each(|topic| {
                p2p.swarm
                    .intent_broadcaster_gossip
                    .subscribe(&IdentTopic::new(topic))
                    .map_err(Error::FailedSubscribtion)
                    // it returns bool of if it were already subscribed. discard
                    // because and can't happens because it's a set
                    .map(|_| ())
            })
            .expect("failed to subscribe to topic");

        Swarm::listen_on(&mut p2p.swarm, config.address.clone()).unwrap();

        for to_dial in &config.peers {
            match Swarm::dial_addr(&mut p2p.swarm, to_dial.clone()) {
                Ok(_) => log::info!("Dialed {:?}", to_dial.clone()),
                Err(e) => {
                    log::debug!("Dial {:?} failed: {:?}", to_dial.clone(), e)
                }
            }
        }
        Ok((p2p, matchmaker_event_receiver))
    }

    pub async fn handle_rpc_event(&mut self, event: rpc_message::Message) {
        match event {
            rpc_message::Message::Intent(
                anoma::protobuf::services::IntentMesage {
                    intent: None,
                    topic,
                },
            ) => {
                log::error!("rpc intent command for topic {} is empty", topic)
            }
            rpc_message::Message::Intent(
                anoma::protobuf::services::IntentMesage {
                    intent: Some(intent),
                    topic,
                },
            ) => {
                if self.swarm.intent_broadcaster_app
                    .apply_intent(intent.clone())
                    .expect("failed to apply intent")
                {
                    let mut intent_bytes = vec![];
                    intent.encode(&mut intent_bytes).unwrap();
                    let _message_id = self.swarm
                        .intent_broadcaster_gossip
                        .publish(IdentTopic::new(topic), intent_bytes);
                }
            }

            rpc_message::Message::Dkg(_dkg_msg) => {
                todo!()
            }
            rpc_message::Message::Topic(
                anoma::protobuf::services::SubscribeTopicMessage {
                    topic: topic_str,
                },
            ) => {
                let topic = IdentTopic::new(&topic_str);
                self.swarm
                    .intent_broadcaster_gossip
                    .subscribe(&topic)
                    .unwrap_or_else(|_| {
                        panic!("failed to subscribe to topic {:?}", topic)
                    });
            }
        };
    }
}
