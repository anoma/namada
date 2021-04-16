use anoma::protobuf::types::{
    intent_broadcaster_message, Intent, IntentBroadcasterMessage, Tx,
};
use anoma::types::Topic;
use libp2p::gossipsub::{IdentTopic, MessageAcceptance};
use libp2p::identity::Keypair;
use libp2p::identity::Keypair::Ed25519;
use libp2p::PeerId;
use prost::Message;
use thiserror::Error;
use tokio::sync::mpsc::Receiver;

use super::dkg::DKG;
use super::gossip_intent::{self, GossipIntent};
use super::network_behaviour::Behaviour;
use super::types::NetworkEvent;

pub type Swarm = libp2p::Swarm<Behaviour>;

#[derive(Error, Debug)]
pub enum Error {
    #[error("Failed initializing the transport: {0}")]
    TransportError(std::io::Error),
    #[error("Failed initializing the broadcaster intent app: {0}")]
    GossipIntentError(gossip_intent::Error),
}
type Result<T> = std::result::Result<T, Error>;

pub struct P2P {
    pub swarm: Swarm,
    pub gossip_intent: Option<GossipIntent>,
    pub dkg: Option<DKG>,
}

impl P2P {
    pub fn new(
        config: &anoma::config::Gossip,
    ) -> Result<(Self, Receiver<NetworkEvent>, Option<Receiver<Tx>>)> {
        let local_key: Keypair = Ed25519(config.gossiper.key.clone());
        let local_peer_id: PeerId = PeerId::from(local_key.public());

        // Set up an encrypted TCP Transport over the Mplex and Yamux protocols
        let transport = libp2p::build_development_transport(local_key.clone())
            .map_err(Error::TransportError)?;

        let (gossipsub, network_event_receiver) = Behaviour::new(local_key);
        let swarm = Swarm::new(transport, gossipsub, local_peer_id);

        let (gossip_intent, matchmaker_event_receiver) =
            if let Some(gossip_intent_conf) = &config.intent_gossip {
                let (gossip_intent, matchmaker_event_receiver) =
                    GossipIntent::new(&gossip_intent_conf)
                        .map_err(Error::GossipIntentError)?;
                (Some(gossip_intent), matchmaker_event_receiver)
            } else {
                (None, None)
            };

        let dkg = if config.topics.contains(&Topic::Dkg) {
            Some(DKG::new())
        } else {
            None
        };
        let mut p2p = Self {
            swarm,
            gossip_intent,
            dkg,
            // ledger,
        };
        p2p.prepare(&config).expect("gossip prepraration failed");

        Ok((p2p, network_event_receiver, matchmaker_event_receiver))
    }

    pub fn prepare(&mut self, config: &anoma::config::Gossip) -> Result<()> {
        for topic in &config.topics {
            let topic = IdentTopic::new(topic.to_string());
            self.swarm.gossipsub.subscribe(&topic).unwrap();
        }

        // Listen on given address
        Swarm::listen_on(&mut self.swarm, config.address.clone()).unwrap();

        // Reach out to another node if specified
        for to_dial in &config.peers {
            match Swarm::dial_addr(&mut self.swarm, to_dial.clone()) {
                Ok(_) => log::info!("Dialed {:?}", to_dial.clone()),
                Err(e) => {
                    log::debug!("Dial {:?} failed: {:?}", to_dial.clone(), e)
                }
            }
        }
        Ok(())
    }

    pub async fn handle_rpc_event(&mut self, intent: Intent) {
        if let Some(gossip_intent) = &mut self.gossip_intent {
            if gossip_intent
                .apply_intent(intent.clone())
                .await
                .expect("failed to apply intent")
            {
                let mut tix_bytes = vec![];
                intent.encode(&mut tix_bytes).unwrap();
                let _message_id = self.swarm.gossipsub.publish(
                    IdentTopic::new(Topic::Intent.to_string()),
                    tix_bytes,
                );
            }
        }
    }

    // pub async fn handle_matchmaker_event(&mut self, event: Option<Tx>) {
    //     if let Some(tx) = event {
    //         println!("sending {:?} from matchmaker", tx);
    //         let ledger_addr =
    //             self.ledger.clone().expect("missing ledger address");
    //         let mut tx_bytes = vec![];
    //         tx.encode(&mut tx_bytes).unwrap();
    //         println!("sending bytes {:?} from matchmaker", tx_bytes);
    //         println!("bytes len {:?}", tx_bytes.len());
    //         let client =
    // HttpClient::new(ledger_addr.parse().unwrap()).unwrap();         let
    // _response = client.broadcast_tx_commit(tx_bytes.into()).await;     }
    // }

    pub async fn handle_network_event(&mut self, event: NetworkEvent) {
        match event {
            NetworkEvent::Message(msg) if msg.topic == Topic::Intent => {
                if let Some(gossip_intent) = &mut self.gossip_intent {
                    let validity = match gossip_intent.parse_raw_msg(&msg.data)
                    {
                        Ok(IntentBroadcasterMessage {
                            message:
                                Some(intent_broadcaster_message::Message::Intent(
                                    intent,
                                )),
                        }) => match gossip_intent.apply_intent(intent).await {
                            Ok(true) => MessageAcceptance::Accept,
                            Ok(false) => MessageAcceptance::Reject,
                            Err(e) => {
                                log::error!(
                                    "Error while trying to apply an intent: {}",
                                    e
                                );
                                MessageAcceptance::Ignore
                            }
                        },
                        Ok(IntentBroadcasterMessage {
                            message:
                                Some(intent_broadcaster_message::Message::Filter(
                                    filter,
                                )),
                        }) => {
                            match gossip_intent.add_filter(filter).await {
                                // Never propagate filter, because node are
                                // only interested on filter of connected
                                // node
                                Ok(true) => MessageAcceptance::Ignore,
                                Ok(false) => MessageAcceptance::Reject,
                                Err(e) => {
                                    log::error!(
                                        "Error while trying to add a filter: \
                                         {}",
                                        e
                                    );
                                    MessageAcceptance::Ignore
                                }
                            }
                        }
                        Ok(..) => MessageAcceptance::Reject,
                        Err(gossip_intent::Error::DecodeError(..)) => {
                            MessageAcceptance::Reject
                        }
                        Err(gossip_intent::Error::PublicFilterSize(_)) => {
                            MessageAcceptance::Reject
                        }
                        Err(gossip_intent::Error::FilterError(_)) => {
                            MessageAcceptance::Reject
                        }
                        Err(gossip_intent::Error::FileError(_)) => {
                            MessageAcceptance::Ignore
                        }
                    };
                    self.swarm
                        .gossipsub
                        .report_message_validation_result(
                            &msg.message_id,
                            &msg.peer,
                            validity,
                        )
                        .expect("Failed to validate the message ");
                } else {
                    self.swarm
                        .gossipsub
                        .report_message_validation_result(
                            &msg.message_id,
                            &msg.peer,
                            MessageAcceptance::Ignore,
                        )
                        .expect(
                            "No application activated in this node, all \
                             messages are ignore",
                        );
                }
            }
            NetworkEvent::Message(msg) => {
                panic!("{:?} not implemented", msg.topic)
            }
        }
    }
}
