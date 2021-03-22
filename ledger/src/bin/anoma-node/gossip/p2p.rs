use anoma::bookkeeper::Bookkeeper;
use anoma::protobuf::types::IntentMessage;
use libp2p::gossipsub::{IdentTopic as Topic, MessageAcceptance};
use libp2p::identity::Keypair;
use libp2p::identity::Keypair::Ed25519;
use libp2p::PeerId;
use prost::Message;
use serde::de::Expected;
use tokio::sync::mpsc::Receiver;

use super::dkg::DKG;
use super::network_behaviour::Behaviour;
use super::orderbook::{self, Orderbook};
use super::types::NetworkEvent;
use super::{config::NetworkConfig, matchmaker::Matchmaker};

pub type Swarm = libp2p::Swarm<Behaviour>;

#[derive(Debug)]
pub enum Error {
    TransportError(std::io::Error),
}
type Result<T> = std::result::Result<T, Error>;

pub struct P2P {
    pub swarm: Swarm,
    pub orderbook: Option<Orderbook>,
    pub dkg: Option<DKG>,
    pub matchmaker: Option<Matchmaker>,
}

impl P2P {
    pub fn new(
        bookkeeper: Bookkeeper,
        orderbook: bool,
        dkg: bool,
        matchmaker: bool,
    ) -> Result<(Self, Receiver<NetworkEvent>)> {
        let local_key: Keypair = Ed25519(bookkeeper.key);
        let local_peer_id: PeerId = PeerId::from(local_key.public());

        // Set up an encrypted TCP Transport over the Mplex and Yamux protocols
        let transport = libp2p::build_development_transport(local_key.clone())
            .map_err(Error::TransportError)?;

        let (gossipsub, network_event_receiver) = Behaviour::new(local_key);
        let swarm = Swarm::new(transport, gossipsub, local_peer_id);
        let orderbook = if orderbook {
            Some(Orderbook::new(matchmaker))
        } else {
            None
        };

        let matchmaker = if matchmaker {
            Some(Matchmaker::new())
        } else {
            None
        };

        let dkg = if dkg { Some(DKG::new()) } else { None };

        Ok((
            Self {
                swarm,
                orderbook,
                dkg,
                matchmaker,
            },
            network_event_receiver,
        ))
    }

    pub fn prepare(&mut self, network_config: &NetworkConfig) {
        if network_config.gossip.orderbook {
            let topic = Topic::from(super::types::Topic::Orderbook);
            self.swarm.gossipsub.subscribe(&topic).unwrap();
        }

        if network_config.gossip.dkg {
            let topic = Topic::from(super::types::Topic::Dkg);
            self.swarm.gossipsub.subscribe(&topic).unwrap();
        }

        // Listen on given address
        Swarm::listen_on(
            &mut self.swarm,
            network_config.local_address.parse().unwrap(),
        )
        .unwrap();

        // Reach out to another node if specified
        for to_dial in &network_config.peers {
            let dialing = to_dial.clone();
            match to_dial.parse() {
                Ok(to_dial) => match Swarm::dial_addr(&mut self.swarm, to_dial)
                {
                    Ok(_) => println!("Dialed {:?}", dialing),
                    Err(e) => {
                        println!("Dial {:?} failed: {:?}", dialing, e)
                    }
                },
                Err(err) => {
                    println!("Failed to parse address to dial: {:?}", err)
                }
            }
        }
    }

    pub fn handle_rpc_event(&mut self, event: Option<IntentMessage>) {
        if let Some(event) = event {
            println!("received {:?} from a client", event);
            if let IntentMessage { intent } = event {
                // if orderbook_node.apply(&i){
                let mut tix_bytes = vec![];
                intent.encode(&mut tix_bytes).unwrap();
                let _message_id = self.swarm.gossipsub.publish(
                    Topic::from(super::types::Topic::Orderbook),
                    tix_bytes,
                );
            }
        }
    }

    pub fn handle_network_event(&mut self, event: Option<NetworkEvent>) {
        if let Some(event) = event {
            println!("received {:?} from the network", event);
            match event {
                NetworkEvent::Message(msg)
                    if msg.topic == super::types::Topic::Orderbook =>
                {
                    if let Some(orderbook) = &mut self.orderbook {
                        let validity = match orderbook.apply(&msg.data) {
                            orderbook::Result::Ok(true) => {
                                MessageAcceptance::Accept
                            }
                            orderbook::Result::Ok(false) => {
                                MessageAcceptance::Ignore
                            }
                            orderbook::Result::Err(
                                orderbook::OrderbookError::DecodeError(..),
                            ) => MessageAcceptance::Reject,
                            _ => MessageAcceptance::Ignore,
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
                            .expect("Failed to validate the message ");
                    }
                }
                NetworkEvent::Message(msg) => {
                    panic!("{:?} not implemented", msg.topic)
                }
            }
        }
    }
}
