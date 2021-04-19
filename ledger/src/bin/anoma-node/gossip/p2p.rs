use anoma::bookkeeper::Bookkeeper;
use anoma::config::Config;
use anoma::protobuf::types::{IntentMessage, Tx};
use anoma::types::Topic;
use libp2p::gossipsub::{IdentTopic, MessageAcceptance};
use libp2p::identity::Keypair;
use libp2p::identity::Keypair::Ed25519;
use libp2p::PeerId;
use prost::Message;
use thiserror::Error;
use tokio::sync::mpsc::Receiver;

use super::dkg::DKG;
use super::network_behaviour::Behaviour;
use super::orderbook::{self, Orderbook};
use super::types::NetworkEvent;

pub type Swarm = libp2p::Swarm<Behaviour>;

#[derive(Error, Debug)]
pub enum Error {
    #[error("Failed initializing the transport: {0}")]
    TransportError(std::io::Error),
}
type Result<T> = std::result::Result<T, Error>;

pub struct P2P {
    pub swarm: Swarm,
    pub orderbook: Option<Orderbook>,
    pub dkg: Option<DKG>,
    pub ledger: Option<String>,
}

impl P2P {
    pub fn new(
        bookkeeper: Bookkeeper,
        orderbook: bool,
        dkg: bool,
        matchmaker: Option<String>,
        tx_template: Option<String>,
        ledger: Option<String>,
    ) -> Result<(Self, Receiver<NetworkEvent>, Option<Receiver<Tx>>)> {
        let local_key: Keypair = Ed25519(bookkeeper.key);
        let local_peer_id: PeerId = PeerId::from(local_key.public());

        // Set up an encrypted TCP Transport over the Mplex and Yamux protocols
        let transport = libp2p::build_development_transport(local_key.clone())
            .map_err(Error::TransportError)?;

        let (gossipsub, network_event_receiver) = Behaviour::new(local_key);
        let swarm = Swarm::new(transport, gossipsub, local_peer_id);

        let (orderbook, matchmaker_event_receiver) = if orderbook {
            let (orderbook, matchmaker_event_receiver) =
                Orderbook::new(matchmaker, tx_template);
            (Some(orderbook), matchmaker_event_receiver)
        } else {
            (None, None)
        };

        let dkg = if dkg { Some(DKG::new()) } else { None };

        Ok((
            Self {
                swarm,
                orderbook,
                dkg,
                ledger,
            },
            network_event_receiver,
            matchmaker_event_receiver,
        ))
    }

    pub fn prepare(&mut self, config: &Config) -> Result<()> {
        for topic in &config.p2p.topics {
            let topic = IdentTopic::new(topic.to_string());
            self.swarm.gossipsub.subscribe(&topic).unwrap();
        }

        // Listen on given address
        Swarm::listen_on(&mut self.swarm, {
            config.p2p.get_address().parse().unwrap()
        })
        .unwrap();

        // Reach out to another node if specified
        for to_dial in &config.p2p.peers {
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
        Ok(())
    }

    pub async fn handle_rpc_event(&mut self, event: IntentMessage) {
        if let (
            IntentMessage {
                intent: Some(intent),
            },
            Some(orderbook),
        ) = (event, &mut self.orderbook)
        {
            if orderbook
                .apply_intent(intent.clone())
                .await
                .expect("failed to apply intent")
            {
                let mut tix_bytes = vec![];
                intent.encode(&mut tix_bytes).unwrap();
                let _message_id = self.swarm.gossipsub.publish(
                    IdentTopic::new(Topic::Orderbook.to_string()),
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
            NetworkEvent::Message(msg) if msg.topic == Topic::Orderbook => {
                if let Some(orderbook) = &mut self.orderbook {
                    let validity =
                        match orderbook.apply_raw_intent(&msg.data).await {
                            orderbook::Result::Ok(true) => {
                                MessageAcceptance::Accept
                            }
                            orderbook::Result::Ok(false) => {
                                MessageAcceptance::Ignore
                            }
                            orderbook::Result::Err(
                                orderbook::OrderbookError::DecodeError(..),
                            ) => MessageAcceptance::Reject,
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
