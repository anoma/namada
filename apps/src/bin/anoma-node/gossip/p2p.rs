use anoma::protobuf::services::rpc_message;
use anoma::protobuf::types::{
    intent_broadcaster_message, IntentBroadcasterMessage, Tx,
};
use libp2p::gossipsub::{IdentTopic, MessageAcceptance};
use libp2p::identity::Keypair;
use libp2p::identity::Keypair::Ed25519;
use libp2p::PeerId;
use prost::Message;
use thiserror::Error;
use tokio::sync::mpsc::Receiver;

use super::intent_broadcaster;
use super::network_behaviour::{Behaviour, IntentBroadcasterEvent};

pub type Swarm = libp2p::Swarm<Behaviour>;

#[derive(Error, Debug)]
pub enum Error {
    #[error("Failed initializing the transport: {0}")]
    TransportError(std::io::Error),
    #[error("Failed initializing the broadcaster intent app: {0}")]
    GossipIntentError(intent_broadcaster::Error),
    #[error("Failed to subscribe")]
    FailedSubscribtion(libp2p::gossipsub::error::SubscriptionError),
}
type Result<T> = std::result::Result<T, Error>;

pub struct P2P {
    pub swarm: Swarm,
    pub intent_process: intent_broadcaster::GossipIntent,
}

impl P2P {
    pub fn new(
        config: &anoma::config::IntentBroadcaster,
    ) -> Result<(Self, Receiver<IntentBroadcasterEvent>, Option<Receiver<Tx>>)>
    {
        let local_key: Keypair = Ed25519(config.gossiper.key.clone());
        let local_peer_id: PeerId = PeerId::from(local_key.public());

        // Set up an encrypted TCP Transport over the Mplex and Yamux protocols
        let transport = libp2p::build_development_transport(local_key.clone())
            .map_err(Error::TransportError)?;

        let (gossipsub, network_event_receiver) =
            Behaviour::new(local_key, config);
        let swarm = Swarm::new(transport, gossipsub, local_peer_id);

        let (intent_process, matchmaker_event_receiver) =
            intent_broadcaster::GossipIntent::new(&config)
                .map_err(Error::GossipIntentError)?;
        let mut p2p = Self {
            swarm,
            intent_process,
        };
        p2p.prepare(&config).expect("gossip prepraration failed");

        Ok((p2p, network_event_receiver, matchmaker_event_receiver))
    }

    pub fn prepare(
        &mut self,
        config: &anoma::config::IntentBroadcaster,
    ) -> Result<()> {
        config
            .topics
            .iter()
            .try_for_each(|topic| {
                let topic = IdentTopic::new(topic);
                self.swarm
                    .intent_broadcaster
                    .subscribe(&topic)
                    .map_err(Error::FailedSubscribtion)
                    // it returns bool of if it were already subscribed
                    .map(|_| ())
            })
            .expect("failed to subscribe to topic");

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

    pub async fn handle_rpc_event(&mut self, event: rpc_message::Message) {
        let intent_process = &mut self.intent_process;
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
                if intent_process
                    .apply_intent(intent.clone())
                    .await
                    .expect("failed to apply intent")
                {
                    let mut intent_bytes = vec![];
                    intent.encode(&mut intent_bytes).unwrap();
                    let _message_id = self
                        .swarm
                        .intent_broadcaster
                        .publish(IdentTopic::new(topic), intent_bytes);
                }
            }

            rpc_message::Message::Dkg(_dkg_msg) => {
                panic!("not yet implemented")
            }
            rpc_message::Message::Topic(
                anoma::protobuf::services::SubscribeTopicMessage {
                    topic: topic_str,
                },
            ) => {
                let topic = IdentTopic::new(&topic_str);
                self.swarm
                    .intent_broadcaster
                    .subscribe(&topic)
                    .unwrap_or_else(|_| {
                        panic!("failed to subscribe to topic {:?}", topic)
                    });
            }
        };
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

    pub async fn handle_network_event(
        &mut self,
        IntentBroadcasterEvent {
            propagation_source,
            message_id,
            source: _,
            data,
            topic: _,
        }: IntentBroadcasterEvent,
    ) {
        let intent_process = &mut self.intent_process;
        let validity = match intent_process.parse_raw_msg(data) {
            Ok(IntentBroadcasterMessage {
                msg: Some(intent_broadcaster_message::Msg::Intent(intent)),
            }) => match intent_process.apply_intent(intent).await {
                Ok(true) => MessageAcceptance::Accept,
                Ok(false) => MessageAcceptance::Reject,
                Err(e) => {
                    log::error!("Error while trying to apply an intent: {}", e);
                    MessageAcceptance::Ignore
                }
            },
            Ok(IntentBroadcasterMessage { msg: None })
            | Err(intent_broadcaster::Error::DecodeError(..)) => {
                MessageAcceptance::Reject
            }
            Err(intent_broadcaster::Error::MatchmakerInit(..))
            | Err(intent_broadcaster::Error::Matchmaker(..)) => {
                MessageAcceptance::Ignore
            }
        };
        self.swarm
            .intent_broadcaster
            .report_message_validation_result(
                &message_id,
                &propagation_source,
                validity,
            )
            .expect("Failed to validate the message ");
    }
}
