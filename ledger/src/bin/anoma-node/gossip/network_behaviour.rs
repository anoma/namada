use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};
use std::time::Duration;

use libp2p::gossipsub::{
    self, Gossipsub, GossipsubEvent, GossipsubMessage, IdentTopic,
    MessageAuthenticity, MessageId, TopicHash, ValidationMode,
};
use libp2p::identity::Keypair;
use libp2p::swarm::NetworkBehaviourEventProcess;
use libp2p::NetworkBehaviour;
use tokio::sync::mpsc::{channel, Receiver, Sender};

use super::types::{self, NetworkEvent};

impl From<GossipsubMessage> for types::NetworkEvent {
    fn from(msg: GossipsubMessage) -> Self {
        Self::Message(types::InternMessage {
            peer: msg
                .source
                .expect("cannot convert message with anonymous message peer"),
            topic: topic_of(&msg.topic),
            message_id: message_id(&msg),
            data: msg.data,
        })
    }
}

pub fn topic_of(topic_hash: &TopicHash) -> anoma::types::Topic {
    if topic_hash
        == &IdentTopic::new(anoma::types::Topic::Dkg.to_string()).hash()
    {
        anoma::types::Topic::Dkg
    } else if topic_hash
        == &IdentTopic::new(anoma::types::Topic::Orderbook.to_string()).hash()
    {
        anoma::types::Topic::Orderbook
    } else {
        panic!("topic_hash does not correspond to any topic of interest")
    }
}

#[derive(NetworkBehaviour)]
pub struct Behaviour {
    pub gossipsub: Gossipsub,
    #[behaviour(ignore)]
    inject_event: Sender<NetworkEvent>,
}

fn message_id(message: &GossipsubMessage) -> MessageId {
    let mut s = DefaultHasher::new();
    message.data.hash(&mut s);
    MessageId::from(s.finish().to_string())
}

impl Behaviour {
    pub fn new(key: Keypair) -> (Self, Receiver<NetworkEvent>) {
        // To content-address message, we can take the hash of message and use
        // it as an ID.

        // Set a custom gossipsub
        let gossipsub_config = gossipsub::GossipsubConfigBuilder::default()
            .protocol_id_prefix("orderbook")
            .heartbeat_interval(Duration::from_secs(10))
            .validation_mode(ValidationMode::Strict)
            .message_id_fn(message_id)
            .validate_messages()
            .build()
            .expect("Valid config");

        let gossipsub: Gossipsub =
            Gossipsub::new(MessageAuthenticity::Signed(key), gossipsub_config)
                .expect("Correct configuration");

        let (inject_event, rx) = channel::<NetworkEvent>(100);
        (
            Self {
                gossipsub,
                inject_event,
            },
            rx,
        )
    }
}

impl NetworkBehaviourEventProcess<GossipsubEvent> for Behaviour {
    // Called when `gossipsub` produces an event.
    fn inject_event(&mut self, event: GossipsubEvent) {
        if let GossipsubEvent::Message { message, .. } = event {
            self.inject_event
                .try_send(NetworkEvent::from(message))
                .unwrap();
        }
    }
}
