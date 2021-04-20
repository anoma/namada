use std::collections::hash_map::DefaultHasher;
use std::collections::HashSet;
use std::hash::{Hash, Hasher};
use std::time::Duration;

use libp2p::gossipsub::subscription_filter::{
    TopicSubscriptionFilter, WhitelistSubscriptionFilter,
};
use libp2p::gossipsub::{
    self, DataTransform, GossipsubEvent, GossipsubMessage, IdentTopic,
    IdentityTransform, MessageAuthenticity, MessageId, TopicHash,
    ValidationMode,
};
use libp2p::identity::Keypair;
use libp2p::swarm::NetworkBehaviourEventProcess;
use libp2p::NetworkBehaviour;
use tokio::sync::mpsc::{channel, Receiver, Sender};

use super::types::{self, NetworkEvent};

pub type SubscriptionFilter = WhitelistSubscriptionFilter;
pub type Gossipsub =
    libp2p::gossipsub::Gossipsub<IdentityTransform, SubscriptionFilter>;

impl From<GossipsubMessage> for types::NetworkEvent {
    fn from(msg: GossipsubMessage) -> Self {
        Self::Message {
            peer: msg
                .source
                .expect("cannot convert message with anonymous message peer"),
            topic: msg.topic.to_string(),
            message_id: message_id(&msg),
            data: msg.data,
        }
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
    pub fn new(
        key: Keypair,
        topics: HashSet<String>,
    ) -> (Self, Receiver<NetworkEvent>) {
        // To content-address message, we can take the hash of message and use
        // it as an ID.

        // Set a custom gossipsub
        let gossipsub_config = gossipsub::GossipsubConfigBuilder::default()
            .protocol_id_prefix("gossip_intent")
            .heartbeat_interval(Duration::from_secs(1))
            .validation_mode(ValidationMode::Strict)
            .message_id_fn(message_id)
            .validate_messages()
            .build()
            .expect("Valid config");

        let filter = WhitelistSubscriptionFilter(
            topics
                .iter()
                .map(|topic| TopicHash::from(IdentTopic::new(topic)))
                .collect(),
        );

        let gossipsub: Gossipsub = Gossipsub::new_with_subscription_filter(
            MessageAuthenticity::Signed(key),
            gossipsub_config,
            filter,
        )
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
