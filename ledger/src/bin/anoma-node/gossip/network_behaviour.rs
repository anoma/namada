use std::collections::HashSet;
use std::time::Duration;

use libp2p::gossipsub::subscription_filter::WhitelistSubscriptionFilter;
use libp2p::gossipsub::{
    self, GossipsubEvent, GossipsubMessage, IdentTopic, IdentityTransform,
    MessageAuthenticity, MessageId, TopicHash, ValidationMode,
};
use libp2p::identity::Keypair;
use libp2p::swarm::NetworkBehaviourEventProcess;
use libp2p::NetworkBehaviour;
use tokio::sync::mpsc::{channel, Receiver, Sender};
use super::gossip_intent::types::IntentBroadcasterEvent;

pub type SubscriptionFilter = WhitelistSubscriptionFilter;
pub type Gossipsub =
    libp2p::gossipsub::Gossipsub<IdentityTransform, SubscriptionFilter>;

impl From<&GossipsubMessage> for IntentBroadcasterEvent {
    fn from(msg: &GossipsubMessage) -> Self {
        Self::Message {
            peer: msg
                .source
                .expect("cannot convert message with anonymous message peer"),
            topic: msg.topic.to_string(),
            data: msg.data.clone(),
        }
    }
}

#[derive(NetworkBehaviour)]
pub struct Behaviour {
    pub intent_broadcaster: Gossipsub,
    // TODO add another gossipsub (or floodsub ?) for dkg message propagation ?
    #[behaviour(ignore)]
    inject_intent_broadcaster_event: Sender<IntentBroadcasterEvent>,
}

pub fn message_id(msg: &GossipsubMessage) -> MessageId {
    let hash = (&IntentBroadcasterEvent::from(msg)).hash();
    MessageId::from(hash)
}

impl Behaviour {
    pub fn new(
        key: Keypair,
        intent_topics: HashSet<String>,
    ) -> (Self, Receiver<IntentBroadcasterEvent>) {
        // Set a custom gossipsub
        let gossipsub_config = gossipsub::GossipsubConfigBuilder::default()
            .protocol_id_prefix("intent_broadcaster")
            .heartbeat_interval(Duration::from_secs(1))
            .validation_mode(ValidationMode::Strict)
            .message_id_fn(message_id)
            .validate_messages()
            .build()
            .expect("Valid config");

        let filter = WhitelistSubscriptionFilter(
            intent_topics
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

        let (inject_event, rx) = channel::<IntentBroadcasterEvent>(100);
        (
            Self {
                intent_broadcaster: gossipsub,
                inject_intent_broadcaster_event: inject_event,
            },
            rx,
        )
    }
}

impl NetworkBehaviourEventProcess<GossipsubEvent> for Behaviour {
    // Called when `gossipsub` produces an event.
    fn inject_event(&mut self, event: GossipsubEvent) {
        if let GossipsubEvent::Message { message, .. } = event {
            self.inject_intent_broadcaster_event
                .try_send(IntentBroadcasterEvent::from(&message))
                .unwrap();
        }
    }
}
