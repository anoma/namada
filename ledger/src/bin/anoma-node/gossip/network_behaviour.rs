use std::time::Duration;

use libp2p::gossipsub::subscription_filter::{
    TopicSubscriptionFilter, WhitelistSubscriptionFilter,
};
use libp2p::gossipsub::{
    self, GossipsubEvent, GossipsubMessage, IdentTopic, IdentityTransform,
    MessageAuthenticity, MessageId, TopicHash, ValidationMode,
};
use libp2p::identity::Keypair;
use libp2p::swarm::NetworkBehaviourEventProcess;
use libp2p::NetworkBehaviour;
use regex::Regex;
use tokio::sync::mpsc::{channel, Receiver, Sender};

use super::gossip_intent::types::IntentBroadcasterEvent;

pub type Gossipsub = libp2p::gossipsub::Gossipsub<
    IdentityTransform,
    IntentBroadcasterSubscriptionFilter,
>;

pub enum IntentBroadcasterSubscriptionFilter {
    RegexFilter(RegexSubscribtionFilter),
    WhitelistFilter(WhitelistSubscriptionFilter),
}

impl TopicSubscriptionFilter for IntentBroadcasterSubscriptionFilter {
    fn can_subscribe(&mut self, topic_hash: &TopicHash) -> bool {
        match self {
            IntentBroadcasterSubscriptionFilter::RegexFilter(filter) => {
                filter.can_subscribe(topic_hash)
            }
            IntentBroadcasterSubscriptionFilter::WhitelistFilter(filter) => {
                filter.can_subscribe(topic_hash)
            }
        }
    }
}

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
    pub intent_broadcaster: libp2p::gossipsub::Gossipsub<
        IdentityTransform,
        IntentBroadcasterSubscriptionFilter,
    >,
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
        config: &anoma::config::Gossip,
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

        let filter = match &config.subscription_filter {
            anoma::config::SubscriptionFilter::RegexFilter(regex) => {
                IntentBroadcasterSubscriptionFilter::RegexFilter(
                    RegexSubscribtionFilter(regex.clone()),
                )
            }
            anoma::config::SubscriptionFilter::WhitelistFilter(topics) => {
                IntentBroadcasterSubscriptionFilter::WhitelistFilter(
                    WhitelistSubscriptionFilter(
                        topics
                            .iter()
                            .map(|topic| {
                                TopicHash::from(IdentTopic::new(topic))
                            })
                            .collect(),
                    ),
                )
            }
        };

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

// TODO this is part of libp2p::gossipsub::subscription_filter but it's cannot
// be exported because it's part of a feature "regex-filter" that is not
// exposed. see issue https://github.com/libp2p/rust-libp2p/issues/2055
pub struct RegexSubscribtionFilter(pub Regex);

impl TopicSubscriptionFilter for RegexSubscribtionFilter {
    fn can_subscribe(&mut self, topic_hash: &TopicHash) -> bool {
        self.0.is_match(topic_hash.as_str())
    }
}
