use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};
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
use libp2p::{NetworkBehaviour, PeerId};
use regex::Regex;
use thiserror::Error;
use tokio::sync::mpsc::{channel, Receiver, Sender};

pub type Gossipsub = libp2p::gossipsub::Gossipsub<
    IdentityTransform,
    IntentBroadcasterSubscriptionFilter,
>;

#[derive(Error, Debug)]
pub enum Error {
    #[error("Failed to send the message through the channel: {0}")]
    FailedToSend(
        tokio::sync::mpsc::error::TrySendError<IntentBroadcasterEvent>,
    ),
    #[error("Failed to subscribe")]
    FailedSubscribtion(libp2p::gossipsub::error::SubscriptionError),
}

// TODO merge type of config and this one ? Maybe not a good idea
pub enum IntentBroadcasterSubscriptionFilter {
    RegexFilter(RegexSubscribtionFilter),
    WhitelistFilter(WhitelistSubscriptionFilter),
}

#[derive(Debug)]
pub struct IntentBroadcasterEvent {
    pub propagation_source: PeerId,
    pub message_id: MessageId,
    pub source: Option<PeerId>,
    pub data: Vec<u8>,
    pub topic: TopicHash,
}

impl From<GossipsubEvent> for IntentBroadcasterEvent {
    // To be used only with Message event
    fn from(event: GossipsubEvent) -> Self {
        if let GossipsubEvent::Message {
            propagation_source,
            message_id,
            message:
                GossipsubMessage {
                    source,
                    data,
                    topic,
                    sequence_number: _,
                },
        } = event
        {
            Self {
                propagation_source,
                message_id,
                source,
                data,
                topic,
            }
        } else {
            panic!("Expected a GossipsubEvent::Message got {:?}", event)
        }
    }
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

pub fn message_id(message: &GossipsubMessage) -> MessageId {
    let mut hasher = DefaultHasher::new();
    message.data.hash(&mut hasher);
    MessageId::from(hasher.finish().to_string())
}

impl Behaviour {
    pub fn new(
        key: Keypair,
        config: &anoma::config::IntentBroadcaster,
    ) -> (Self, Receiver<IntentBroadcasterEvent>) {
        // Set a custom gossipsub
        let gossipsub_config = gossipsub::GossipsubConfigBuilder::default()
            .protocol_id_prefix("intent_broadcaster")
            .heartbeat_interval(Duration::from_secs(10))
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

        let intent_broadcaster: Gossipsub =
            Gossipsub::new_with_subscription_filter(
                MessageAuthenticity::Signed(key),
                gossipsub_config,
                filter,
            )
            .expect("Correct configuration");

        let (inject_intent_broadcaster_event, rx) =
            channel::<IntentBroadcasterEvent>(100);
        (
            Self {
                intent_broadcaster,
                inject_intent_broadcaster_event,
            },
            rx,
        )
    }
}

impl NetworkBehaviourEventProcess<GossipsubEvent> for Behaviour {
    // Called when `gossipsub` produces an event.
    fn inject_event(&mut self, event: GossipsubEvent) {
        match event {
            GossipsubEvent::Message { .. } => self
                .inject_intent_broadcaster_event
                .try_send(IntentBroadcasterEvent::from(event))
                .map_err(Error::FailedToSend)
                .unwrap_or_else(|e| {
                    panic!("failed to send to the channel {}", e)
                }),
            GossipsubEvent::Subscribed { peer_id: _, topic } => {
                self.intent_broadcaster
                    .subscribe(&IdentTopic::new(topic.into_string()))
                    .map_err(Error::FailedSubscribtion)
                    .unwrap_or_else(|e| {
                        log::error!("failed to subscribe: {:}", e);
                        false
                    });
            }
            GossipsubEvent::Unsubscribed {
                peer_id: _,
                topic: _,
            } => {}
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
