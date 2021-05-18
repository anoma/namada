use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};
use std::time::Duration;

use anoma::proto::types::{
    intent_broadcaster_message, IntentBroadcasterMessage,
};
use anoma::types::MatchmakerMessage;
use libp2p::gossipsub::subscription_filter::{
    TopicSubscriptionFilter, WhitelistSubscriptionFilter,
};
use libp2p::gossipsub::{
    self, GossipsubEvent, GossipsubMessage, IdentTopic, IdentityTransform,
    MessageAcceptance, MessageAuthenticity, MessageId, TopicHash,
    ValidationMode,
};
use libp2p::identity::Keypair;
use libp2p::mdns::{Mdns, MdnsConfig, MdnsEvent};
use libp2p::swarm::{NetworkBehaviour, NetworkBehaviourEventProcess};
use libp2p::{NetworkBehaviour, PeerId};
use regex::Regex;
use thiserror::Error;
use tokio::sync::mpsc::Receiver;

use super::intent_broadcaster;

#[derive(Error, Debug)]
pub enum Error {
    #[error("Failed to subscribe")]
    FailedSubscribtion(libp2p::gossipsub::error::SubscriptionError),
    #[error("Failed initializing the intent broadcaster app: {0}")]
    GossipIntentError(intent_broadcaster::Error),
    #[error("Failed initializing the topic filter: {0}")]
    Filter(String),
    #[error("Failed initializing the gossip network: {0}")]
    GossipConfig(String),
    #[error("Failed initializing mdns: {0}")]
    Mdns(std::io::Error),
}

pub type Result<T> = std::result::Result<T, Error>;

pub type Gossipsub = libp2p::gossipsub::Gossipsub<
    IdentityTransform,
    IntentBroadcasterSubscriptionFilter,
>;

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
    pub intent_broadcaster_gossip: libp2p::gossipsub::Gossipsub<
        IdentityTransform,
        IntentBroadcasterSubscriptionFilter,
    >,
    local_discovery: Mdns,
    // TODO add another gossipsub (or floodsub ?) for dkg message propagation ?
    #[behaviour(ignore)]
    pub intent_broadcaster_app: intent_broadcaster::GossipIntent,
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
    ) -> Result<(Self, Option<Receiver<MatchmakerMessage>>)> {
        // Set a custom gossipsub
        let gossipsub_config = gossipsub::GossipsubConfigBuilder::default()
            .protocol_id_prefix("intent_broadcaster")
            .heartbeat_interval(Duration::from_secs(1))
            .validation_mode(ValidationMode::Strict)
            .message_id_fn(message_id)
            .validate_messages()
            .mesh_outbound_min(1)
            .mesh_n_low(2)
            .mesh_n(3)
            .mesh_n_high(6)
            .build()
            .map_err(|s| Error::GossipConfig(s.to_string()))?;

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

        let mut intent_broadcaster_gossip: Gossipsub =
            Gossipsub::new_with_subscription_filter(
                MessageAuthenticity::Signed(key),
                gossipsub_config,
                filter,
            )
            .map_err(|s| Error::Filter(s.to_string()))?;

        let (intent_broadcaster_app, matchmaker_event_receiver) =
            intent_broadcaster::GossipIntent::new(&config)
                .map_err(Error::GossipIntentError)?;

        config
            .topics
            .iter()
            .try_for_each(|topic| {
                intent_broadcaster_gossip
                    .subscribe(&IdentTopic::new(topic))
                    .map_err(Error::FailedSubscribtion)
                    // it returns bool signifying if it was already subscribed.
                    // discard because it can't be false as the config.topics is
                    // a hash set
                    .map(|_| ())
            })
            .expect("failed to subscribe to topic");

        let local_discovery = {
            let rt = tokio::runtime::Runtime::new().unwrap();
            rt.block_on(Mdns::new(MdnsConfig::default()))
                .map_err(Error::Mdns)?
        };
        Ok((
            Self {
                intent_broadcaster_gossip,
                local_discovery,
                intent_broadcaster_app,
            },
            matchmaker_event_receiver,
        ))
    }

    fn handle_intent(
        &mut self,
        intent: anoma::proto::types::Intent,
    ) -> MessageAcceptance {
        match self.intent_broadcaster_app.apply_intent(intent) {
            Ok(true) => MessageAcceptance::Accept,
            Ok(false) => MessageAcceptance::Reject,
            Err(e) => {
                tracing::error!("Error while trying to apply an intent: {}", e);
                match e {
                    intent_broadcaster::Error::DecodeError(_) => {
                        panic!("can't happens, because intent already decoded")
                    }
                    intent_broadcaster::Error::MatchmakerInit(err)
                    | intent_broadcaster::Error::Matchmaker(err) => {
                        tracing::info!(
                            "error while running the matchmaker: {:?}",
                            err
                        );
                        MessageAcceptance::Ignore
                    }
                }
            }
        }
    }

    fn handle_raw_intent(
        &mut self,
        data: impl AsRef<[u8]>,
    ) -> MessageAcceptance {
        match self.intent_broadcaster_app.parse_raw_msg(data) {
            Ok(IntentBroadcasterMessage {
                msg: Some(intent_broadcaster_message::Msg::Intent(intent)),
            }) => self.handle_intent(intent),
            Ok(IntentBroadcasterMessage { msg: None }) => {
                tracing::info!("Empty message, rejecting it");
                MessageAcceptance::Reject
            }
            Err(err) => match err {
                intent_broadcaster::Error::DecodeError(..) => {
                    tracing::info!(
                        "error while decoding the intent: {:?}",
                        err
                    );
                    MessageAcceptance::Reject
                }
                intent_broadcaster::Error::MatchmakerInit(..)
                | intent_broadcaster::Error::Matchmaker(..) => {
                    panic!("can't happens, because intent already decoded")
                }
            },
        }
    }
}

impl NetworkBehaviourEventProcess<GossipsubEvent> for Behaviour {
    fn inject_event(&mut self, event: GossipsubEvent) {
        tracing::info!("received : {:?}", event);
        match event {
            GossipsubEvent::Message {
                message,
                propagation_source,
                message_id,
            } => {
                let validity = self.handle_raw_intent(message.data);
                self.intent_broadcaster_gossip
                    .report_message_validation_result(
                        &message_id,
                        &propagation_source,
                        validity,
                    )
                    .expect("Failed to validate the message ");
            }
            GossipsubEvent::Subscribed { peer_id: _, topic } => {
                self.intent_broadcaster_gossip
                    .subscribe(&IdentTopic::new(topic.into_string()))
                    .map_err(Error::FailedSubscribtion)
                    .unwrap_or_else(|e| {
                        tracing::error!("failed to subscribe: {:?}", e);
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

impl NetworkBehaviourEventProcess<MdnsEvent> for Behaviour {
    // Called when `mdns` produces an event.
    fn inject_event(&mut self, event: MdnsEvent) {
        match event {
            MdnsEvent::Discovered(list) => {
                for (peer, _addr) in list {
                    // tracing::info!("discovering peer {} : {} ", peer, addr);
                    self.intent_broadcaster_gossip.inject_connected(&peer);
                }
            }
            MdnsEvent::Expired(list) => {
                for (peer, _addr) in list {
                    if self.local_discovery.has_node(&peer) {
                        self.intent_broadcaster_gossip
                            .inject_disconnected(&peer);
                    }
                }
            }
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
