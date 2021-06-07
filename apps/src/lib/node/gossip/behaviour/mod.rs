mod discovery;
use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};
use std::time::Duration;

use libp2p::gossipsub::subscription_filter::regex::RegexSubscriptionFilter;
use libp2p::gossipsub::subscription_filter::{
    TopicSubscriptionFilter, WhitelistSubscriptionFilter,
};
use libp2p::gossipsub::{
    self, GossipsubEvent, GossipsubMessage, IdentTopic, IdentityTransform,
    MessageAcceptance, MessageAuthenticity, MessageId, TopicHash,
    ValidationMode,
};
use libp2p::identity::Keypair;
use libp2p::swarm::toggle::Toggle;
use libp2p::swarm::NetworkBehaviourEventProcess;
use libp2p::{NetworkBehaviour, PeerId};
use thiserror::Error;
use tokio::sync::mpsc::Receiver;

use self::discovery::DiscoveryEvent;
use super::intent_broadcaster;
use crate::node::gossip::behaviour::discovery::{
    DiscoveryBehaviour, DiscoveryConfigBuilder,
};
use crate::proto::types::{
    intent_broadcaster_message, IntentBroadcasterMessage,
};
use crate::types::MatchmakerMessage;

#[derive(Error, Debug)]
pub enum Error {
    #[error("Failed to subscribe")]
    FailedSubscription(libp2p::gossipsub::error::SubscriptionError),
    #[error("Failed initializing the intent broadcaster app: {0}")]
    GossipIntentError(intent_broadcaster::Error),
    #[error("Failed initializing the topic filter: {0}")]
    Filter(String),
    #[error("Failed initializing the gossip behaviour: {0}")]
    GossipConfig(String),
    #[error("Failed on the the discovery behaviour config: {0}")]
    DiscoveryConfig(String),
    #[error("Failed initializing the discovery behaviour: {0}")]
    Discovery(discovery::Error),
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
    RegexFilter(RegexSubscriptionFilter),
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
    discovery: Toggle<discovery::DiscoveryBehaviour>,
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
        config: &crate::config::IntentBroadcaster,
    ) -> Result<(Self, Option<Receiver<MatchmakerMessage>>)> {
        let peer_id = PeerId::from_public_key(key.public());

        // Set a custom gossipsub
        let gossipsub_config = gossipsub::GossipsubConfigBuilder::default()
            .protocol_id_prefix("intent_broadcaster")
            .heartbeat_interval(Duration::from_secs(10))
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
            crate::config::SubscriptionFilter::RegexFilter(regex) => {
                IntentBroadcasterSubscriptionFilter::RegexFilter(
                    RegexSubscriptionFilter(regex.clone()),
                )
            }
            crate::config::SubscriptionFilter::WhitelistFilter(topics) => {
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
                    .map_err(Error::FailedSubscription)
                    // it returns bool signifying if it was already subscribed.
                    // discard because it can't be false as the config.topics is
                    // a hash set
                    .map(|_| ())
            })
            .expect("failed to subscribe to topic");

        // TODO: check silent fail if not bootstrap_peers is not multiaddr
        let discovery_opt = if let Some(dis_config) = &config.discover_peer {
            let discovery_config = DiscoveryConfigBuilder::default()
                .with_user_defined(dis_config.bootstrap_peers.clone())
                .discovery_limit(dis_config.max_discovery_peers)
                .with_kademlia(dis_config.kademlia)
                .with_mdns(dis_config.mdns)
                .use_kademlia_disjoint_query_paths(true)
                .build()
                .map_err(|s| Error::DiscoveryConfig(s.to_string()))?;

            Some(
                DiscoveryBehaviour::new(peer_id, discovery_config)
                    .map_err(Error::Discovery)?,
            )
        } else {
            None
        };
        // println!("{:?}", discovery_opt)
        tracing::debug!("discovery: {:?}", discovery_opt.is_some());
        Ok((
            Self {
                intent_broadcaster_gossip,
                discovery: discovery_opt.into(),
                intent_broadcaster_app,
            },
            matchmaker_event_receiver,
        ))
    }

    fn handle_intent(
        &mut self,
        intent: crate::proto::types::Intent,
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
                    .map_err(Error::FailedSubscription)
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

impl NetworkBehaviourEventProcess<DiscoveryEvent> for Behaviour {
    fn inject_event(&mut self, event: DiscoveryEvent) {
        // TODO: nothing to do for the moment, everything should be taking care
        // of by the behaviour
        match event {
            DiscoveryEvent::Connected(p) => {
                tracing::debug!("connected to {}", p);
            }
            DiscoveryEvent::Disconnected(p) => {
                tracing::debug!("disconnected to {}", p);
            }
        }
    }
}
