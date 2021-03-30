use libp2p::gossipsub::{IdentTopic, MessageId, TopicHash};
use libp2p::PeerId;

#[derive(Debug, PartialEq)]
pub enum Topic {
    Dkg,
    Orderbook,
}

impl From<Topic> for IdentTopic {
    fn from(topic: Topic) -> Self {
        IdentTopic::new(topic.to_string())
    }
}
impl From<Topic> for TopicHash {
    fn from(topic: Topic) -> Self {
        IdentTopic::from(topic).hash()
    }
}
impl From<&TopicHash> for Topic {
    fn from(topic_hash: &TopicHash) -> Self {
        if topic_hash == &TopicHash::from(Topic::Dkg) {
            Topic::Dkg
        } else if topic_hash == &TopicHash::from(Topic::Orderbook) {
            Topic::Orderbook
        } else {
            panic!("topic_hash does not correspond to any topic of interest")
        }
    }
}

impl std::fmt::Display for Topic {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}",
            match self {
                Self::Dkg => "dkg",
                Self::Orderbook => "orderbook",
            }
        )
    }
}

#[derive(Debug)]
pub struct InternMessage {
    pub peer: PeerId,
    pub topic: Topic,
    pub message_id: MessageId,
    pub data: Vec<u8>,
}

#[derive(Debug)]
pub enum NetworkEvent {
    Message(InternMessage),
}
