use libp2p::gossipsub::MessageId;
use libp2p::PeerId;

#[derive(Debug, PartialEq)]
pub enum Topic {
    Dkg,
    Orderbook,
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
