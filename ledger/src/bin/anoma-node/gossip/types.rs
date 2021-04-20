use libp2p::gossipsub::MessageId;
use libp2p::PeerId;

#[derive(Debug)]
pub enum NetworkEvent {
    Message {
        peer: PeerId,
        topic: String,
        message_id: MessageId,
        data: Vec<u8>,
    },
}
