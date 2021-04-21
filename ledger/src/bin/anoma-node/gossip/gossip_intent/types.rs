use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};

use libp2p::gossipsub::MessageId;
use libp2p::PeerId;

#[derive(Debug, Hash)]
pub enum IntentBroadcasterEvent {
    Message {
        peer: PeerId,
        topic: String,
        data: Vec<u8>,
    },
}

impl IntentBroadcasterEvent {
    pub fn hash(&self) -> String {
        let IntentBroadcasterEvent::Message { data, .. } = self;
        let mut hasher = DefaultHasher::new();
        data.hash(&mut hasher);
        hasher.finish().to_string()
    }

    pub fn message_id(&self) -> MessageId {
        let hash = self.hash();
        MessageId::from(hash)
    }
}
