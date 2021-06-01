use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};

use prost::Message;
use thiserror::Error;

use super::generated::{services, types};

#[derive(Error, Debug)]
pub enum Error {
    #[error("Error decoding a transaction from bytes: {0}")]
    TxDecodingError(prost::DecodeError),
    #[error("Error decoding an IntentGossipMessage from bytes: {0}")]
    IntentDecodingError(prost::DecodeError),
    #[error("Error decoding an DkgGossipMessage from bytes: {0}")]
    DkgDecodingError(prost::DecodeError),
    #[error("Intent is empty")]
    NoIntentError,
    #[error("Dkg is empty")]
    NoDkgError,
}

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Debug)]
pub struct Tx {
    inner: types::Tx,
}

impl Tx {
    pub fn from(tx_bytes: impl AsRef<[u8]>) -> Result<Self> {
        let inner = types::Tx::decode(tx_bytes.as_ref())
            .map_err(Error::TxDecodingError)?;
        Ok(Tx { inner })
    }

    pub fn new(code: Vec<u8>, data: Option<Vec<u8>>) -> Self {
        let inner = types::Tx {
            code,
            data,
            timestamp: Some(std::time::SystemTime::now().into()),
        };
        Tx { inner }
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = vec![];
        self.inner
            .encode(&mut bytes)
            .expect("encoding a transaction failed");
        bytes
    }

    pub fn code(&self) -> Vec<u8> {
        self.inner.code.clone()
    }

    pub fn data(&self) -> Vec<u8> {
        match &self.inner.data {
            Some(d) => d.clone(),
            None => Vec::new(),
        }
    }

    pub fn timestamp(&self) -> std::time::SystemTime {
        match &self.inner.timestamp {
            Some(t) => t.clone().into(),
            None => std::time::SystemTime::now(),
        }
    }
}

#[derive(Debug, PartialEq)]
pub struct IntentGossipMessage {
    inner: types::IntentGossipMessage,
}

impl IntentGossipMessage {
    pub fn from(intent_bytes: impl AsRef<[u8]>) -> Result<Self> {
        let inner = types::IntentGossipMessage::decode(intent_bytes.as_ref())
            .map_err(Error::IntentDecodingError)?;
        match &inner.msg {
            Some(_) => Ok(IntentGossipMessage { inner }),
            None => Err(Error::NoIntentError),
        }
    }

    pub fn new(intent: Intent) -> Self {
        let inner = types::IntentGossipMessage {
            msg: Some(types::intent_gossip_message::Msg::Intent(
                intent.convert(),
            )),
        };
        IntentGossipMessage { inner }
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = vec![];
        self.inner
            .encode(&mut bytes)
            .expect("encoding an intent failed");
        bytes
    }

    pub fn intent(&self) -> Intent {
        match &self.inner.msg {
            Some(types::intent_gossip_message::Msg::Intent(i)) => {
                Intent::from(i.clone())
            }
            _ => unreachable!(),
        }
    }
}

#[allow(dead_code)]
#[derive(Debug, PartialEq)]
pub struct DkgGossipMessage {
    inner: types::DkgGossipMessage,
}

#[allow(dead_code)]
impl DkgGossipMessage {
    pub fn from(dkg_bytes: impl AsRef<[u8]>) -> Result<Self> {
        let inner = types::DkgGossipMessage::decode(dkg_bytes.as_ref())
            .map_err(Error::DkgDecodingError)?;
        match &inner.dkg_message {
            Some(_) => Ok(DkgGossipMessage { inner }),
            None => Err(Error::NoDkgError),
        }
    }

    pub fn new(dkg: Dkg) -> Self {
        let message = types::dkg_gossip_message::DkgMessage::Dkg(dkg.convert());
        let inner = types::DkgGossipMessage {
            dkg_message: Some(message),
        };
        DkgGossipMessage { inner }
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = vec![];
        self.inner
            .encode(&mut bytes)
            .expect("encoding a DKG failed");
        bytes
    }

    pub fn dkg(&self) -> Dkg {
        match &self.inner.dkg_message {
            Some(types::dkg_gossip_message::DkgMessage::Dkg(d)) => {
                Dkg::from(d.clone())
            }
            _ => unreachable!(),
        }
    }
}

pub struct RpcMessage {
    inner: services::RpcMessage,
}

impl RpcMessage {
    pub fn new_intent(intent: Intent, topic: String) -> Self {
        let message = IntentMessage::new(intent, topic);
        let inner = services::RpcMessage {
            message: Some(services::rpc_message::Message::Intent(
                message.convert(),
            )),
        };
        RpcMessage { inner }
    }

    pub fn new_topic(topic: String) -> Self {
        let message = SubscribeTopicMessage::new(topic);
        let inner = services::RpcMessage {
            message: Some(services::rpc_message::Message::Topic(
                message.convert(),
            )),
        };
        RpcMessage { inner }
    }

    pub fn convert(&self) -> services::RpcMessage {
        self.inner.clone()
    }
}

#[derive(Debug, PartialEq)]
pub struct IntentMessage {
    inner: services::IntentMessage,
}

impl IntentMessage {
    pub fn from(message: services::IntentMessage) -> Result<Self> {
        match message.intent {
            Some(_) => Ok(IntentMessage { inner: message }),
            None => Err(Error::NoIntentError),
        }
    }

    pub fn new(intent: Intent, topic: String) -> Self {
        IntentMessage {
            inner: services::IntentMessage {
                intent: Some(intent.convert()),
                topic,
            },
        }
    }

    pub fn intent(&self) -> Intent {
        Intent::from(self.inner.intent.clone().expect("no intent"))
    }

    pub fn topic(&self) -> String {
        self.inner.topic.clone()
    }

    pub fn convert(&self) -> services::IntentMessage {
        self.inner.clone()
    }
}

#[derive(Debug, PartialEq)]
pub struct SubscribeTopicMessage {
    inner: services::SubscribeTopicMessage,
}

impl From<services::SubscribeTopicMessage> for SubscribeTopicMessage {
    fn from(inner: services::SubscribeTopicMessage) -> Self {
        SubscribeTopicMessage { inner }
    }
}

impl SubscribeTopicMessage {
    pub fn new(topic: String) -> Self {
        let inner = services::SubscribeTopicMessage { topic };
        SubscribeTopicMessage { inner }
    }

    pub fn topic(&self) -> String {
        self.inner.topic.clone()
    }

    pub fn convert(&self) -> services::SubscribeTopicMessage {
        self.inner.clone()
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct Intent {
    inner: types::Intent,
}

impl From<types::Intent> for Intent {
    fn from(inner: types::Intent) -> Self {
        Intent { inner }
    }
}

impl Intent {
    pub fn new(data: Vec<u8>) -> Self {
        Intent {
            inner: types::Intent {
                data,
                timestamp: Some(std::time::SystemTime::now().into()),
            },
        }
    }

    pub fn data(&self) -> Vec<u8> {
        self.inner.data.clone()
    }

    pub fn timestamp(&self) -> std::time::SystemTime {
        match &self.inner.timestamp {
            Some(t) => t.clone().into(),
            None => std::time::SystemTime::now(),
        }
    }

    pub fn id(&self) -> IntentId {
        let mut hasher = DefaultHasher::new();
        self.hash(&mut hasher);
        IntentId::from(hasher.finish().to_string())
    }

    pub fn convert(&self) -> types::Intent {
        types::Intent {
            data: self.data(),
            timestamp: Some(self.timestamp().into()),
        }
    }
}

#[allow(clippy::derive_hash_xor_eq)]
impl Hash for Intent {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.data().hash(state);
        self.timestamp().hash(state);
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct IntentId(pub Vec<u8>);

impl<T: Into<Vec<u8>>> From<T> for IntentId {
    fn from(value: T) -> Self {
        Self(value.into())
    }
}

#[allow(dead_code)]
#[derive(Clone, Debug, PartialEq)]
pub struct Dkg {
    inner: types::Dkg,
}

impl From<types::Dkg> for Dkg {
    fn from(inner: types::Dkg) -> Self {
        Dkg { inner }
    }
}

#[allow(dead_code)]
impl Dkg {
    pub fn new(data: String) -> Self {
        let inner = types::Dkg { data };
        Dkg { inner }
    }

    pub fn data(&self) -> String {
        self.inner.data.clone()
    }

    pub fn convert(&self) -> types::Dkg {
        self.inner.clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tx() {
        let code = "wasm code".as_bytes().to_owned();
        let data = Some("arbitrary data".as_bytes().to_owned());
        let tx = Tx::new(code.clone(), data.clone());

        let types_tx = types::Tx {
            code: code,
            data: data,
            timestamp: Some(std::time::SystemTime::now().into()),
        };
        let mut bytes = vec![];
        types_tx.encode(&mut bytes).expect("encoding failed");
        let tx_from_types = Tx::from(&bytes).expect("decoding failed");

        assert_eq!(tx_from_types.code(), tx.code());
        assert_eq!(tx_from_types.data(), tx.data());
    }

    #[test]
    fn test_intent_gossip_message() {
        let data = "arbitrary data".as_bytes().to_owned();
        let intent = Intent::new(data);
        let message = IntentGossipMessage::new(intent.clone());
        assert_eq!(message.intent(), intent);

        let bytes = message.to_bytes();
        let message_from_bytes =
            IntentGossipMessage::from(bytes).expect("decoding failed");
        assert_eq!(message_from_bytes, message);
    }

    #[test]
    fn test_dkg_gossip_message() {
        let data = "arbitrary string".to_owned();
        let dkg = Dkg::new(data);
        let message = DkgGossipMessage::new(dkg.clone());
        assert_eq!(message.dkg(), dkg);

        let bytes = message.to_bytes();
        let message_from_bytes =
            DkgGossipMessage::from(bytes).expect("decoding failed");
        assert_eq!(message_from_bytes, message);
    }

    #[test]
    fn test_intent_message() {
        let data = "arbitrary data".as_bytes().to_owned();
        let intent = Intent::new(data);
        let topic = "arbitrary string".to_owned();
        let intent_message = IntentMessage::new(intent.clone(), topic.clone());
        assert_eq!(intent_message.intent(), intent);
        assert_eq!(intent_message.topic(), topic);

        let intent_rpc_message = RpcMessage::new_intent(intent, topic);
        match intent_rpc_message.convert().message {
            Some(services::rpc_message::Message::Intent(i)) => {
                let message_from_types =
                    IntentMessage::from(i).expect("no intent");
                assert_eq!(intent_message, message_from_types);
            }
            _ => panic!("no intent message"),
        }
    }

    #[test]
    fn test_topic_message() {
        let topic = "arbitrary string".to_owned();
        let topic_message = SubscribeTopicMessage::new(topic.clone());
        assert_eq!(topic_message.topic(), topic);

        let topic_rpc_message = RpcMessage::new_topic(topic.clone());
        match topic_rpc_message.convert().message {
            Some(services::rpc_message::Message::Topic(t)) => {
                let message_from_types = SubscribeTopicMessage::from(t);
                assert_eq!(topic_message, message_from_types);
            }
            _ => panic!("no intent message"),
        }
    }

    #[test]
    fn test_intent() {
        let data = "arbitrary data".as_bytes().to_owned();
        let intent = Intent::new(data.clone());
        assert_eq!(intent.data(), data);

        let types_intent = intent.convert();
        let intent_from_types = Intent::from(types_intent);
        assert_eq!(intent_from_types, intent);
    }

    #[test]
    fn test_dkg() {
        let data = "arbitrary string".to_owned();
        let dkg = Dkg::new(data.clone());
        assert_eq!(dkg.data(), data);

        let types_dkg = dkg.convert();
        let dkg_from_types = Dkg::from(types_dkg);
        assert_eq!(dkg_from_types, dkg);
    }
}
