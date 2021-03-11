use super::mempool::{IntentId, Mempool};
use super::types::{InternMessage, Topic};
use anoma::protobuf::types::Intent;
use prost::Message;

#[derive(Debug, Clone)]
pub enum Error {
    DecodeError(prost::DecodeError),
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::DecodeError(prost_error) => write!(f, "{}", prost_error),
        }
    }
}
impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Error::DecodeError(prost_error) => Some(prost_error),
        }
    }
}

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Debug)]
pub struct Orderbook {
    pub mempool: Mempool,
}
impl Orderbook {
    pub fn new() -> Self {
        Self {
            mempool: Mempool::new(),
        }
    }

    pub fn apply(
        &mut self,
        InternMessage { topic, data, .. }: &InternMessage,
    ) -> Result<bool> {
        if let Topic::Orderbook = topic {
            let intent =
                Intent::decode(&data[..]).map_err(Error::DecodeError)?;
            println!("Intent {:?} added to local mempool", intent);
            self.mempool.put(&IntentId::new(&intent), intent);
            Ok(true)
        } else {
            Ok(false)
        }
    }
}
