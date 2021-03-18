use anoma::protobuf::types::Intent;
use prost::Message;

use super::mempool::{IntentId, Mempool};
use super::types::{InternMessage, Topic};

#[derive(Debug, Clone)]
pub enum OrderbookError {
    DecodeError(prost::DecodeError),
}

impl std::fmt::Display for OrderbookError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::DecodeError(prost_error) => write!(f, "{}", prost_error),
        }
    }
}
impl std::error::Error for OrderbookError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::DecodeError(prost_error) => Some(prost_error),
        }
    }
}

pub type Result<T> = std::result::Result<T, OrderbookError>;

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
        data: &Vec<u8>
    ) -> Result<bool> {
        let intent =
            Intent::decode(&data[..]).map_err(OrderbookError::DecodeError)?;
        Ok(true)
    }
}
