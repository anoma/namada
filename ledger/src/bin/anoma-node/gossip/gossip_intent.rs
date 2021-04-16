use anoma::protobuf::types::{
    Intent, IntentBroadcasterMessage, Tx,
};
use prost::Message;
use thiserror::Error;
use tokio::sync::mpsc::Receiver;

use super::matchmaker::Matchmaker;
use super::mempool::Mempool;

#[derive(Error, Debug)]
pub enum Error {
    #[error("Error while decoding intent: {0}")]
    DecodeError(prost::DecodeError),
}

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Debug)]
pub struct GossipIntent {
    pub mempool: Mempool,
    pub matchmaker: Option<Matchmaker>,
}

impl GossipIntent {
    pub fn new(
        config: &anoma::config::IntentGossip,
    ) -> (Self, Option<Receiver<Tx>>) {
        let (matchmaker, matchmaker_event_receiver) =
            if let Some(matchmaker) = &config.matchmaker {
                let (matchmaker, matchmaker_event_receiver) =
                    Matchmaker::new(&matchmaker);
                (Some(matchmaker), Some(matchmaker_event_receiver))
            } else {
                (None, None)
            };
        (
            Self {
                mempool: Mempool::new(),
                matchmaker,
            },
            matchmaker_event_receiver,
        )
    }

    pub async fn apply_intent(&mut self, intent: Intent) -> Result<bool> {
        if let Some(matchmaker) = &mut self.matchmaker {
            matchmaker.try_match_intent(&intent).await;
            let _result = matchmaker.add(intent);
        }
        Ok(true)
    }

    pub async fn apply_raw_intent(&mut self, data: &Vec<u8>) -> Result<bool> {
        let intent = Intent::decode(&data[..]).map_err(Error::DecodeError)?;
        self.apply_intent(intent).await
    }
}
