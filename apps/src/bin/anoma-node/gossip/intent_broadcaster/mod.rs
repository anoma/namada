mod filter;
mod matchmaker;
mod mempool;

use std::collections::HashSet;

use anoma::protobuf::types::{Intent, IntentBroadcasterMessage, Tx};
use matchmaker::Matchmaker;
use prost::Message;
use thiserror::Error;
use tokio::sync::mpsc::Receiver;

// TODO split Error and Result type in two, one for Result/Error that can only
// happens locally and the other that can happens locally and in the network
#[derive(Error, Debug)]
pub enum Error {
    #[error("Error while decoding intent: {0}")]
    DecodeError(prost::DecodeError),
    #[error("Error initializing the matchmaker: {0}")]
    MatchmakerInit(matchmaker::Error),
    #[error("Error running the matchmaker: {0}")]
    Matchmaker(matchmaker::Error),
}

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Debug)]
pub struct GossipIntent {
    pub matchmaker: Option<Matchmaker>,
}

impl GossipIntent {
    pub fn new(
        config: &anoma::config::IntentBroadcaster,
    ) -> Result<(Self, Option<(Receiver<(Tx, HashSet<Vec<u8>>)>, String)>)>
    {
        let (matchmaker, matchmaker_event_receiver) = if let Some(matchmaker) =
            &config.matchmaker
        {
            let (matchmaker, matchmaker_event_receiver) =
                Matchmaker::new(&matchmaker).map_err(Error::MatchmakerInit)?;
            (Some(matchmaker), Some(matchmaker_event_receiver))
        } else {
            (None, None)
        };
        Ok((Self { matchmaker }, matchmaker_event_receiver))
    }

    fn apply_matchmaker(&mut self, intent: Intent) -> Option<Result<bool>> {
        self.matchmaker.as_mut().map(|matchmaker| {
            matchmaker
                .try_match_intent(&intent)
                .map_err(Error::Matchmaker)
        })
    }

    pub fn apply_intent(&mut self, intent: Intent) -> Result<bool> {
        self.apply_matchmaker(intent);
        Ok(true)
    }

    pub fn parse_raw_msg(
        &mut self,
        data: impl AsRef<[u8]>,
    ) -> Result<IntentBroadcasterMessage> {
        IntentBroadcasterMessage::decode(data.as_ref())
            .map_err(Error::DecodeError)
    }

    pub fn match_found(&mut self, intents: HashSet<Vec<u8>>) {
        self.matchmaker.as_mut().map(|mm| mm.match_found(intents));
    }
}
