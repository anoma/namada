use anoma::protobuf::types::{Filter, Intent, IntentBroadcasterMessage, Tx};
use libp2p::PeerId;
use prost::Message;
use thiserror::Error;
use tokio::sync::mpsc::Receiver;

use super::filter::{self, FilterValidate};
use super::matchmaker::Matchmaker;
use super::mempool::FilterMempool;

pub const MAX_SIZE_PUBLIC_FILTER: u64 = bytesize::MB;

// TODO split Error and Result type in two, one for Result/Error that can only
// happens localy and the other that can happens locally and in the network
#[derive(Error, Debug)]
pub enum Error {
    #[error("Error while decoding intent: {0}")]
    DecodeError(prost::DecodeError),
    #[error("Error while running filter: {0}")]
    Filter(filter::Error),
    #[error("Filter is too big: {0}")]
    FilterSize(u64),
    #[error("Error initializing the matchmaker: {0}")]
    MatchmakerInit(super::matchmaker::Error),
    #[error("Error while getting the metadata of the file: {0}")]
    File(std::io::Error),
    #[error("Error while inserting the filter into the filter mempool: {0}")]
    FilterMempool(super::mempool::Error),
    #[error("Failed to create filter: {0}")]
    FilterInit(super::filter::Error),
}

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Debug)]
pub struct GossipIntent {
    pub filter_mempool: FilterMempool,
    pub filter: Option<Filter>,
    pub matchmaker: Option<Matchmaker>,
}

impl GossipIntent {
    pub fn new(
        config: &anoma::config::IntentGossip,
    ) -> Result<(Self, Option<Receiver<Tx>>)> {
        let (matchmaker, matchmaker_event_receiver) = if let Some(matchmaker) =
            &config.matchmaker
        {
            let (matchmaker, matchmaker_event_receiver) =
                Matchmaker::new(&matchmaker).map_err(Error::MatchmakerInit)?;
            (Some(matchmaker), Some(matchmaker_event_receiver))
        } else {
            (None, None)
        };
        let filter = if let Some(path) = &config.public_filter_path {
            let metadata = std::fs::metadata(&path).map_err(Error::File)?;
            let len = metadata.len();
            if len > MAX_SIZE_PUBLIC_FILTER {
                return Err(Error::FilterSize(len));
            } else {
                Some(Filter::from_file(path).map_err(Error::FilterInit)?)
            }
        } else {
            None
        };
        Ok((
            Self {
                filter,
                matchmaker,
                filter_mempool: FilterMempool::new(),
            },
            matchmaker_event_receiver,
        ))
    }

    // returns true if no filter is define for that gossiper
    async fn apply_filter(&self, intent: &Intent) -> Result<bool> {
        self.filter
            .as_ref()
            .map(|f| f.validate(intent))
            .transpose()
            .map(|v| v.unwrap_or(true))
            .map_err(Error::Filter)
    }

    async fn apply_matchmaker(&mut self, intent: Intent) {
        if let Some(matchmaker) = &mut self.matchmaker {
            matchmaker.try_match_intent(&intent).await;
        }
    }

    pub async fn apply_intent(&mut self, intent: Intent) -> Result<bool> {
        if self.apply_filter(&intent).await? {
            self.apply_matchmaker(intent).await;
            Ok(true)
        }
    }

    pub async fn add_filter(
        &mut self,
        peer_id: PeerId,
        filter: Filter,
    ) -> Result<bool> {
        self.filter_mempool
            .put(peer_id, filter)
            .map_err(Error::FilterMempool)
    }

    pub fn parse_raw_msg(
        &mut self,
        data: impl AsRef<[u8]>,
    ) -> Result<IntentBroadcasterMessage> {
        IntentBroadcasterMessage::decode(data.as_ref())
            .map_err(Error::DecodeError)
    }
}
