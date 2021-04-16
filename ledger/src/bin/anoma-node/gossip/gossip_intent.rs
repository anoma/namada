use anoma::protobuf::types::{
    Intent, IntentBroadcasterMessage, PublicFilter, Tx,
};
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
    FilterError(filter::Error),
    #[error("Filter is too big: {0}")]
    PublicFilterSize(u64),
    #[error("Error while getting the metadata of the file: {0}")]
    FileError(std::io::Error),
    #[error("Error while getting the metadata of the file: {0}")]
    FilterMempoolError(super::mempool::Error),
}

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Debug)]
pub struct GossipIntent {
    pub filter_mempool: FilterMempool,
    pub filter: Option<PublicFilter>,
    pub matchmaker: Option<Matchmaker>,
}

impl GossipIntent {
    pub fn new(
        config: &anoma::config::IntentGossip,
    ) -> Result<(Self, Option<Receiver<Tx>>)> {
        let (matchmaker, matchmaker_event_receiver) =
            if let Some(matchmaker) = &config.matchmaker {
                let (matchmaker, matchmaker_event_receiver) =
                    Matchmaker::new(&matchmaker);
                (Some(matchmaker), Some(matchmaker_event_receiver))
            } else {
                (None, None)
            };
        let filter = if let Some(path) = &config.public_filter_path {
            let metadata =
                std::fs::metadata(&path).map_err(Error::FileError)?;
            let len = metadata.len();
            if len > MAX_SIZE_PUBLIC_FILTER {
                return Err(Error::PublicFilterSize(len));
            } else {
                Some(PublicFilter::from_file(path))
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

    async fn apply_matchmaker(&mut self, intent: Intent) {
        if let Some(matchmaker) = &mut self.matchmaker {
            matchmaker.try_match_intent(&intent).await;
            let _result = matchmaker.add(intent);
        }
    }

    pub async fn apply_intent(&mut self, intent: Intent) -> Result<bool> {
        if let Some(filter) = &mut self.filter {
            if filter.validate(&intent).map_err(Error::FilterError)? {
                self.apply_matchmaker(intent).await;
                Ok(true)
            } else {
                Ok(false)
            }
        } else {
            self.apply_matchmaker(intent).await;
            Ok(true)
        }
    }

    pub async fn add_filter(&mut self, peer_id:PeerId, filter: PublicFilter) -> Result<bool> {
        self.filter_mempool.put(peer_id, filter).map_err(Error::FilterMempoolError)
    }

    pub fn parse_raw_msg(
        &mut self,
        data: impl AsRef<[u8]>,
    ) -> Result<IntentBroadcasterMessage> {
        IntentBroadcasterMessage::decode(data.as_ref())
            .map_err(Error::DecodeError)
    }
}
