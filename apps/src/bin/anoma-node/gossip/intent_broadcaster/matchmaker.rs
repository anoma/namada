use std::collections::HashSet;

use anoma::config;
use anoma::protobuf::types::Intent;
use anoma::protobuf::{IntentId, MatchmakerMessage};
use thiserror::Error;
use tokio::sync::mpsc::{channel, Receiver, Sender};

use super::filter::Filter;
use super::mempool::{self, IntentMempool};
use crate::vm;

#[derive(Debug)]
pub struct Matchmaker {
    mempool: IntentMempool,
    filter: Option<Filter>,
    inject_mm_message: Sender<MatchmakerMessage>,
    matchmaker_code: Vec<u8>,
    tx_code: Vec<u8>,
}

#[derive(Error, Debug)]
pub enum Error {
    #[error("Failed to add intent to mempool: {0}")]
    MempoolFailed(mempool::Error),
    #[error("Failed to run matchmaker prog: {0}")]
    RunnerFailed(vm::Error),
    #[error("Failed to read file: {0}")]
    FileFailed(std::io::Error),
    #[error("Failed to create filter: {0}")]
    FilterInit(super::filter::Error),
    #[error("Failed to run filter: {0}")]
    Filter(super::filter::Error),
}

type Result<T> = std::result::Result<T, Error>;

impl Matchmaker {
    pub fn new(
        config: &config::Matchmaker,
    ) -> Result<(Self, (Receiver<MatchmakerMessage>, String))> {
        let (inject_mm_message, receiver_mm_message) = channel(100);
        let matchmaker_code =
            std::fs::read(&config.matchmaker).map_err(Error::FileFailed)?;
        let tx_code =
            std::fs::read(&config.tx_template).map_err(Error::FileFailed)?;
        let filter = config
            .filter
            .as_ref()
            .map(Filter::from_file)
            .transpose()
            .map_err(Error::FilterInit)?;
        Ok((
            Self {
                mempool: IntentMempool::new(),
                filter,
                inject_mm_message,
                matchmaker_code,
                tx_code,
            },
            (receiver_mm_message, config.ledger_address.to_string()),
        ))
    }

    // returns true if no filter is define for that matchmaker
    fn apply_filter(&self, intent: &Intent) -> Result<bool> {
        self.filter
            .as_ref()
            .map(|f| f.validate(intent))
            .transpose()
            .map(|v| v.unwrap_or(true))
            .map_err(Error::Filter)
    }

    // add the intent to the matchmaker mempool and tries to find a match for
    // that intent
    pub fn try_match_intent(&mut self, intent: &Intent) -> Result<bool> {
        if self.apply_filter(intent)? {
            self.mempool
                .put(intent.clone())
                .map_err(Error::MempoolFailed)?;
            let tx_code = &self.tx_code;
            let matchmaker_runner = vm::MatchmakerRunner::new();
            let matchmaker_code = &self.matchmaker_code;
            let inject_tx = &self.inject_tx;
            Ok(self.mempool.find_map(
                &intent,
                &|id1: &IntentId, i1: &Intent, id2: &IntentId, i2: &Intent| {
                    matchmaker_runner
                        .run(
                            matchmaker_code.clone(),
                            &id1.0,
                            &i1.data,
                            &id2.0,
                            &i2.data,
                            tx_code,
                            inject_tx.clone(),
                        )
                        .map_err(Error::RunnerFailed)
                        .unwrap()
                },
            ))
        } else {
            Ok(false)
        }
    }

    pub fn match_found(&mut self, intents: HashSet<Vec<u8>>) {
        intents.into_iter().for_each(|intent_id| {
            self.mempool.remove(&IntentId::from(intent_id));
        });
    }
}
