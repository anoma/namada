use anoma::protobuf::types::{Intent, Tx};
use thiserror::Error;
use tokio::sync::mpsc::{channel, Receiver, Sender};

use super::mempool::{self, Mempool};
use crate::vm;

#[derive(Debug)]
pub struct Matchmaker {
    pub mempool: Mempool,
    inject_tx: Sender<Tx>,
    matchmaker_code: Vec<u8>,
    tx_code: Vec<u8>,
}

#[derive(Error, Debug)]
pub enum Error {
    #[error("Failed to add intent to mempool: {0}")]
    MempoolFailed(mempool::Error),
    #[error("Failed to run matchmaker prog: {0}")]
    RunnerFailed(vm::Error),
}

type Result<T> = std::result::Result<T, Error>;

impl Matchmaker {
    pub fn new(config: &anoma::config::Matchmaker) -> (Self, Receiver<Tx>) {
        let (inject_tx, rx) = channel::<Tx>(100);
        (
            Self {
                mempool: Mempool::new(),
                matchmaker_code: std::fs::read(&config.matchmaker).unwrap(),
                tx_code: std::fs::read(&config.tx_template).unwrap(),
                inject_tx,
            },
            rx,
        )
    }

    pub fn add(&mut self, intent: Intent) -> Result<bool> {
        self.mempool.put(intent).map_err(Error::MempoolFailed)
    }

    pub async fn try_match_intent(&mut self, intent: &Intent) -> bool {
        let tx_code = &self.tx_code;
        let matchmaker_runner = vm::MatchmakerRunner::new();
        let matchmaker_code = &self.matchmaker_code;
        let inject_tx = &self.inject_tx;
        self.mempool.find_map(&intent, &|i1: &Intent, i2: &Intent| {
            matchmaker_runner
                .run(
                    matchmaker_code.clone(),
                    &i1.data,
                    &i2.data,
                    tx_code,
                    inject_tx.clone(),
                )
                .map_err(Error::RunnerFailed)
                .unwrap()
        })
    }
}
