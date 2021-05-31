use anoma_shared::vm;
use prost::Message;
use tendermint::net;
use tendermint_rpc::{Client, HttpClient};
use thiserror::Error;
use tokio::sync::mpsc::{channel, Receiver, Sender};

use super::filter::Filter;
use super::mempool::{self, IntentMempool};
use crate::config;
use crate::proto::types::Intent;
use crate::proto::IntentId;
use crate::types::MatchmakerMessage;

#[derive(Debug)]
pub struct Matchmaker {
    mempool: IntentMempool,
    filter: Option<Filter>,
    inject_mm_message: Sender<MatchmakerMessage>,
    matchmaker_code: Vec<u8>,
    tx_code: Vec<u8>,
    // the matchmaker's state as arbitrary bytes
    data: Vec<u8>,
    ledger_address: net::Address,
}

#[derive(Error, Debug)]
pub enum Error {
    #[error("Failed to add intent to mempool: {0}")]
    MempoolFailed(mempool::Error),
    #[error("Failed to run matchmaker prog: {0}")]
    RunnerFailed(vm::wasm::wasm_runner::Error),
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
    ) -> Result<(Self, Receiver<MatchmakerMessage>)> {
        let (inject_mm_message, receiver_mm_message) = channel(100);
        let matchmaker_code =
            std::fs::read(&config.matchmaker).map_err(Error::FileFailed)?;
        let tx_code =
            std::fs::read(&config.tx_code).map_err(Error::FileFailed)?;
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
                data: Vec::new(),
                ledger_address: config.ledger_address.clone(),
            },
            receiver_mm_message,
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
            // let matchmaker_runner = vm::MatchmakerRunner::new();
            // Ok(matchmaker_runner
            //     .run(
            //         &self.matchmaker_code.clone(),
            //         &self.data,
            //         &IntentId::new(&intent).0,
            //         &intent.data,
            //         &self.tx_code,
            //         self.inject_mm_message.clone(),
            //     )
            //     .map_err(Error::RunnerFailed)
            //     .unwrap())
            todo!()
        } else {
            Ok(false)
        }
    }

    pub async fn handle_mm_message(&mut self, mm_message: MatchmakerMessage) {
        match mm_message {
            MatchmakerMessage::InjectTx(tx) => {
                let mut tx_bytes = vec![];
                tx.encode(&mut tx_bytes).unwrap();
                let client =
                    HttpClient::new(self.ledger_address.clone()).unwrap();
                let response =
                    client.broadcast_tx_commit(tx_bytes.into()).await;
                println!("{:#?}", response);
            }
            MatchmakerMessage::RemoveIntents(intents_id) => {
                intents_id.into_iter().for_each(|intent_id| {
                    self.mempool.remove(&IntentId::from(intent_id));
                });
            }
            MatchmakerMessage::UpdateData(mm_data) => {
                self.data = mm_data;
            }
        }
    }
}
