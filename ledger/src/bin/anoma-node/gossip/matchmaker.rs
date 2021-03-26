use anoma::protobuf::types::{Intent, Tx};
use borsh::{BorshDeserialize, BorshSerialize};
use serde::{Deserialize, Serialize};
use tokio::sync::mpsc::{channel, Receiver, Sender};

use super::mempool::{Mempool, MempoolError};

#[derive(Debug)]
pub struct Matchmaker {
    pub mempool: Mempool,
    pub tx_code: Vec<u8>,
    event_chan: Sender<Tx>,
}

pub enum MatchmakerError {
    MempoolFailed(MempoolError),
}

// Currently only for two party transfer of token with exact match of amount

#[derive(Debug, BorshSerialize, BorshDeserialize)]
pub struct IntentTxData {
    pub addr_a: String,
    pub addr_b: String,
    pub token_a_b: String,
    pub amount_a_b: u64,
    pub token_b_a: String,
    pub amount_b_a: u64,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct IntentData {
    pub addr: String,
    pub token_sell: String,
    pub amount_sell: u64,
    pub token_buy: String,
    pub amount_buy: u64,
}

type Result<T> = std::result::Result<T, MatchmakerError>;

impl Matchmaker {
    pub fn new(tx_code_path: String) -> (Self, Receiver<Tx>) {
        let (event_chan, rx) = channel::<Tx>(100);
        println!("creating matchmaker with tx_template : {:?}", tx_code_path);
        (
            Self {
                mempool: Mempool::new(),
                tx_code: std::fs::read(tx_code_path).unwrap(),
                event_chan,
            },
            rx,
        )
    }

    pub fn add(&mut self, intent: Intent) -> Result<bool> {
        self.mempool
            .put(intent)
            .map_err(MatchmakerError::MempoolFailed)
    }

    fn find(code: &Vec<u8>, intent1: &Intent, intent2: &Intent) -> Option<Tx> {
        let data_intent_1: IntentData =
            serde_json::from_slice(&mut &intent1.data[..])
                .expect("matchmaker does not understand data's intent");
        let data_intent_2: IntentData =
            serde_json::from_slice(&mut &intent2.data[..])
                .expect("matchmaker does not understand data's intent");
        println!("testing data {:?} with {:?} ", data_intent_1, data_intent_2);
        println!("{:?} with {:?} ", data_intent_1, data_intent_2);
        if data_intent_1.token_sell == data_intent_2.token_buy
            && data_intent_1.amount_sell == data_intent_2.amount_buy
            && data_intent_1.token_buy == data_intent_2.token_sell
            && data_intent_1.amount_buy == data_intent_2.amount_sell
        {
            let data_dec = IntentTxData {
                addr_a: data_intent_1.addr,
                addr_b: data_intent_2.addr,
                token_a_b: data_intent_1.token_sell,
                amount_a_b: data_intent_1.amount_sell,
                token_b_a: data_intent_1.token_buy,
                amount_b_a: data_intent_1.amount_buy,
            };
            let mut data = Vec::with_capacity(1024);
            data_dec
                .serialize(&mut data)
                .expect("Error while serializing tx data");
            let tx = Tx {
                code: code.clone(),
                data: Some(data),
            };
            Some(tx)
        } else {
            None
        }
    }

    async fn find_map(&mut self, intent: &Intent) -> Option<Tx> {
        let code = self.tx_code.clone();
        let res = self.mempool.find_map(&intent, &|i1, i2| {
            let res = Self::find(&code, i1, i2);
            res
        });
        res
    }

    pub async fn find_and_send(&mut self, intent: &Intent) -> bool {
        let tx_opt = self.find_map(intent).await;
        match tx_opt {
            Some(tx) => {
                let _result = self.event_chan.send(tx).await;
                true
            }
            None => false,
        }
    }
}
