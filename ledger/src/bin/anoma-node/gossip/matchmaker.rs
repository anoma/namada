use super::mempool::{self, Mempool, MempoolError};
use anoma::protobuf::types::Intent;
use borsh::{BorshDeserialize, BorshSerialize};

#[derive(Debug)]
pub struct Matchmaker {
    pub mempool: Mempool,
}

pub enum MatchmakerError {
    MempoolFailed(MempoolError),
    MatchFailed(MempoolError),
}

// Currently only for two party transfer of token with exact match of amount

#[derive(BorshSerialize, BorshDeserialize)]
pub struct TxData {
    pub addr_a: String,
    pub addr_b: String,
    pub token_a_b: String,
    pub amount_a_b: u64,
    pub token_b_a: String,
    pub amount_b_a: u64,
}

type Result<T> = std::result::Result<T, MatchmakerError>;

impl Matchmaker {
    pub fn new() -> Self {
        Self {
            mempool: Mempool::new(),
        }
    }

    pub fn add(&mut self, intent: Intent) -> Result<bool> {
        self.mempool
            .put(intent)
            .map_err(MatchmakerError::MempoolFailed)
    }
    fn find(_intent1: &Intent, _intent2: &Intent) -> Option<Vec<u8>> {
        let data = TxData {
            addr_a: String::from("va"),
            addr_b: String::from("ba"),
            token_a_b: String::from("eth"),
            amount_a_b: 80,
            token_b_a: String::from("xtz"),
            amount_b_a: 10,
        };
        let mut result = Vec::with_capacity(1024);
        // TODO error handling
        data.serialize(&mut result).unwrap();
        Some(result)
    }

    pub async fn find_map(
        &mut self,
        intent: Intent,
    ) -> Result<Option<Vec<u8>>> {
        self.mempool
            .find_map(&intent, &Self::find)
            .map_err(MatchmakerError::MatchFailed)
    }
}
