use borsh::{BorshDeserialize, BorshSerialize};

#[derive(Debug, Clone, PartialEq, BorshSerialize, BorshDeserialize)]
pub struct Intent {
    pub addr: String,
    pub token_sell: String,
    pub amount_sell: u64,
    pub token_buy: String,
    pub amount_buy: u64,
}

#[derive(Debug, Clone, PartialEq, BorshSerialize, BorshDeserialize)]
pub struct Transfer {
    pub source: String,
    pub target: String,
    pub token: String,
    pub amount: u64,
}

#[derive(Debug, Clone, PartialEq, BorshSerialize, BorshDeserialize)]
pub struct TxData {
    pub transfers: Vec<Transfer>,
}
