use borsh::{BorshDeserialize, BorshSerialize};

#[derive(Debug, Clone, PartialEq, BorshSerialize, BorshDeserialize)]
pub struct TxDataExchange {
    pub addr_a: String,
    pub addr_b: String,
    pub token_a_b: String,
    pub amount_a_b: u64,
    pub token_b_a: String,
    pub amount_b_a: u64,
}

#[derive(Debug, Clone, PartialEq, BorshSerialize, BorshDeserialize)]
pub struct IntentData {
    pub addr: String,
    pub token_sell: String,
    pub amount_sell: u64,
    pub token_buy: String,
    pub amount_buy: u64,
}
