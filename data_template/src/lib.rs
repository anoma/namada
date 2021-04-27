use anoma_shared::types::{token, Address};
use borsh::{BorshDeserialize, BorshSerialize};

#[derive(Debug, Clone, PartialEq, BorshSerialize, BorshDeserialize)]
pub struct Intent {
    pub addr: Address,
    pub token_sell: Address,
    pub amount_sell: token::Amount,
    pub token_buy: Address,
    pub amount_buy: token::Amount,
}

#[derive(Debug, Clone, PartialEq, BorshSerialize, BorshDeserialize)]
pub struct Transfer {
    pub source: Address,
    pub target: Address,
    pub token: Address,
    pub amount: token::Amount,
}

#[derive(Debug, Clone, PartialEq, BorshSerialize, BorshDeserialize)]
pub struct TxData {
    pub transfers: Vec<Transfer>,
}
