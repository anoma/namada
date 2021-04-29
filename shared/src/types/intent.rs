use borsh::{BorshDeserialize, BorshSerialize};

use crate::types::{token, Address};

#[derive(Debug, Clone, PartialEq, BorshSerialize, BorshDeserialize)]
pub struct Intent {
    pub addr: Address,
    pub token_sell: Address,
    pub amount_sell: token::Amount,
    pub token_buy: Address,
    pub amount_buy: token::Amount,
}
