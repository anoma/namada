use borsh::{BorshDeserialize, BorshSerialize};

use crate::types::key::ed25519::Signed;
use crate::types::{token, Address};

#[derive(Debug, Clone, PartialEq, BorshSerialize, BorshDeserialize)]
pub struct Intent {
    pub addr: Address,
    pub token_sell: Address,
    pub amount_sell: token::Amount,
    pub token_buy: Address,
    pub amount_buy: token::Amount,
}

/// These are two transfers crafted from two matched [`Intent`]s.
#[derive(Debug, Clone, BorshSerialize, BorshDeserialize)]
pub struct IntentTransfers {
    pub intent_1: Signed<Intent>,
    pub transfer_1: token::Transfer,
    pub intent_2: Signed<Intent>,
    pub transfer_2: token::Transfer,
}
