use std::collections::{HashMap, HashSet};

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

/// These are transfers crafted from matched [`Intent`]s.
#[derive(Debug, Clone, BorshSerialize, BorshDeserialize)]
pub struct IntentTransfers {
    pub transfers: HashSet<token::Transfer>,
    // TODO benchmark between an map or a set, see which is less costly
    pub intents: HashMap<Address, Signed<Intent>>,
}

impl IntentTransfers {
    pub fn empty() -> Self {
        Self {
            transfers: HashSet::new(),
            intents: HashMap::new(),
        }
    }
}
