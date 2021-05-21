use std::collections::{HashMap, HashSet};

use borsh::{BorshDeserialize, BorshSerialize};
use serde::{Deserialize, Serialize};

use super::DbKeySeg;
use crate::types::key::ed25519::Signed;
use crate::types::{token, Address, Key, KeySeg};
#[derive(
    Debug,
    Clone,
    PartialEq,
    BorshSerialize,
    BorshDeserialize,
    Serialize,
    Deserialize,
)]
pub struct Intent {
    pub addr: Address,
    pub token_sell: Address,
    pub amount_sell: token::Amount,
    pub token_buy: Address,
    pub amount_buy: token::Amount,
}

/// These are transfers crafted from matched [`Intent`]s.
#[derive(
    Debug, Clone, BorshSerialize, BorshDeserialize, Serialize, Deserialize,
)]
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

const INVALID_INTENT_STORAGE_KEY: &str = "invalid_intent";

/// Obtain a storage key for user's invalid intent set.
pub fn invalid_intent_key(owner: &Address) -> Key {
    Key::from(owner.to_db_key())
        .push(&INVALID_INTENT_STORAGE_KEY.to_owned())
        .expect("Cannot obtain a storage key")
}

/// Check if the given storage key is a key for a set of intent sig. If it is,
/// returns the owner.
pub fn is_invalid_intent_key(key: &Key) -> Option<&Address> {
    match &key.segments[..] {
        [DbKeySeg::AddressSeg(owner), DbKeySeg::StringSeg(key)]
            if key == INVALID_INTENT_STORAGE_KEY =>
        {
            Some(owner)
        }
        _ => None,
    }
}
