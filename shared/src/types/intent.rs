//! Intent data definitions and transaction and validity-predicate helpers.

use std::collections::{HashMap, HashSet};

use borsh::{BorshDeserialize, BorshSerialize};
use serde::{Deserialize, Serialize};

use crate::types::address::Address;
use crate::types::key::ed25519::Signed;
use crate::types::storage::{DbKeySeg, Key, KeySeg};
use crate::types::token;
#[derive(
    Debug,
    Clone,
    PartialEq,
    BorshSerialize,
    BorshDeserialize,
    Serialize,
    Deserialize,
)]

/// A simple intent for fungible token trade
pub struct Intent {
    /// The source address
    pub addr: Address,
    /// The token to be sold
    pub token_sell: Address,
    /// The amount of token to be sold
    pub amount_sell: token::Amount,
    /// The token to be bought
    pub token_buy: Address,
    /// The amount of token to be bought
    pub amount_buy: token::Amount,
}

/// These are transfers crafted from matched [`Intent`]s.
#[derive(
    Debug, Clone, BorshSerialize, BorshDeserialize, Serialize, Deserialize,
)]
pub struct IntentTransfers {
    /// Transfers crafted from the matched intents
    pub transfers: HashSet<token::Transfer>,
    // TODO benchmark between an map or a set, see which is less costly
    /// The intents that were matched
    pub intents: HashMap<Address, Signed<Intent>>,
}

impl IntentTransfers {
    /// Create an empty [`IntentTransfers`].
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
