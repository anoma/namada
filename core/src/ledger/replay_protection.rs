//! Replay protection storage

use crate::types::address::{Address, InternalAddress};
use crate::types::hash::Hash;
use crate::types::storage::{DbKeySeg, Key, KeySeg};

/// Internal replay protection address
pub const ADDRESS: Address =
    Address::Internal(InternalAddress::ReplayProtection);

/// Check if a key is a replay protection key
pub fn is_replay_protection_key(key: &Key) -> bool {
    matches!(&key.segments[0], DbKeySeg::AddressSeg(addr) if addr == &ADDRESS)
}

/// Get the transaction hash key
pub fn get_replay_protection_key(hash: &Hash) -> Key {
    Key::from(ADDRESS.to_db_key())
        .push(&hash.to_string())
        .expect("Cannot obtain a valid db key")
}
