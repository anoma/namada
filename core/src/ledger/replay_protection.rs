//! Replay protection storage

use crate::types::address::{Address, InternalAddress};
use crate::types::storage::{DbKeySeg, Key};

/// Internal replay protection address
pub const ADDRESS: Address =
    Address::Internal(InternalAddress::ReplayProtection);

/// Check if a key is a replay protection key
pub fn is_tx_hash_key(key: &Key) -> bool {
    matches!(&key.segments[0], DbKeySeg::AddressSeg(addr) if addr == &ADDRESS)
}
