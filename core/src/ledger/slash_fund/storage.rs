//! Slash fund storage

use crate::types::storage::{DbKeySeg, Key};

/// Check if a key is a slash fund key
pub fn is_slash_fund_key(key: &Key) -> bool {
    matches!(&key.segments[0], DbKeySeg::AddressSeg(addr) if addr == &super::ADDRESS)
}
