use namada_macros::StorageKeys;

use super::ADDRESS;
use crate::types::storage::{DbKeySeg, Key};

/// Storage keys for ledger parameters.
#[derive(StorageKeys)]
struct Keys {
    active_counsil: &'static str,
    counsil_members: &'static str,
}

/// Returns if the key is a pgf counsil treasury key.
pub fn is_counsil_treasury_key(key: &Key) -> bool {
    matches!(&key.segments[0], DbKeySeg::AddressSeg(addr) if addr == &ADDRESS)
}

/// Returns if the key is an active_counsil storage key.
pub fn is_active_counsil_key(key: &Key) -> bool {
    matches!(&key.segments[..], [
        DbKeySeg::AddressSeg(addr),
        DbKeySeg::StringSeg(active_counsil),
    ] if addr == &ADDRESS && active_counsil == Keys::VALUES.active_counsil)
}

/// Returns if the key is an counsil_members storage key.
pub fn is_counsil_members_key(key: &Key) -> bool {
    matches!(&key.segments[..], [
        DbKeySeg::AddressSeg(addr),
        DbKeySeg::StringSeg(counsil_members),
    ] if addr == &ADDRESS && counsil_members == Keys::VALUES.counsil_members)
}

/// Storage key used for active_counsil.
pub fn get_counsil_address_key() -> Key {
    Key {
        segments: vec![
            DbKeySeg::AddressSeg(ADDRESS),
            DbKeySeg::StringSeg(Keys::VALUES.active_counsil.to_string()),
        ],
    }
}

/// Storage key used for counsil_members.
pub fn get_counsil_members_key() -> Key {
    Key {
        segments: vec![
            DbKeySeg::AddressSeg(ADDRESS),
            DbKeySeg::StringSeg(Keys::VALUES.counsil_members.to_string()),
        ],
    }
}
