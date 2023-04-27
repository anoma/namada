use namada_macros::StorageKeys;

use crate::ledger::pgf::ADDRESS;
use crate::types::storage::{DbKeySeg, Key, KeySeg};

/// Storage keys for pgf internal address.
#[derive(StorageKeys)]
struct Keys {
    stewards: &'static str,
    payments: &'static str,
    inflation_rate: &'static str,
}

/// Check if key is inside governance address space
pub fn is_pgf_key(key: &Key) -> bool {
    matches!(&key.segments[0], DbKeySeg::AddressSeg(addr) if addr == &ADDRESS)
}

/// Check if key is a steward key
pub fn is_stewards_key(key: &Key) -> bool {
    matches!(&key.segments[..], [DbKeySeg::AddressSeg(addr), DbKeySeg::StringSeg(prefix)] if addr == &ADDRESS && prefix == Keys::VALUES.stewards)
}

/// Check if key is a payments key
pub fn is_payments_key(key: &Key) -> bool {
    matches!(&key.segments[..], [DbKeySeg::AddressSeg(addr), DbKeySeg::StringSeg(prefix)] if addr == &ADDRESS && prefix == Keys::VALUES.payments)
}

/// Check if key is a inflation rate key
pub fn is_inflation_rate_key(key: &Key) -> bool {
    matches!(&key.segments[..], [DbKeySeg::AddressSeg(addr), DbKeySeg::StringSeg(prefix)] if addr == &ADDRESS && prefix == Keys::VALUES.inflation_rate)
}

/// Get key for stewards key
pub fn get_stewards_key() -> Key {
    Key::from(ADDRESS.to_db_key())
        .push(&Keys::VALUES.stewards.to_owned())
        .expect("Cannot obtain a storage key")
}

/// Get key for payments key
pub fn get_payments_key() -> Key {
    Key::from(ADDRESS.to_db_key())
        .push(&Keys::VALUES.payments.to_owned())
        .expect("Cannot obtain a storage key")
}

/// Get key for inflation rate key
pub fn get_inflation_rate_key() -> Key {
    Key::from(ADDRESS.to_db_key())
        .push(&Keys::VALUES.inflation_rate.to_owned())
        .expect("Cannot obtain a storage key")
}
