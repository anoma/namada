//! Parameters storage

use namada_macros::StorageKeys;

use super::ADDRESS;
use crate::types::storage::{DbKeySeg, Key};

/// Storage keys for ledger parameters.
#[derive(StorageKeys)]
struct Keys {
    epoch_duration: &'static str,
    epochs_per_year: &'static str,
    implicit_vp: &'static str,
    max_expected_time_per_block: &'static str,
    pos_gain_d: &'static str,
    pos_gain_p: &'static str,
    pos_inflation_amount: &'static str,
    staked_ratio: &'static str,
    tx_whitelist: &'static str,
    vp_whitelist: &'static str,
}

/// Returns if the key is a parameter key.
pub fn is_parameter_key(key: &Key) -> bool {
    matches!(&key.segments[0], DbKeySeg::AddressSeg(addr) if addr == &ADDRESS)
}

/// Returns if the key is a protocol parameter key.
pub fn is_protocol_parameter_key(key: &Key) -> bool {
    let segment = match &key.segments[..] {
        [DbKeySeg::AddressSeg(addr), DbKeySeg::StringSeg(segment)]
            if addr == &ADDRESS =>
        {
            segment.as_str()
        }
        _ => return false,
    };
    Keys::ALL.binary_search(&segment).is_ok()
}

/// Returns if the key is an epoch storage key.
pub fn is_epoch_duration_storage_key(key: &Key) -> bool {
    matches!(&key.segments[..], [
        DbKeySeg::AddressSeg(addr),
        DbKeySeg::StringSeg(epoch_duration),
    ] if addr == &ADDRESS && epoch_duration == Keys::VALUES.epoch_duration)
}

/// Returns if the key is the max_expected_time_per_block key.
pub fn is_max_expected_time_per_block_key(key: &Key) -> bool {
    matches!(&key.segments[..], [
        DbKeySeg::AddressSeg(addr),
        DbKeySeg::StringSeg(max_expected_time_per_block),
    ] if addr == &ADDRESS && max_expected_time_per_block == Keys::VALUES.max_expected_time_per_block)
}

/// Returns if the key is the tx_whitelist key.
pub fn is_tx_whitelist_key(key: &Key) -> bool {
    matches!(&key.segments[..], [
        DbKeySeg::AddressSeg(addr),
        DbKeySeg::StringSeg(tx_whitelist),
    ] if addr == &ADDRESS && tx_whitelist == Keys::VALUES.tx_whitelist)
}

/// Returns if the key is the vp_whitelist key.
pub fn is_vp_whitelist_key(key: &Key) -> bool {
    matches!(&key.segments[..], [
        DbKeySeg::AddressSeg(addr),
        DbKeySeg::StringSeg(vp_whitelist),
    ] if addr == &ADDRESS && vp_whitelist == Keys::VALUES.vp_whitelist)
}

/// Returns if the key is the implicit VP key.
pub fn is_implicit_vp_key(key: &Key) -> bool {
    matches!(&key.segments[..], [
        DbKeySeg::AddressSeg(addr),
        DbKeySeg::StringSeg(sub_key),
    ] if addr == &ADDRESS && sub_key == Keys::VALUES.implicit_vp)
}

/// Returns if the key is the epoch_per_year key.
pub fn is_epochs_per_year_key(key: &Key) -> bool {
    matches!(&key.segments[..], [
        DbKeySeg::AddressSeg(addr),
        DbKeySeg::StringSeg(epochs_per_year),
    ] if addr == &ADDRESS && epochs_per_year == Keys::VALUES.epochs_per_year)
}

/// Returns if the key is the pos_gain_p key.
pub fn is_pos_gain_p_key(key: &Key) -> bool {
    matches!(&key.segments[..], [
        DbKeySeg::AddressSeg(addr),
        DbKeySeg::StringSeg(pos_gain_p),
    ] if addr == &ADDRESS && pos_gain_p == Keys::VALUES.pos_gain_p)
}

/// Returns if the key is the pos_gain_d key.
pub fn is_pos_gain_d_key(key: &Key) -> bool {
    matches!(&key.segments[..], [
        DbKeySeg::AddressSeg(addr),
        DbKeySeg::StringSeg(pos_gain_d),
    ] if addr == &ADDRESS && pos_gain_d == Keys::VALUES.pos_gain_d)
}

/// Returns if the key is the staked ratio key.
pub fn is_staked_ratio_key(key: &Key) -> bool {
    matches!(&key.segments[..], [
        DbKeySeg::AddressSeg(addr),
        DbKeySeg::StringSeg(staked_ratio),
    ] if addr == &ADDRESS && staked_ratio == Keys::VALUES.staked_ratio)
}

/// Returns if the key is the PoS reward rate key.
pub fn is_pos_inflation_amount_key(key: &Key) -> bool {
    matches!(&key.segments[..], [
        DbKeySeg::AddressSeg(addr),
        DbKeySeg::StringSeg(pos_inflation_amount),
    ] if addr == &ADDRESS && pos_inflation_amount == Keys::VALUES.pos_inflation_amount)
}

/// Storage key used for epoch parameter.
pub fn get_epoch_duration_storage_key() -> Key {
    Key {
        segments: vec![
            DbKeySeg::AddressSeg(ADDRESS),
            DbKeySeg::StringSeg(Keys::VALUES.epoch_duration.to_string()),
        ],
    }
}

/// Storage key used for vp whitelist parameter.
pub fn get_vp_whitelist_storage_key() -> Key {
    Key {
        segments: vec![
            DbKeySeg::AddressSeg(ADDRESS),
            DbKeySeg::StringSeg(Keys::VALUES.vp_whitelist.to_string()),
        ],
    }
}

/// Storage key used for tx whitelist parameter.
pub fn get_tx_whitelist_storage_key() -> Key {
    Key {
        segments: vec![
            DbKeySeg::AddressSeg(ADDRESS),
            DbKeySeg::StringSeg(Keys::VALUES.tx_whitelist.to_string()),
        ],
    }
}

/// Storage key used for max_epected_time_per_block parameter.
pub fn get_max_expected_time_per_block_key() -> Key {
    Key {
        segments: vec![
            DbKeySeg::AddressSeg(ADDRESS),
            DbKeySeg::StringSeg(
                Keys::VALUES.max_expected_time_per_block.to_string(),
            ),
        ],
    }
}

/// Storage key used for implicit VP parameter.
pub fn get_implicit_vp_key() -> Key {
    Key {
        segments: vec![
            DbKeySeg::AddressSeg(ADDRESS),
            DbKeySeg::StringSeg(Keys::VALUES.implicit_vp.to_string()),
        ],
    }
}

/// Storage key used for epochs_per_year parameter.
pub fn get_epochs_per_year_key() -> Key {
    Key {
        segments: vec![
            DbKeySeg::AddressSeg(ADDRESS),
            DbKeySeg::StringSeg(Keys::VALUES.epochs_per_year.to_string()),
        ],
    }
}

/// Storage key used for pos_gain_p parameter.
pub fn get_pos_gain_p_key() -> Key {
    Key {
        segments: vec![
            DbKeySeg::AddressSeg(ADDRESS),
            DbKeySeg::StringSeg(Keys::VALUES.pos_gain_p.to_string()),
        ],
    }
}

/// Storage key used for pos_gain_d parameter.
pub fn get_pos_gain_d_key() -> Key {
    Key {
        segments: vec![
            DbKeySeg::AddressSeg(ADDRESS),
            DbKeySeg::StringSeg(Keys::VALUES.pos_gain_d.to_string()),
        ],
    }
}

/// Storage key used for staked ratio parameter.
pub fn get_staked_ratio_key() -> Key {
    Key {
        segments: vec![
            DbKeySeg::AddressSeg(ADDRESS),
            DbKeySeg::StringSeg(Keys::VALUES.staked_ratio.to_string()),
        ],
    }
}

/// Storage key used for the inflation amount parameter.
pub fn get_pos_inflation_amount_key() -> Key {
    Key {
        segments: vec![
            DbKeySeg::AddressSeg(ADDRESS),
            DbKeySeg::StringSeg(Keys::VALUES.pos_inflation_amount.to_string()),
        ],
    }
}
