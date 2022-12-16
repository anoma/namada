//! Parameters storage
use super::ADDRESS;
use crate::types::storage::{DbKeySeg, Key};

const EPOCH_DURATION_KEY: &str = "epoch_duration";
const VP_WHITELIST_KEY: &str = "vp_whitelist";
const TX_WHITELIST_KEY: &str = "tx_whitelist";
const MAX_EXPECTED_TIME_PER_BLOCK_KEY: &str = "max_expected_time_per_block";
const IMPLICIT_VP_KEY: &str = "implicit_vp";
const EPOCHS_PER_YEAR_KEY: &str = "epochs_per_year";
const POS_GAIN_P_KEY: &str = "pos_gain_p";
const POS_GAIN_D_KEY: &str = "pos_gain_d";
const STAKED_RATIO_KEY: &str = "staked_ratio_key";
const POS_INFLATION_AMOUNT_KEY: &str = "pos_inflation_amount_key";

// keep these keys in sync with the defs above;
// make sure to store them in sorted order!
const ALL_KEYS: &[&str] = &[
    EPOCH_DURATION_KEY,
    EPOCHS_PER_YEAR_KEY,
    IMPLICIT_VP_KEY,
    MAX_EXPECTED_TIME_PER_BLOCK_KEY,
    POS_GAIN_D_KEY,
    POS_GAIN_P_KEY,
    POS_INFLATION_AMOUNT_KEY,
    STAKED_RATIO_KEY,
    TX_WHITELIST_KEY,
    VP_WHITELIST_KEY,
];

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
    ALL_KEYS.binary_search(&segment).is_ok()
}

/// Returns if the key is an epoch storage key.
pub fn is_epoch_duration_storage_key(key: &Key) -> bool {
    matches!(&key.segments[..], [
        DbKeySeg::AddressSeg(addr),
        DbKeySeg::StringSeg(epoch_duration),
    ] if addr == &ADDRESS && epoch_duration == EPOCH_DURATION_KEY)
}

/// Returns if the key is the max_expected_time_per_block key.
pub fn is_max_expected_time_per_block_key(key: &Key) -> bool {
    matches!(&key.segments[..], [
        DbKeySeg::AddressSeg(addr),
        DbKeySeg::StringSeg(max_expected_time_per_block),
    ] if addr == &ADDRESS && max_expected_time_per_block == MAX_EXPECTED_TIME_PER_BLOCK_KEY)
}

/// Returns if the key is the tx_whitelist key.
pub fn is_tx_whitelist_key(key: &Key) -> bool {
    matches!(&key.segments[..], [
        DbKeySeg::AddressSeg(addr),
        DbKeySeg::StringSeg(tx_whitelist),
    ] if addr == &ADDRESS && tx_whitelist == TX_WHITELIST_KEY)
}

/// Returns if the key is the vp_whitelist key.
pub fn is_vp_whitelist_key(key: &Key) -> bool {
    matches!(&key.segments[..], [
        DbKeySeg::AddressSeg(addr),
        DbKeySeg::StringSeg(vp_whitelist),
    ] if addr == &ADDRESS && vp_whitelist == VP_WHITELIST_KEY)
}

/// Returns if the key is the implicit VP key.
pub fn is_implicit_vp_key(key: &Key) -> bool {
    matches!(&key.segments[..], [
        DbKeySeg::AddressSeg(addr),
        DbKeySeg::StringSeg(sub_key),
    ] if addr == &ADDRESS && sub_key == IMPLICIT_VP_KEY)
}

/// Returns if the key is the epoch_per_year key.
pub fn is_epochs_per_year_key(key: &Key) -> bool {
    matches!(&key.segments[..], [
        DbKeySeg::AddressSeg(addr),
        DbKeySeg::StringSeg(epochs_per_year),
    ] if addr == &ADDRESS && epochs_per_year == EPOCHS_PER_YEAR_KEY)
}

/// Returns if the key is the pos_gain_p key.
pub fn is_pos_gain_p_key(key: &Key) -> bool {
    matches!(&key.segments[..], [
        DbKeySeg::AddressSeg(addr),
        DbKeySeg::StringSeg(pos_gain_p),
    ] if addr == &ADDRESS && pos_gain_p == POS_GAIN_P_KEY)
}

/// Returns if the key is the pos_gain_d key.
pub fn is_pos_gain_d_key(key: &Key) -> bool {
    matches!(&key.segments[..], [
        DbKeySeg::AddressSeg(addr),
        DbKeySeg::StringSeg(pos_gain_d),
    ] if addr == &ADDRESS && pos_gain_d == POS_GAIN_D_KEY)
}

/// Returns if the key is the staked ratio key.
pub fn is_staked_ratio_key(key: &Key) -> bool {
    matches!(&key.segments[..], [
        DbKeySeg::AddressSeg(addr),
        DbKeySeg::StringSeg(staked_ratio),
    ] if addr == &ADDRESS && staked_ratio == STAKED_RATIO_KEY)
}

/// Returns if the key is the PoS reward rate key.
pub fn is_pos_inflation_amount_key(key: &Key) -> bool {
    matches!(&key.segments[..], [
        DbKeySeg::AddressSeg(addr),
        DbKeySeg::StringSeg(pos_inflation_amount),
    ] if addr == &ADDRESS && pos_inflation_amount == POS_INFLATION_AMOUNT_KEY)
}

/// Storage key used for epoch parameter.
pub fn get_epoch_duration_storage_key() -> Key {
    Key {
        segments: vec![
            DbKeySeg::AddressSeg(ADDRESS),
            DbKeySeg::StringSeg(EPOCH_DURATION_KEY.to_string()),
        ],
    }
}

/// Storage key used for vp whitelist parameter.
pub fn get_vp_whitelist_storage_key() -> Key {
    Key {
        segments: vec![
            DbKeySeg::AddressSeg(ADDRESS),
            DbKeySeg::StringSeg(VP_WHITELIST_KEY.to_string()),
        ],
    }
}

/// Storage key used for tx whitelist parameter.
pub fn get_tx_whitelist_storage_key() -> Key {
    Key {
        segments: vec![
            DbKeySeg::AddressSeg(ADDRESS),
            DbKeySeg::StringSeg(TX_WHITELIST_KEY.to_string()),
        ],
    }
}

/// Storage key used for max_epected_time_per_block parameter.
pub fn get_max_expected_time_per_block_key() -> Key {
    Key {
        segments: vec![
            DbKeySeg::AddressSeg(ADDRESS),
            DbKeySeg::StringSeg(MAX_EXPECTED_TIME_PER_BLOCK_KEY.to_string()),
        ],
    }
}

/// Storage key used for implicit VP parameter.
pub fn get_implicit_vp_key() -> Key {
    Key {
        segments: vec![
            DbKeySeg::AddressSeg(ADDRESS),
            DbKeySeg::StringSeg(IMPLICIT_VP_KEY.to_string()),
        ],
    }
}

/// Storage key used for epochs_per_year parameter.
pub fn get_epochs_per_year_key() -> Key {
    Key {
        segments: vec![
            DbKeySeg::AddressSeg(ADDRESS),
            DbKeySeg::StringSeg(EPOCHS_PER_YEAR_KEY.to_string()),
        ],
    }
}

/// Storage key used for pos_gain_p parameter.
pub fn get_pos_gain_p_key() -> Key {
    Key {
        segments: vec![
            DbKeySeg::AddressSeg(ADDRESS),
            DbKeySeg::StringSeg(POS_GAIN_P_KEY.to_string()),
        ],
    }
}

/// Storage key used for pos_gain_d parameter.
pub fn get_pos_gain_d_key() -> Key {
    Key {
        segments: vec![
            DbKeySeg::AddressSeg(ADDRESS),
            DbKeySeg::StringSeg(POS_GAIN_D_KEY.to_string()),
        ],
    }
}

/// Storage key used for staked ratio parameter.
pub fn get_staked_ratio_key() -> Key {
    Key {
        segments: vec![
            DbKeySeg::AddressSeg(ADDRESS),
            DbKeySeg::StringSeg(STAKED_RATIO_KEY.to_string()),
        ],
    }
}

/// Storage key used for the inflation amount parameter.
pub fn get_pos_inflation_amount_key() -> Key {
    Key {
        segments: vec![
            DbKeySeg::AddressSeg(ADDRESS),
            DbKeySeg::StringSeg(POS_INFLATION_AMOUNT_KEY.to_string()),
        ],
    }
}
