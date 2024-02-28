use namada_core::address::Address;
use namada_core::key::common;
use namada_core::storage::{self, DbKeySeg};
use namada_macros::StorageKeys;
use namada_storage::collections::lazy_map::LazyMap;
use namada_storage::collections::{lazy_map, LazyCollection};

/// Storage keys for account.
#[derive(StorageKeys)]
struct Keys {
    public_keys: &'static str,
    threshold: &'static str,
    protocol_public_keys: &'static str,
}

/// Obtain a storage key for user's public key.
pub fn pks_key_prefix(owner: &Address) -> storage::Key {
    storage::Key {
        segments: vec![
            DbKeySeg::AddressSeg(owner.to_owned()),
            DbKeySeg::StringSeg(Keys::VALUES.public_keys.to_string()),
        ],
    }
}

/// LazyMap handler for the user's public key subspace
pub fn pks_handle(owner: &Address) -> LazyMap<u8, common::PublicKey> {
    LazyMap::open(pks_key_prefix(owner))
}

/// Check if the given storage key is a public key. If it is, returns the owner.
pub fn is_pks_key(key: &storage::Key) -> Option<&Address> {
    match &key.segments[..] {
        [
            DbKeySeg::AddressSeg(owner),
            DbKeySeg::StringSeg(prefix),
            DbKeySeg::StringSeg(data),
            DbKeySeg::StringSeg(index),
        ] if prefix.as_str() == Keys::VALUES.public_keys
            && data.as_str() == lazy_map::DATA_SUBKEY
            && index.parse::<u8>().is_ok() =>
        {
            Some(owner)
        }
        _ => None,
    }
}

/// Check if the given storage key is a threshol key.
pub fn is_threshold_key(key: &storage::Key) -> Option<&Address> {
    match &key.segments[..] {
        [DbKeySeg::AddressSeg(owner), DbKeySeg::StringSeg(prefix)]
            if prefix.as_str() == Keys::VALUES.threshold =>
        {
            Some(owner)
        }
        _ => None,
    }
}

/// Obtain the storage key for a user threshold
pub fn threshold_key(owner: &Address) -> storage::Key {
    storage::Key {
        segments: vec![
            DbKeySeg::AddressSeg(owner.to_owned()),
            DbKeySeg::StringSeg(Keys::VALUES.threshold.to_string()),
        ],
    }
}

/// Obtain a storage key for user's protocol public key.
pub fn protocol_pk_key(owner: &Address) -> storage::Key {
    storage::Key {
        segments: vec![
            DbKeySeg::AddressSeg(owner.to_owned()),
            DbKeySeg::StringSeg(Keys::VALUES.protocol_public_keys.to_string()),
        ],
    }
}

/// Check if the given storage key is a public key. If it is, returns the owner.
pub fn is_protocol_pk_key(key: &storage::Key) -> Option<&Address> {
    match &key.segments[..] {
        [DbKeySeg::AddressSeg(owner), DbKeySeg::StringSeg(key)]
            if key.as_str() == Keys::VALUES.protocol_public_keys =>
        {
            Some(owner)
        }
        _ => None,
    }
}
