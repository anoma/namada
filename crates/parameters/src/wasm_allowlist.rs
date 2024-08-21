use namada_core::hash::Hash;
use namada_state::{Key, StorageRead, StorageResult};

use crate::storage::{
    get_tx_allowlist_storage_key, get_vp_allowlist_storage_key,
};

/// Check if the given tx code `Hash` is in the allowlist. When the allowlist is
/// empty it always returns true.
pub fn is_tx_allowed<S>(storage: &S, tx_hash: &Hash) -> StorageResult<bool>
where
    S: StorageRead,
{
    let key = get_tx_allowlist_storage_key();
    is_allowed(storage, key, tx_hash)
}

/// Check if the given VP code `Hash` is in the allowlist. When the allowlist is
/// empty it always returns true.
pub fn is_vp_allowed<S>(storage: &S, vp_hash: &Hash) -> StorageResult<bool>
where
    S: StorageRead,
{
    let key = get_vp_allowlist_storage_key();
    is_allowed(storage, key, vp_hash)
}

fn is_allowed<S>(
    storage: &S,
    allowlist_key: Key,
    hash: &Hash,
) -> StorageResult<bool>
where
    S: StorageRead,
{
    let allowlist: Vec<String> =
        storage.read(&allowlist_key)?.unwrap_or_default();
    // if allowlist is empty, allow any
    Ok(allowlist.is_empty()
        || allowlist.contains(&hash.to_string().to_lowercase()))
}
