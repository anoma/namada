//! Cryptographic signature keys storage API

use std::collections::HashMap;

use super::*;
use crate::types::address::Address;
use crate::types::key::*;

/// Init the subspace of a new account
pub fn init_account_storage<S>(
    storage: &mut S,
    owner: &Address,
    public_keys: &[common::PublicKey],
    threshold: u8,
) -> Result<()>
where
    S: StorageWrite + StorageRead,
{
    for (index, public_key) in public_keys.iter().enumerate() {
        let index = index as u8;
        pks_handle(owner).insert(storage, index, public_key.clone())?;
    }
    let threshold_key = threshold_key(owner);
    storage.write(&threshold_key, threshold)
}

/// Get the threshold associated with an account
pub fn threshold<S>(storage: &S, owner: &Address) -> Result<Option<u8>>
where
    S: StorageRead,
{
    let threshold_key = threshold_key(owner);
    storage.read(&threshold_key)
}

/// Get the public keys index map associated with an account
pub fn public_keys<S>(
    storage: &S,
    owner: &Address,
) -> Result<HashMap<u8, common::PublicKey>>
where
    S: StorageRead,
{
    let mut public_keys_map = HashMap::new();

    for item in pks_handle(owner).iter(storage)? {
        let (index, public_key) = item?;
        public_keys_map.insert(index, public_key);
    }
    Ok(public_keys_map)
}
