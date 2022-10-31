//! Cryptographic signature keys storage API

use super::*;
use crate::types::address::Address;
use crate::types::key::*;

/// Get the public key associated with the given address. Returns `Ok(None)` if
/// not found.
pub fn get<S>(storage: &S, owner: &Address) -> Result<Option<common::PublicKey>>
where
    S: for<'iter> StorageRead<'iter>,
{
    let key = pk_key(owner);
    storage.read(&key)
}

/// Reveal a PK of an implicit account - the PK is written into the storage
/// of the address derived from the PK.
pub fn reveal_pk<S>(storage: &mut S, pk: &common::PublicKey) -> Result<()>
where
    S: StorageWrite,
{
    let addr: Address = pk.into();
    let key = pk_key(&addr);
    storage.write(&key, pk)
}
