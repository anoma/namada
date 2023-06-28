//! Cryptographic signature keys storage API

use super::*;
use crate::types::address::Address;
use crate::types::key::*;

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
