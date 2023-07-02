//! Cryptographic signature keys storage API

use super::*;
use crate::types::address::Address;
use crate::types::key::*;

/// Reveal a PK of an implicit account - the PK is written into the storage
/// of the address derived from the PK.
pub fn reveal_pk<S>(
    storage: &mut S,
    public_key: &common::PublicKey,
) -> Result<()>
where
    S: StorageWrite + StorageRead,
{
    let owner: Address = public_key.into();
    pks_handle(&owner).insert(storage, 0, public_key.clone())?;

    Ok(())
}
