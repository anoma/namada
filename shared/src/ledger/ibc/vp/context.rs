//! Contexts for IBC validity predicate

use std::collections::{BTreeSet, HashMap, HashSet};

use borsh::{BorshDeserialize, BorshSerialize};
use namada_core::ledger::ibc::storage::is_ibc_key;
use namada_core::ledger::ibc::{IbcCommonContext, IbcStorageContext};
use namada_core::ledger::storage::write_log::StorageModification;
use namada_core::ledger::storage::{self as ledger_storage, StorageHasher};
use namada_core::ledger::storage_api::StorageRead;
use namada_core::types::address::{Address, InternalAddress};
use namada_core::types::ibc::IbcEvent;
use namada_core::types::storage::{BlockHeight, Header, Key};
use namada_core::types::token::{is_any_token_balance_key, Amount};

use super::Error;
use crate::ledger::native_vp::CtxPreStorageRead;
use crate::vm::WasmCacheAccess;

#[derive(Debug)]
pub struct PseudoExecutionContext<'view, 'a, DB, H, CA>
where
    DB: 'static + ledger_storage::DB + for<'iter> ledger_storage::DBIter<'iter>,
    H: 'static + StorageHasher,
    CA: 'static + WasmCacheAccess,
{
    /// Temporary store for pseudo execution
    store: HashMap<Key, StorageModification>,
    /// Context to read the previous value
    ctx: CtxPreStorageRead<'view, 'a, DB, H, CA>,
    /// IBC event
    pub event: BTreeSet<IbcEvent>,
}

impl<'view, 'a, DB, H, CA> PseudoExecutionContext<'view, 'a, DB, H, CA>
where
    DB: 'static + ledger_storage::DB + for<'iter> ledger_storage::DBIter<'iter>,
    H: 'static + StorageHasher,
    CA: 'static + WasmCacheAccess,
{
    pub fn new(ctx: CtxPreStorageRead<'view, 'a, DB, H, CA>) -> Self {
        Self {
            store: HashMap::new(),
            ctx,
            event: BTreeSet::new(),
        }
    }

    pub fn get_changed_keys(&self) -> HashSet<&Key> {
        self.store.keys().filter(|k| is_ibc_key(k)).collect()
    }

    pub fn get_changed_value(&self, key: &Key) -> Option<&StorageModification> {
        self.store.get(key)
    }
}

impl<'view, 'a, DB, H, CA> IbcStorageContext
    for PseudoExecutionContext<'view, 'a, DB, H, CA>
where
    DB: 'static + ledger_storage::DB + for<'iter> ledger_storage::DBIter<'iter>,
    H: 'static + StorageHasher,
    CA: 'static + WasmCacheAccess,
{
    type Error = Error;
    type PrefixIter<'iter> = ledger_storage::PrefixIter<'iter, DB> where Self: 'iter;

    fn read(&self, key: &Key) -> Result<Option<Vec<u8>>, Self::Error> {
        match self.store.get(key) {
            Some(StorageModification::Write { ref value }) => {
                Ok(Some(value.clone()))
            }
            Some(StorageModification::Delete) => Ok(None),
            Some(StorageModification::Temp { .. }) => {
                unreachable!("Temp shouldn't be inserted")
            }
            Some(StorageModification::InitAccount { .. }) => {
                unreachable!("InitAccount shouldn't be inserted")
            }
            None => self.ctx.read_bytes(key).map_err(Error::NativeVpError),
        }
    }

    fn iter_prefix<'iter>(
        &'iter self,
        prefix: &Key,
    ) -> Result<Self::PrefixIter<'iter>, Self::Error> {
        // NOTE: Read only the previous state since the updated state isn't
        // needed for the caller
        self.ctx.iter_prefix(prefix).map_err(Error::NativeVpError)
    }

    fn iter_next<'iter>(
        &'iter self,
        iter: &mut Self::PrefixIter<'iter>,
    ) -> Result<Option<(String, Vec<u8>)>, Self::Error> {
        self.ctx.iter_next(iter).map_err(Error::NativeVpError)
    }

    fn write(&mut self, key: &Key, value: Vec<u8>) -> Result<(), Self::Error> {
        self.store
            .insert(key.clone(), StorageModification::Write { value });
        Ok(())
    }

    fn delete(&mut self, key: &Key) -> Result<(), Self::Error> {
        self.store.insert(key.clone(), StorageModification::Delete);
        Ok(())
    }

    fn emit_ibc_event(&mut self, event: IbcEvent) -> Result<(), Self::Error> {
        self.event.insert(event);
        Ok(())
    }

    fn transfer_token(
        &mut self,
        src: &Key,
        dest: &Key,
        amount: Amount,
    ) -> Result<(), Self::Error> {
        let src_owner = is_any_token_balance_key(src);
        let mut src_bal = match src_owner {
            Some([_, Address::Internal(InternalAddress::IbcMint)]) => {
                Amount::max()
            }
            Some([_, Address::Internal(InternalAddress::IbcBurn)]) => {
                unreachable!("Invalid transfer from IBC burn address")
            }
            _ => match self.read(src)? {
                Some(v) => {
                    Amount::try_from_slice(&v[..]).map_err(Error::Decoding)?
                }
                None => unreachable!("The source has no balance"),
            },
        };
        src_bal.spend(&amount);
        let dest_owner = is_any_token_balance_key(dest);
        let mut dest_bal = match dest_owner {
            Some([_, Address::Internal(InternalAddress::IbcMint)]) => {
                unreachable!("Invalid transfer to IBC mint address")
            }
            _ => match self.read(dest)? {
                Some(v) => {
                    Amount::try_from_slice(&v[..]).map_err(Error::Decoding)?
                }
                None => Amount::default(),
            },
        };
        dest_bal.receive(&amount);

        self.write(
            src,
            src_bal.try_to_vec().expect("encoding shouldn't failed"),
        )?;
        self.write(
            dest,
            dest_bal.try_to_vec().expect("encoding shouldn't failed"),
        )?;

        Ok(())
    }

    /// Get the current height of this chain
    fn get_height(&self) -> Result<BlockHeight, Self::Error> {
        self.ctx.get_block_height().map_err(Error::NativeVpError)
    }

    /// Get the block header of this chain
    fn get_header(
        &self,
        height: BlockHeight,
    ) -> Result<Option<Header>, Self::Error> {
        self.ctx
            .get_block_header(height)
            .map_err(Error::NativeVpError)
    }

    fn log_string(&self, message: String) {
        tracing::debug!("{} in the pseudo execution for IBC VP", message);
    }
}

impl<'view, 'a, DB, H, CA> IbcCommonContext
    for PseudoExecutionContext<'view, 'a, DB, H, CA>
where
    DB: 'static + ledger_storage::DB + for<'iter> ledger_storage::DBIter<'iter>,
    H: 'static + StorageHasher,
    CA: 'static + WasmCacheAccess,
{
}

#[derive(Debug)]
pub struct VpValidationContext<'view, 'a, DB, H, CA>
where
    DB: 'static + ledger_storage::DB + for<'iter> ledger_storage::DBIter<'iter>,
    H: 'static + StorageHasher,
    CA: 'static + WasmCacheAccess,
{
    /// Context to read the post value
    ctx: CtxPreStorageRead<'view, 'a, DB, H, CA>,
}

impl<'view, 'a, DB, H, CA> VpValidationContext<'view, 'a, DB, H, CA>
where
    DB: 'static + ledger_storage::DB + for<'iter> ledger_storage::DBIter<'iter>,
    H: 'static + StorageHasher,
    CA: 'static + WasmCacheAccess,
{
    pub fn new(ctx: CtxPreStorageRead<'view, 'a, DB, H, CA>) -> Self {
        Self { ctx }
    }
}

impl<'view, 'a, DB, H, CA> IbcStorageContext
    for VpValidationContext<'view, 'a, DB, H, CA>
where
    DB: 'static + ledger_storage::DB + for<'iter> ledger_storage::DBIter<'iter>,
    H: 'static + StorageHasher,
    CA: 'static + WasmCacheAccess,
{
    type Error = Error;
    type PrefixIter<'iter> = ledger_storage::PrefixIter<'iter, DB> where Self: 'iter;

    fn read(&self, key: &Key) -> Result<Option<Vec<u8>>, Self::Error> {
        self.ctx.read_bytes(key).map_err(Error::NativeVpError)
    }

    fn iter_prefix<'iter>(
        &'iter self,
        prefix: &Key,
    ) -> Result<Self::PrefixIter<'iter>, Self::Error> {
        self.ctx.iter_prefix(prefix).map_err(Error::NativeVpError)
    }

    fn iter_next<'iter>(
        &'iter self,
        iter: &mut Self::PrefixIter<'iter>,
    ) -> Result<Option<(String, Vec<u8>)>, Self::Error> {
        self.ctx.iter_next(iter).map_err(Error::NativeVpError)
    }

    fn write(&mut self, _key: &Key, _data: Vec<u8>) -> Result<(), Self::Error> {
        unimplemented!("Validation doesn't write any data")
    }

    fn delete(&mut self, _key: &Key) -> Result<(), Self::Error> {
        unimplemented!("Validation doesn't delete any data")
    }

    fn emit_ibc_event(&mut self, _event: IbcEvent) -> Result<(), Self::Error> {
        unimplemented!("Validation doesn't emit an event")
    }

    /// Transfer token
    fn transfer_token(
        &mut self,
        _src: &Key,
        _dest: &Key,
        _amount: Amount,
    ) -> Result<(), Self::Error> {
        unimplemented!("Validation doesn't transfer")
    }

    fn get_height(&self) -> Result<BlockHeight, Self::Error> {
        self.ctx.get_block_height().map_err(Error::NativeVpError)
    }

    fn get_header(
        &self,
        height: BlockHeight,
    ) -> Result<Option<Header>, Self::Error> {
        self.ctx
            .get_block_header(height)
            .map_err(Error::NativeVpError)
    }

    /// Logging
    fn log_string(&self, message: String) {
        tracing::debug!("{} for validation in IBC VP", message);
    }
}

impl<'view, 'a, DB, H, CA> IbcCommonContext
    for VpValidationContext<'view, 'a, DB, H, CA>
where
    DB: 'static + ledger_storage::DB + for<'iter> ledger_storage::DBIter<'iter>,
    H: 'static + StorageHasher,
    CA: 'static + WasmCacheAccess,
{
}
