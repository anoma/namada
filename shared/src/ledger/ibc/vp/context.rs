//! Contexts for IBC validity predicate

use std::collections::{BTreeSet, HashMap, HashSet};

use borsh::BorshSerialize;
use namada_core::ledger::ibc::storage::is_ibc_key;
use namada_core::ledger::ibc::{IbcCommonContext, IbcStorageContext};
use namada_core::ledger::storage::write_log::StorageModification;
use namada_core::ledger::storage::{self as ledger_storage, StorageHasher};
use namada_core::ledger::storage_api::StorageRead;
use namada_core::types::address::{Address, InternalAddress};
use namada_core::types::ibc::IbcEvent;
use namada_core::types::storage::{BlockHeight, Header, Key};
use namada_core::types::token::{self, Amount, DenominatedAmount};

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

    fn has_key(&self, key: &Key) -> Result<bool, Self::Error> {
        Ok(self.store.contains_key(key)
            || self.ctx.has_key(key).map_err(Error::NativeVpError)?)
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

    fn get_ibc_event(
        &self,
        event_type: impl AsRef<str>,
    ) -> Result<Option<IbcEvent>, Self::Error> {
        for event in &self.event {
            if event.event_type == *event_type.as_ref() {
                return Ok(Some(event.clone()));
            }
        }
        Ok(None)
    }

    fn transfer_token(
        &mut self,
        src: &Address,
        dest: &Address,
        token: &Address,
        amount: DenominatedAmount,
    ) -> Result<(), Self::Error> {
        let src_key = token::balance_key(token, src);
        let dest_key = token::balance_key(token, dest);
        let src_bal: Option<Amount> =
            self.ctx.read(&src_key).map_err(Error::NativeVpError)?;
        let mut src_bal = src_bal.expect("The source has no balance");
        src_bal.spend(&amount.amount);
        let mut dest_bal: Amount = self
            .ctx
            .read(&dest_key)
            .map_err(Error::NativeVpError)?
            .unwrap_or_default();
        dest_bal.receive(&amount.amount);

        self.write(
            &src_key,
            src_bal.try_to_vec().expect("encoding shouldn't failed"),
        )?;
        self.write(
            &dest_key,
            dest_bal.try_to_vec().expect("encoding shouldn't failed"),
        )
    }

    fn mint_token(
        &mut self,
        target: &Address,
        token: &Address,
        amount: DenominatedAmount,
    ) -> Result<(), Self::Error> {
        let target_key = token::balance_key(token, target);
        let mut target_bal: Amount = self
            .ctx
            .read(&target_key)
            .map_err(Error::NativeVpError)?
            .unwrap_or_default();
        target_bal.receive(&amount.amount);

        let minted_key = token::minted_balance_key(token);
        let mut minted_bal: Amount = self
            .ctx
            .read(&minted_key)
            .map_err(Error::NativeVpError)?
            .unwrap_or_default();
        minted_bal.receive(&amount.amount);

        self.write(
            &target_key,
            target_bal.try_to_vec().expect("encoding shouldn't failed"),
        )?;
        self.write(
            &minted_key,
            minted_bal.try_to_vec().expect("encoding shouldn't failed"),
        )?;

        let minter_key = token::minter_key(token);
        self.write(
            &minter_key,
            Address::Internal(InternalAddress::Ibc)
                .try_to_vec()
                .expect("encoding shouldn't failed"),
        )
    }

    fn burn_token(
        &mut self,
        target: &Address,
        token: &Address,
        amount: DenominatedAmount,
    ) -> Result<(), Self::Error> {
        let target_key = token::balance_key(token, target);
        let mut target_bal: Amount = self
            .ctx
            .read(&target_key)
            .map_err(Error::NativeVpError)?
            .unwrap_or_default();
        target_bal.spend(&amount.amount);

        let minted_key = token::minted_balance_key(token);
        let mut minted_bal: Amount = self
            .ctx
            .read(&minted_key)
            .map_err(Error::NativeVpError)?
            .unwrap_or_default();
        minted_bal.spend(&amount.amount);

        self.write(
            &target_key,
            target_bal.try_to_vec().expect("encoding shouldn't failed"),
        )?;
        self.write(
            &minted_key,
            minted_bal.try_to_vec().expect("encoding shouldn't failed"),
        )
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

    fn has_key(&self, key: &Key) -> Result<bool, Self::Error> {
        self.ctx.has_key(key).map_err(Error::NativeVpError)
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

    fn get_ibc_event(
        &self,
        _event_type: impl AsRef<str>,
    ) -> Result<Option<IbcEvent>, Self::Error> {
        unimplemented!("Validation doesn't get an event")
    }

    fn transfer_token(
        &mut self,
        _src: &Address,
        _dest: &Address,
        _token: &Address,
        _amount: DenominatedAmount,
    ) -> Result<(), Self::Error> {
        unimplemented!("Validation doesn't transfer")
    }

    fn mint_token(
        &mut self,
        _target: &Address,
        _token: &Address,
        _amount: DenominatedAmount,
    ) -> Result<(), Self::Error> {
        unimplemented!("Validation doesn't mint")
    }

    fn burn_token(
        &mut self,
        _target: &Address,
        _token: &Address,
        _amount: DenominatedAmount,
    ) -> Result<(), Self::Error> {
        unimplemented!("Validation doesn't burn")
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
