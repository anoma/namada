//! Contexts for IBC validity predicate

use std::collections::BTreeSet;
use std::marker::PhantomData;

use namada_core::address::{Address, InternalAddress};
use namada_core::arith::checked;
use namada_core::borsh::BorshSerializeExt;
use namada_core::collections::{HashMap, HashSet};
use namada_core::storage::{BlockHeight, Epoch, Epochs, Header, Key, TxIndex};
use namada_core::token::{self, Amount};
use namada_events::Event;
use namada_gas::MEMORY_ACCESS_GAS_PER_BYTE;
use namada_state::write_log::StorageModification;
use namada_state::{
    PrefixIter, StateRead, StorageError, StorageRead, StorageWrite,
};
use namada_vp::native_vp::{CtxPreStorageRead, VpEvaluator};
use namada_vp::VpEnv;

use crate::event::IbcEvent;
use crate::storage::is_ibc_key;
use crate::{IbcCommonContext, IbcStorageContext};

/// Result of a storage API call.
pub type Result<T> = std::result::Result<T, namada_state::StorageError>;

/// Pseudo execution environment context for ibc native vp
#[derive(Debug)]
pub struct PseudoExecutionContext<'view, 'a, S, CA, EVAL, Token>
where
    S: 'static + StateRead,
    EVAL: VpEvaluator<'a, S, CA, EVAL>,
{
    /// Execution context and storage
    pub storage: PseudoExecutionStorage<'view, 'a, S, CA, EVAL>,
    /// Token type
    pub token: PhantomData<Token>,
}

/// Pseudo execution environment context storage for ibc native vp
#[derive(Debug)]
pub struct PseudoExecutionStorage<'view, 'a, S, CA, EVAL>
where
    S: 'static + StateRead,
    EVAL: VpEvaluator<'a, S, CA, EVAL>,
{
    /// Temporary store for pseudo execution
    store: HashMap<Key, StorageModification>,
    /// Context to read the previous value
    ctx: CtxPreStorageRead<'view, 'a, S, CA, EVAL>,
    /// IBC event
    pub event: BTreeSet<Event>,
}

impl<'view, 'a, S, CA, EVAL, Token>
    PseudoExecutionContext<'view, 'a, S, CA, EVAL, Token>
where
    S: 'static + StateRead,
    EVAL: VpEvaluator<'a, S, CA, EVAL>,
{
    /// Generate new pseudo execution context
    pub fn new(ctx: CtxPreStorageRead<'view, 'a, S, CA, EVAL>) -> Self {
        Self {
            storage: PseudoExecutionStorage {
                store: HashMap::new(),
                ctx,
                event: BTreeSet::new(),
            },
            token: PhantomData,
        }
    }

    /// Get the set of changed keys
    pub(crate) fn get_changed_keys(&self) -> HashSet<&Key> {
        self.storage
            .store
            .keys()
            .filter(|k| is_ibc_key(k))
            .collect()
    }

    /// Get the changed value
    pub(crate) fn get_changed_value(
        &self,
        key: &Key,
    ) -> Option<&StorageModification> {
        self.storage.store.get(key)
    }
}

impl<'view, 'a, S, CA, EVAL> StorageRead
    for PseudoExecutionStorage<'view, 'a, S, CA, EVAL>
where
    S: 'static + StateRead,
    CA: 'static + Clone,
    EVAL: 'static + VpEvaluator<'a, S, CA, EVAL>,
{
    type PrefixIter<'iter> = PrefixIter<'iter, <S as StateRead>::D> where
Self: 'iter;

    fn read_bytes(&self, key: &Key) -> Result<Option<Vec<u8>>> {
        match self.store.get(key) {
            Some(StorageModification::Write { ref value }) => {
                let gas = checked!(key.len() + value.len())? as u64;
                self.ctx
                    .ctx
                    .charge_gas(checked!(gas * MEMORY_ACCESS_GAS_PER_BYTE)?)?;
                Ok(Some(value.clone()))
            }
            Some(StorageModification::Delete) => {
                let len = key.len() as u64;
                self.ctx
                    .ctx
                    .charge_gas(checked!(len * MEMORY_ACCESS_GAS_PER_BYTE)?)?;
                Ok(None)
            }
            Some(StorageModification::InitAccount { .. }) => Err(
                StorageError::new_const("InitAccount shouldn't be inserted"),
            ),
            None => {
                let len = key.len() as u64;
                self.ctx
                    .ctx
                    .charge_gas(checked!(len * MEMORY_ACCESS_GAS_PER_BYTE)?)?;
                self.ctx.read_bytes(key)
            }
        }
    }

    fn has_key(&self, key: &Key) -> Result<bool> {
        Ok(self.store.contains_key(key) || self.ctx.has_key(key)?)
    }

    fn iter_prefix<'iter>(
        &'iter self,
        prefix: &Key,
    ) -> Result<Self::PrefixIter<'iter>> {
        // NOTE: Read only the previous state since the updated state isn't
        // needed for the caller
        self.ctx.iter_prefix(prefix)
    }

    fn iter_next<'iter>(
        &'iter self,
        iter: &mut Self::PrefixIter<'iter>,
    ) -> Result<Option<(String, Vec<u8>)>> {
        self.ctx.iter_next(iter)
    }

    fn get_chain_id(&self) -> Result<String> {
        self.ctx.get_chain_id()
    }

    fn get_block_height(&self) -> Result<BlockHeight> {
        self.ctx.get_block_height()
    }

    fn get_block_header(&self, height: BlockHeight) -> Result<Option<Header>> {
        self.ctx.get_block_header(height)
    }

    fn get_block_epoch(&self) -> Result<Epoch> {
        self.ctx.get_block_epoch()
    }

    fn get_tx_index(&self) -> Result<TxIndex> {
        self.ctx.get_tx_index()
    }

    fn get_native_token(&self) -> Result<Address> {
        self.ctx.get_native_token()
    }

    fn get_pred_epochs(&self) -> Result<Epochs> {
        self.ctx.get_pred_epochs()
    }
}

impl<'view, 'a, S, CA, EVAL> StorageWrite
    for PseudoExecutionStorage<'view, 'a, S, CA, EVAL>
where
    S: 'static + StateRead,
    CA: 'static + Clone,
    EVAL: 'static + VpEvaluator<'a, S, CA, EVAL>,
{
    fn write_bytes(
        &mut self,
        key: &Key,
        value: impl AsRef<[u8]>,
    ) -> Result<()> {
        let value = value.as_ref().to_vec();
        let gas = checked!(key.len() + value.len())? as u64;
        self.store
            .insert(key.clone(), StorageModification::Write { value });
        self.ctx
            .ctx
            .charge_gas(checked!(gas * MEMORY_ACCESS_GAS_PER_BYTE)?)
    }

    fn delete(&mut self, key: &Key) -> Result<()> {
        self.store.insert(key.clone(), StorageModification::Delete);
        let len = key.len() as u64;
        self.ctx
            .ctx
            .charge_gas(checked!(len * MEMORY_ACCESS_GAS_PER_BYTE)?)
    }
}

impl<'view, 'a, S, CA, EVAL, Token> IbcStorageContext
    for PseudoExecutionContext<'view, 'a, S, CA, EVAL, Token>
where
    S: 'static + StateRead,
    EVAL: 'static + VpEvaluator<'a, S, CA, EVAL>,
    CA: 'static + Clone,
    Token: token::Keys
        + token::Write<
            PseudoExecutionStorage<'view, 'a, S, CA, EVAL>,
            Err = StorageError,
        >,
{
    type Storage = PseudoExecutionStorage<'view, 'a, S, CA, EVAL>;

    fn storage(&self) -> &Self::Storage {
        &self.storage
    }

    fn storage_mut(&mut self) -> &mut Self::Storage {
        &mut self.storage
    }

    fn emit_ibc_event(&mut self, event: IbcEvent) -> Result<()> {
        self.storage.event.insert(event.into());
        Ok(())
    }

    fn transfer_token(
        &mut self,
        src: &Address,
        dest: &Address,
        token: &Address,
        amount: Amount,
    ) -> Result<()> {
        let storage = self.storage_mut();
        Token::transfer(storage, token, src, dest, amount)
    }

    fn mint_token(
        &mut self,
        target: &Address,
        token: &Address,
        amount: Amount,
    ) -> Result<()> {
        let storage = self.storage_mut();
        Token::credit_tokens(storage, token, target, amount)?;

        let minter_key = Token::minter_key(token);
        StorageWrite::write(
            storage,
            &minter_key,
            Address::Internal(InternalAddress::Ibc).serialize_to_vec(),
        )
    }

    fn burn_token(
        &mut self,
        target: &Address,
        token: &Address,
        amount: Amount,
    ) -> Result<()> {
        let storage = self.storage_mut();
        Token::burn_tokens(storage, token, target, amount)
    }

    fn insert_verifier(&mut self, _verifier: &Address) -> Result<()> {
        Ok(())
    }

    fn log_string(&self, message: String) {
        tracing::debug!("{message} in the pseudo execution for IBC VP");
    }
}

impl<'view, 'a, S, CA, EVAL, Token> IbcCommonContext
    for PseudoExecutionContext<'view, 'a, S, CA, EVAL, Token>
where
    S: 'static + StateRead,
    CA: 'static + Clone,
    EVAL: 'static + VpEvaluator<'a, S, CA, EVAL>,
    Token: token::Keys
        + token::Write<
            PseudoExecutionStorage<'view, 'a, S, CA, EVAL>,
            Err = StorageError,
        >,
{
}

/// Ibc native vp validation context
#[derive(Debug)]
pub struct VpValidationContext<'view, 'a, S, CA, EVAL>
where
    S: 'static + StateRead,
    EVAL: VpEvaluator<'a, S, CA, EVAL>,
{
    /// Context to read the post value
    ctx: CtxPreStorageRead<'view, 'a, S, CA, EVAL>,
}

impl<'view, 'a, S, CA, EVAL> VpValidationContext<'view, 'a, S, CA, EVAL>
where
    S: 'static + StateRead,
    EVAL: VpEvaluator<'a, S, CA, EVAL>,
{
    /// Generate a new ibc vp validation context
    pub fn new(ctx: CtxPreStorageRead<'view, 'a, S, CA, EVAL>) -> Self {
        Self { ctx }
    }
}

impl<'view, 'a, S, CA, EVAL> StorageRead
    for VpValidationContext<'view, 'a, S, CA, EVAL>
where
    S: 'static + StateRead,
    CA: 'static + Clone,
    EVAL: 'static + VpEvaluator<'a, S, CA, EVAL>,
{
    type PrefixIter<'iter> = PrefixIter<'iter, <S as StateRead>::D> where Self: 'iter;

    fn read_bytes(&self, key: &Key) -> Result<Option<Vec<u8>>> {
        self.ctx.read_bytes(key)
    }

    fn has_key(&self, key: &Key) -> Result<bool> {
        self.ctx.has_key(key)
    }

    fn iter_prefix<'iter>(
        &'iter self,
        prefix: &Key,
    ) -> Result<Self::PrefixIter<'iter>> {
        self.ctx.iter_prefix(prefix)
    }

    fn iter_next<'iter>(
        &'iter self,
        iter: &mut Self::PrefixIter<'iter>,
    ) -> Result<Option<(String, Vec<u8>)>> {
        self.ctx.iter_next(iter)
    }

    fn get_chain_id(&self) -> Result<String> {
        self.ctx.get_chain_id()
    }

    fn get_block_height(&self) -> Result<BlockHeight> {
        self.ctx.get_block_height()
    }

    fn get_block_header(&self, height: BlockHeight) -> Result<Option<Header>> {
        self.ctx.get_block_header(height)
    }

    fn get_block_epoch(&self) -> Result<Epoch> {
        self.ctx.get_block_epoch()
    }

    fn get_tx_index(&self) -> Result<TxIndex> {
        self.ctx.get_tx_index()
    }

    fn get_native_token(&self) -> Result<Address> {
        self.ctx.get_native_token()
    }

    fn get_pred_epochs(&self) -> Result<Epochs> {
        self.ctx.get_pred_epochs()
    }
}

impl<'view, 'a, S, CA, EVAL> StorageWrite
    for VpValidationContext<'view, 'a, S, CA, EVAL>
where
    S: 'static + StateRead,
    CA: 'static + Clone,
    EVAL: VpEvaluator<'a, S, CA, EVAL>,
{
    fn write_bytes(
        &mut self,
        _key: &Key,
        _val: impl AsRef<[u8]>,
    ) -> Result<()> {
        unimplemented!("Validation doesn't write any data")
    }

    fn delete(&mut self, _key: &Key) -> Result<()> {
        unimplemented!("Validation doesn't delete any data")
    }
}

impl<'view, 'a, S, CA, EVAL> IbcStorageContext
    for VpValidationContext<'view, 'a, S, CA, EVAL>
where
    S: 'static + StateRead,
    CA: 'static + Clone,
    EVAL: 'static + VpEvaluator<'a, S, CA, EVAL>,
{
    type Storage = Self;

    fn storage(&self) -> &Self::Storage {
        self
    }

    fn storage_mut(&mut self) -> &mut Self::Storage {
        self
    }

    fn emit_ibc_event(&mut self, _event: IbcEvent) -> Result<()> {
        unimplemented!("Validation doesn't emit an event")
    }

    fn transfer_token(
        &mut self,
        _src: &Address,
        _dest: &Address,
        _token: &Address,
        _amount: Amount,
    ) -> Result<()> {
        unimplemented!("Validation doesn't transfer")
    }

    fn mint_token(
        &mut self,
        _target: &Address,
        _token: &Address,
        _amount: Amount,
    ) -> Result<()> {
        unimplemented!("Validation doesn't mint")
    }

    fn burn_token(
        &mut self,
        _target: &Address,
        _token: &Address,
        _amount: Amount,
    ) -> Result<()> {
        unimplemented!("Validation doesn't burn")
    }

    fn insert_verifier(&mut self, _verifier: &Address) -> Result<()> {
        Ok(())
    }

    /// Logging
    fn log_string(&self, message: String) {
        tracing::debug!("{message} for validation in IBC VP");
    }
}

impl<'view, 'a, S, CA, EVAL> IbcCommonContext
    for VpValidationContext<'view, 'a, S, CA, EVAL>
where
    S: 'static + StateRead,
    CA: 'static + Clone,
    EVAL: 'static + VpEvaluator<'a, S, CA, EVAL>,
{
}
