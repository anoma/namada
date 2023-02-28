//! IBC lower-level functions for transactions.

pub use namada_core::ledger::ibc::{Error, IbcActions, IbcStorageContext};
use namada_core::ledger::ibc::{ProofSpec, TransferModule};
use namada_core::ledger::storage_api::{StorageRead, StorageWrite};
use namada_core::ledger::tx_env::TxEnv;
pub use namada_core::types::ibc::IbcEvent;
use namada_core::types::storage::{BlockHeight, Header, Key};
use namada_core::types::token::Amount;

use crate::token::transfer_with_keys;
use crate::{Ctx, KeyValIterator};

impl IbcStorageContext for Ctx {
    type Error = crate::Error;
    type PrefixIter<'iter> = KeyValIterator<(String, Vec<u8>)>;

    fn read(
        &self,
        key: &Key,
    ) -> std::result::Result<Option<Vec<u8>>, Self::Error> {
        self.read_bytes(key)
    }

    fn write(
        &mut self,
        key: &Key,
        data: Vec<u8>,
    ) -> std::result::Result<(), Self::Error> {
        self.write_bytes(key, data)?;
        Ok(())
    }

    fn iter_prefix<'iter>(
        &'iter self,
        prefix: &Key,
    ) -> Result<Self::PrefixIter<'iter>, Self::Error> {
        StorageRead::iter_prefix(self, prefix)
    }

    fn iter_next<'iter>(
        &'iter self,
        iter: &mut Self::PrefixIter<'iter>,
    ) -> Result<Option<(String, Vec<u8>)>, Self::Error> {
        StorageRead::iter_next(self, iter)
    }

    fn delete(&mut self, key: &Key) -> std::result::Result<(), Self::Error> {
        StorageWrite::delete(self, key)
    }

    fn emit_ibc_event(
        &mut self,
        event: IbcEvent,
    ) -> std::result::Result<(), Self::Error> {
        <Ctx as TxEnv>::emit_ibc_event(self, &event)
    }

    fn transfer_token(
        &mut self,
        src: &Key,
        dest: &Key,
        amount: Amount,
    ) -> std::result::Result<(), Self::Error> {
        transfer_with_keys(self, src, dest, amount)
    }

    fn get_height(&self) -> std::result::Result<BlockHeight, Self::Error> {
        self.get_block_height()
    }

    fn get_header(
        &self,
        height: BlockHeight,
    ) -> std::result::Result<Option<Header>, Self::Error> {
        self.get_block_header(height)
    }

    fn get_chain_id(&self) -> Result<String, Self::Error> {
        StorageRead::get_chain_id(self)
    }

    fn get_proof_specs(&self) -> Vec<ProofSpec> {
        unimplemented!("Transaction doesn't need the proof specs")
    }

    fn log_string(&self, message: String) {
        super::log_string(message);
    }
}

pub fn ibc_actions(ctx: &'static mut Ctx) -> IbcActions<Ctx> {
    IbcActions::new(ctx)
}

pub fn transfer_module<C>(
    actions: &'static mut IbcActions<C>,
) -> TransferModule<C>
where
    C: IbcStorageContext + 'static,
{
    TransferModule::new(actions)
}

pub fn add_transfer_module<C>(
    actions: &'static mut IbcActions<C>,
    module: TransferModule<C>,
) where
    C: IbcStorageContext + std::fmt::Debug + 'static,
{
    actions.add_route(module.module_id(), module);
}
