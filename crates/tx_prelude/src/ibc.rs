//! IBC lower-level functions for transactions.

use std::cell::RefCell;
use std::collections::BTreeSet;
use std::rc::Rc;

use namada_core::address::Address;
use namada_core::token::Amount;
pub use namada_ibc::event::{IbcEvent, IbcEventType};
pub use namada_ibc::storage::{
    burn_tokens, client_state_key, is_ibc_key, mint_limit_key, mint_tokens,
    throughput_limit_key, upgraded_client_state_key,
    upgraded_consensus_state_key,
};
pub use namada_ibc::trace::ibc_token;
pub use namada_ibc::{
    IbcActions, IbcCommonContext, IbcStorageContext, NftTransferModule,
    ProofSpec, TransferModule,
};

use super::token::transfer;
use super::{parameters, token, Ctx};
use crate::{Result, TxEnv};

/// IBC actions to handle an IBC message. The `verifiers` inserted into the set
/// must be inserted into the tx context with `Ctx::insert_verifier` after tx
/// execution.
pub fn ibc_actions(
    ctx: &mut Ctx,
) -> IbcActions<'_, CtxWrapper, parameters::Store<Ctx>, token::Store<Ctx>> {
    let ctx = Rc::new(RefCell::new(CtxWrapper(ctx.clone())));
    let verifiers = Rc::new(RefCell::new(BTreeSet::<Address>::new()));
    let mut actions = IbcActions::new(ctx.clone(), verifiers.clone());
    let module = TransferModule::new(ctx.clone(), verifiers);
    actions.add_transfer_module(module);
    let module = NftTransferModule::<CtxWrapper, token::Store<Ctx>>::new(ctx);
    actions.add_transfer_module(module);
    actions
}

/// A wrapper type to impl foreign traits on foreign type
#[derive(Debug)]
pub struct CtxWrapper(Ctx);

impl IbcStorageContext for CtxWrapper {
    type Storage = Ctx;

    fn storage(&self) -> &Self::Storage {
        &self.0
    }

    fn storage_mut(&mut self) -> &mut Self::Storage {
        &mut self.0
    }

    fn log_string(&self, message: String) {
        super::log_string(message);
    }

    fn emit_ibc_event(&mut self, event: IbcEvent) -> Result<()> {
        <Ctx as TxEnv>::emit_event(&mut self.0, event)
    }

    fn transfer_token(
        &mut self,
        src: &Address,
        dest: &Address,
        token: &Address,
        amount: Amount,
    ) -> Result<()> {
        transfer(&mut self.0, src, dest, token, amount)
    }

    fn mint_token(
        &mut self,
        target: &Address,
        token: &Address,
        amount: Amount,
    ) -> Result<()> {
        mint_tokens::<_, token::Store<_>>(&mut self.0, target, token, amount)
    }

    fn burn_token(
        &mut self,
        target: &Address,
        token: &Address,
        amount: Amount,
    ) -> Result<()> {
        burn_tokens::<_, token::Store<_>>(&mut self.0, target, token, amount)
    }

    fn insert_verifier(&mut self, addr: &Address) -> Result<()> {
        TxEnv::insert_verifier(&mut self.0, addr)
    }
}

impl IbcCommonContext for CtxWrapper {}
