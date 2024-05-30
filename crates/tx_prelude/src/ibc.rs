//! IBC lower-level functions for transactions.

use std::cell::RefCell;
use std::collections::BTreeSet;
use std::rc::Rc;

use namada_core::address::Address;
use namada_core::token::Amount;
use namada_events::EventTypeBuilder;
pub use namada_ibc::event::{IbcEvent, IbcEventType};
pub use namada_ibc::storage::{
    burn_tokens, ibc_token, is_ibc_key, mint_limit_key, mint_tokens,
    throughput_limit_key,
};
pub use namada_ibc::{
    IbcActions, IbcCommonContext, IbcStorageContext, NftTransferModule,
    ProofSpec, TransferModule,
};
use namada_tx_env::TxEnv;

use crate::token::transfer;
use crate::{Ctx, Error};

/// IBC actions to handle an IBC message. The `verifiers` inserted into the set
/// must be inserted into the tx context with `Ctx::insert_verifier` after tx
/// execution.
pub fn ibc_actions(ctx: &mut Ctx) -> IbcActions<'_, Ctx> {
    let ctx = Rc::new(RefCell::new(ctx.clone()));
    let verifiers = Rc::new(RefCell::new(BTreeSet::<Address>::new()));
    let mut actions = IbcActions::new(ctx.clone(), verifiers.clone());
    let module = TransferModule::new(ctx.clone(), verifiers);
    actions.add_transfer_module(module);
    let module = NftTransferModule::new(ctx);
    actions.add_transfer_module(module);
    actions
}

impl IbcStorageContext for Ctx {
    fn emit_ibc_event(
        &mut self,
        event: IbcEvent,
    ) -> std::result::Result<(), Error> {
        <Ctx as TxEnv>::emit_event(self, event)
    }

    fn get_ibc_events(
        &self,
        event_type: impl AsRef<str>,
    ) -> Result<Vec<IbcEvent>, Error> {
        let event_type = EventTypeBuilder::new_of::<IbcEvent>()
            .with_segment(event_type.as_ref())
            .build();

        Ok(<Ctx as TxEnv>::get_events(self, &event_type)?
            .into_iter()
            .filter_map(|event| IbcEvent::try_from(event).ok())
            .collect())
    }

    fn transfer_token(
        &mut self,
        src: &Address,
        dest: &Address,
        token: &Address,
        amount: Amount,
    ) -> std::result::Result<(), Error> {
        transfer(self, src, dest, token, amount)
    }

    fn mint_token(
        &mut self,
        target: &Address,
        token: &Address,
        amount: Amount,
    ) -> Result<(), Error> {
        mint_tokens(self, target, token, amount)
    }

    fn burn_token(
        &mut self,
        target: &Address,
        token: &Address,
        amount: Amount,
    ) -> Result<(), Error> {
        burn_tokens(self, target, token, amount)
    }

    fn insert_verifier(&mut self, addr: &Address) -> Result<(), Error> {
        TxEnv::insert_verifier(self, addr)
    }

    fn log_string(&self, message: String) {
        super::log_string(message);
    }
}

impl IbcCommonContext for Ctx {}
