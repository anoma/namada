//! IBC lower-level functions for transactions.

use std::cell::RefCell;
use std::rc::Rc;

use namada_core::address::{Address, InternalAddress};
pub use namada_core::ibc::{IbcEvent, IbcShieldedTransfer};
use namada_core::token::DenominatedAmount;
pub use namada_ibc::storage::is_ibc_key;
pub use namada_ibc::{
    IbcActions, IbcCommonContext, IbcStorageContext, ProofSpec, TransferModule,
};
use namada_token::denom_to_amount;
use namada_tx_env::TxEnv;

use crate::token::{burn, mint, transfer};
use crate::{Ctx, Error};

/// IBC actions to handle an IBC message
pub fn ibc_actions(ctx: &mut Ctx) -> IbcActions<Ctx> {
    let ctx = Rc::new(RefCell::new(ctx.clone()));
    let mut actions = IbcActions::new(ctx.clone());
    let module = TransferModule::new(ctx);
    actions.add_transfer_module(module.module_id(), module);
    actions
}

impl IbcStorageContext for Ctx {
    fn emit_ibc_event(
        &mut self,
        event: IbcEvent,
    ) -> std::result::Result<(), Error> {
        <Ctx as TxEnv>::emit_ibc_event(self, &event)
    }

    fn get_ibc_events(
        &self,
        event_type: impl AsRef<str>,
    ) -> Result<Vec<IbcEvent>, Error> {
        <Ctx as TxEnv>::get_ibc_events(self, &event_type)
    }

    fn transfer_token(
        &mut self,
        src: &Address,
        dest: &Address,
        token: &Address,
        amount: DenominatedAmount,
    ) -> std::result::Result<(), Error> {
        transfer(self, src, dest, token, amount)
    }

    fn handle_masp_tx(
        &mut self,
        shielded: &masp_primitives::transaction::Transaction,
        pin_key: Option<&str>,
    ) -> Result<(), Error> {
        namada_token::utils::handle_masp_tx(self, shielded, pin_key)?;
        namada_token::utils::update_note_commitment_tree(self, shielded)
    }

    fn mint_token(
        &mut self,
        target: &Address,
        token: &Address,
        amount: DenominatedAmount,
    ) -> Result<(), Error> {
        mint(
            self,
            &Address::Internal(InternalAddress::Ibc),
            target,
            token,
            denom_to_amount(amount, token, self)?,
        )
    }

    fn burn_token(
        &mut self,
        target: &Address,
        token: &Address,
        amount: DenominatedAmount,
    ) -> Result<(), Error> {
        burn(self, target, token, denom_to_amount(amount, token, self)?)
    }

    fn log_string(&self, message: String) {
        super::log_string(message);
    }
}

impl IbcCommonContext for Ctx {}
