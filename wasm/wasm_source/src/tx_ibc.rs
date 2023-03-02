//! A tx for IBC.
//! This tx executes an IBC operation according to the given IBC message as the
//! tx_data. This tx uses an IBC message wrapped inside
//! `key::ed25519::SignedTxData` as its input as declared in `ibc` crate.

use namada_tx_prelude::*;

#[transaction]
fn apply_tx(ctx: &mut Ctx, tx_data: Vec<u8>) -> TxResult {
    let signed = SignedTxData::try_from_slice(&tx_data[..])
        .wrap_err("failed to decode SignedTxData")?;
    let data = signed.data.ok_or_err_msg("Missing data")?;

    // ibc-rs `Module` requires `static ctx. It is enough for The ctx to live at
    // least in `actions.execution()`.
    // https://github.com/cosmos/ibc-rs/issues/490
    let mut module_ctx = ctx.clone();
    let ref_mut_ctx = unsafe {
        core::mem::transmute::<&mut Ctx, &'static mut Ctx>(&mut module_ctx)
    };
    let module = IbcTransferModule::new(ref_mut_ctx);

    let mut actions = IbcActions::new(ctx);
    actions.add_route(module.module_id(), module);

    actions.execute(&data).into_storage_result()
}
