//! A tx for token transfer.
//! This tx uses `token::Transfer` wrapped inside `SignedTxData`
//! as its input as declared in `shared` crate.

use namada_tx_prelude::*;

#[transaction]
fn apply_tx(ctx: &mut Ctx, tx_data: Vec<u8>) -> TxResult {
    let signed = SignedTxData::try_from_slice(&tx_data[..])
        .wrap_err("failed to decode SignedTxData")?;
    let data = signed.data.ok_or_err_msg("Missing data")?;
    let transfer = token::Transfer::try_from_slice(&data[..])
        .wrap_err("failed to decode token::Transfer")?;
    debug_log!("apply_tx called with transfer: {:#?}", transfer);
    
    match pgf::pgf_transfer(ctx, transfer) {
        Ok(Some(counsil_address)) => ctx.insert_verifier(&counsil_address),
        _ => {
            debug_log!("Invalid pgf transfer.");
            panic!()
        }
    };

    Ok(())
}
