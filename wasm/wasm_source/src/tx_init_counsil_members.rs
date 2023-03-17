//! A tx to initialize a new established address with a given public key and
//! a validity predicate.

use namada_tx_prelude::*;

#[transaction]
fn apply_tx(ctx: &mut Ctx, tx_data: Vec<u8>) -> TxResult {
    let signed = SignedTxData::try_from_slice(&tx_data[..])
        .wrap_err("failed to decode SignedTxData")?;
    let data = signed.data.ok_or_err_msg("Missing data")?;
    let tx_data =
        transaction::counsil_treasury::PgfCounsilMembers::try_from_slice(
            &data[..],
        )
        .wrap_err("failed to decode PgfCounsilMembers")?;
    debug_log!("apply_tx called to update counsil");

    let counsil = pgf::get_current_counsil(ctx)?;
    match counsil {
        Some(counsil) => {
            pgf::update_pgf_counsil_treasury_members(ctx, tx_data)?;
            ctx.insert_verifier(&counsil.address)?;
            debug_log!("Pgf counsil treasury members updated");
        }
        None => {
            debug_log!("Error while updating Pgf counsil treasury members");
            panic!()
        }
    }

    Ok(())
}
