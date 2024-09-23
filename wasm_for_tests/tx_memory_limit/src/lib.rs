use namada_tx_prelude::*;

#[transaction]
fn apply_tx(_ctx: &mut Ctx, tx_data: BatchedTx) -> TxResult {
    let len =
        usize::try_from_slice(&tx_data.to_ref().data().as_ref().unwrap()[..])
            .unwrap();
    log_string(format!("allocate len {}", len));
    let bytes: Vec<u8> = vec![6_u8; len];
    // use the variable to prevent it from compiler optimizing it away
    log_string(format!("{:?}", &bytes[..8]));
    Ok(())
}
