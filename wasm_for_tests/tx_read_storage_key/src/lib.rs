use namada_tx_prelude::*;

#[transaction]
fn apply_tx(ctx: &mut Ctx, tx_data: BatchedTx) -> TxResult {
    // Allocates a memory of size given from the `tx_data (usize)`
    let key = storage::Key::try_from_slice(
        &tx_data.to_ref().data().as_ref().unwrap()[..],
    )
    .unwrap();
    log_string(format!("key {}", key));
    let _result: Vec<u8> = ctx.read(&key)?.unwrap();
    Ok(())
}
