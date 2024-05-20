use namada_tx_prelude::*;

#[transaction]
fn apply_tx(ctx: &mut Ctx, tx_data: BatchedTx) -> TxResult {
    let BatchedTx {
        tx: tx_data,
        ref cmt,
    } = tx_data;
    // Allocates a memory of size given from the `tx_data (usize)`
    let key =
        storage::Key::try_from_slice(&tx_data.data(cmt).as_ref().unwrap()[..])
            .unwrap();
    log_string(format!("key {}", key));
    let _result: Vec<u8> = ctx.read(&key)?.unwrap();
    Ok(())
}
