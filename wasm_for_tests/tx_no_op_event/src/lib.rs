use namada_tx_prelude::*;

#[transaction]
fn apply_tx(ctx: &mut Ctx, tx_data: BatchedTx) -> TxResult {
    // Emit an event with the message contained in the transaction's data
    let data = ctx.get_tx_data(&tx_data)?;
    let data_str = String::try_from_slice(&data[..])
        .wrap_err("Failed to decode String tx data")?;
    let mut event = Event::new(EventType::new("test"), EventLevel::Tx);
    event.extend(Log(data_str));
    ctx.emit_event(event).wrap_err("Failed to emit event")?;

    Ok(())
}
