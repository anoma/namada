use namada_tx_prelude::*;

#[transaction(gas = 1000)]
fn apply_tx(_ctx: &mut Ctx, _tx_data: Tx) -> TxResult {
    Err(Error::SimpleMessage("failed tx"))
}