//! A tx for adding a transfer request across the Ethereum bridge
//! into the bridge pool.
use namada_tx_prelude::eth_bridge_pool::{
    BRIDGE_POOL_ADDRESS, GasFee, PendingTransfer, TransferToEthereum,
    get_pending_key,
};
use namada_tx_prelude::parameters::native_erc20_key;
use namada_tx_prelude::*;

#[transaction]
fn apply_tx(ctx: &mut Ctx, tx_data: BatchedTx) -> TxResult {
    let data = ctx.get_tx_data(&tx_data)?;
    let transfer = PendingTransfer::try_from_slice(&data[..])
        .map_err(|e| Error::wrap("Error deserializing PendingTransfer", e))?;
    debug_log!("Received transfer to add to Bridge pool");
    // pay the gas fees
    let GasFee {
        token: ref fee_token_addr,
        amount,
        ref payer,
    } = transfer.gas_fee;
    token::transfer(ctx, payer, &BRIDGE_POOL_ADDRESS, fee_token_addr, amount)?;
    debug_log!("Bridge pool token transfer succeeded");
    let TransferToEthereum {
        asset,
        ref sender,
        amount,
        ..
    } = transfer.transfer;
    // if minting wNam, escrow the correct amount
    if asset == native_erc20_address(ctx)? {
        let nam_addr = ctx.get_native_token()?;
        token::transfer(ctx, sender, &address::ETH_BRIDGE, &nam_addr, amount)?;
    } else {
        // Otherwise we escrow ERC20 tokens.
        let token = transfer.token_address();
        token::transfer(ctx, sender, &BRIDGE_POOL_ADDRESS, &token, amount)?;
    }
    debug_log!("Bridge pool escrow succeeded");
    // add transfer into the pool
    let pending_key = get_pending_key(&transfer);
    ctx.write(&pending_key, transfer)
        .wrap_err("Could not write transfer to bridge pool")?;
    Ok(())
}

fn native_erc20_address(ctx: &mut Ctx) -> Result<EthAddress> {
    debug_log!("Trying to get wnam key for Bridge pool transfer");
    let addr = ctx
        .read(&native_erc20_key())
        .wrap_err("Could not read wrapped NAM address")?
        .ok_or_err_msg("Wrapped NAM address must be present in storage")?;
    debug_log!("Got wnam key for Bridge pool transfer: {addr}");
    Ok(addr)
}
