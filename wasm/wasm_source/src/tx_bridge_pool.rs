//! A tx for adding a transfer request across the Ethereum bridge
//! into the bridge pool.
use borsh::{BorshDeserialize, BorshSerialize};
use eth_bridge::storage::{bridge_pool, native_erc20_key, wrapped_erc20s};
use eth_bridge_pool::{GasFee, PendingTransfer, TransferToEthereum};
use namada_tx_prelude::*;

#[transaction]
fn apply_tx(ctx: &mut Ctx, tx_data: Vec<u8>) -> TxResult {
    let signed = SignedTxData::try_from_slice(&tx_data[..]).unwrap();
    let transfer =
        PendingTransfer::try_from_slice(&signed.data.unwrap()[..]).unwrap();
    // pay the gas fees
    let GasFee { amount, ref payer } = transfer.gas_fee;
    token::transfer(
        ctx,
        payer,
        &bridge_pool::BRIDGE_POOL_ADDRESS,
        &address::nam(),
        None,
        amount,
    )?;
    let TransferToEthereum {
        ref asset,
        ref sender,
        amount,
        ..
    } = transfer.transfer;
    // if minting wNam, escrow the correct amount
    if *asset == native_erc20_address(ctx) {
        token::transfer(
            ctx,
            sender,
            &eth_bridge::ADDRESS,
            &address::nam(),
            None,
            amount,
        )?;
    } else {
        // Otherwise we escrow ERC20 tokens.
        let sub_prefix = wrapped_erc20s::sub_prefix(&transfer.transfer.asset);
        token::transfer(
            ctx,
            sender,
            &bridge_pool::BRIDGE_POOL_ADDRESS,
            &eth_bridge::ADDRESS,
            Some(sub_prefix),
            amount,
        )?;
    }
    // add transfer into the pool
    let pending_key = bridge_pool::get_pending_key(&transfer);
    ctx.write_bytes(&pending_key, transfer.try_to_vec().unwrap())
        .unwrap();
    Ok(())
}

fn native_erc20_address(ctx: &mut Ctx) -> EthAddress {
    let addr = ctx.read_bytes(&native_erc20_key()).unwrap().unwrap();
    BorshDeserialize::try_from_slice(addr.as_slice()).unwrap()
}
