use borsh::{BorshDeserialize, BorshSerialize};
use namada::proto::Tx;
use namada::types::eth_bridge_pool::{
    GasFee, PendingTransfer, TransferToEthereum,
};

use super::tx::process_tx;
use crate::cli::{args, safe_exit, Context};
use crate::facade::tendermint::abci::Code;
use crate::facade::tendermint_rpc::{Client, HttpClient};
use crate::node::ledger::rpc::{BridgePoolSubpath, Path};

const ADD_TRANSFER_WASM: &str = "tx_bridge_pool.wasm";

/// Craft a transaction that adds a transfer to the Ethereum bridge pool.
pub async fn add_to_eth_bridge_pool(
    ctx: Context,
    args: args::EthereumBridgePool,
) {
    let args::EthereumBridgePool {
        ref tx,
        asset,
        recipient,
        ref sender,
        amount,
        gas_amount,
        ref gas_payer,
    } = args;
    let tx_code = ctx.read_wasm(ADD_TRANSFER_WASM);
    let transfer = PendingTransfer {
        transfer: TransferToEthereum {
            asset,
            recipient,
            sender: ctx.get(sender),
            amount,
            // TODO: Add real nonce
            nonce: Default::default(),
        },
        gas_fee: GasFee {
            amount: gas_amount,
            payer: ctx.get(gas_payer),
        },
    };
    let data = transfer.try_to_vec().unwrap();
    let transfer_tx = Tx::new(tx_code, Some(data));
    // this should not initialize any new addresses, so we ignore the result.
    process_tx(ctx, tx, transfer_tx, None).await;
}

/// Construct a proof that a set of transfers are in the bridge pool.
pub async fn construct_bridge_pool_proof(args: args::BridgePoolProof) {
    let client = HttpClient::new(args.query.ledger_address).unwrap();
    let path = Path::EthereumBridgePool(BridgePoolSubpath::Proof);
    let data = args.transfers.try_to_vec().unwrap();
    let response = client
        .abci_query(Some(path.into()), data, None, false)
        .await
        .unwrap();
    if response.code != Code::Ok {
        println!("{}", response.info);
    } else {
        println!("ABI Encoded Proof:\n {:#?}", response.value);
    }
}

/// Query the contents of the Ethereum bridge pool.
/// Prints out a json payload.
pub async fn query_bridge_pool(args: args::Query) {
    let client = HttpClient::new(args.ledger_address).unwrap();
    let path = Path::EthereumBridgePool(BridgePoolSubpath::Contents);
    let response = client
        .abci_query(Some(path.into()), vec![], None, false)
        .await
        .unwrap();
    if response.code != Code::Ok {
        println!("{}", response.info);
    } else {
        let transfers: Vec<PendingTransfer> =
            BorshDeserialize::try_from_slice(response.value.as_slice())
                .unwrap_or_else(|_| {
                    tracing::info!(
                        "Could not parse the response from the ledger."
                    );
                    safe_exit(1)
                });
        println!("{:#?}", serde_json::to_string_pretty(&transfers));
    }
}
