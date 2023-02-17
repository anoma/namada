use std::collections::HashMap;
use std::io::Write;
use std::sync::Arc;

use borsh::BorshSerialize;
use ethbridge_bridge_contract::Bridge;
use namada::eth_bridge::ethers::abi::AbiDecode;
use namada::eth_bridge::ethers::prelude::{Http, Provider};
use namada::eth_bridge::structs::RelayProof;
use namada::ledger::queries::RPC;
use namada::proto::Tx;
use namada::types::address::Address;
use namada::types::eth_abi::Encode;
use namada::types::eth_bridge_pool::{
    GasFee, PendingTransfer, TransferToEthereum,
};
use namada::types::keccak::KeccakHash;
use namada::types::token::Amount;
use serde::{Deserialize, Serialize};

use super::super::signing::TxSigningKey;
use super::super::tx::process_tx;
use crate::cli::{args, safe_exit, Context};
use crate::facade::tendermint_rpc::HttpClient;

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
        },
        gas_fee: GasFee {
            amount: gas_amount,
            payer: ctx.get(gas_payer),
        },
    };
    let data = transfer.try_to_vec().unwrap();
    let transfer_tx = Tx::new(tx_code, Some(data));
    // this should not initialize any new addresses, so we ignore the result.
    process_tx(ctx, tx, transfer_tx, TxSigningKey::None).await;
}

/// A json serializable representation of the Ethereum
/// bridge pool.
#[derive(Serialize, Deserialize)]
struct BridgePoolResponse {
    bridge_pool_contents: HashMap<String, PendingTransfer>,
}

/// Query the contents of the Ethereum bridge pool.
/// Prints out a json payload.
pub async fn query_bridge_pool(args: args::Query) {
    let client = HttpClient::new(args.ledger_address).unwrap();
    let response: Vec<PendingTransfer> = RPC
        .shell()
        .eth_bridge()
        .read_ethereum_bridge_pool(&client)
        .await
        .unwrap();
    let pool_contents: HashMap<String, PendingTransfer> = response
        .into_iter()
        .map(|transfer| (transfer.keccak256().to_string(), transfer))
        .collect();
    if pool_contents.is_empty() {
        println!("Bridge pool is empty.");
        return;
    }
    let contents = BridgePoolResponse {
        bridge_pool_contents: pool_contents,
    };
    println!("{}", serde_json::to_string_pretty(&contents).unwrap());
}

/// Query the contents of the Ethereum bridge pool that
/// is covered by the latest signed root.
/// Prints out a json payload.
pub async fn query_signed_bridge_pool(
    args: args::Query,
) -> HashMap<String, PendingTransfer> {
    let client = HttpClient::new(args.ledger_address).unwrap();
    let response: Vec<PendingTransfer> = RPC
        .shell()
        .eth_bridge()
        .read_signed_ethereum_bridge_pool(&client)
        .await
        .unwrap();
    let pool_contents: HashMap<String, PendingTransfer> = response
        .into_iter()
        .map(|transfer| (transfer.keccak256().to_string(), transfer))
        .collect();
    if pool_contents.is_empty() {
        println!("Bridge pool is empty.");
        safe_exit(0);
    }
    let contents = BridgePoolResponse {
        bridge_pool_contents: pool_contents.clone(),
    };
    println!("{}", serde_json::to_string_pretty(&contents).unwrap());
    pool_contents
}

/// Iterates over all ethereum events
/// and returns the amount of voting power
/// backing each `TransferToEthereum` event.
///
/// Prints a json payload.
pub async fn query_relay_progress(args: args::Query) {
    let client = HttpClient::new(args.ledger_address).unwrap();
    let resp = RPC
        .shell()
        .eth_bridge()
        .transfer_to_ethereum_progress(&client)
        .await
        .unwrap();
    println!("{}", serde_json::to_string_pretty(&resp).unwrap());
}

/// Internal methdod to construct a proof that a set of transfers are in the
/// bridge pool.
async fn construct_bridge_pool_proof(
    client: &HttpClient,
    transfers: &[KeccakHash],
    relayer: Address,
) -> Vec<u8> {
    let in_progress = RPC
        .shell()
        .eth_bridge()
        .transfer_to_ethereum_progress(client)
        .await
        .unwrap();

    let warnings: Vec<_> = in_progress
        .keys()
        .filter_map(|k| {
            let hash = PendingTransfer::from(k).keccak256();
            transfers.contains(&hash).then_some(hash)
        })
        .collect();

    if !warnings.is_empty() {
        println!(
            "\x1b[93mWarning: The following hashes correspond to transfers \
             \nthat have been relayed but do not yet have a quorum of \
             \nvalidator signatures; thus they are still in the bridge \
             pool:\n\x1b[0m{:?}",
            warnings
        );
        print!("\nDo you wish to proceed? (y/n): ");
        std::io::stdout().flush().unwrap();
        loop {
            let mut buffer = String::new();
            let stdin = std::io::stdin();
            stdin.read_line(&mut buffer).unwrap_or_else(|e| {
                println!("Encountered error reading from STDIN: {:?}", e);
                safe_exit(1)
            });
            match buffer.trim() {
                "y" => break,
                "n" => safe_exit(0),
                _ => {
                    print!("Expected 'y' or 'n'. Please try again: ");
                    std::io::stdout().flush().unwrap();
                }
            }
        }
    }

    let data = (transfers, relayer).try_to_vec().unwrap();
    let response = RPC
        .shell()
        .eth_bridge()
        .generate_bridge_pool_proof(client, Some(data), None, false)
        .await;

    match response {
        Ok(response) => response.data,
        Err(e) => {
            println!("Encountered error constructing proof:\n{:?}", e);
            safe_exit(1)
        }
    }
}

/// A response from construction a bridge pool proof.
#[derive(Serialize)]
struct BridgePoolProofResponse {
    hashes: Vec<KeccakHash>,
    relayer_address: Address,
    total_fees: Amount,
    abi_encoded_proof: Vec<u8>,
}

/// Construct a merkle proof of a batch of transfers in
/// the bridge pool and return it to the user (as opposed
/// to relaying it to ethereum).
pub async fn construct_proof(args: args::BridgePoolProof) {
    let client = HttpClient::new(args.query.ledger_address).unwrap();
    let bp_proof_bytes = construct_bridge_pool_proof(
        &client,
        &args.transfers,
        args.relayer.clone(),
    )
    .await;
    let bp_proof: RelayProof = match AbiDecode::decode(&bp_proof_bytes) {
        Ok(proof) => proof,
        Err(error) => {
            println!("Unable to decode the generated proof: {:?}", error);
            safe_exit(1)
        }
    };
    let resp = BridgePoolProofResponse {
        hashes: args.transfers,
        relayer_address: args.relayer,
        total_fees: bp_proof
            .transfers
            .iter()
            .map(|t| t.fee.as_u64())
            .sum::<u64>()
            .into(),
        abi_encoded_proof: bp_proof_bytes,
    };
    println!("{}", serde_json::to_string(&resp).unwrap());
}

/// Relay a validator set update, signed off for a given epoch.
pub async fn relay_bridge_pool_proof(args: args::RelayBridgePoolProof) {
    let nam_client = HttpClient::new(args.query.ledger_address).unwrap();
    let bp_proof =
        construct_bridge_pool_proof(&nam_client, &args.transfers, args.relayer)
            .await;
    let eth_client =
        Arc::new(Provider::<Http>::try_from(&args.eth_rpc_endpoint).unwrap());
    let bridge = match RPC
        .shell()
        .eth_bridge()
        .read_bridge_contract(&nam_client)
        .await
    {
        Ok(address) => Bridge::new(address.address, eth_client),
        error => {
            println!(
                "Failed to retreive the Ethereum Bridge smart contract \
                 address from storage with reason:\n{:?}\n\nPerhaps the \
                 Ethereum bridge is not active.",
                error
            );
            safe_exit(1)
        }
    };
    let bp_proof = match AbiDecode::decode(&bp_proof) {
        Ok(proof) => proof,
        Err(error) => {
            println!("Unable to decode the generated proof: {:?}", error);
            safe_exit(1)
        }
    };
    let mut relay_op = bridge.transfer_to_erc(bp_proof);
    if let Some(gas) = args.gas {
        relay_op.tx.set_gas(gas);
    }
    if let Some(gas_price) = args.gas_price {
        relay_op.tx.set_gas_price(gas_price);
    }
    if let Some(eth_addr) = args.eth_addr {
        relay_op.tx.set_from(eth_addr.into());
    }

    let pending_tx = relay_op.send().await.unwrap();
    let transf_result = pending_tx
        .confirmations(args.confirmations as usize)
        .await
        .unwrap();

    println!("{transf_result:?}");
}

mod recommendations {
    use super::*;
    const BASE_GAS: u64 = 800_000;
    const TRANSFER_FEE: i64 = 50_000;

    /// The different states while trying to solve
    /// for a recommended batch of transfers.
    struct AlgorithState {
        /// We are scanning transfers that increase
        /// net profits to the relayer. However, we
        /// are not in the feasible region.
        profitable: bool,
        /// We are scanning solutions that satisfy the
        /// requirements of the input.
        feasible_region: bool,
    }

    /// Recommend the most economical batch of transfers to relay based
    /// on a conversion rate estimates from NAM to ETH and gas usage
    /// heuristics.
    pub async fn recommend_batch(args: args::RecommendBatch) {
        let client =
            HttpClient::new(args.query.ledger_address.clone()).unwrap();
        // get transfers that can already been relayed but are awaiting a quorum
        // of backing votes.
        let in_progress = RPC
            .shell()
            .eth_bridge()
            .transfer_to_ethereum_progress(&client)
            .await
            .unwrap()
            .keys()
            .map(PendingTransfer::from)
            .collect::<Vec<_>>();

        let gwei_per_nam =
            (10u64.pow(9) as f64 / args.nam_per_eth).floor() as u64;

        // we don't recommend transfers that have already been relayed
        let mut contents: Vec<(String, i64, PendingTransfer)> =
            query_signed_bridge_pool(args.query)
                .await
                .into_iter()
                .filter_map(|(k, v)| {
                    if !in_progress.contains(&v) {
                        Some((
                            k,
                            TRANSFER_FEE
                                - u64::from(v.gas_fee.amount * gwei_per_nam)
                                    as i64,
                            v,
                        ))
                    } else {
                        None
                    }
                })
                .collect();

        // sort transfers in decreasing amounts of profitability
        contents.sort_by_key(|(_, cost, _)| *cost);

        let max_gas = args.max_gas.unwrap_or(u64::MAX);
        let max_cost = args.gas.map(|x| x as i64).unwrap_or_default();
        let mut state = AlgorithState {
            profitable: true,
            feasible_region: false,
        };

        let mut total_gas = BASE_GAS;
        let mut total_cost = BASE_GAS as i64;
        let mut total_fees = 0;
        let mut recommendation = vec![];
        for (hash, cost, transfer) in contents.into_iter() {
            let next_total_gas = total_gas + TRANSFER_FEE as u64;
            let next_total_cost = total_cost + cost;
            let next_total_fees =
                total_fees + u64::from(transfer.gas_fee.amount);
            if cost < 0 {
                if total_gas <= max_gas && total_cost <= max_cost {
                    state.feasible_region = true;
                } else if state.feasible_region {
                    // once we leave the feasible region, we will never re-enter
                    // it.
                    break;
                }
                recommendation.push(hash);
            } else {
                state.profitable = false;
                let is_feasible =
                    total_gas <= max_gas && total_cost <= max_cost;
                // once we leave the feasible region, we will never re-enter it.
                if state.feasible_region && !is_feasible {
                    break;
                } else {
                    recommendation.push(hash);
                }
            }
            total_cost = next_total_cost;
            total_gas = next_total_gas;
            total_fees = next_total_fees;
        }

        if state.feasible_region && !recommendation.is_empty() {
            println!("Recommended batch: {:?}", recommendation);
            println!("Total gas (in gwei): {}", total_gas);
            println!("Total cost (in gwei): {}", total_cost);
            println!("Total fees (in NAM): {}", total_fees);
        } else {
            println!(
                "Unable to find a recommendation satisfying the input \
                 parameters."
            )
        }
    }
}

pub use recommendations::recommend_batch;
