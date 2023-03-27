//! Namada client CLI.

use std::time::Duration;

use color_eyre::eyre::Result;
use namada_apps::cli::cmds::*;
use namada_apps::cli::{self, safe_exit};
use namada_apps::client::{rpc, tx, utils};
use namada_apps::facade::tendermint::block::Height;
use namada_apps::facade::tendermint_config::net::Address as TendermintAddress;
use namada_apps::facade::tendermint_rpc::{Client, HttpClient};
use tokio::time::sleep;

const WAIT_FOR_LEDGER_SYNC: u64 = 5;

pub async fn main() -> Result<()> {
    match cli::namada_client_cli()? {
        cli::NamadaClient::WithContext(cmd_box) => {
            let (cmd, ctx) = *cmd_box;
            use NamadaClientWithContext as Sub;
            match cmd {
                // Ledger cmds
                Sub::TxCustom(TxCustom(args)) => {
                    wait_until_node_is_synched(&args.tx.ledger_address).await;
                    tx::submit_custom(ctx, args).await;
                }
                Sub::TxTransfer(TxTransfer(args)) => {
                    wait_until_node_is_synched(&args.tx.ledger_address).await;
                    tx::submit_transfer(ctx, args).await;
                }
                Sub::TxIbcTransfer(TxIbcTransfer(args)) => {
                    wait_until_node_is_synched(&args.tx.ledger_address).await;
                    tx::submit_ibc_transfer(ctx, args).await;
                }
                Sub::TxUpdateVp(TxUpdateVp(args)) => {
                    wait_until_node_is_synched(&args.tx.ledger_address).await;
                    tx::submit_update_vp(ctx, args).await;
                }
                Sub::TxInitAccount(TxInitAccount(args)) => {
                    wait_until_node_is_synched(&args.tx.ledger_address).await;
                    tx::submit_init_account(ctx, args).await;
                }
                Sub::TxInitValidator(TxInitValidator(args)) => {
                    wait_until_node_is_synched(&args.tx.ledger_address).await;
                    tx::submit_init_validator(ctx, args).await;
                }
                Sub::TxInitProposal(TxInitProposal(args)) => {
                    wait_until_node_is_synched(&args.tx.ledger_address).await;
                    tx::submit_init_proposal(ctx, args).await;
                }
                Sub::TxVoteProposal(TxVoteProposal(args)) => {
                    wait_until_node_is_synched(&args.tx.ledger_address).await;
                    tx::submit_vote_proposal(ctx, args).await;
                }
                Sub::TxRevealPk(TxRevealPk(args)) => {
                    wait_until_node_is_synched(&args.tx.ledger_address).await;
                    tx::submit_reveal_pk(ctx, args).await;
                }
                Sub::Bond(Bond(args)) => {
                    wait_until_node_is_synched(&args.tx.ledger_address).await;
                    tx::submit_bond(ctx, args).await;
                }
                Sub::Unbond(Unbond(args)) => {
                    wait_until_node_is_synched(&args.tx.ledger_address).await;
                    tx::submit_unbond(ctx, args).await;
                }
                Sub::Withdraw(Withdraw(args)) => {
                    wait_until_node_is_synched(&args.tx.ledger_address).await;
                    tx::submit_withdraw(ctx, args).await;
                }
                // Ledger queries
                Sub::QueryEpoch(QueryEpoch(args)) => {
                    wait_until_node_is_synched(&args.ledger_address).await;
                    rpc::query_and_print_epoch(args).await;
                }
                Sub::QueryTransfers(QueryTransfers(args)) => {
                    wait_until_node_is_synched(&args.query.ledger_address)
                        .await;
                    rpc::query_transfers(ctx, args).await;
                }
                Sub::QueryConversions(QueryConversions(args)) => {
                    wait_until_node_is_synched(&args.query.ledger_address)
                        .await;
                    rpc::query_conversions(ctx, args).await;
                }
                Sub::QueryBlock(QueryBlock(args)) => {
                    wait_until_node_is_synched(&args.ledger_address).await;
                    rpc::query_block(args).await;
                }
                Sub::QueryBalance(QueryBalance(args)) => {
                    wait_until_node_is_synched(&args.query.ledger_address)
                        .await;
                    rpc::query_balance(ctx, args).await;
                }
                Sub::QueryBonds(QueryBonds(args)) => {
                    wait_until_node_is_synched(&args.query.ledger_address)
                        .await;
                    rpc::query_bonds(ctx, args).await;
                }
                Sub::QueryBondedStake(QueryBondedStake(args)) => {
                    wait_until_node_is_synched(&args.query.ledger_address)
                        .await;
                    rpc::query_bonded_stake(ctx, args).await;
                }
                Sub::QueryCommissionRate(QueryCommissionRate(args)) => {
                    wait_until_node_is_synched(&args.query.ledger_address)
                        .await;
                    rpc::query_and_print_commission_rate(ctx, args).await;
                }
                Sub::QuerySlashes(QuerySlashes(args)) => {
                    wait_until_node_is_synched(&args.query.ledger_address)
                        .await;
                    rpc::query_slashes(ctx, args).await;
                }
                Sub::QueryDelegations(QueryDelegations(args)) => {
                    wait_until_node_is_synched(&args.query.ledger_address)
                        .await;
                    rpc::query_delegations(ctx, args).await;
                }
                Sub::QueryResult(QueryResult(args)) => {
                    wait_until_node_is_synched(&args.query.ledger_address)
                        .await;
                    rpc::query_result(ctx, args).await;
                }
                Sub::QueryRawBytes(QueryRawBytes(args)) => {
                    wait_until_node_is_synched(&args.query.ledger_address)
                        .await;
                    rpc::query_raw_bytes(ctx, args).await;
                }

                Sub::QueryProposal(QueryProposal(args)) => {
                    wait_until_node_is_synched(&args.query.ledger_address)
                        .await;
                    rpc::query_proposal(ctx, args).await;
                }
                Sub::QueryProposalResult(QueryProposalResult(args)) => {
                    wait_until_node_is_synched(&args.query.ledger_address)
                        .await;
                    rpc::query_proposal_result(ctx, args).await;
                }
                Sub::QueryProtocolParameters(QueryProtocolParameters(args)) => {
                    wait_until_node_is_synched(&args.query.ledger_address)
                        .await;
                    rpc::query_protocol_parameters(ctx, args).await;
                }
            }
        }
        cli::NamadaClient::WithoutContext(cmd, global_args) => match cmd {
            // Utils cmds
            Utils::JoinNetwork(JoinNetwork(args)) => {
                utils::join_network(global_args, args).await
            }
            Utils::FetchWasms(FetchWasms(args)) => {
                utils::fetch_wasms(global_args, args).await
            }
            Utils::InitNetwork(InitNetwork(args)) => {
                utils::init_network(global_args, args)
            }
            Utils::InitGenesisValidator(InitGenesisValidator(args)) => {
                utils::init_genesis_validator(global_args, args)
            }
        },
    }
    Ok(())
}

/// Wait for a first block and node to be synced. Will attempt to
async fn wait_until_node_is_synched(ledger_address: &TendermintAddress) {
    let client = HttpClient::new(ledger_address.clone()).unwrap();
    let height_one = Height::try_from(1_u64).unwrap();
    let mut try_count = 0;

    loop {
        let node_status = client.status().await;
        match node_status {
            Ok(status) => {
                let latest_block_height = status.sync_info.latest_block_height;
                let is_catching_up = status.sync_info.catching_up;
                let is_at_least_height_one = latest_block_height >= height_one;
                if is_at_least_height_one && !is_catching_up {
                    return;
                } else {
                    if try_count > MAX_TRIES {
                        println!(
                            "Node is still catching up, wait for it to finish \
                             synching."
                        );
                        safe_exit(1)
                    } else {
                        println!("Waiting for node to sync...");
                        sleep(Duration::from_secs(
                            WAIT_FOR_LEDGER_SYNC * try_count,
                        ))
                        .await;
                    }
                    try_count += 1;
                }
            }
            Err(e) => {
                eprintln!("Failed to query node status with error: {}", e);
                safe_exit(1)
            }
        }
    }
}
