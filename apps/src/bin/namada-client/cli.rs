//! Namada client CLI.

use std::time::Duration;

use color_eyre::eyre::Result;
use namada_apps::cli::args::CliToSdk;
use namada_apps::cli::cmds::*;
use namada_apps::cli::{self, safe_exit};
use namada_apps::client::{rpc, tx, utils};
use namada_apps::facade::tendermint::block::Height;
use namada_apps::facade::tendermint_config::net::Address as TendermintAddress;
use namada_apps::facade::tendermint_rpc::{Client, HttpClient};
use namada_apps::wallet::CliWalletUtils;
use tokio::time::sleep;

pub async fn main() -> Result<()> {
    match cli::namada_client_cli()? {
        cli::NamadaClient::WithContext(cmd_box) => {
            let (cmd, mut ctx) = *cmd_box;
            use NamadaClientWithContext as Sub;
            match cmd {
                // Ledger cmds
                Sub::TxCustom(TxCustom(args)) => {
                    wait_until_node_is_synched(&args.tx.ledger_address).await;
                    let client =
                        HttpClient::new(args.tx.ledger_address.clone())
                            .unwrap();
                    let args = args.to_sdk(&mut ctx);
                    let dry_run = args.tx.dry_run;
                    tx::submit_custom::<HttpClient, CliWalletUtils>(
                        &client,
                        &mut ctx.wallet,
                        args,
                    )
                    .await?;
                    if !dry_run {
                        namada_apps::wallet::save(&ctx.wallet)
                            .unwrap_or_else(|err| eprintln!("{}", err));
                    } else {
                        println!(
                            "Transaction dry run. No addresses have been \
                             saved."
                        )
                    }
                }
                Sub::TxTransfer(TxTransfer(args)) => {
                    wait_until_node_is_synched(&args.tx.ledger_address).await;
                    let client =
                        HttpClient::new(args.tx.ledger_address.clone())
                            .unwrap();
                    let args = args.to_sdk(&mut ctx);
                    tx::submit_transfer::<HttpClient, CliWalletUtils, _>(
                        &client,
                        &mut ctx.wallet,
                        &mut ctx.shielded,
                        args,
                    )
                    .await?;
                }
                Sub::TxIbcTransfer(TxIbcTransfer(args)) => {
                    wait_until_node_is_synched(&args.tx.ledger_address).await;
                    let client =
                        HttpClient::new(args.tx.ledger_address.clone())
                            .unwrap();
                    let args = args.to_sdk(&mut ctx);
                    tx::submit_ibc_transfer::<HttpClient, CliWalletUtils>(
                        &client,
                        &mut ctx.wallet,
                        args,
                    )
                    .await?;
                }
                Sub::TxUpdateVp(TxUpdateVp(args)) => {
                    wait_until_node_is_synched(&args.tx.ledger_address).await;
                    let client =
                        HttpClient::new(args.tx.ledger_address.clone())
                            .unwrap();
                    let args = args.to_sdk(&mut ctx);
                    tx::submit_update_vp::<HttpClient, CliWalletUtils>(
                        &client,
                        &mut ctx.wallet,
                        args,
                    )
                    .await?;
                }
                Sub::TxInitAccount(TxInitAccount(args)) => {
                    wait_until_node_is_synched(&args.tx.ledger_address).await;
                    let client =
                        HttpClient::new(args.tx.ledger_address.clone())
                            .unwrap();
                    let args = args.to_sdk(&mut ctx);
                    let dry_run = args.tx.dry_run;
                    tx::submit_init_account::<HttpClient, CliWalletUtils>(
                        &client,
                        &mut ctx.wallet,
                        args,
                    )
                    .await?;
                    if !dry_run {
                        namada_apps::wallet::save(&ctx.wallet)
                            .unwrap_or_else(|err| eprintln!("{}", err));
                    } else {
                        println!(
                            "Transaction dry run. No addresses have been \
                             saved."
                        )
                    }
                }
                Sub::TxInitValidator(TxInitValidator(args)) => {
                    wait_until_node_is_synched(&args.tx.ledger_address).await;
                    let client =
                        HttpClient::new(args.tx.ledger_address.clone())
                            .unwrap();
                    let args = args.to_sdk(&mut ctx);
                    tx::submit_init_validator::<HttpClient>(&client, &mut ctx, args)
                        .await;
                }
                Sub::TxInitProposal(TxInitProposal(args)) => {
                    wait_until_node_is_synched(&args.tx.ledger_address).await;
                    let client =
                        HttpClient::new(args.tx.ledger_address.clone())
                            .unwrap();
                    let args = args.to_sdk(&mut ctx);
                    tx::submit_init_proposal::<HttpClient>(&client, ctx, args)
                        .await?;
                }
                Sub::TxVoteProposal(TxVoteProposal(args)) => {
                    wait_until_node_is_synched(&args.tx.ledger_address).await;
                    let client =
                        HttpClient::new(args.tx.ledger_address.clone())
                            .unwrap();
                    let args = args.to_sdk(&mut ctx);
                    tx::submit_vote_proposal::<HttpClient>(
                        &client,
                        &mut ctx,
                        args,
                    )
                    .await?;
                }
                Sub::TxRevealPk(TxRevealPk(args)) => {
                    wait_until_node_is_synched(&args.tx.ledger_address).await;
                    let client =
                        HttpClient::new(args.tx.ledger_address.clone())
                            .unwrap();
                    let args = args.to_sdk(&mut ctx);
                    tx::submit_reveal_pk::<HttpClient, CliWalletUtils>(
                        &client,
                        &mut ctx.wallet,
                        args,
                    )
                    .await?;
                }
                Sub::Bond(Bond(args)) => {
                    wait_until_node_is_synched(&args.tx.ledger_address).await;
                    let client =
                        HttpClient::new(args.tx.ledger_address.clone())
                            .unwrap();
                    let args = args.to_sdk(&mut ctx);
                    tx::submit_bond::<HttpClient, CliWalletUtils>(
                        &client,
                        &mut ctx.wallet,
                        args,
                    )
                    .await?;
                }
                Sub::Unbond(Unbond(args)) => {
                    wait_until_node_is_synched(&args.tx.ledger_address).await;
                    let client =
                        HttpClient::new(args.tx.ledger_address.clone())
                            .unwrap();
                    let args = args.to_sdk(&mut ctx);
                    tx::submit_unbond::<HttpClient, CliWalletUtils>(
                        &client,
                        &mut ctx.wallet,
                        args,
                    )
                    .await?;
                }
                Sub::Withdraw(Withdraw(args)) => {
                    wait_until_node_is_synched(&args.tx.ledger_address).await;
                    let client =
                        HttpClient::new(args.tx.ledger_address.clone())
                            .unwrap();
                    let args = args.to_sdk(&mut ctx);
                    tx::submit_withdraw::<HttpClient, CliWalletUtils>(
                        &client,
                        &mut ctx.wallet,
                        args,
                    )
                    .await?;
                }
                // Ledger queries
                Sub::QueryEpoch(QueryEpoch(args)) => {
                    wait_until_node_is_synched(&args.ledger_address).await;
                    let client = HttpClient::new(args.ledger_address).unwrap();
                    rpc::query_and_print_epoch(&client).await;
                }
                Sub::QueryTransfers(QueryTransfers(args)) => {
                    wait_until_node_is_synched(&args.query.ledger_address)
                        .await;
                    let client =
                        HttpClient::new(args.query.ledger_address.clone())
                            .unwrap();
                    let args = args.to_sdk(&mut ctx);
                    rpc::query_transfers(
                        &client,
                        &mut ctx.wallet,
                        &mut ctx.shielded,
                        args,
                    )
                    .await;
                }
                Sub::QueryConversions(QueryConversions(args)) => {
                    wait_until_node_is_synched(&args.query.ledger_address)
                        .await;
                    let client =
                        HttpClient::new(args.query.ledger_address.clone())
                            .unwrap();
                    let args = args.to_sdk(&mut ctx);
                    rpc::query_conversions(&client, &mut ctx.wallet, args).await;
                }
                Sub::QueryBlock(QueryBlock(args)) => {
                    wait_until_node_is_synched(&args.ledger_address).await;
                    let client =
                        HttpClient::new(args.ledger_address.clone()).unwrap();
                    rpc::query_block(&client).await;
                }
                Sub::QueryBalance(QueryBalance(args)) => {
                    wait_until_node_is_synched(&args.query.ledger_address)
                        .await;
                    let client =
                        HttpClient::new(args.query.ledger_address.clone())
                            .unwrap();
                    let args = args.to_sdk(&mut ctx);
                    rpc::query_balance(
                        &client,
                        &mut ctx.wallet,
                        &mut ctx.shielded,
                        args,
                    )
                    .await;
                }
                Sub::QueryBonds(QueryBonds(args)) => {
                    wait_until_node_is_synched(&args.query.ledger_address)
                        .await;
                    let client =
                        HttpClient::new(args.query.ledger_address.clone())
                            .unwrap();
                    let args = args.to_sdk(&mut ctx);
                    rpc::query_bonds(&client, &mut ctx.wallet, args).await;
                }
                Sub::QueryBondedStake(QueryBondedStake(args)) => {
                    wait_until_node_is_synched(&args.query.ledger_address)
                        .await;
                    let client =
                        HttpClient::new(args.query.ledger_address.clone())
                            .unwrap();
                    let args = args.to_sdk(&mut ctx);
                    rpc::query_bonded_stake(&client, args).await;
                }
                Sub::QueryCommissionRate(QueryCommissionRate(args)) => {
                    wait_until_node_is_synched(&args.query.ledger_address)
                        .await;
                    let client =
                        HttpClient::new(args.query.ledger_address.clone())
                            .unwrap();
                    let args = args.to_sdk(&mut ctx);
                    rpc::query_and_print_commission_rate(&client, &mut ctx.wallet, args).await;
                }
                Sub::QuerySlashes(QuerySlashes(args)) => {
                    wait_until_node_is_synched(&args.query.ledger_address)
                        .await;
                    let client =
                        HttpClient::new(args.query.ledger_address.clone())
                            .unwrap();
                    let args = args.to_sdk(&mut ctx);
                    rpc::query_slashes(&client, &mut ctx.wallet, args).await;
                }
                Sub::QueryDelegations(QueryDelegations(args)) => {
                    wait_until_node_is_synched(&args.query.ledger_address)
                        .await;
                    let client =
                        HttpClient::new(args.query.ledger_address.clone())
                            .unwrap();
                    let args = args.to_sdk(&mut ctx);
                    rpc::query_delegations(&client, &mut ctx.wallet, args).await;
                }
                Sub::QueryResult(QueryResult(args)) => {
                    wait_until_node_is_synched(&args.query.ledger_address)
                        .await;
                    // Connect to the Tendermint server holding the transactions
                    let client =
                        HttpClient::new(args.query.ledger_address.clone())
                            .unwrap();
                    let args = args.to_sdk(&mut ctx);
                    rpc::query_result(&client, args).await;
                }
                Sub::QueryRawBytes(QueryRawBytes(args)) => {
                    wait_until_node_is_synched(&args.query.ledger_address)
                        .await;
                    let client =
                        HttpClient::new(args.query.ledger_address.clone())
                            .unwrap();
                    let args = args.to_sdk(&mut ctx);
                    rpc::query_raw_bytes(&client, args).await;
                }

                Sub::QueryProposal(QueryProposal(args)) => {
                    wait_until_node_is_synched(&args.query.ledger_address)
                        .await;
                    let client =
                        HttpClient::new(args.query.ledger_address.clone())
                            .unwrap();
                    let args = args.to_sdk(&mut ctx);
                    rpc::query_proposal(&client, args).await;
                }
                Sub::QueryProposalResult(QueryProposalResult(args)) => {
                    wait_until_node_is_synched(&args.query.ledger_address)
                        .await;
                    let client =
                        HttpClient::new(args.query.ledger_address.clone())
                            .unwrap();
                    let args = args.to_sdk(&mut ctx);
                    rpc::query_proposal_result(&client, args).await;
                }
                Sub::QueryProtocolParameters(QueryProtocolParameters(args)) => {
                    wait_until_node_is_synched(&args.query.ledger_address)
                        .await;
                    let client =
                        HttpClient::new(args.query.ledger_address.clone())
                            .unwrap();
                    let args = args.to_sdk(&mut ctx);
                    rpc::query_protocol_parameters(&client, args).await;
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
    let mut try_count = 0_u64;
    const MAX_TRIES: u64 = 5;

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
                        println!(
                            " Waiting for {} ({}/{} tries)...",
                            if is_at_least_height_one {
                                "a first block"
                            } else {
                                "node to sync"
                            },
                            try_count + 1,
                            MAX_TRIES
                        );
                        sleep(Duration::from_secs((try_count + 1).pow(2)))
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
