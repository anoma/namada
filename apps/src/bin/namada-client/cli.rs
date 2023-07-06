//! Namada client CLI.

use color_eyre::eyre::{eyre, Report, Result};
use namada::ledger::eth_bridge::bridge_pool;
use namada::ledger::rpc::wait_until_node_is_synched;
use namada::ledger::{signing, tx};
use namada::types::control_flow::ProceedOrElse;
use namada_apps::cli;
use namada_apps::cli::args::CliToSdk;
use namada_apps::cli::cmds::*;
use namada_apps::client::{rpc, tx, utils};
use namada_apps::facade::tendermint_rpc::HttpClient;

fn error() -> Report {
    eyre!("Fatal error")
}

pub async fn main() -> Result<()> {
    match cli::namada_client_cli()? {
        cli::NamadaClient::WithContext(cmd_box) => {
            let (cmd, mut ctx) = *cmd_box;
            use NamadaClientWithContext as Sub;
            match cmd {
                // Ledger cmds
                Sub::TxCustom(TxCustom(mut args)) => {
                    let client = HttpClient::new(utils::take_config_address(
                        &mut args.tx.ledger_address,
                    ))
                    .unwrap();
                    wait_until_node_is_synched(&client)
                        .await
                        .proceed_or_else(error)?;
                    let args = args.to_sdk(&mut ctx);
                    let dry_run = args.tx.dry_run;
                    tx::submit_custom::<HttpClient>(&client, &mut ctx, args)
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
                Sub::TxTransfer(TxTransfer(mut args)) => {
                    let client = HttpClient::new(utils::take_config_address(
                        &mut args.tx.ledger_address,
                    ))
                    .unwrap();
                    wait_until_node_is_synched(&client)
                        .await
                        .proceed_or_else(error)?;
                    let args = args.to_sdk(&mut ctx);
                    tx::submit_transfer(&client, ctx, args).await?;
                }
                Sub::TxIbcTransfer(TxIbcTransfer(mut args)) => {
                    let client = HttpClient::new(utils::take_config_address(
                        &mut args.tx.ledger_address,
                    ))
                    .unwrap();
                    wait_until_node_is_synched(&client)
                        .await
                        .proceed_or_else(error)?;
                    let args = args.to_sdk(&mut ctx);
                    tx::submit_ibc_transfer::<HttpClient>(&client, ctx, args)
                        .await?;
                }
                Sub::TxUpdateVp(TxUpdateVp(mut args)) => {
                    let client = HttpClient::new(utils::take_config_address(
                        &mut args.tx.ledger_address,
                    ))
                    .unwrap();
                    wait_until_node_is_synched(&client)
                        .await
                        .proceed_or_else(error)?;
                    let args = args.to_sdk(&mut ctx);
                    tx::submit_update_vp::<HttpClient>(&client, &mut ctx, args)
                        .await?;
                }
                Sub::TxInitAccount(TxInitAccount(mut args)) => {
                    let client = HttpClient::new(utils::take_config_address(
                        &mut args.tx.ledger_address,
                    ))
                    .unwrap();
                    wait_until_node_is_synched(&client)
                        .await
                        .proceed_or_else(error)?;
                    let args = args.to_sdk(&mut ctx);
                    let dry_run = args.tx.dry_run;
                    tx::submit_init_account::<HttpClient>(
                        &client, &mut ctx, args,
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
                Sub::TxInitValidator(TxInitValidator(mut args)) => {
                    let client = HttpClient::new(utils::take_config_address(
                        &mut args.tx.ledger_address,
                    ))
                    .unwrap();
                    wait_until_node_is_synched(&client)
                        .await
                        .proceed_or_else(error)?;
                    let args = args.to_sdk(&mut ctx);
                    tx::submit_init_validator::<HttpClient>(&client, ctx, args)
                        .await?;
                }
                Sub::TxInitProposal(TxInitProposal(mut args)) => {
                    let client = HttpClient::new(utils::take_config_address(
                        &mut args.tx.ledger_address,
                    ))
                    .unwrap();
                    wait_until_node_is_synched(&client)
                        .await
                        .proceed_or_else(error)?;
                    let args = args.to_sdk(&mut ctx);
                    tx::submit_init_proposal::<HttpClient>(&client, ctx, args)
                        .await?;
                }
                Sub::TxVoteProposal(TxVoteProposal(mut args)) => {
                    let client = HttpClient::new(utils::take_config_address(
                        &mut args.tx.ledger_address,
                    ))
                    .unwrap();
                    wait_until_node_is_synched(&client)
                        .await
                        .proceed_or_else(error)?;
                    let args = args.to_sdk(&mut ctx);
                    tx::submit_vote_proposal::<HttpClient>(&client, ctx, args)
                        .await?;
                }
                Sub::TxRevealPk(TxRevealPk(mut args)) => {
                    let client = HttpClient::new(utils::take_config_address(
                        &mut args.tx.ledger_address,
                    ))
                    .unwrap();
                    wait_until_node_is_synched(&client)
                        .await
                        .proceed_or_else(error)?;
                    let args = args.to_sdk(&mut ctx);
                    tx::submit_reveal_pk::<HttpClient>(&client, &mut ctx, args)
                        .await?;
                }
                Sub::Bond(Bond(mut args)) => {
                    let client = HttpClient::new(utils::take_config_address(
                        &mut args.tx.ledger_address,
                    ))
                    .unwrap();
                    wait_until_node_is_synched(&client)
                        .await
                        .proceed_or_else(error)?;
                    let args = args.to_sdk(&mut ctx);
                    tx::submit_bond::<HttpClient>(&client, &mut ctx, args)
                        .await?;
                }
                Sub::Unbond(Unbond(mut args)) => {
                    let client = HttpClient::new(utils::take_config_address(
                        &mut args.tx.ledger_address,
                    ))
                    .unwrap();
                    wait_until_node_is_synched(&client)
                        .await
                        .proceed_or_else(error)?;
                    let args = args.to_sdk(&mut ctx);
                    tx::submit_unbond::<HttpClient>(&client, &mut ctx, args)
                        .await?;
                }
                Sub::Withdraw(Withdraw(mut args)) => {
                    let client = HttpClient::new(utils::take_config_address(
                        &mut args.tx.ledger_address,
                    ))
                    .unwrap();
                    wait_until_node_is_synched(&client)
                        .await
                        .proceed_or_else(error)?;
                    let args = args.to_sdk(&mut ctx);
                    tx::submit_withdraw::<HttpClient>(&client, ctx, args)
                        .await?;
                }
                Sub::TxCommissionRateChange(TxCommissionRateChange(args)) => {
                    wait_until_node_is_synched(&args.tx.ledger_address).await;
                    let client =
                        HttpClient::new(args.tx.ledger_address.clone())
                            .unwrap();
                    let args = args.to_sdk(&mut ctx);
                    tx::submit_validator_commission_change::<HttpClient>(
                        &client, ctx, args,
                    )
                    .await?;
                }
                // Eth bridge
                Sub::AddToEthBridgePool(args) => {
                    let mut args = args.0;
                    let client = HttpClient::new(utils::take_config_address(
                        &mut args.tx.ledger_address,
                    ))
                    .unwrap();
                    wait_until_node_is_synched(&client)
                        .await
                        .proceed_or_else(error)?;
                    let args = args.to_sdk(&mut ctx);
                    let tx_args = args.tx.clone();
                    let (tx, addr, pk) = bridge_pool::build_bridge_pool_tx(
                        &client,
                        &mut ctx.wallet,
                        args,
                    )
                    .await
                    .unwrap();
                    tx::submit_reveal_aux(
                        &client,
                        &mut ctx,
                        &tx_args,
                        addr,
                        pk.clone(),
                        &mut tx,
                    )
                    .await?;
                    signing::sign_tx(&mut ctx.wallet, &mut tx, &tx_args, &pk)
                        .await?;
                    tx::process_tx(&client, &mut ctx.wallet, &tx_args, tx)
                        .await?;
                }
                // Ledger queries
                Sub::QueryEpoch(QueryEpoch(mut args)) => {
                    let client = HttpClient::new(utils::take_config_address(
                        &mut args.ledger_address,
                    ))
                    .unwrap();
                    wait_until_node_is_synched(&client)
                        .await
                        .proceed_or_else(error)?;
                    rpc::query_and_print_epoch(&client).await;
                }
                Sub::QueryTransfers(QueryTransfers(mut args)) => {
                    let client = HttpClient::new(utils::take_config_address(
                        &mut args.query.ledger_address,
                    ))
                    .unwrap();
                    wait_until_node_is_synched(&client)
                        .await
                        .proceed_or_else(error)?;
                    let args = args.to_sdk(&mut ctx);
                    rpc::query_transfers(
                        &client,
                        &mut ctx.wallet,
                        &mut ctx.shielded,
                        args,
                    )
                    .await;
                }
                Sub::QueryConversions(QueryConversions(mut args)) => {
                    let client = HttpClient::new(utils::take_config_address(
                        &mut args.query.ledger_address,
                    ))
                    .unwrap();
                    wait_until_node_is_synched(&client)
                        .await
                        .proceed_or_else(error)?;
                    let args = args.to_sdk(&mut ctx);
                    rpc::query_conversions(&client, &mut ctx.wallet, args)
                        .await;
                }
                Sub::QueryBlock(QueryBlock(mut args)) => {
                    let client = HttpClient::new(utils::take_config_address(
                        &mut args.ledger_address,
                    ))
                    .unwrap();
                    wait_until_node_is_synched(&client)
                        .await
                        .proceed_or_else(error)?;
                    rpc::query_block(&client).await;
                }
                Sub::QueryBalance(QueryBalance(mut args)) => {
                    let client = HttpClient::new(utils::take_config_address(
                        &mut args.query.ledger_address,
                    ))
                    .unwrap();
                    wait_until_node_is_synched(&client)
                        .await
                        .proceed_or_else(error)?;
                    let args = args.to_sdk(&mut ctx);
                    rpc::query_balance(
                        &client,
                        &mut ctx.wallet,
                        &mut ctx.shielded,
                        args,
                    )
                    .await;
                }
                Sub::QueryBonds(QueryBonds(mut args)) => {
                    let client = HttpClient::new(utils::take_config_address(
                        &mut args.query.ledger_address,
                    ))
                    .unwrap();
                    wait_until_node_is_synched(&client)
                        .await
                        .proceed_or_else(error)?;
                    let args = args.to_sdk(&mut ctx);
                    rpc::query_bonds(&client, &mut ctx.wallet, args)
                        .await
                        .expect("expected successful query of bonds");
                }
                Sub::QueryBondedStake(QueryBondedStake(mut args)) => {
                    let client = HttpClient::new(utils::take_config_address(
                        &mut args.query.ledger_address,
                    ))
                    .unwrap();
                    wait_until_node_is_synched(&client)
                        .await
                        .proceed_or_else(error)?;
                    let args = args.to_sdk(&mut ctx);
                    rpc::query_bonded_stake(&client, args).await;
                }
                Sub::QueryCommissionRate(QueryCommissionRate(mut args)) => {
                    let client = HttpClient::new(utils::take_config_address(
                        &mut args.query.ledger_address,
                    ))
                    .unwrap();
                    wait_until_node_is_synched(&client)
                        .await
                        .proceed_or_else(error)?;
                    let args = args.to_sdk(&mut ctx);
                    rpc::query_and_print_commission_rate(
                        &client,
                        &mut ctx.wallet,
                        args,
                    )
                    .await;
                }
                Sub::QuerySlashes(QuerySlashes(mut args)) => {
                    let client = HttpClient::new(utils::take_config_address(
                        &mut args.query.ledger_address,
                    ))
                    .unwrap();
                    wait_until_node_is_synched(&client)
                        .await
                        .proceed_or_else(error)?;
                    let args = args.to_sdk(&mut ctx);
                    rpc::query_slashes(&client, &mut ctx.wallet, args).await;
                }
                Sub::QueryDelegations(QueryDelegations(mut args)) => {
                    let client = HttpClient::new(utils::take_config_address(
                        &mut args.query.ledger_address,
                    ))
                    .unwrap();
                    wait_until_node_is_synched(&client)
                        .await
                        .proceed_or_else(error)?;
                    let args = args.to_sdk(&mut ctx);
                    rpc::query_delegations(&client, &mut ctx.wallet, args)
                        .await;
                }
                Sub::QueryFindValidator(QueryFindValidator(mut args)) => {
                    let client = HttpClient::new(utils::take_config_address(
                        &mut args.query.ledger_address,
                    ))
                    .unwrap();
                    wait_until_node_is_synched(&client)
                        .await
                        .proceed_or_else(error)?;
                    let args = args.to_sdk(&mut ctx);
                    rpc::query_find_validator(&client, args).await;
                }
                Sub::QueryResult(QueryResult(mut args)) => {
                    let client = HttpClient::new(utils::take_config_address(
                        &mut args.query.ledger_address,
                    ))
                    .unwrap();
                    wait_until_node_is_synched(&client)
                        .await
                        .proceed_or_else(error)?;
                    let args = args.to_sdk(&mut ctx);
                    rpc::query_result(&client, args).await;
                }
                Sub::QueryRawBytes(QueryRawBytes(mut args)) => {
                    let client = HttpClient::new(utils::take_config_address(
                        &mut args.query.ledger_address,
                    ))
                    .unwrap();
                    wait_until_node_is_synched(&client)
                        .await
                        .proceed_or_else(error)?;
                    let args = args.to_sdk(&mut ctx);
                    rpc::query_raw_bytes(&client, args).await;
                }

                Sub::QueryProposal(QueryProposal(mut args)) => {
                    let client = HttpClient::new(utils::take_config_address(
                        &mut args.query.ledger_address,
                    ))
                    .unwrap();
                    wait_until_node_is_synched(&client)
                        .await
                        .proceed_or_else(error)?;
                    let args = args.to_sdk(&mut ctx);
                    rpc::query_proposal(&client, args).await;
                }
                Sub::QueryProposalResult(QueryProposalResult(mut args)) => {
                    let client = HttpClient::new(utils::take_config_address(
                        &mut args.query.ledger_address,
                    ))
                    .unwrap();
                    wait_until_node_is_synched(&client)
                        .await
                        .proceed_or_else(error)?;
                    let args = args.to_sdk(&mut ctx);
                    rpc::query_proposal_result(&client, args).await;
                }
                Sub::QueryProtocolParameters(QueryProtocolParameters(
                    mut args,
                )) => {
                    let client = HttpClient::new(utils::take_config_address(
                        &mut args.query.ledger_address,
                    ))
                    .unwrap();
                    wait_until_node_is_synched(&client)
                        .await
                        .proceed_or_else(error)?;
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
            Utils::PkToTmAddress(PkToTmAddress(args)) => {
                utils::pk_to_tm_address(global_args, args)
            }
            Utils::DefaultBaseDir(DefaultBaseDir(args)) => {
                utils::default_base_dir(global_args, args)
            }
        },
    }
    Ok(())
}
