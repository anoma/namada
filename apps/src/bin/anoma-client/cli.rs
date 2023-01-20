//! Anoma client CLI.

use color_eyre::eyre::Result;
use namada_apps::cli;
use namada_apps::cli::args::CliToSdk;
use namada_apps::cli::cmds::*;
use namada_apps::client::tm::RpcHttpClient;
use namada_apps::client::{rpc, tx, utils};
use namada_apps::wallet::CliWalletUtils;
use tendermint_rpc::{HttpClient, SubscriptionClient, WebSocketClient};

pub async fn main() -> Result<()> {
    match cli::anoma_client_cli()? {
        cli::AnomaClient::WithContext(cmd_box) => {
            let (cmd, mut ctx) = *cmd_box;
            use AnomaClientWithContext as Sub;
            match cmd {
                // Ledger cmds
                Sub::TxCustom(TxCustom(args)) => {
                    let client =
                        HttpClient::new(args.tx.ledger_address.clone())
                            .unwrap();
                    let client = RpcHttpClient::new(client);
                    let args = args.to_sdk(&mut ctx);
                    let dry_run = args.tx.dry_run;
                    tx::submit_custom::<
                        RpcHttpClient<HttpClient>,
                        CliWalletUtils,
                    >(&client, &mut ctx.wallet, args)
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
                    let client =
                        HttpClient::new(args.tx.ledger_address.clone())
                            .unwrap();
                    let client = RpcHttpClient::new(client);
                    let args = args.to_sdk(&mut ctx);
                    tx::submit_transfer::<
                        RpcHttpClient<HttpClient>,
                        CliWalletUtils,
                        _,
                    >(
                        &client, &mut ctx.wallet, &mut ctx.shielded, args
                    )
                    .await?;
                }
                Sub::TxIbcTransfer(TxIbcTransfer(args)) => {
                    let client =
                        HttpClient::new(args.tx.ledger_address.clone())
                            .unwrap();
                    let client = RpcHttpClient::new(client);
                    let args = args.to_sdk(&mut ctx);
                    tx::submit_ibc_transfer::<
                        RpcHttpClient<HttpClient>,
                        CliWalletUtils,
                    >(&client, &mut ctx.wallet, args)
                    .await?;
                }
                Sub::TxUpdateVp(TxUpdateVp(args)) => {
                    let client =
                        HttpClient::new(args.tx.ledger_address.clone())
                            .unwrap();
                    let client = RpcHttpClient::new(client);
                    let args = args.to_sdk(&mut ctx);
                    tx::submit_update_vp::<
                        RpcHttpClient<HttpClient>,
                        CliWalletUtils,
                    >(&client, &mut ctx.wallet, args)
                    .await?;
                }
                Sub::TxInitAccount(TxInitAccount(args)) => {
                    let client =
                        HttpClient::new(args.tx.ledger_address.clone())
                            .unwrap();
                    let client = RpcHttpClient::new(client);
                    let args = args.to_sdk(&mut ctx);
                    let dry_run = args.tx.dry_run;
                    tx::submit_init_account::<
                        RpcHttpClient<HttpClient>,
                        CliWalletUtils,
                    >(&client, &mut ctx.wallet, args)
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
                    let client =
                        HttpClient::new(args.tx.ledger_address.clone())
                            .unwrap();
                    let client = RpcHttpClient::new(client);
                    let args = args.to_sdk(&mut ctx);
                    tx::submit_init_validator::<RpcHttpClient<HttpClient>>(
                        &client, ctx, args,
                    )
                    .await;
                }
                Sub::TxInitProposal(TxInitProposal(args)) => {
                    let client =
                        HttpClient::new(args.tx.ledger_address.clone())
                            .unwrap();
                    let client = RpcHttpClient::new(client);
                    let args = args.to_sdk(&mut ctx);
                    tx::submit_init_proposal::<RpcHttpClient<HttpClient>>(
                        &client, ctx, args,
                    )
                    .await?;
                }
                Sub::TxVoteProposal(TxVoteProposal(args)) => {
                    let client =
                        HttpClient::new(args.tx.ledger_address.clone())
                            .unwrap();
                    let client = RpcHttpClient::new(client);
                    let args = args.to_sdk(&mut ctx);
                    tx::submit_vote_proposal::<
                        RpcHttpClient<HttpClient>,
                        CliWalletUtils,
                    >(&client, &mut ctx.wallet, args)
                    .await?;
                }
                Sub::TxRevealPk(TxRevealPk(args)) => {
                    let client =
                        HttpClient::new(args.tx.ledger_address.clone())
                            .unwrap();
                    let client = RpcHttpClient::new(client);
                    let args = args.to_sdk(&mut ctx);
                    tx::submit_reveal_pk::<
                        RpcHttpClient<HttpClient>,
                        CliWalletUtils,
                    >(&client, &mut ctx.wallet, args)
                    .await?;
                }
                Sub::Bond(Bond(args)) => {
                    let client =
                        HttpClient::new(args.tx.ledger_address.clone())
                            .unwrap();
                    let client = RpcHttpClient::new(client);
                    let args = args.to_sdk(&mut ctx);
                    tx::submit_bond::<RpcHttpClient<HttpClient>, CliWalletUtils>(
                        &client,
                        &mut ctx.wallet,
                        args,
                    )
                    .await?;
                }
                Sub::Unbond(Unbond(args)) => {
                    let client =
                        HttpClient::new(args.tx.ledger_address.clone())
                            .unwrap();
                    let client = RpcHttpClient::new(client);
                    let args = args.to_sdk(&mut ctx);
                    tx::submit_unbond::<
                        RpcHttpClient<HttpClient>,
                        CliWalletUtils,
                    >(&client, &mut ctx.wallet, args)
                    .await?;
                }
                Sub::Withdraw(Withdraw(args)) => {
                    let client =
                        HttpClient::new(args.tx.ledger_address.clone())
                            .unwrap();
                    let client = RpcHttpClient::new(client);
                    let args = args.to_sdk(&mut ctx);
                    tx::submit_withdraw::<
                        RpcHttpClient<HttpClient>,
                        CliWalletUtils,
                    >(&client, &mut ctx.wallet, args)
                    .await?;
                }
                // Ledger queries
                Sub::QueryEpoch(QueryEpoch(args)) => {
                    let client = HttpClient::new(args.ledger_address).unwrap();
                    let client = RpcHttpClient::new(client);
                    rpc::query_epoch(&client).await;
                }
                Sub::QueryTransfers(QueryTransfers(args)) => {
                    let client =
                        HttpClient::new(args.query.ledger_address.clone())
                            .unwrap();
                    let client = RpcHttpClient::new(client);
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
                    let client =
                        HttpClient::new(args.query.ledger_address.clone())
                            .unwrap();
                    let client = RpcHttpClient::new(client);
                    let args = args.to_sdk(&mut ctx);
                    rpc::query_conversions(&client, args).await;
                }
                Sub::QueryBlock(QueryBlock(args)) => {
                    let client =
                        HttpClient::new(args.ledger_address.clone()).unwrap();
                    let client = RpcHttpClient::new(client);
                    rpc::query_block(&client).await;
                }
                Sub::QueryBalance(QueryBalance(args)) => {
                    let client =
                        HttpClient::new(args.query.ledger_address.clone())
                            .unwrap();
                    let client = RpcHttpClient::new(client);
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
                    let client =
                        HttpClient::new(args.query.ledger_address.clone())
                            .unwrap();
                    let client = RpcHttpClient::new(client);
                    let args = args.to_sdk(&mut ctx);
                    rpc::query_bonds(&client, args).await;
                }
                Sub::QueryBondedStake(QueryBondedStake(args)) => {
                    let client =
                        HttpClient::new(args.query.ledger_address.clone())
                            .unwrap();
                    let client = RpcHttpClient::new(client);
                    let args = args.to_sdk(&mut ctx);
                    rpc::query_bonded_stake(&client, args).await;
                }
                Sub::QueryCommissionRate(QueryCommissionRate(args)) => {
                    let client =
                        HttpClient::new(args.query.ledger_address.clone())
                            .unwrap();
                    let client = RpcHttpClient::new(client);
                    let args = args.to_sdk(&mut ctx);
                    rpc::query_commission_rate(&client, args).await;
                }
                Sub::QuerySlashes(QuerySlashes(args)) => {
                    let client =
                        HttpClient::new(args.query.ledger_address.clone())
                            .unwrap();
                    let client = RpcHttpClient::new(client);
                    let args = args.to_sdk(&mut ctx);
                    rpc::query_slashes(&client, args).await;
                }
                Sub::QueryResult(QueryResult(args)) => {
                    // Connect to the Tendermint server holding the transactions
                    let client =
                        HttpClient::new(args.query.ledger_address.clone())
                            .unwrap();
                    let client = RpcHttpClient::new(client);
                    let args = args.to_sdk(&mut ctx);
                    rpc::query_result(&client, args).await;
                }
                Sub::QueryRawBytes(QueryRawBytes(args)) => {
                    let client =
                        HttpClient::new(args.query.ledger_address.clone())
                            .unwrap();
                    let client = RpcHttpClient::new(client);
                    let args = args.to_sdk(&mut ctx);
                    rpc::query_raw_bytes(&client, args).await;
                }

                Sub::QueryProposal(QueryProposal(args)) => {
                    let client =
                        HttpClient::new(args.query.ledger_address.clone())
                            .unwrap();
                    let client = RpcHttpClient::new(client);
                    let args = args.to_sdk(&mut ctx);
                    rpc::query_proposal(&client, args).await;
                }
                Sub::QueryProposalResult(QueryProposalResult(args)) => {
                    let client =
                        HttpClient::new(args.query.ledger_address.clone())
                            .unwrap();
                    let client = RpcHttpClient::new(client);
                    let args = args.to_sdk(&mut ctx);
                    rpc::query_proposal_result(&client, args).await;
                }
                Sub::QueryProtocolParameters(QueryProtocolParameters(args)) => {
                    let client =
                        HttpClient::new(args.query.ledger_address.clone())
                            .unwrap();
                    let client = RpcHttpClient::new(client);
                    let args = args.to_sdk(&mut ctx);
                    rpc::query_protocol_parameters(&client, args).await;
                }
            }
        }
        cli::AnomaClient::WithoutContext(cmd, global_args) => match cmd {
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
