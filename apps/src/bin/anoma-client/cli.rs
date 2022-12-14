//! Anoma client CLI.

use color_eyre::eyre::Result;
use namada_apps::cli;
use namada_apps::cli::cmds::*;
use namada_apps::client::{rpc, tx, utils};
use tendermint_rpc::{HttpClient, WebSocketClient, SubscriptionClient};

pub async fn main() -> Result<()> {
    match cli::anoma_client_cli()? {
        cli::AnomaClient::WithContext(cmd_box) => {
            let (cmd, mut ctx) = *cmd_box;
            use AnomaClientWithContext as Sub;
            match cmd {
                // Ledger cmds
                Sub::TxCustom(TxCustom(args)) => {
                    let client = HttpClient::new(args.tx.ledger_address.clone()).unwrap();
                    let args = args.to_sdk(&mut ctx);
                    tx::submit_custom(&client, ctx, args).await;
                }
                Sub::TxTransfer(TxTransfer(args)) => {
                    let client = HttpClient::new(args.tx.ledger_address.clone()).unwrap();
                    let args = args.to_sdk(&mut ctx);
                    tx::submit_transfer(&client, ctx, args).await;
                }
                Sub::TxIbcTransfer(TxIbcTransfer(args)) => {
                    let client = HttpClient::new(args.tx.ledger_address.clone()).unwrap();
                    let args = args.to_sdk(&mut ctx);
                    tx::submit_ibc_transfer(&client, ctx, args).await;
                }
                Sub::TxUpdateVp(TxUpdateVp(args)) => {
                    let client = HttpClient::new(args.tx.ledger_address.clone()).unwrap();
                    let args = args.to_sdk(&mut ctx);
                    tx::submit_update_vp(&client, ctx, args).await;
                }
                Sub::TxInitAccount(TxInitAccount(args)) => {
                    let client = HttpClient::new(args.tx.ledger_address.clone()).unwrap();
                    let args = args.to_sdk(&mut ctx);
                    tx::submit_init_account(&client, ctx, args).await;
                }
                Sub::TxInitValidator(TxInitValidator(args)) => {
                    let client = HttpClient::new(args.tx.ledger_address.clone()).unwrap();
                    let args = args.to_sdk(&mut ctx);
                    tx::submit_init_validator(&client, ctx, args).await;
                }
                Sub::TxInitProposal(TxInitProposal(args)) => {
                    let client = HttpClient::new(args.tx.ledger_address.clone()).unwrap();
                    let args = args.to_sdk(&mut ctx);
                    tx::submit_init_proposal(&client, ctx, args).await;
                }
                Sub::TxVoteProposal(TxVoteProposal(args)) => {
                    let client = HttpClient::new(args.tx.ledger_address.clone()).unwrap();
                    let args = args.to_sdk(&mut ctx);
                    tx::submit_vote_proposal(&client, ctx, args).await;
                }
                Sub::TxRevealPk(TxRevealPk(args)) => {
                    let client = HttpClient::new(args.tx.ledger_address.clone()).unwrap();
                    let args = args.to_sdk(&mut ctx);
                    tx::submit_reveal_pk(&client, ctx, args).await;
                }
                Sub::Bond(Bond(args)) => {
                    let client = HttpClient::new(args.tx.ledger_address.clone()).unwrap();
                    let args = args.to_sdk(&mut ctx);
                    tx::submit_bond(&client, ctx, args).await;
                }
                Sub::Unbond(Unbond(args)) => {
                    let client = HttpClient::new(args.tx.ledger_address.clone()).unwrap();
                    let args = args.to_sdk(&mut ctx);
                    tx::submit_unbond(&client, ctx, args).await;
                }
                Sub::Withdraw(Withdraw(args)) => {
                    let client = HttpClient::new(args.tx.ledger_address.clone()).unwrap();
                    let args = args.to_sdk(&mut ctx);
                    tx::submit_withdraw(&client, ctx, args).await;
                }
                // Ledger queries
                Sub::QueryEpoch(QueryEpoch(args)) => {
                    let client = HttpClient::new(args.ledger_address).unwrap();
                    rpc::query_epoch(&client).await;
                }
                Sub::QueryTransfers(QueryTransfers(args)) => {
                    let args = args.to_sdk(&mut ctx);
                    rpc::query_transfers(ctx, args).await;
                }
                Sub::QueryConversions(QueryConversions(args)) => {
                    let client = HttpClient::new(args.query.ledger_address.clone()).unwrap();
                    let args = args.to_sdk(&mut ctx);
                    rpc::query_conversions(&client, ctx, args).await;
                }
                Sub::QueryBlock(QueryBlock(args)) => {
                    let client = HttpClient::new(args.ledger_address.clone()).unwrap();
                    let args = args.to_sdk(&mut ctx);
                    rpc::query_block(&client, args).await;
                }
                Sub::QueryBalance(QueryBalance(args)) => {
                    let client = HttpClient::new(args.query.ledger_address.clone()).unwrap();
                    let args = args.to_sdk(&mut ctx);
                    rpc::query_balance(&client, ctx, args).await;
                }
                Sub::QueryBonds(QueryBonds(args)) => {
                    let client = HttpClient::new(args.query.ledger_address.clone()).unwrap();
                    let args = args.to_sdk(&mut ctx);
                    rpc::query_bonds(&client, ctx, args).await;
                }
                Sub::QueryBondedStake(QueryBondedStake(args)) => {
                    let client = HttpClient::new(args.query.ledger_address.clone()).unwrap();
                    let args = args.to_sdk(&mut ctx);
                    rpc::query_bonded_stake(&client, ctx, args).await;
                }
                Sub::QueryCommissionRate(QueryCommissionRate(args)) => {
                    let client = HttpClient::new(args.query.ledger_address.clone()).unwrap();
                    let args = args.to_sdk(&mut ctx);
                    rpc::query_commission_rate(&client, ctx, args).await;
                }
                Sub::QuerySlashes(QuerySlashes(args)) => {
                    let client = HttpClient::new(args.query.ledger_address.clone()).unwrap();
                    let args = args.to_sdk(&mut ctx);
                    rpc::query_slashes(&client, ctx, args).await;
                }
                Sub::QueryResult(QueryResult(args)) => {
                    // Connect to the Tendermint server holding the transactions
                    let (client, driver) = WebSocketClient::new(args.query.ledger_address.clone()).await?;
                    let driver_handle = tokio::spawn(async move { driver.run().await });
                    let args = args.to_sdk(&mut ctx);
                    rpc::query_result(&client, ctx, args).await;
                    // Signal to the driver to terminate.
                    client.close()?;
                    // Await the driver's termination to ensure proper connection closure.
                    let _ = driver_handle.await.unwrap_or_else(|x| {
                        eprintln!("{}", x);
                        cli::safe_exit(1)
                    });
                }
                Sub::QueryRawBytes(QueryRawBytes(args)) => {
                    let client = HttpClient::new(args.query.ledger_address.clone()).unwrap();
                    let args = args.to_sdk(&mut ctx);
                    rpc::query_raw_bytes(&client, ctx, args).await;
                }

                Sub::QueryProposal(QueryProposal(args)) => {
                    let client = HttpClient::new(args.query.ledger_address.clone()).unwrap();
                    let args = args.to_sdk(&mut ctx);
                    rpc::query_proposal(&client, ctx, args).await;
                }
                Sub::QueryProposalResult(QueryProposalResult(args)) => {
                    let client = HttpClient::new(args.query.ledger_address.clone()).unwrap();
                    let args = args.to_sdk(&mut ctx);
                    rpc::query_proposal_result(&client, ctx, args).await;
                }
                Sub::QueryProtocolParameters(QueryProtocolParameters(args)) => {
                    let client = HttpClient::new(args.query.ledger_address.clone()).unwrap();
                    let args = args.to_sdk(&mut ctx);
                    rpc::query_protocol_parameters(&client, ctx, args).await;
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
