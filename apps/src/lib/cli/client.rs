use color_eyre::eyre::{eyre, Report, Result};
use namada::ledger::eth_bridge::bridge_pool;
use namada::sdk::tx::dump_tx;
use namada::sdk::{signing, tx as sdk_tx};
use namada::types::control_flow::ProceedOrElse;
use namada::types::io::Io;

use crate::cli;
use crate::cli::api::{CliApi, CliClient};
use crate::cli::args::CliToSdk;
use crate::cli::cmds::*;
use crate::client::{rpc, tx, utils};

fn error() -> Report {
    eyre!("Fatal error")
}

impl<IO: Io> CliApi<IO> {
    pub async fn handle_client_command<C>(
        client: Option<C>,
        cmd: cli::NamadaClient,
    ) -> Result<()>
    where
        C: CliClient,
    {
        match cmd {
            cli::NamadaClient::WithContext(cmd_box) => {
                let (cmd, mut ctx) = *cmd_box;
                use NamadaClientWithContext as Sub;
                match cmd {
                    // Ledger cmds
                    Sub::TxCustom(TxCustom(mut args)) => {
                        let client = client.unwrap_or_else(|| {
                            C::from_tendermint_address(
                                &mut args.tx.ledger_address,
                            )
                        });
                        client
                            .wait_until_node_is_synced::<IO>()
                            .await
                            .proceed_or_else(error)?;
                        let args = args.to_sdk(&mut ctx);
                        let dry_run =
                            args.tx.dry_run || args.tx.dry_run_wrapper;
                        tx::submit_custom::<_, IO>(&client, &mut ctx, args)
                            .await?;
                        if !dry_run {
                            crate::wallet::save(&ctx.wallet)
                                .unwrap_or_else(|err| eprintln!("{}", err));
                        } else {
                            IO::println(
                                "Transaction dry run. No addresses have been \
                                 saved.",
                            )
                        }
                    }
                    Sub::TxTransfer(TxTransfer(mut args)) => {
                        let client = client.unwrap_or_else(|| {
                            C::from_tendermint_address(
                                &mut args.tx.ledger_address,
                            )
                        });
                        client
                            .wait_until_node_is_synced::<IO>()
                            .await
                            .proceed_or_else(error)?;
                        let args = args.to_sdk(&mut ctx);
                        tx::submit_transfer::<_, IO>(&client, ctx, args)
                            .await?;
                    }
                    Sub::TxIbcTransfer(TxIbcTransfer(mut args)) => {
                        let client = client.unwrap_or_else(|| {
                            C::from_tendermint_address(
                                &mut args.tx.ledger_address,
                            )
                        });
                        client
                            .wait_until_node_is_synced::<IO>()
                            .await
                            .proceed_or_else(error)?;
                        let args = args.to_sdk(&mut ctx);
                        tx::submit_ibc_transfer::<_, IO>(&client, ctx, args)
                            .await?;
                    }
                    Sub::TxUpdateAccount(TxUpdateAccount(mut args)) => {
                        let client = client.unwrap_or_else(|| {
                            C::from_tendermint_address(
                                &mut args.tx.ledger_address,
                            )
                        });
                        client
                            .wait_until_node_is_synced::<IO>()
                            .await
                            .proceed_or_else(error)?;
                        let args = args.to_sdk(&mut ctx);
                        tx::submit_update_account::<_, IO>(
                            &client, &mut ctx, args,
                        )
                        .await?;
                    }
                    Sub::TxInitAccount(TxInitAccount(mut args)) => {
                        let client = client.unwrap_or_else(|| {
                            C::from_tendermint_address(
                                &mut args.tx.ledger_address,
                            )
                        });
                        client
                            .wait_until_node_is_synced::<IO>()
                            .await
                            .proceed_or_else(error)?;
                        let args = args.to_sdk(&mut ctx);
                        let dry_run =
                            args.tx.dry_run || args.tx.dry_run_wrapper;
                        tx::submit_init_account::<_, IO>(
                            &client, &mut ctx, args,
                        )
                        .await?;
                        if !dry_run {
                            crate::wallet::save(&ctx.wallet)
                                .unwrap_or_else(|err| eprintln!("{}", err));
                        } else {
                            IO::println(
                                "Transaction dry run. No addresses have been \
                                 saved.",
                            )
                        }
                    }
                    Sub::TxInitValidator(TxInitValidator(mut args)) => {
                        let client = client.unwrap_or_else(|| {
                            C::from_tendermint_address(
                                &mut args.tx.ledger_address,
                            )
                        });
                        client
                            .wait_until_node_is_synced::<IO>()
                            .await
                            .proceed_or_else(error)?;
                        let args = args.to_sdk(&mut ctx);
                        tx::submit_init_validator::<_, IO>(&client, ctx, args)
                            .await?;
                    }
                    Sub::TxInitProposal(TxInitProposal(mut args)) => {
                        let client = client.unwrap_or_else(|| {
                            C::from_tendermint_address(
                                &mut args.tx.ledger_address,
                            )
                        });
                        client
                            .wait_until_node_is_synced::<IO>()
                            .await
                            .proceed_or_else(error)?;
                        let args = args.to_sdk(&mut ctx);
                        tx::submit_init_proposal::<_, IO>(&client, ctx, args)
                            .await?;
                    }
                    Sub::TxVoteProposal(TxVoteProposal(mut args)) => {
                        let client = client.unwrap_or_else(|| {
                            C::from_tendermint_address(
                                &mut args.tx.ledger_address,
                            )
                        });
                        client
                            .wait_until_node_is_synced::<IO>()
                            .await
                            .proceed_or_else(error)?;
                        let args = args.to_sdk(&mut ctx);
                        tx::submit_vote_proposal::<_, IO>(&client, ctx, args)
                            .await?;
                    }
                    Sub::TxRevealPk(TxRevealPk(mut args)) => {
                        let client = client.unwrap_or_else(|| {
                            C::from_tendermint_address(
                                &mut args.tx.ledger_address,
                            )
                        });
                        client
                            .wait_until_node_is_synced::<IO>()
                            .await
                            .proceed_or_else(error)?;
                        let args = args.to_sdk(&mut ctx);
                        tx::submit_reveal_pk::<_, IO>(&client, &mut ctx, args)
                            .await?;
                    }
                    Sub::Bond(Bond(mut args)) => {
                        let client = client.unwrap_or_else(|| {
                            C::from_tendermint_address(
                                &mut args.tx.ledger_address,
                            )
                        });
                        client
                            .wait_until_node_is_synced::<IO>()
                            .await
                            .proceed_or_else(error)?;
                        let args = args.to_sdk(&mut ctx);
                        tx::submit_bond::<_, IO>(&client, &mut ctx, args)
                            .await?;
                    }
                    Sub::Unbond(Unbond(mut args)) => {
                        let client = client.unwrap_or_else(|| {
                            C::from_tendermint_address(
                                &mut args.tx.ledger_address,
                            )
                        });
                        client
                            .wait_until_node_is_synced::<IO>()
                            .await
                            .proceed_or_else(error)?;
                        let args = args.to_sdk(&mut ctx);
                        tx::submit_unbond::<_, IO>(&client, &mut ctx, args)
                            .await?;
                    }
                    Sub::Withdraw(Withdraw(mut args)) => {
                        let client = client.unwrap_or_else(|| {
                            C::from_tendermint_address(
                                &mut args.tx.ledger_address,
                            )
                        });
                        client
                            .wait_until_node_is_synced::<IO>()
                            .await
                            .proceed_or_else(error)?;
                        let args = args.to_sdk(&mut ctx);
                        tx::submit_withdraw::<_, IO>(&client, ctx, args)
                            .await?;
                    }
                    Sub::TxCommissionRateChange(TxCommissionRateChange(
                        mut args,
                    )) => {
                        let client = client.unwrap_or_else(|| {
                            C::from_tendermint_address(
                                &mut args.tx.ledger_address,
                            )
                        });
                        client
                            .wait_until_node_is_synced::<IO>()
                            .await
                            .proceed_or_else(error)?;
                        let args = args.to_sdk(&mut ctx);
                        tx::submit_validator_commission_change::<_, IO>(
                            &client, ctx, args,
                        )
                        .await?;
                    }
                    // Eth bridge
                    Sub::AddToEthBridgePool(args) => {
                        let mut args = args.0;
                        let client = client.unwrap_or_else(|| {
                            C::from_tendermint_address(
                                &mut args.tx.ledger_address,
                            )
                        });
                        client
                            .wait_until_node_is_synced::<IO>()
                            .await
                            .proceed_or_else(error)?;
                        let args = args.to_sdk(&mut ctx);
                        let tx_args = args.tx.clone();

                        let default_signer = Some(args.sender.clone());
                        let signing_data = tx::aux_signing_data::<_, IO>(
                            &client,
                            &mut ctx.wallet,
                            &args.tx,
                            Some(args.sender.clone()),
                            default_signer,
                        )
                        .await?;

                        let (mut tx, _epoch) =
                            bridge_pool::build_bridge_pool_tx::<_, _, _, IO>(
                                &client,
                                &mut ctx.wallet,
                                &mut ctx.shielded,
                                args.clone(),
                                signing_data.fee_payer.clone(),
                            )
                            .await?;

                        signing::generate_test_vector::<_, _, IO>(
                            &client,
                            &mut ctx.wallet,
                            &tx,
                        )
                        .await?;

                        if args.tx.dump_tx {
                            dump_tx::<IO>(&args.tx, tx);
                        } else {
                            tx::submit_reveal_aux::<_, IO>(
                                &client,
                                &mut ctx,
                                tx_args.clone(),
                                &args.sender,
                            )
                            .await?;

                            signing::sign_tx(
                                &mut ctx.wallet,
                                &tx_args,
                                &mut tx,
                                signing_data,
                            )?;

                            sdk_tx::process_tx::<_, _, IO>(
                                &client,
                                &mut ctx.wallet,
                                &tx_args,
                                tx,
                            )
                            .await?;
                        }
                    }
                    Sub::TxUnjailValidator(TxUnjailValidator(mut args)) => {
                        let client = client.unwrap_or_else(|| {
                            C::from_tendermint_address(
                                &mut args.tx.ledger_address,
                            )
                        });
                        client
                            .wait_until_node_is_synced::<IO>()
                            .await
                            .proceed_or_else(error)?;
                        let args = args.to_sdk(&mut ctx);
                        tx::submit_unjail_validator::<_, IO>(
                            &client, ctx, args,
                        )
                        .await?;
                    }
                    Sub::TxUpdateStewardCommission(
                        TxUpdateStewardCommission(mut args),
                    ) => {
                        let client = client.unwrap_or_else(|| {
                            C::from_tendermint_address(
                                &mut args.tx.ledger_address,
                            )
                        });
                        client
                            .wait_until_node_is_synced::<IO>()
                            .await
                            .proceed_or_else(error)?;
                        let args = args.to_sdk(&mut ctx);
                        tx::submit_update_steward_commission::<_, IO>(
                            &client, ctx, args,
                        )
                        .await?;
                    }
                    Sub::TxResignSteward(TxResignSteward(mut args)) => {
                        let client = client.unwrap_or_else(|| {
                            C::from_tendermint_address(
                                &mut args.tx.ledger_address,
                            )
                        });
                        client
                            .wait_until_node_is_synced::<IO>()
                            .await
                            .proceed_or_else(error)?;
                        let args = args.to_sdk(&mut ctx);
                        tx::submit_resign_steward::<_, IO>(&client, ctx, args)
                            .await?;
                    }
                    // Ledger queries
                    Sub::QueryEpoch(QueryEpoch(mut args)) => {
                        let client = client.unwrap_or_else(|| {
                            C::from_tendermint_address(&mut args.ledger_address)
                        });
                        client
                            .wait_until_node_is_synced::<IO>()
                            .await
                            .proceed_or_else(error)?;
                        rpc::query_and_print_epoch::<_, IO>(&client).await;
                    }
                    Sub::QueryValidatorState(QueryValidatorState(mut args)) => {
                        let client = client.unwrap_or_else(|| {
                            C::from_tendermint_address(
                                &mut args.query.ledger_address,
                            )
                        });
                        client
                            .wait_until_node_is_synced::<IO>()
                            .await
                            .proceed_or_else(error)?;
                        let args = args.to_sdk(&mut ctx);
                        rpc::query_and_print_validator_state::<_, IO>(
                            &client,
                            &mut ctx.wallet,
                            args,
                        )
                        .await;
                    }
                    Sub::QueryTransfers(QueryTransfers(mut args)) => {
                        let client = client.unwrap_or_else(|| {
                            C::from_tendermint_address(
                                &mut args.query.ledger_address,
                            )
                        });
                        client
                            .wait_until_node_is_synced::<IO>()
                            .await
                            .proceed_or_else(error)?;
                        let args = args.to_sdk(&mut ctx);
                        rpc::query_transfers::<_, _, IO>(
                            &client,
                            &mut ctx.wallet,
                            &mut ctx.shielded,
                            args,
                        )
                        .await;
                    }
                    Sub::QueryConversions(QueryConversions(mut args)) => {
                        let client = client.unwrap_or_else(|| {
                            C::from_tendermint_address(
                                &mut args.query.ledger_address,
                            )
                        });
                        client
                            .wait_until_node_is_synced::<IO>()
                            .await
                            .proceed_or_else(error)?;
                        let args = args.to_sdk(&mut ctx);
                        rpc::query_conversions::<_, IO>(
                            &client,
                            &mut ctx.wallet,
                            args,
                        )
                        .await;
                    }
                    Sub::QueryBlock(QueryBlock(mut args)) => {
                        let client = client.unwrap_or_else(|| {
                            C::from_tendermint_address(&mut args.ledger_address)
                        });
                        client
                            .wait_until_node_is_synced::<IO>()
                            .await
                            .proceed_or_else(error)?;
                        rpc::query_block::<_, IO>(&client).await;
                    }
                    Sub::QueryBalance(QueryBalance(mut args)) => {
                        let client = client.unwrap_or_else(|| {
                            C::from_tendermint_address(
                                &mut args.query.ledger_address,
                            )
                        });
                        client
                            .wait_until_node_is_synced::<IO>()
                            .await
                            .proceed_or_else(error)?;
                        let args = args.to_sdk(&mut ctx);
                        rpc::query_balance::<_, _, IO>(
                            &client,
                            &mut ctx.wallet,
                            &mut ctx.shielded,
                            args,
                        )
                        .await;
                    }
                    Sub::QueryBonds(QueryBonds(mut args)) => {
                        let client = client.unwrap_or_else(|| {
                            C::from_tendermint_address(
                                &mut args.query.ledger_address,
                            )
                        });
                        client
                            .wait_until_node_is_synced::<IO>()
                            .await
                            .proceed_or_else(error)?;
                        let args = args.to_sdk(&mut ctx);
                        rpc::query_bonds::<_, IO>(
                            &client,
                            &mut ctx.wallet,
                            args,
                        )
                        .await
                        .expect("expected successful query of bonds");
                    }
                    Sub::QueryBondedStake(QueryBondedStake(mut args)) => {
                        let client = client.unwrap_or_else(|| {
                            C::from_tendermint_address(
                                &mut args.query.ledger_address,
                            )
                        });
                        client
                            .wait_until_node_is_synced::<IO>()
                            .await
                            .proceed_or_else(error)?;
                        let args = args.to_sdk(&mut ctx);
                        rpc::query_bonded_stake::<_, IO>(&client, args).await;
                    }
                    Sub::QueryCommissionRate(QueryCommissionRate(mut args)) => {
                        let client = client.unwrap_or_else(|| {
                            C::from_tendermint_address(
                                &mut args.query.ledger_address,
                            )
                        });
                        client
                            .wait_until_node_is_synced::<IO>()
                            .await
                            .proceed_or_else(error)?;
                        let args = args.to_sdk(&mut ctx);
                        rpc::query_and_print_commission_rate::<_, IO>(
                            &client,
                            &mut ctx.wallet,
                            args,
                        )
                        .await;
                    }
                    Sub::QuerySlashes(QuerySlashes(mut args)) => {
                        let client = client.unwrap_or_else(|| {
                            C::from_tendermint_address(
                                &mut args.query.ledger_address,
                            )
                        });
                        client
                            .wait_until_node_is_synced::<IO>()
                            .await
                            .proceed_or_else(error)?;
                        let args = args.to_sdk(&mut ctx);
                        rpc::query_slashes::<_, IO>(
                            &client,
                            &mut ctx.wallet,
                            args,
                        )
                        .await;
                    }
                    Sub::QueryDelegations(QueryDelegations(mut args)) => {
                        let client = client.unwrap_or_else(|| {
                            C::from_tendermint_address(
                                &mut args.query.ledger_address,
                            )
                        });
                        client
                            .wait_until_node_is_synced::<IO>()
                            .await
                            .proceed_or_else(error)?;
                        let args = args.to_sdk(&mut ctx);
                        rpc::query_delegations::<_, IO>(
                            &client,
                            &mut ctx.wallet,
                            args,
                        )
                        .await;
                    }
                    Sub::QueryFindValidator(QueryFindValidator(mut args)) => {
                        let client = client.unwrap_or_else(|| {
                            C::from_tendermint_address(
                                &mut args.query.ledger_address,
                            )
                        });
                        client
                            .wait_until_node_is_synced::<IO>()
                            .await
                            .proceed_or_else(error)?;
                        let args = args.to_sdk(&mut ctx);
                        rpc::query_find_validator::<_, IO>(&client, args).await;
                    }
                    Sub::QueryResult(QueryResult(mut args)) => {
                        let client = client.unwrap_or_else(|| {
                            C::from_tendermint_address(
                                &mut args.query.ledger_address,
                            )
                        });
                        client
                            .wait_until_node_is_synced::<IO>()
                            .await
                            .proceed_or_else(error)?;
                        let args = args.to_sdk(&mut ctx);
                        rpc::query_result::<_, IO>(&client, args).await;
                    }
                    Sub::QueryRawBytes(QueryRawBytes(mut args)) => {
                        let client = client.unwrap_or_else(|| {
                            C::from_tendermint_address(
                                &mut args.query.ledger_address,
                            )
                        });
                        client
                            .wait_until_node_is_synced::<IO>()
                            .await
                            .proceed_or_else(error)?;
                        let args = args.to_sdk(&mut ctx);
                        rpc::query_raw_bytes::<_, IO>(&client, args).await;
                    }
                    Sub::QueryProposal(QueryProposal(mut args)) => {
                        let client = client.unwrap_or_else(|| {
                            C::from_tendermint_address(
                                &mut args.query.ledger_address,
                            )
                        });
                        client
                            .wait_until_node_is_synced::<IO>()
                            .await
                            .proceed_or_else(error)?;
                        let args = args.to_sdk(&mut ctx);
                        rpc::query_proposal::<_, IO>(&client, args).await;
                    }
                    Sub::QueryProposalResult(QueryProposalResult(mut args)) => {
                        let client = client.unwrap_or_else(|| {
                            C::from_tendermint_address(
                                &mut args.query.ledger_address,
                            )
                        });
                        client
                            .wait_until_node_is_synced::<IO>()
                            .await
                            .proceed_or_else(error)?;
                        let args = args.to_sdk(&mut ctx);
                        rpc::query_proposal_result::<_, IO>(&client, args)
                            .await;
                    }
                    Sub::QueryProtocolParameters(QueryProtocolParameters(
                        mut args,
                    )) => {
                        let client = client.unwrap_or_else(|| {
                            C::from_tendermint_address(
                                &mut args.query.ledger_address,
                            )
                        });
                        client
                            .wait_until_node_is_synced::<IO>()
                            .await
                            .proceed_or_else(error)?;
                        let args = args.to_sdk(&mut ctx);
                        rpc::query_protocol_parameters::<_, IO>(&client, args)
                            .await;
                    }
                    Sub::QueryPgf(QueryPgf(mut args)) => {
                        let client = client.unwrap_or_else(|| {
                            C::from_tendermint_address(
                                &mut args.query.ledger_address,
                            )
                        });
                        client
                            .wait_until_node_is_synced::<IO>()
                            .await
                            .proceed_or_else(error)?;
                        let args = args.to_sdk(&mut ctx);
                        rpc::query_pgf::<_, IO>(&client, args).await;
                    }
                    Sub::QueryAccount(QueryAccount(mut args)) => {
                        let client = client.unwrap_or_else(|| {
                            C::from_tendermint_address(
                                &mut args.query.ledger_address,
                            )
                        });
                        client
                            .wait_until_node_is_synced::<IO>()
                            .await
                            .proceed_or_else(error)?;
                        let args = args.to_sdk(&mut ctx);
                        rpc::query_account::<_, IO>(&client, args).await;
                    }
                    Sub::SignTx(SignTx(mut args)) => {
                        let client = client.unwrap_or_else(|| {
                            C::from_tendermint_address(
                                &mut args.tx.ledger_address,
                            )
                        });
                        client
                            .wait_until_node_is_synced::<IO>()
                            .await
                            .proceed_or_else(error)?;
                        let args = args.to_sdk(&mut ctx);
                        tx::sign_tx::<_, IO>(&client, &mut ctx, args).await?;
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
                Utils::EpochSleep(EpochSleep(args)) => {
                    let mut ctx = cli::Context::new::<IO>(global_args)
                        .expect("expected to construct a context");
                    let mut ledger_address = args.ledger_address.clone();
                    let client =
                        C::from_tendermint_address(&mut ledger_address);
                    client
                        .wait_until_node_is_synced::<IO>()
                        .await
                        .proceed_or_else(error)?;
                    let args = args.to_sdk(&mut ctx);
                    rpc::epoch_sleep::<_, IO>(&client, args).await;
                }
            },
        }
        Ok(())
    }
}
