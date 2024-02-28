use color_eyre::eyre::Result;
use masp_primitives::zip32::ExtendedFullViewingKey;
use namada::io::Io;
use namada_sdk::{Namada, NamadaImpl};

use crate::cli;
use crate::cli::api::{CliApi, CliClient};
use crate::cli::args::CliToSdk;
use crate::cli::cmds::*;
use crate::client::{rpc, tx, utils};

impl CliApi {
    pub async fn handle_client_command<C, IO: Io>(
        client: Option<C>,
        cmd: cli::NamadaClient,
        io: IO,
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
                    Sub::TxCustom(TxCustom(args)) => {
                        // TODO: too much boilerplate to setup client
                        let chain_ctx = ctx.borrow_mut_chain_or_exit();
                        let ledger_address =
                            chain_ctx.get(&args.tx.ledger_address);
                        let client = client.unwrap_or_else(|| {
                            C::from_tendermint_address(&ledger_address)
                        });
                        client.wait_until_node_is_synced(&io).await?;
                        let args = args.to_sdk(&mut ctx);
                        let namada = ctx.to_sdk(client, io);
                        let dry_run =
                            args.tx.dry_run || args.tx.dry_run_wrapper;
                        tx::submit_custom(&namada, args).await?;
                        if !dry_run {
                            namada
                                .wallet()
                                .await
                                .save()
                                .unwrap_or_else(|err| eprintln!("{}", err));
                        } else {
                            namada.io().println(
                                "Transaction dry run. No addresses have been \
                                 saved.",
                            )
                        }
                    }
                    Sub::TxTransfer(TxTransfer(args)) => {
                        let chain_ctx = ctx.borrow_mut_chain_or_exit();
                        let ledger_address =
                            chain_ctx.get(&args.tx.ledger_address);
                        let client = client.unwrap_or_else(|| {
                            C::from_tendermint_address(&ledger_address)
                        });
                        client.wait_until_node_is_synced(&io).await?;
                        let args = args.to_sdk(&mut ctx);
                        let namada = ctx.to_sdk(client, io);
                        tx::submit_transfer(&namada, args).await?;
                    }
                    Sub::TxIbcTransfer(TxIbcTransfer(args)) => {
                        let chain_ctx = ctx.borrow_mut_chain_or_exit();
                        let ledger_address =
                            chain_ctx.get(&args.tx.ledger_address);
                        let client = client.unwrap_or_else(|| {
                            C::from_tendermint_address(&ledger_address)
                        });
                        client.wait_until_node_is_synced(&io).await?;
                        let args = args.to_sdk(&mut ctx);
                        let namada = ctx.to_sdk(client, io);
                        tx::submit_ibc_transfer(&namada, args).await?;
                    }
                    Sub::TxUpdateAccount(TxUpdateAccount(args)) => {
                        let chain_ctx = ctx.borrow_mut_chain_or_exit();
                        let ledger_address =
                            chain_ctx.get(&args.tx.ledger_address);
                        let client = client.unwrap_or_else(|| {
                            C::from_tendermint_address(&ledger_address)
                        });
                        client.wait_until_node_is_synced(&io).await?;
                        let args = args.to_sdk(&mut ctx);
                        let namada = ctx.to_sdk(client, io);
                        tx::submit_update_account(&namada, args).await?;
                    }
                    Sub::TxInitAccount(TxInitAccount(args)) => {
                        let chain_ctx = ctx.borrow_mut_chain_or_exit();
                        let ledger_address =
                            chain_ctx.get(&args.tx.ledger_address);
                        let client = client.unwrap_or_else(|| {
                            C::from_tendermint_address(&ledger_address)
                        });
                        client.wait_until_node_is_synced(&io).await?;
                        let args = args.to_sdk(&mut ctx);
                        let namada = ctx.to_sdk(client, io);
                        let dry_run =
                            args.tx.dry_run || args.tx.dry_run_wrapper;
                        tx::submit_init_account(&namada, args).await?;
                        if !dry_run {
                            namada
                                .wallet()
                                .await
                                .save()
                                .unwrap_or_else(|err| eprintln!("{}", err));
                        } else {
                            namada.io().println(
                                "Transaction dry run. No addresses have been \
                                 saved.",
                            )
                        }
                    }
                    Sub::TxBecomeValidator(TxBecomeValidator(args)) => {
                        let chain_ctx = ctx.borrow_mut_chain_or_exit();
                        let ledger_address =
                            chain_ctx.get(&args.tx.ledger_address);
                        let client = client.unwrap_or_else(|| {
                            C::from_tendermint_address(&ledger_address)
                        });
                        client.wait_until_node_is_synced(&io).await?;
                        let args = args.to_sdk(&mut ctx);
                        let cli::context::ChainContext {
                            wallet,
                            mut config,
                            shielded,
                            native_token,
                        } = ctx.take_chain_or_exit();
                        let namada = NamadaImpl::native_new(
                            client,
                            wallet,
                            shielded,
                            io,
                            native_token,
                        );
                        tx::submit_become_validator(&namada, &mut config, args)
                            .await?;
                    }
                    Sub::TxInitValidator(TxInitValidator(args)) => {
                        let chain_ctx = ctx.borrow_mut_chain_or_exit();
                        let ledger_address =
                            chain_ctx.get(&args.tx.ledger_address);
                        let client = client.unwrap_or_else(|| {
                            C::from_tendermint_address(&ledger_address)
                        });
                        client.wait_until_node_is_synced(&io).await?;
                        let args = args.to_sdk(&mut ctx);
                        let cli::context::ChainContext {
                            wallet,
                            mut config,
                            shielded,
                            native_token,
                        } = ctx.take_chain_or_exit();
                        let namada = NamadaImpl::native_new(
                            client,
                            wallet,
                            shielded,
                            io,
                            native_token,
                        );
                        tx::submit_init_validator(&namada, &mut config, args)
                            .await?;
                    }
                    Sub::TxInitProposal(TxInitProposal(args)) => {
                        let chain_ctx = ctx.borrow_mut_chain_or_exit();
                        let ledger_address =
                            chain_ctx.get(&args.tx.ledger_address);
                        let client = client.unwrap_or_else(|| {
                            C::from_tendermint_address(&ledger_address)
                        });
                        client.wait_until_node_is_synced(&io).await?;
                        let args = args.to_sdk(&mut ctx);
                        let namada = ctx.to_sdk(client, io);
                        tx::submit_init_proposal(&namada, args).await?;
                    }
                    Sub::TxVoteProposal(TxVoteProposal(args)) => {
                        let chain_ctx = ctx.borrow_mut_chain_or_exit();
                        let ledger_address =
                            chain_ctx.get(&args.tx.ledger_address);
                        let client = client.unwrap_or_else(|| {
                            C::from_tendermint_address(&ledger_address)
                        });
                        client.wait_until_node_is_synced(&io).await?;
                        let args = args.to_sdk(&mut ctx);
                        let namada = ctx.to_sdk(client, io);
                        tx::submit_vote_proposal(&namada, args).await?;
                    }
                    Sub::TxRevealPk(TxRevealPk(args)) => {
                        let chain_ctx = ctx.borrow_mut_chain_or_exit();
                        let ledger_address =
                            chain_ctx.get(&args.tx.ledger_address);
                        let client = client.unwrap_or_else(|| {
                            C::from_tendermint_address(&ledger_address)
                        });
                        client.wait_until_node_is_synced(&io).await?;
                        let args = args.to_sdk(&mut ctx);
                        let namada = ctx.to_sdk(client, io);
                        tx::submit_reveal_pk(&namada, args).await?;
                    }
                    Sub::Bond(Bond(args)) => {
                        let chain_ctx = ctx.borrow_mut_chain_or_exit();
                        let ledger_address =
                            chain_ctx.get(&args.tx.ledger_address);
                        let client = client.unwrap_or_else(|| {
                            C::from_tendermint_address(&ledger_address)
                        });
                        client.wait_until_node_is_synced(&io).await?;
                        let args = args.to_sdk(&mut ctx);
                        let namada = ctx.to_sdk(client, io);
                        tx::submit_bond(&namada, args).await?;
                    }
                    Sub::Unbond(Unbond(args)) => {
                        let chain_ctx = ctx.borrow_mut_chain_or_exit();
                        let ledger_address =
                            chain_ctx.get(&args.tx.ledger_address);
                        let client = client.unwrap_or_else(|| {
                            C::from_tendermint_address(&ledger_address)
                        });
                        client.wait_until_node_is_synced(&io).await?;
                        let args = args.to_sdk(&mut ctx);
                        let namada = ctx.to_sdk(client, io);
                        tx::submit_unbond(&namada, args).await?;
                    }
                    Sub::Withdraw(Withdraw(args)) => {
                        let chain_ctx = ctx.borrow_mut_chain_or_exit();
                        let ledger_address =
                            chain_ctx.get(&args.tx.ledger_address);
                        let client = client.unwrap_or_else(|| {
                            C::from_tendermint_address(&ledger_address)
                        });
                        client.wait_until_node_is_synced(&io).await?;
                        let args = args.to_sdk(&mut ctx);
                        let namada = ctx.to_sdk(client, io);
                        tx::submit_withdraw(&namada, args).await?;
                    }
                    Sub::ClaimRewards(ClaimRewards(args)) => {
                        let chain_ctx = ctx.borrow_mut_chain_or_exit();
                        let ledger_address =
                            chain_ctx.get(&args.tx.ledger_address);
                        let client = client.unwrap_or_else(|| {
                            C::from_tendermint_address(&ledger_address)
                        });
                        client.wait_until_node_is_synced(&io).await?;
                        let args = args.to_sdk(&mut ctx);
                        let namada = ctx.to_sdk(client, io);
                        tx::submit_claim_rewards(&namada, args).await?;
                    }
                    Sub::Redelegate(Redelegate(args)) => {
                        let chain_ctx = ctx.borrow_mut_chain_or_exit();
                        let ledger_address =
                            chain_ctx.get(&args.tx.ledger_address);
                        let client = client.unwrap_or_else(|| {
                            C::from_tendermint_address(&ledger_address)
                        });
                        client.wait_until_node_is_synced(&io).await?;
                        let args = args.to_sdk(&mut ctx);
                        let namada = ctx.to_sdk(client, io);
                        tx::submit_redelegate(&namada, args).await?;
                    }
                    Sub::TxCommissionRateChange(TxCommissionRateChange(
                        args,
                    )) => {
                        let chain_ctx = ctx.borrow_mut_chain_or_exit();
                        let ledger_address =
                            chain_ctx.get(&args.tx.ledger_address);
                        let client = client.unwrap_or_else(|| {
                            C::from_tendermint_address(&ledger_address)
                        });
                        client.wait_until_node_is_synced(&io).await?;
                        let args = args.to_sdk(&mut ctx);
                        let namada = ctx.to_sdk(client, io);
                        tx::submit_validator_commission_change(&namada, args)
                            .await?;
                    }
                    Sub::TxChangeConsensusKey(TxChangeConsensusKey(args)) => {
                        let chain_ctx = ctx.borrow_mut_chain_or_exit();
                        let ledger_address =
                            chain_ctx.get(&args.tx.ledger_address);
                        let client = client.unwrap_or_else(|| {
                            C::from_tendermint_address(&ledger_address)
                        });
                        client.wait_until_node_is_synced(&io).await?;
                        let args = args.to_sdk(&mut ctx);
                        let cli::context::ChainContext {
                            wallet,
                            mut config,
                            shielded,
                            native_token,
                        } = ctx.take_chain_or_exit();
                        let namada = NamadaImpl::native_new(
                            client,
                            wallet,
                            shielded,
                            io,
                            native_token,
                        );
                        tx::submit_change_consensus_key(
                            &namada,
                            &mut config,
                            args,
                        )
                        .await?;
                    }
                    Sub::TxMetadataChange(TxMetadataChange(args)) => {
                        let chain_ctx = ctx.borrow_mut_chain_or_exit();
                        let ledger_address =
                            chain_ctx.get(&args.tx.ledger_address);
                        let client = client.unwrap_or_else(|| {
                            C::from_tendermint_address(&ledger_address)
                        });
                        client.wait_until_node_is_synced(&io).await?;
                        let args = args.to_sdk(&mut ctx);
                        let namada = ctx.to_sdk(client, io);
                        tx::submit_validator_metadata_change(&namada, args)
                            .await?;
                    }
                    Sub::ShieldedSync(ShieldedSync(args)) => {
                        let client = client.unwrap_or_else(|| {
                            C::from_tendermint_address(&args.ledger_address)
                        });
                        client.wait_until_node_is_synced(&io).await?;
                        let args = args.to_sdk(&mut ctx);
                        let chain_ctx = ctx.take_chain_or_exit();
                        let vks = chain_ctx
                            .wallet
                            .get_viewing_keys()
                            .values()
                            .copied()
                            .map(|vk| ExtendedFullViewingKey::from(vk).fvk.vk)
                            .chain(args.viewing_keys.into_iter().map(|vk| {
                                ExtendedFullViewingKey::from(vk).fvk.vk
                            }))
                            .collect::<Vec<_>>();
                        let sks = args
                            .spending_keys
                            .into_iter()
                            .map(|sk| sk.into())
                            .collect::<Vec<_>>();
                        crate::client::masp::syncing(
                            chain_ctx.shielded,
                            &client,
                            &io,
                            args.batch_size,
                            args.last_query_height,
                            &sks,
                            &vks,
                        )
                        .await?;
                    }
                    // Eth bridge
                    Sub::AddToEthBridgePool(args) => {
                        let args = args.0;
                        let chain_ctx = ctx.borrow_mut_chain_or_exit();
                        let ledger_address =
                            chain_ctx.get(&args.tx.ledger_address);
                        let client = client.unwrap_or_else(|| {
                            C::from_tendermint_address(&ledger_address)
                        });
                        client.wait_until_node_is_synced(&io).await?;
                        let args = args.to_sdk(&mut ctx);
                        let namada = ctx.to_sdk(client, io);
                        tx::submit_bridge_pool_tx(&namada, args).await?;
                    }
                    Sub::TxUnjailValidator(TxUnjailValidator(args)) => {
                        let chain_ctx = ctx.borrow_mut_chain_or_exit();
                        let ledger_address =
                            chain_ctx.get(&args.tx.ledger_address);
                        let client = client.unwrap_or_else(|| {
                            C::from_tendermint_address(&ledger_address)
                        });
                        client.wait_until_node_is_synced(&io).await?;
                        let args = args.to_sdk(&mut ctx);
                        let namada = ctx.to_sdk(client, io);
                        tx::submit_unjail_validator(&namada, args).await?;
                    }
                    Sub::TxDeactivateValidator(TxDeactivateValidator(args)) => {
                        let chain_ctx = ctx.borrow_mut_chain_or_exit();
                        let ledger_address =
                            chain_ctx.get(&args.tx.ledger_address);
                        let client = client.unwrap_or_else(|| {
                            C::from_tendermint_address(&ledger_address)
                        });
                        client.wait_until_node_is_synced(&io).await?;
                        let args = args.to_sdk(&mut ctx);
                        let namada = ctx.to_sdk(client, io);
                        tx::submit_deactivate_validator(&namada, args).await?;
                    }
                    Sub::TxReactivateValidator(TxReactivateValidator(args)) => {
                        let chain_ctx = ctx.borrow_mut_chain_or_exit();
                        let ledger_address =
                            chain_ctx.get(&args.tx.ledger_address);
                        let client = client.unwrap_or_else(|| {
                            C::from_tendermint_address(&ledger_address)
                        });
                        client.wait_until_node_is_synced(&io).await?;
                        let args = args.to_sdk(&mut ctx);
                        let namada = ctx.to_sdk(client, io);
                        tx::submit_reactivate_validator(&namada, args).await?;
                    }
                    Sub::TxUpdateStewardCommission(
                        TxUpdateStewardCommission(args),
                    ) => {
                        let chain_ctx = ctx.borrow_mut_chain_or_exit();
                        let ledger_address =
                            chain_ctx.get(&args.tx.ledger_address);
                        let client = client.unwrap_or_else(|| {
                            C::from_tendermint_address(&ledger_address)
                        });
                        client.wait_until_node_is_synced(&io).await?;
                        let args = args.to_sdk(&mut ctx);
                        let namada = ctx.to_sdk(client, io);
                        tx::submit_update_steward_commission(&namada, args)
                            .await?;
                    }
                    Sub::TxResignSteward(TxResignSteward(args)) => {
                        let chain_ctx = ctx.borrow_mut_chain_or_exit();
                        let ledger_address =
                            chain_ctx.get(&args.tx.ledger_address);
                        let client = client.unwrap_or_else(|| {
                            C::from_tendermint_address(&ledger_address)
                        });
                        client.wait_until_node_is_synced(&io).await?;
                        let args = args.to_sdk(&mut ctx);
                        let namada = ctx.to_sdk(client, io);
                        tx::submit_resign_steward(&namada, args).await?;
                    }
                    // Ledger queries
                    Sub::QueryEpoch(QueryEpoch(args)) => {
                        let chain_ctx = ctx.borrow_mut_chain_or_exit();
                        let ledger_address =
                            chain_ctx.get(&args.ledger_address);
                        let client = client.unwrap_or_else(|| {
                            C::from_tendermint_address(&ledger_address)
                        });
                        client.wait_until_node_is_synced(&io).await?;
                        let namada = ctx.to_sdk(client, io);
                        rpc::query_and_print_epoch(&namada).await;
                    }
                    Sub::QueryNextEpochInfo(QueryNextEpochInfo(args)) => {
                        let chain_ctx = ctx.borrow_mut_chain_or_exit();
                        let ledger_address =
                            chain_ctx.get(&args.ledger_address);
                        let client = client.unwrap_or_else(|| {
                            C::from_tendermint_address(&ledger_address)
                        });
                        client.wait_until_node_is_synced(&io).await?;
                        let namada = ctx.to_sdk(client, io);
                        rpc::query_and_print_next_epoch_info(&namada).await;
                    }
                    Sub::QueryStatus(QueryStatus(args)) => {
                        let chain_ctx = ctx.borrow_mut_chain_or_exit();
                        let ledger_address =
                            chain_ctx.get(&args.ledger_address);
                        let client = client.unwrap_or_else(|| {
                            C::from_tendermint_address(&ledger_address)
                        });
                        let namada = ctx.to_sdk(client, io);
                        rpc::query_and_print_status(&namada).await;
                    }
                    Sub::QueryValidatorState(QueryValidatorState(args)) => {
                        let chain_ctx = ctx.borrow_mut_chain_or_exit();
                        let ledger_address =
                            chain_ctx.get(&args.query.ledger_address);
                        let client = client.unwrap_or_else(|| {
                            C::from_tendermint_address(&ledger_address)
                        });
                        client.wait_until_node_is_synced(&io).await?;
                        let args = args.to_sdk(&mut ctx);
                        let namada = ctx.to_sdk(client, io);
                        rpc::query_and_print_validator_state(&namada, args)
                            .await;
                    }
                    Sub::QueryTransfers(QueryTransfers(args)) => {
                        let chain_ctx = ctx.borrow_mut_chain_or_exit();
                        let ledger_address =
                            chain_ctx.get(&args.query.ledger_address);
                        let client = client.unwrap_or_else(|| {
                            C::from_tendermint_address(&ledger_address)
                        });
                        client.wait_until_node_is_synced(&io).await?;
                        let args = args.to_sdk(&mut ctx);
                        let namada = ctx.to_sdk(client, io);
                        rpc::query_transfers(&namada, args).await;
                    }
                    Sub::QueryConversions(QueryConversions(args)) => {
                        let chain_ctx = ctx.borrow_mut_chain_or_exit();
                        let ledger_address =
                            chain_ctx.get(&args.query.ledger_address);
                        let client = client.unwrap_or_else(|| {
                            C::from_tendermint_address(&ledger_address)
                        });
                        client.wait_until_node_is_synced(&io).await?;
                        let args = args.to_sdk(&mut ctx);
                        let namada = ctx.to_sdk(client, io);
                        rpc::query_conversions(&namada, args).await;
                    }
                    Sub::QueryMaspRewardTokens(QueryMaspRewardTokens(args)) => {
                        let chain_ctx = ctx.borrow_mut_chain_or_exit();
                        let ledger_address =
                            chain_ctx.get(&args.ledger_address);
                        let client = client.unwrap_or_else(|| {
                            C::from_tendermint_address(&ledger_address)
                        });
                        client.wait_until_node_is_synced(&io).await?;
                        let namada = ctx.to_sdk(client, io);
                        rpc::query_masp_reward_tokens(&namada).await;
                    }
                    Sub::QueryBlock(QueryBlock(args)) => {
                        let chain_ctx = ctx.borrow_mut_chain_or_exit();
                        let ledger_address =
                            chain_ctx.get(&args.ledger_address);
                        let client = client.unwrap_or_else(|| {
                            C::from_tendermint_address(&ledger_address)
                        });
                        client.wait_until_node_is_synced(&io).await?;
                        let namada = ctx.to_sdk(client, io);
                        rpc::query_block(&namada).await;
                    }
                    Sub::QueryBalance(QueryBalance(args)) => {
                        let chain_ctx = ctx.borrow_mut_chain_or_exit();
                        let ledger_address =
                            chain_ctx.get(&args.query.ledger_address);
                        let client = client.unwrap_or_else(|| {
                            C::from_tendermint_address(&ledger_address)
                        });
                        client.wait_until_node_is_synced(&io).await?;
                        let args = args.to_sdk(&mut ctx);
                        let namada = ctx.to_sdk(client, io);
                        rpc::query_balance(&namada, args).await;
                    }
                    Sub::QueryBonds(QueryBonds(args)) => {
                        let chain_ctx = ctx.borrow_mut_chain_or_exit();
                        let ledger_address =
                            chain_ctx.get(&args.query.ledger_address);
                        let client = client.unwrap_or_else(|| {
                            C::from_tendermint_address(&ledger_address)
                        });
                        client.wait_until_node_is_synced(&io).await?;
                        let args = args.to_sdk(&mut ctx);
                        let namada = ctx.to_sdk(client, io);
                        rpc::query_bonds(&namada, args)
                            .await
                            .expect("expected successful query of bonds");
                    }
                    Sub::QueryBondedStake(QueryBondedStake(args)) => {
                        let chain_ctx = ctx.borrow_mut_chain_or_exit();
                        let ledger_address =
                            chain_ctx.get(&args.query.ledger_address);
                        let client = client.unwrap_or_else(|| {
                            C::from_tendermint_address(&ledger_address)
                        });
                        client.wait_until_node_is_synced(&io).await?;
                        let args = args.to_sdk(&mut ctx);
                        let namada = ctx.to_sdk(client, io);
                        rpc::query_bonded_stake(&namada, args).await;
                    }
                    Sub::QueryCommissionRate(QueryCommissionRate(args)) => {
                        let chain_ctx = ctx.borrow_mut_chain_or_exit();
                        let ledger_address =
                            chain_ctx.get(&args.query.ledger_address);
                        let client = client.unwrap_or_else(|| {
                            C::from_tendermint_address(&ledger_address)
                        });
                        client.wait_until_node_is_synced(&io).await?;
                        let args = args.to_sdk(&mut ctx);
                        let namada = ctx.to_sdk(client, io);
                        rpc::query_and_print_commission_rate(&namada, args)
                            .await;
                    }
                    Sub::QueryMetaData(QueryMetaData(args)) => {
                        let chain_ctx = ctx.borrow_mut_chain_or_exit();
                        let ledger_address =
                            chain_ctx.get(&args.query.ledger_address);
                        let client = client.unwrap_or_else(|| {
                            C::from_tendermint_address(&ledger_address)
                        });
                        client.wait_until_node_is_synced(&io).await?;
                        let args = args.to_sdk(&mut ctx);
                        let namada = ctx.to_sdk(client, io);
                        rpc::query_and_print_metadata(&namada, args).await;
                    }
                    Sub::QuerySlashes(QuerySlashes(args)) => {
                        let chain_ctx = ctx.borrow_mut_chain_or_exit();
                        let ledger_address =
                            chain_ctx.get(&args.query.ledger_address);
                        let client = client.unwrap_or_else(|| {
                            C::from_tendermint_address(&ledger_address)
                        });
                        client.wait_until_node_is_synced(&io).await?;
                        let args = args.to_sdk(&mut ctx);
                        let namada = ctx.to_sdk(client, io);
                        rpc::query_slashes(&namada, args).await;
                    }
                    Sub::QueryRewards(QueryRewards(args)) => {
                        let chain_ctx = ctx.borrow_mut_chain_or_exit();
                        let ledger_address =
                            chain_ctx.get(&args.query.ledger_address);
                        let client = client.unwrap_or_else(|| {
                            C::from_tendermint_address(&ledger_address)
                        });
                        client.wait_until_node_is_synced(&io).await?;
                        let args = args.to_sdk(&mut ctx);
                        let namada = ctx.to_sdk(client, io);
                        rpc::query_and_print_rewards(&namada, args).await;
                    }
                    Sub::QueryDelegations(QueryDelegations(args)) => {
                        let chain_ctx = ctx.borrow_mut_chain_or_exit();
                        let ledger_address =
                            chain_ctx.get(&args.query.ledger_address);
                        let client = client.unwrap_or_else(|| {
                            C::from_tendermint_address(&ledger_address)
                        });
                        client.wait_until_node_is_synced(&io).await?;
                        let args = args.to_sdk(&mut ctx);
                        let namada = ctx.to_sdk(client, io);
                        rpc::query_delegations(&namada, args).await;
                    }
                    Sub::QueryFindValidator(QueryFindValidator(args)) => {
                        let chain_ctx = ctx.borrow_mut_chain_or_exit();
                        let ledger_address =
                            chain_ctx.get(&args.query.ledger_address);
                        let client = client.unwrap_or_else(|| {
                            C::from_tendermint_address(&ledger_address)
                        });
                        client.wait_until_node_is_synced(&io).await?;
                        let args = args.to_sdk(&mut ctx);
                        let namada = ctx.to_sdk(client, io);
                        rpc::query_find_validator(&namada, args).await;
                    }
                    Sub::QueryResult(QueryResult(args)) => {
                        let chain_ctx = ctx.borrow_mut_chain_or_exit();
                        let ledger_address =
                            chain_ctx.get(&args.query.ledger_address);
                        let client = client.unwrap_or_else(|| {
                            C::from_tendermint_address(&ledger_address)
                        });
                        client.wait_until_node_is_synced(&io).await?;
                        let args = args.to_sdk(&mut ctx);
                        let namada = ctx.to_sdk(client, io);
                        rpc::query_result(&namada, args).await;
                    }
                    Sub::QueryRawBytes(QueryRawBytes(args)) => {
                        let chain_ctx = ctx.borrow_mut_chain_or_exit();
                        let ledger_address =
                            chain_ctx.get(&args.query.ledger_address);
                        let client = client.unwrap_or_else(|| {
                            C::from_tendermint_address(&ledger_address)
                        });
                        client.wait_until_node_is_synced(&io).await?;
                        let args = args.to_sdk(&mut ctx);
                        let namada = ctx.to_sdk(client, io);
                        rpc::query_raw_bytes(&namada, args).await;
                    }
                    Sub::QueryProposal(QueryProposal(args)) => {
                        let chain_ctx = ctx.borrow_mut_chain_or_exit();
                        let ledger_address =
                            chain_ctx.get(&args.query.ledger_address);
                        let client = client.unwrap_or_else(|| {
                            C::from_tendermint_address(&ledger_address)
                        });
                        client.wait_until_node_is_synced(&io).await?;
                        let args = args.to_sdk(&mut ctx);
                        let namada = ctx.to_sdk(client, io);
                        rpc::query_proposal(&namada, args).await;
                    }
                    Sub::QueryProposalResult(QueryProposalResult(args)) => {
                        let chain_ctx = ctx.borrow_mut_chain_or_exit();
                        let ledger_address =
                            chain_ctx.get(&args.query.ledger_address);
                        let client = client.unwrap_or_else(|| {
                            C::from_tendermint_address(&ledger_address)
                        });
                        client.wait_until_node_is_synced(&io).await?;
                        let args = args.to_sdk(&mut ctx);
                        let namada = ctx.to_sdk(client, io);
                        rpc::query_proposal_result(&namada, args).await;
                    }
                    Sub::QueryProposalVotes(QueryProposalVotes(args)) => {
                        let chain_ctx = ctx.borrow_mut_chain_or_exit();
                        let ledger_address =
                            chain_ctx.get(&args.query.ledger_address);
                        let client = client.unwrap_or_else(|| {
                            C::from_tendermint_address(&ledger_address)
                        });
                        client.wait_until_node_is_synced(&io).await?;
                        let args = args.to_sdk(&mut ctx);
                        let namada = ctx.to_sdk(client, io);
                        rpc::query_proposal_votes(&namada, args).await;
                    }
                    Sub::QueryProtocolParameters(QueryProtocolParameters(
                        args,
                    )) => {
                        let chain_ctx = ctx.borrow_mut_chain_or_exit();
                        let ledger_address =
                            chain_ctx.get(&args.query.ledger_address);
                        let client = client.unwrap_or_else(|| {
                            C::from_tendermint_address(&ledger_address)
                        });
                        client.wait_until_node_is_synced(&io).await?;
                        let args = args.to_sdk(&mut ctx);
                        let namada = ctx.to_sdk(client, io);
                        rpc::query_protocol_parameters(&namada, args).await;
                    }
                    Sub::QueryPgf(QueryPgf(args)) => {
                        let chain_ctx = ctx.borrow_mut_chain_or_exit();
                        let ledger_address =
                            chain_ctx.get(&args.query.ledger_address);
                        let client = client.unwrap_or_else(|| {
                            C::from_tendermint_address(&ledger_address)
                        });
                        client.wait_until_node_is_synced(&io).await?;
                        let args = args.to_sdk(&mut ctx);
                        let namada = ctx.to_sdk(client, io);
                        rpc::query_pgf(&namada, args).await;
                    }
                    Sub::QueryAccount(QueryAccount(args)) => {
                        let chain_ctx = ctx.borrow_mut_chain_or_exit();
                        let ledger_address =
                            chain_ctx.get(&args.query.ledger_address);
                        let client = client.unwrap_or_else(|| {
                            C::from_tendermint_address(&ledger_address)
                        });
                        client.wait_until_node_is_synced(&io).await?;
                        let args = args.to_sdk(&mut ctx);
                        let namada = ctx.to_sdk(client, io);
                        rpc::query_account(&namada, args).await;
                    }
                    Sub::SignTx(SignTx(args)) => {
                        let chain_ctx = ctx.borrow_mut_chain_or_exit();
                        let ledger_address =
                            chain_ctx.get(&args.tx.ledger_address);
                        let client = client.unwrap_or_else(|| {
                            C::from_tendermint_address(&ledger_address)
                        });
                        client.wait_until_node_is_synced(&io).await?;
                        let args = args.to_sdk(&mut ctx);
                        let namada = ctx.to_sdk(client, io);
                        tx::sign_tx(&namada, args).await?;
                    }
                    Sub::GenIbcShieldedTransfer(GenIbcShieldedTransfer(
                        args,
                    )) => {
                        let chain_ctx = ctx.borrow_mut_chain_or_exit();
                        let ledger_address =
                            chain_ctx.get(&args.query.ledger_address);
                        let client = client.unwrap_or_else(|| {
                            C::from_tendermint_address(&ledger_address)
                        });
                        client.wait_until_node_is_synced(&io).await?;
                        let args = args.to_sdk(&mut ctx);
                        let namada = ctx.to_sdk(client, io);
                        tx::gen_ibc_shielded_transfer(&namada, args).await?;
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
                Utils::ValidateWasm(ValidateWasm(args)) => {
                    utils::validate_wasm(args)
                }
                Utils::InitNetwork(InitNetwork(args)) => {
                    utils::init_network(global_args, args)
                }
                Utils::GenesisBond(GenesisBond(args)) => {
                    utils::genesis_bond(args)
                }
                Utils::DeriveGenesisAddresses(DeriveGenesisAddresses(args)) => {
                    utils::derive_genesis_addresses(global_args, args)
                }
                Utils::InitGenesisEstablishedAccount(
                    InitGenesisEstablishedAccount(args),
                ) => utils::init_genesis_established_account(global_args, args),
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
                    let chain_ctx = ctx.borrow_mut_chain_or_exit();
                    let ledger_address = chain_ctx.get(&args.ledger_address);
                    let client = C::from_tendermint_address(&ledger_address);
                    client.wait_until_node_is_synced(&io).await?;
                    let args = args.to_sdk(&mut ctx);
                    let namada = ctx.to_sdk(client, io);
                    rpc::epoch_sleep(&namada, args).await;
                }
                Utils::ValidateGenesisTemplates(ValidateGenesisTemplates(
                    args,
                )) => utils::validate_genesis_templates(global_args, args),
                Utils::TestGenesis(TestGenesis(args)) => {
                    utils::test_genesis(args)
                }
                Utils::SignGenesisTxs(SignGenesisTxs(args)) => {
                    utils::sign_genesis_tx(global_args, args).await
                }
            },
        }
        Ok(())
    }
}
