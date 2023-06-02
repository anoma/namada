//! Namada client CLI.

use std::time::Duration;

use color_eyre::eyre::Result;
use namada_apps::cli::cmds::*;
use namada_apps::cli::{self, args, Context, safe_exit};
use namada_apps::client::{rpc, tx, utils};
use namada_apps::facade::tendermint::block::Height;
use namada_apps::facade::tendermint_config::net::Address as TendermintAddress;
use namada_apps::facade::tendermint_rpc::{Client, HttpClient};
use tokio::time::sleep;
use namada::types::token::{Amount, DenominatedAmount, Denomination};
use namada_apps::cli::args::{InputAmount, Tx};
use namada_apps::cli::context::FromContext;
use namada_apps::config::TendermintMode;

pub async fn main() -> Result<()> {
    let test_cmd = NamadaClientWithContext::TxTransfer(TxTransfer(args::TxTransfer{
        tx: Tx {
            dry_run: false,
            dump_tx: false,
            force: false,
            broadcast_only: false,
            ledger_address: TendermintAddress::Tcp {peer_id: None, host: "127.0.0.1".to_string(), port: 27657},
            initialized_account_alias: None,
            fee_amount: InputAmount::Unvalidated(DenominatedAmount { amount: Amount::zero(), denom: Denomination(6) }),
            fee_token: FromContext::new("NAM".into()),
            gas_limit: Default::default(),
            expiration: None,
            signing_key: None,
            signer: Some(FromContext::new("Bertha".into())),
        },
        source: FromContext::new("xsktest1qqqqqqqqqqqqqqpagte43rsza46v55dlz8cffahv0fnr6eqacvnrkyuf9lmndgal7c2k4r7f7zu2yr5rjwr374unjjeuzrh6mquzy6grfdcnnu5clzaq2llqhr70a8yyx0p62aajqvrqjxrht3myuyypsvm725uyt5vm0fqzrzuuedtf6fala4r4nnazm9y9hq5yu6pq24arjskmpv4mdgfn3spffxxv8ugvym36kmnj45jcvvmm227vqjm5fq8882yhjsq97p7xrwqqd82s0".into()),
        target: FromContext::new("Christel".into()),
        token: FromContext::new("ETH".into()),
        sub_prefix: None,
        amount: InputAmount::Unvalidated(DenominatedAmount { amount: Amount::from_uint(30, 0).unwrap(), denom: Denomination(0) }),
    }));
    match cli::namada_client_cli()? {
        cli::NamadaClient::WithContext(cmd_box) => {
            let (cmd, ctx) = *cmd_box;
            use NamadaClientWithContext as Sub;
            /*let global_args = args::Global {
                chain_id: None,
                base_dir: " /tmp/.tmpmalzmo".into(),
                wasm_dir: None,
                mode: Some(TendermintMode::Full)
            };

            let ctx = Context::new(global_args).unwrap();
            println!("{:?}", test_cmd);*/
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
                    rpc::query_bonds(ctx, args).await.unwrap();
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
