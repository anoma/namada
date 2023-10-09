use std::sync::Arc;

use color_eyre::eyre::{eyre, Report, Result};
use namada::eth_bridge::ethers::providers::{Http, Provider};
use namada::ledger::eth_bridge::{bridge_pool, validator_set};
use namada::types::control_flow::ProceedOrElse;
use namada::types::io::Io;

use crate::cli;
use crate::cli::api::{CliApi, CliClient};
use crate::cli::args::{CliToSdk, CliToSdkCtxless};
use crate::cli::cmds::*;

fn error() -> Report {
    eyre!("Fatal error")
}

impl CliApi {
    pub async fn handle_relayer_command<C>(
        client: Option<C>,
        cmd: cli::NamadaRelayer,
        io: &impl Io,
    ) -> Result<()>
    where
        C: CliClient,
    {
        match cmd {
            cli::NamadaRelayer::EthBridgePoolWithCtx(boxed) => {
                let (sub, mut ctx) = *boxed;
                match sub {
                    EthBridgePoolWithCtx::RecommendBatch(RecommendBatch(
                        mut args,
                    )) => {
                        let client = client.unwrap_or_else(|| {
                            C::from_tendermint_address(
                                &mut args.query.ledger_address,
                            )
                        });
                        client
                            .wait_until_node_is_synced(io)
                            .await
                            .proceed_or_else(error)?;
                        let args = args.to_sdk(&mut ctx);
                        let namada = ctx.to_sdk(&client, io);
                        bridge_pool::recommend_batch(&namada, args)
                            .await
                            .proceed_or_else(error)?;
                    }
                }
            }
            cli::NamadaRelayer::EthBridgePoolWithoutCtx(sub) => match sub {
                EthBridgePoolWithoutCtx::ConstructProof(ConstructProof(
                    mut args,
                )) => {
                    let client = client.unwrap_or_else(|| {
                        C::from_tendermint_address(
                            &mut args.query.ledger_address,
                        )
                    });
                    client
                        .wait_until_node_is_synced(io)
                        .await
                        .proceed_or_else(error)?;
                    let args = args.to_sdk_ctxless();
                    bridge_pool::construct_proof(&client, io, args)
                        .await
                        .proceed_or_else(error)?;
                }
                EthBridgePoolWithoutCtx::RelayProof(RelayProof(mut args)) => {
                    let client = client.unwrap_or_else(|| {
                        C::from_tendermint_address(
                            &mut args.query.ledger_address,
                        )
                    });
                    client
                        .wait_until_node_is_synced(io)
                        .await
                        .proceed_or_else(error)?;
                    let eth_client = Arc::new(
                        Provider::<Http>::try_from(&args.eth_rpc_endpoint)
                            .unwrap(),
                    );
                    let args = args.to_sdk_ctxless();
                    bridge_pool::relay_bridge_pool_proof(
                        eth_client, &client, io, args,
                    )
                    .await
                    .proceed_or_else(error)?;
                }
                EthBridgePoolWithoutCtx::QueryPool(QueryEthBridgePool(
                    mut query,
                )) => {
                    let client = client.unwrap_or_else(|| {
                        C::from_tendermint_address(&mut query.ledger_address)
                    });
                    client
                        .wait_until_node_is_synced(io)
                        .await
                        .proceed_or_else(error)?;
                    bridge_pool::query_bridge_pool(&client, io).await;
                }
                EthBridgePoolWithoutCtx::QuerySigned(
                    QuerySignedBridgePool(mut query),
                ) => {
                    let client = client.unwrap_or_else(|| {
                        C::from_tendermint_address(&mut query.ledger_address)
                    });
                    client
                        .wait_until_node_is_synced(io)
                        .await
                        .proceed_or_else(error)?;
                    bridge_pool::query_signed_bridge_pool(&client, io)
                        .await
                        .proceed_or_else(error)?;
                }
                EthBridgePoolWithoutCtx::QueryRelays(QueryRelayProgress(
                    mut query,
                )) => {
                    let client = client.unwrap_or_else(|| {
                        C::from_tendermint_address(&mut query.ledger_address)
                    });
                    client
                        .wait_until_node_is_synced(io)
                        .await
                        .proceed_or_else(error)?;
                    bridge_pool::query_relay_progress(&client, io).await;
                }
            },
            cli::NamadaRelayer::ValidatorSet(sub) => match sub {
                ValidatorSet::BridgeValidatorSet(BridgeValidatorSet(
                    mut args,
                )) => {
                    let client = client.unwrap_or_else(|| {
                        C::from_tendermint_address(
                            &mut args.query.ledger_address,
                        )
                    });
                    client
                        .wait_until_node_is_synced(io)
                        .await
                        .proceed_or_else(error)?;
                    let args = args.to_sdk_ctxless();
                    validator_set::query_bridge_validator_set(
                        &client, io, args,
                    )
                    .await;
                }
                ValidatorSet::GovernanceValidatorSet(
                    GovernanceValidatorSet(mut args),
                ) => {
                    let client = client.unwrap_or_else(|| {
                        C::from_tendermint_address(
                            &mut args.query.ledger_address,
                        )
                    });
                    client
                        .wait_until_node_is_synced(io)
                        .await
                        .proceed_or_else(error)?;
                    let args = args.to_sdk_ctxless();
                    validator_set::query_governnace_validator_set(
                        &client, io, args,
                    )
                    .await;
                }
                ValidatorSet::ValidatorSetProof(ValidatorSetProof(
                    mut args,
                )) => {
                    let client = client.unwrap_or_else(|| {
                        C::from_tendermint_address(
                            &mut args.query.ledger_address,
                        )
                    });
                    client
                        .wait_until_node_is_synced(io)
                        .await
                        .proceed_or_else(error)?;
                    let args = args.to_sdk_ctxless();
                    validator_set::query_validator_set_update_proof(
                        &client, io, args,
                    )
                    .await;
                }
                ValidatorSet::ValidatorSetUpdateRelay(
                    ValidatorSetUpdateRelay(mut args),
                ) => {
                    let client = client.unwrap_or_else(|| {
                        C::from_tendermint_address(
                            &mut args.query.ledger_address,
                        )
                    });
                    client
                        .wait_until_node_is_synced(io)
                        .await
                        .proceed_or_else(error)?;
                    let eth_client = Arc::new(
                        Provider::<Http>::try_from(&args.eth_rpc_endpoint)
                            .unwrap(),
                    );
                    let args = args.to_sdk_ctxless();
                    validator_set::relay_validator_set_update(
                        eth_client, &client, io, args,
                    )
                    .await
                    .proceed_or_else(error)?;
                }
            },
        }
        Ok(())
    }
}
