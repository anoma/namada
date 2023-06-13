//! Namada relayer CLI.

use std::sync::Arc;

use color_eyre::eyre::{eyre, Report, Result};
use namada::eth_bridge::ethers::providers::{Http, Provider};
use namada::ledger::eth_bridge::{bridge_pool, validator_set};
use namada::ledger::rpc::wait_until_node_is_synched;
use namada::types::control_flow::ProceedOrElse;
use namada_apps::cli::args::CliToSdkCtxless;
use namada_apps::cli::{self, cmds};
use namada_apps::client::utils;
use namada_apps::facade::tendermint_rpc::HttpClient;

fn error() -> Report {
    eyre!("Fatal error")
}

pub async fn main() -> Result<()> {
    let (cmd, _) = cli::namada_relayer_cli()?;
    match cmd {
        cmds::NamadaRelayer::EthBridgePool(sub) => match sub {
            cmds::EthBridgePool::RecommendBatch(mut args) => {
                let client = HttpClient::new(utils::take_config_address(
                    &mut args.query.ledger_address,
                ))
                .unwrap();
                wait_until_node_is_synched(&client)
                    .await
                    .proceed_or_else(error)?;
                let args = args.to_sdk_ctxless();
                bridge_pool::recommend_batch(&client, args)
                    .await
                    .proceed_or_else(error)?;
            }
            cmds::EthBridgePool::ConstructProof(mut args) => {
                let client = HttpClient::new(utils::take_config_address(
                    &mut args.query.ledger_address,
                ))
                .unwrap();
                wait_until_node_is_synched(&client)
                    .await
                    .proceed_or_else(error)?;
                let args = args.to_sdk_ctxless();
                bridge_pool::construct_proof(&client, args)
                    .await
                    .proceed_or_else(error)?;
            }
            cmds::EthBridgePool::RelayProof(mut args) => {
                let client = HttpClient::new(utils::take_config_address(
                    &mut args.query.ledger_address,
                ))
                .unwrap();
                wait_until_node_is_synched(&client)
                    .await
                    .proceed_or_else(error)?;
                let eth_client = Arc::new(
                    Provider::<Http>::try_from(&args.eth_rpc_endpoint).unwrap(),
                );
                let args = args.to_sdk_ctxless();
                bridge_pool::relay_bridge_pool_proof(eth_client, &client, args)
                    .await
                    .proceed_or_else(error)?;
            }
            cmds::EthBridgePool::QueryPool(mut query) => {
                let client = HttpClient::new(utils::take_config_address(
                    &mut query.ledger_address,
                ))
                .unwrap();
                wait_until_node_is_synched(&client)
                    .await
                    .proceed_or_else(error)?;
                bridge_pool::query_bridge_pool(&client).await;
            }
            cmds::EthBridgePool::QuerySigned(mut query) => {
                let client = HttpClient::new(utils::take_config_address(
                    &mut query.ledger_address,
                ))
                .unwrap();
                wait_until_node_is_synched(&client)
                    .await
                    .proceed_or_else(error)?;
                bridge_pool::query_signed_bridge_pool(&client)
                    .await
                    .proceed_or_else(error)?;
            }
            cmds::EthBridgePool::QueryRelays(mut query) => {
                let client = HttpClient::new(utils::take_config_address(
                    &mut query.ledger_address,
                ))
                .unwrap();
                wait_until_node_is_synched(&client)
                    .await
                    .proceed_or_else(error)?;
                bridge_pool::query_relay_progress(&client).await;
            }
        },
        cmds::NamadaRelayer::ValidatorSet(sub) => match sub {
            cmds::ValidatorSet::ConsensusValidatorSet(mut args) => {
                let client = HttpClient::new(utils::take_config_address(
                    &mut args.query.ledger_address,
                ))
                .unwrap();
                wait_until_node_is_synched(&client)
                    .await
                    .proceed_or_else(error)?;
                let args = args.to_sdk_ctxless();
                validator_set::query_validator_set_args(&client, args).await;
            }
            cmds::ValidatorSet::ValidatorSetProof(mut args) => {
                let client = HttpClient::new(utils::take_config_address(
                    &mut args.query.ledger_address,
                ))
                .unwrap();
                wait_until_node_is_synched(&client)
                    .await
                    .proceed_or_else(error)?;
                let args = args.to_sdk_ctxless();
                validator_set::query_validator_set_update_proof(&client, args)
                    .await;
            }
            cmds::ValidatorSet::ValidatorSetUpdateRelay(mut args) => {
                let client = HttpClient::new(utils::take_config_address(
                    &mut args.query.ledger_address,
                ))
                .unwrap();
                wait_until_node_is_synched(&client)
                    .await
                    .proceed_or_else(error)?;
                let eth_client = Arc::new(
                    Provider::<Http>::try_from(&args.eth_rpc_endpoint).unwrap(),
                );
                let args = args.to_sdk_ctxless();
                validator_set::relay_validator_set_update(
                    eth_client, &client, args,
                )
                .await
                .proceed_or_else(error)?;
            }
        },
    }
    Ok(())
}
