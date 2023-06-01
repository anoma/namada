//! Namada relayer CLI.

use color_eyre::eyre::Result;
use namada::ledger::eth_bridge::{bridge_pool, validator_set};
use namada::ledger::rpc::wait_until_node_is_synched;
use namada_apps::cli::{self, cmds, safe_exit};
use namada_apps::facade::tendermint_rpc::HttpClient;

pub async fn main() -> Result<()> {
    let (cmd, _) = cli::namada_relayer_cli()?;
    match cmd {
        cmds::NamadaRelayer::EthBridgePool(sub) => match sub {
            cmds::EthBridgePool::RecommendBatch(mut args) => {
                let client = HttpClient::new(std::mem::take(
                    &mut args.tx.ledger_address,
                ))
                .unwrap();
                if wait_until_node_is_synched(&client).await.is_break() {
                    safe_exit(1);
                }
                let args = args.to_sdk(&mut ctx);
                bridge_pool::recommend_batch(&client, args).await;
            }
            cmds::EthBridgePool::ConstructProof(mut args) => {
                let client = HttpClient::new(std::mem::take(
                    &mut args.tx.ledger_address,
                ))
                .unwrap();
                if wait_until_node_is_synched(&client).await.is_break() {
                    safe_exit(1);
                }
                let args = args.to_sdk(&mut ctx);
                bridge_pool::construct_proof(&client, args).await;
            }
            cmds::EthBridgePool::RelayProof(mut args) => {
                let client = HttpClient::new(std::mem::take(
                    &mut args.tx.ledger_address,
                ))
                .unwrap();
                if wait_until_node_is_synched(&client).await.is_break() {
                    safe_exit(1);
                }
                let args = args.to_sdk(&mut ctx);
                bridge_pool::relay_bridge_pool_proof(&client, args).await;
            }
            cmds::EthBridgePool::QueryPool(mut query) => {
                let client = HttpClient::new(std::mem::take(
                    &mut args.tx.ledger_address,
                ))
                .unwrap();
                if wait_until_node_is_synched(&client).await.is_break() {
                    safe_exit(1);
                }
                let args = args.to_sdk(&mut ctx);
                bridge_pool::query_bridge_pool(&client, query).await;
            }
            cmds::EthBridgePool::QuerySigned(mut query) => {
                let client = HttpClient::new(std::mem::take(
                    &mut args.tx.ledger_address,
                ))
                .unwrap();
                if wait_until_node_is_synched(&client).await.is_break() {
                    safe_exit(1);
                }
                let args = args.to_sdk(&mut ctx);
                bridge_pool::query_signed_bridge_pool(&client, query).await;
            }
            cmds::EthBridgePool::QueryRelays(mut query) => {
                let client = HttpClient::new(std::mem::take(
                    &mut args.tx.ledger_address,
                ))
                .unwrap();
                if wait_until_node_is_synched(&client).await.is_break() {
                    safe_exit(1);
                }
                let args = args.to_sdk(&mut ctx);
                bridge_pool::query_relay_progress(&client, query).await;
            }
        },
        cmds::NamadaRelayer::ValidatorSet(sub) => match sub {
            cmds::ValidatorSet::ConsensusValidatorSet(mut args) => {
                let client = HttpClient::new(std::mem::take(
                    &mut args.tx.ledger_address,
                ))
                .unwrap();
                if wait_until_node_is_synched(&client).await.is_break() {
                    safe_exit(1);
                }
                let args = args.to_sdk(&mut ctx);
                validator_set::query_validator_set_args(&client, args).await;
            }
            cmds::ValidatorSet::ValidatorSetProof(mut args) => {
                let client = HttpClient::new(std::mem::take(
                    &mut args.tx.ledger_address,
                ))
                .unwrap();
                if wait_until_node_is_synched(&client).await.is_break() {
                    safe_exit(1);
                }
                let args = args.to_sdk(&mut ctx);
                validator_set::query_validator_set_update_proof(&client, args)
                    .await;
            }
            cmds::ValidatorSet::ValidatorSetUpdateRelay(mut args) => {
                let client = HttpClient::new(std::mem::take(
                    &mut args.tx.ledger_address,
                ))
                .unwrap();
                if wait_until_node_is_synched(&client).await.is_break() {
                    safe_exit(1);
                }
                let args = args.to_sdk(&mut ctx);
                validator_set::relay_validator_set_update(&client, args).await;
            }
        },
    }
    Ok(())
}
