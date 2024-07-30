use color_eyre::eyre::Result;
use namada_sdk::io::Io;

use crate::cli;
use crate::cli::api::{CliApi, CliClient};

impl CliApi {
    #[cfg(not(feature = "namada-eth-bridge"))]
    pub async fn handle_relayer_command<C>(
        _client: Option<C>,
        _cmd: cli::NamadaRelayer,
        io: impl Io,
    ) -> Result<()>
    where
        C: CliClient,
    {
        use namada_sdk::display_line;

        display_line!(&io, "The Namada Ethereum bridge is disabled");
        Ok(())
    }

    #[cfg(feature = "namada-eth-bridge")]
    pub async fn handle_relayer_command<C>(
        client: Option<C>,
        cmd: cli::NamadaRelayer,
        io: impl Io,
    ) -> Result<()>
    where
        C: CliClient,
    {
        use namada_sdk::eth_bridge::{bridge_pool, validator_set};

        use crate::cli::args::{CliToSdk, CliToSdkCtxless};
        use crate::cli::cmds::*;
        use crate::cli::utils::get_eth_rpc_client;

        match cmd {
            cli::NamadaRelayer::EthBridgePoolWithCtx(boxed) => {
                let (sub, mut ctx) = *boxed;
                match sub {
                    EthBridgePoolWithCtx::RecommendBatch(RecommendBatch(
                        args,
                    )) => {
                        let chain_ctx = ctx.borrow_mut_chain_or_exit();
                        let ledger_address =
                            chain_ctx.get(&args.query.ledger_address);
                        let client = client.unwrap_or_else(|| {
                            C::from_tendermint_address(&ledger_address)
                        });
                        client.wait_until_node_is_synced(&io).await?;
                        let args = args.to_sdk(&mut ctx)?;
                        let namada = ctx.to_sdk(client, io);
                        bridge_pool::recommend_batch(&namada, args).await?;
                    }
                }
            }
            cli::NamadaRelayer::EthBridgePoolWithoutCtx(sub) => match sub {
                EthBridgePoolWithoutCtx::ConstructProof(ConstructProof(
                    args,
                )) => {
                    let client = client.unwrap_or_else(|| {
                        C::from_tendermint_address(&args.ledger_address)
                    });
                    client.wait_until_node_is_synced(&io).await?;
                    let args = args.to_sdk_ctxless();
                    bridge_pool::construct_proof(&client, &io, args).await?;
                }
                EthBridgePoolWithoutCtx::RelayProof(RelayProof(args)) => {
                    let client = client.unwrap_or_else(|| {
                        C::from_tendermint_address(&args.ledger_address)
                    });
                    client.wait_until_node_is_synced(&io).await?;
                    let eth_client =
                        get_eth_rpc_client(&args.eth_rpc_endpoint).await;
                    let args = args.to_sdk_ctxless();
                    bridge_pool::relay_bridge_pool_proof(
                        eth_client, &client, &io, args,
                    )
                    .await?;
                }
                EthBridgePoolWithoutCtx::QueryPool(QueryEthBridgePool(
                    query,
                )) => {
                    let client = client.unwrap_or_else(|| {
                        C::from_tendermint_address(&query.ledger_address)
                    });
                    client.wait_until_node_is_synced(&io).await?;
                    bridge_pool::query_bridge_pool(&client, &io).await?;
                }
                EthBridgePoolWithoutCtx::QuerySigned(
                    QuerySignedBridgePool(query),
                ) => {
                    let client = client.unwrap_or_else(|| {
                        C::from_tendermint_address(&query.ledger_address)
                    });
                    client.wait_until_node_is_synced(&io).await?;
                    bridge_pool::query_signed_bridge_pool(&client, &io).await?;
                }
                EthBridgePoolWithoutCtx::QueryRelays(QueryRelayProgress(
                    query,
                )) => {
                    let client = client.unwrap_or_else(|| {
                        C::from_tendermint_address(&query.ledger_address)
                    });
                    client.wait_until_node_is_synced(&io).await?;
                    bridge_pool::query_relay_progress(&client, &io).await?;
                }
            },
            cli::NamadaRelayer::ValidatorSet(sub) => match sub {
                ValidatorSet::BridgeValidatorSet(BridgeValidatorSet(args)) => {
                    let client = client.unwrap_or_else(|| {
                        C::from_tendermint_address(&args.ledger_address)
                    });
                    client.wait_until_node_is_synced(&io).await?;
                    let args = args.to_sdk_ctxless();
                    validator_set::query_bridge_validator_set(
                        &client, &io, args,
                    )
                    .await?;
                }
                ValidatorSet::GovernanceValidatorSet(
                    GovernanceValidatorSet(args),
                ) => {
                    let client = client.unwrap_or_else(|| {
                        C::from_tendermint_address(&args.ledger_address)
                    });
                    client.wait_until_node_is_synced(&io).await?;
                    let args = args.to_sdk_ctxless();
                    validator_set::query_governnace_validator_set(
                        &client, &io, args,
                    )
                    .await?;
                }
                ValidatorSet::ValidatorSetProof(ValidatorSetProof(args)) => {
                    let client = client.unwrap_or_else(|| {
                        C::from_tendermint_address(&args.ledger_address)
                    });
                    client.wait_until_node_is_synced(&io).await?;
                    let args = args.to_sdk_ctxless();
                    validator_set::query_validator_set_update_proof(
                        &client, &io, args,
                    )
                    .await?;
                }
                ValidatorSet::ValidatorSetUpdateRelay(
                    ValidatorSetUpdateRelay(args),
                ) => {
                    let client = client.unwrap_or_else(|| {
                        C::from_tendermint_address(&args.ledger_address)
                    });
                    client.wait_until_node_is_synced(&io).await?;
                    let eth_client =
                        get_eth_rpc_client(&args.eth_rpc_endpoint).await;
                    let args = args.to_sdk_ctxless();
                    validator_set::relay_validator_set_update(
                        eth_client, &client, &io, args,
                    )
                    .await?;
                }
            },
        }
        Ok(())
    }
}
