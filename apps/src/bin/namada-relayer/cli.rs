//! Namada client CLI.

use color_eyre::eyre::Result;
use namada_apps::cli;
use namada_apps::cli::cmds;
use namada_apps::client::eth_bridge_pool;

pub async fn main() -> Result<()> {
    let (cmd, ctx) = cli::namada_relayer_cli()?;
    use cmds::EthBridgePool as Sub;
    match cmd {
        Sub::ConstructProof(args) => {
            eth_bridge_pool::construct_bridge_pool_proof(ctx, args).await;
        }
        Sub::QueryPool(query) => {
            eth_bridge_pool::query_bridge_pool(query).await;
        }
    }
    Ok(())
}
