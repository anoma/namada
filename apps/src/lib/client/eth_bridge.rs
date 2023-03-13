pub mod bridge_pool;
pub mod validator_set;

use std::ops::ControlFlow;
use std::time::Duration as StdDuration;

use tokio::time::{Duration, Instant};
use web30::client::Web3;

use crate::cli;
use crate::node::ledger::ethereum_oracle::eth_syncing_status;
use crate::timeouts::TimeoutStrategy;

/// Arguments to [`block_on_eth_sync`].
pub struct BlockOnEthSync<'rpc_url> {
    /// The deadline before we timeout in the CLI.
    pub deadline: Instant,
    /// The RPC timeout duration. Should be shorter than
    /// the value of `delta_sleep`.
    pub rpc_timeout: StdDuration,
    /// The duration of sleep calls between each RPC timeout.
    pub delta_sleep: Duration,
    /// The address of the Ethereum RPC.
    pub url: &'rpc_url str,
}

/// Block until Ethereum finishes synchronizing.
pub async fn block_on_eth_sync(args: BlockOnEthSync<'_>) {
    let BlockOnEthSync {
        deadline,
        rpc_timeout,
        delta_sleep,
        url,
    } = args;
    println!("Attempting to synchronize with the Ethereum network");
    let client = Web3::new(url, rpc_timeout);
    TimeoutStrategy::LinearBackoff { delta: delta_sleep }
        .timeout(deadline, || async {
            let Ok(status) = eth_syncing_status(&client).await else {
            return ControlFlow::Continue(());
        };
            if status.is_synchronized() {
                ControlFlow::Break(())
            } else {
                ControlFlow::Continue(())
            }
        })
        .await
        .unwrap_or_else(|_| {
            println!("Timed out while waiting for Ethereum to synchronize");
            cli::safe_exit(1);
        });
    println!("The Ethereum node is up to date");
}

/// Block until Ethereum finishes synchronizing.
pub async fn eth_sync_or_exit(url: &str) {
    let client = Web3::new(url, std::time::Duration::from_secs(3));
    let is_synchronized = eth_syncing_status(&client)
        .await
        .map(|status| status.is_synchronized())
        .unwrap_or_else(|err| {
            println!(
                "An error occurred while fetching the Ethereum \
                 synchronization status: {err}"
            );
            cli::safe_exit(1);
        });
    if !is_synchronized {
        println!("The Ethereum node has not finished synchronizing");
        cli::safe_exit(1);
    }
}
