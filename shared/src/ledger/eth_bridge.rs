//! Ethereum bridge utilities shared between `wasm` and the `cli`.

pub mod bridge_pool;
pub mod validator_set;

use std::ops::ControlFlow;

use itertools::Either;
pub use namada_core::ledger::eth_bridge::storage::wrapped_erc20s;
pub use namada_core::ledger::eth_bridge::{ADDRESS, INTERNAL_ADDRESS};
pub use namada_ethereum_bridge::parameters::*;
pub use namada_ethereum_bridge::storage::eth_bridge_queries::*;
use num256::Uint256;
use tokio::task::LocalSet;
use web30::client::Web3;
use web30::jsonrpc::error::Web3Error;

use crate::types::control_flow::time::{
    Duration, Error as TimeoutError, Instant, SleepStrategy,
};
use crate::types::control_flow::{self, Halt, TryHalt};

const DEFAULT_BACKOFF: Duration = std::time::Duration::from_millis(500);
const DEFAULT_CEILING: Duration = std::time::Duration::from_secs(30);

/// The result of querying an Ethereum nodes syncing status.
pub enum SyncStatus {
    /// The fullnode is syncing.
    Syncing,
    /// The fullnode is synced up to the given block height.
    AtHeight(Uint256),
}

impl SyncStatus {
    /// Returns true if [`SyncStatus`] reflects a synchronized node.
    pub fn is_synchronized(&self) -> bool {
        matches!(self, SyncStatus::AtHeight(_))
    }
}

/// Fetch the sync status of an Ethereum node.
#[inline]
pub async fn eth_syncing_status(
    client: &Web3,
) -> Result<SyncStatus, TimeoutError> {
    eth_syncing_status_timeout(
        client,
        DEFAULT_BACKOFF,
        Instant::now() + DEFAULT_CEILING,
    )
    .await
}

/// Fetch the sync status of an Ethereum node, with a custom time
/// out duration.
///
/// Queries to the Ethereum node are interspersed with constant backoff
/// sleeps of `backoff_duration`, before ultimately timing out at `deadline`.
pub async fn eth_syncing_status_timeout(
    client: &Web3,
    backoff_duration: Duration,
    deadline: Instant,
) -> Result<SyncStatus, TimeoutError> {
    SleepStrategy::Constant(backoff_duration)
        .timeout(deadline, || async {
            ControlFlow::Break(match client.eth_block_number().await {
                Ok(height) if height == 0u64.into() => SyncStatus::Syncing,
                Ok(height) => SyncStatus::AtHeight(height),
                Err(Web3Error::SyncingNode(_)) => SyncStatus::Syncing,
                Err(_) => return ControlFlow::Continue(()),
            })
        })
        .await
}

/// Arguments to [`block_on_eth_sync`].
pub struct BlockOnEthSync<'rpc_url> {
    /// The deadline before we timeout in the CLI.
    pub deadline: Instant,
    /// The RPC timeout duration. Should be shorter than
    /// the value of `delta_sleep`.
    pub rpc_timeout: Duration,
    /// The duration of sleep calls between each RPC timeout.
    pub delta_sleep: Duration,
    /// The address of the Ethereum RPC.
    pub url: &'rpc_url str,
}

/// Block until Ethereum finishes synchronizing.
pub async fn block_on_eth_sync(args: BlockOnEthSync<'_>) -> Halt<()> {
    let BlockOnEthSync {
        deadline,
        rpc_timeout,
        delta_sleep,
        url,
    } = args;
    tracing::info!("Attempting to synchronize with the Ethereum network");
    let client = Web3::new(url, rpc_timeout);
    SleepStrategy::LinearBackoff { delta: delta_sleep }
        .timeout(deadline, || async {
            let local_set = LocalSet::new();
            let status_fut = local_set
                .run_until(async { eth_syncing_status(&client).await });
            let Ok(status) = status_fut.await else {
                return ControlFlow::Continue(());
            };
            if status.is_synchronized() {
                ControlFlow::Break(())
            } else {
                ControlFlow::Continue(())
            }
        })
        .await
        .try_halt(|_| {
            tracing::error!(
                "Timed out while waiting for Ethereum to synchronize"
            );
        })?;
    tracing::info!("The Ethereum node is up to date");
    control_flow::proceed(())
}

/// Check if Ethereum has finished synchronizing. In case it has
/// not, perform `action`.
pub async fn eth_sync_or<F, T>(url: &str, mut action: F) -> Halt<Either<T, ()>>
where
    F: FnMut() -> T,
{
    let client = Web3::new(url, std::time::Duration::from_secs(3));
    let local_set = LocalSet::new();
    let status_fut =
        local_set.run_until(async { eth_syncing_status(&client).await });
    let is_synchronized = status_fut
        .await
        .map(|status| status.is_synchronized())
        .try_halt(|err| {
            tracing::error!(
                "An error occurred while fetching the Ethereum \
                 synchronization status: {err}"
            );
        })?;
    if is_synchronized {
        control_flow::proceed(Either::Right(()))
    } else {
        control_flow::proceed(Either::Left(action()))
    }
}

/// Check if Ethereum has finished synchronizing. In case it has
/// not, end execution.
pub async fn eth_sync_or_exit(url: &str) -> Halt<()> {
    eth_sync_or(url, || {
        tracing::error!("The Ethereum node has not finished synchronizing");
    })
    .await?
    .try_halt(|_| ())
}
