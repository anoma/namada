//! Ethereum bridge utilities shared between `wasm` and the `cli`.

pub mod bridge_pool;
pub mod validator_set;

use std::ops::ControlFlow;

pub use ethers;
use ethers::providers::Middleware;
use itertools::Either;
pub use namada_core::ethereum_structs as structs;
pub use namada_ethereum_bridge::storage::eth_bridge_queries::*;
pub use namada_ethereum_bridge::storage::parameters::*;
pub use namada_ethereum_bridge::storage::wrapped_erc20s;
pub use namada_ethereum_bridge::{ADDRESS, *};
use num256::Uint256;

use crate::control_flow::time::{
    Constant, Duration, Instant, LinearBackoff, Sleep,
};
use crate::error::{Error, EthereumBridgeError};
use crate::io::Io;
use crate::{display_line, edisplay_line};

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
pub async fn eth_syncing_status<C>(client: &C) -> Result<SyncStatus, Error>
where
    C: Middleware,
{
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
pub async fn eth_syncing_status_timeout<C>(
    client: &C,
    backoff_duration: Duration,
    deadline: Instant,
) -> Result<SyncStatus, Error>
where
    C: Middleware,
{
    Sleep {
        strategy: Constant(backoff_duration),
    }
    .timeout(deadline, || async {
        let fut_syncing = client.syncing();
        let fut_block_num = client.get_block_number();
        let Ok(status) = futures::try_join!(fut_syncing, fut_block_num,) else {
            return ControlFlow::Continue(());
        };
        ControlFlow::Break(match status {
            (ethers::types::SyncingStatus::IsFalse, height)
                if height != 0u64.into() =>
            {
                SyncStatus::AtHeight(height.as_u64().into())
            }
            _ => SyncStatus::Syncing,
        })
    })
    .await
    .map_err(|_| Error::EthereumBridge(EthereumBridgeError::NodeTimeout))
}

/// Arguments to [`block_on_eth_sync`].
pub struct BlockOnEthSync {
    /// The deadline before we timeout in the CLI.
    pub deadline: Instant,
    /// The duration of sleep calls between each RPC timeout.
    pub delta_sleep: Duration,
}

/// Block until Ethereum finishes synchronizing.
pub async fn block_on_eth_sync<C, IO: Io>(
    client: &C,
    io: &IO,
    args: BlockOnEthSync,
) -> Result<(), Error>
where
    C: Middleware,
{
    let BlockOnEthSync {
        deadline,
        delta_sleep,
    } = args;
    display_line!(io, "Attempting to synchronize with the Ethereum network");
    Sleep {
        strategy: LinearBackoff { delta: delta_sleep },
    }
    .timeout(deadline, || async {
        let Ok(status) = eth_syncing_status(client).await else {
            return ControlFlow::Continue(());
        };
        if status.is_synchronized() {
            ControlFlow::Break(())
        } else {
            ControlFlow::Continue(())
        }
    })
    .await
    .map_err(|_| {
        edisplay_line!(
            io,
            "Timed out while waiting for Ethereum to synchronize"
        );
        Error::EthereumBridge(EthereumBridgeError::NodeTimeout)
    })?;
    display_line!(io, "The Ethereum node is up to date");
    Ok(())
}

/// Check if Ethereum has finished synchronizing. In case it has
/// not, perform `action`.
pub async fn eth_sync_or<C, F, T, IO: Io>(
    client: &C,
    io: &IO,
    mut action: F,
) -> Result<Either<T, ()>, Error>
where
    C: Middleware,
    F: FnMut() -> T,
{
    let is_synchronized = eth_syncing_status(client)
        .await
        .map(|status| status.is_synchronized())
        .map_err(|err| {
            edisplay_line!(
                io,
                "An error occurred while fetching the Ethereum \
                 synchronization status: {err}"
            );
            err
        })?;
    if is_synchronized {
        Ok(Either::Right(()))
    } else {
        Ok(Either::Left(action()))
    }
}

/// Check if Ethereum has finished synchronizing. In case it has
/// not, end execution.
pub async fn eth_sync_or_exit<C, IO: Io>(
    client: &C,
    io: &IO,
) -> Result<(), Error>
where
    C: Middleware,
{
    eth_sync_or(client, io, || {
        edisplay_line!(io, "The Ethereum node has not finished synchronizing");
    })
    .await?;
    Ok(())
}
