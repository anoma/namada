pub mod bridge_pool;
pub mod validator_set;

use std::ops::ControlFlow;

use tokio::time::{Duration, Instant};
use web30::client::Web3;

use crate::node::ledger::ethereum_oracle::eth_syncing_status;
use crate::timeouts::TimeoutStrategy;

/// Block until Ethereum finishes synchronizing.
pub async fn block_on_eth_sync(deadline: Instant, url: &str) {
    let client = Web3::new(url, std::time::Duration::from_secs(10));
    TimeoutStrategy::LinearBackoff {
        delta: Duration::from_secs(1),
    }
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
    .expect("Timed out while waiting for Ethereum to synchronize");
}
