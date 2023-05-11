//! Time out logic for futures.

use std::future::Future;
use std::ops::ControlFlow;

use tokio::time::error::Elapsed;
use tokio::time::{Duration, Instant};

/// A timeout strategy to
#[derive(Debug, Clone)]
pub enum SleepStrategy {
    /// A constant timeout strategy.
    Constant(Duration),
    /// A linear timeout strategy.
    LinearBackoff {
        /// The amount of time added to each consecutive timeout.
        delta: Duration,
    },
}

impl SleepStrategy {
    /// Sleep and update the `backoff` timeout, if necessary.
    async fn sleep_update(&self, backoff: &mut Duration) {
        match self {
            Self::Constant(sleep_duration) => {
                tokio::time::sleep(*sleep_duration).await;
            }
            Self::LinearBackoff { delta } => {
                *backoff += *delta;
                tokio::time::sleep(*backoff).await;
            }
        }
    }

    /// Execute a fallible task.
    ///
    /// Different retries will result in a sleep operation,
    /// with the current [`SleepStrategy`].
    pub async fn run<T, F, G>(&self, mut future_gen: G) -> T
    where
        G: FnMut() -> F,
        F: Future<Output = ControlFlow<T>>,
    {
        let mut backoff = Duration::from_secs(0);
        loop {
            let fut = future_gen();
            match fut.await {
                ControlFlow::Continue(()) => {
                    self.sleep_update(&mut backoff).await;
                }
                ControlFlow::Break(ret) => break ret,
            }
        }
    }

    /// Run a time constrained task until the given deadline.
    ///
    /// Different retries will result in a sleep operation,
    /// with the current [`SleepStrategy`].
    pub async fn timeout<T, F, G>(
        &self,
        deadline: Instant,
        future_gen: G,
    ) -> Result<T, Elapsed>
    where
        G: FnMut() -> F,
        F: Future<Output = ControlFlow<T>>,
    {
        tokio::time::timeout_at(
            deadline,
            async move { self.run(future_gen).await },
        )
        .await
    }
}
