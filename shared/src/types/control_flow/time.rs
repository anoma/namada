//! Time related logic for futures.

use std::future::Future;
use std::ops::ControlFlow;

use namada_core::hints;
use thiserror::Error;

/// Future task related errors.
#[derive(Error, Debug)]
pub enum Error {
    /// A future timed out.
    #[error("The future timed out")]
    Elapsed,
    /// A future ran for the max number of allowed times.
    #[error("Maximum number of retries exceeded")]
    MaxRetriesExceeded,
}

/// A sleep strategy to be applied to fallible runs of arbitrary tasks.
pub trait SleepStrategy {
    /// The state of the sleep strategy.
    type State;

    /// Return a new sleep strategy state.
    fn new_state() -> Self::State;

    /// Calculate a duration from a sleep strategy state.
    fn backoff(&self, state: &Self::State) -> Duration;

    /// Update the state of the sleep strategy.
    fn next_state(&self, state: &mut Self::State);
}

/// Constant sleep strategy.
#[derive(Debug, Clone)]
pub struct Constant(pub Duration);

impl Default for Constant {
    fn default() -> Self {
        Self(Duration::from_secs(1))
    }
}

impl SleepStrategy for Constant {
    type State = ();

    fn new_state() {
        // NOOP
    }

    fn backoff(&self, _: &()) -> Duration {
        self.0
    }

    fn next_state(&self, _: &mut ()) {
        // NOOP
    }
}

/// Linear backoff sleep strategy.
#[derive(Debug, Clone)]
pub struct LinearBackoff {
    /// The amount of time added to each consecutive sleep.
    pub delta: Duration,
}

impl Default for LinearBackoff {
    fn default() -> Self {
        Self {
            delta: Duration::from_secs(1),
        }
    }
}

impl SleepStrategy for LinearBackoff {
    type State = Duration;

    fn new_state() -> Duration {
        Duration::from_secs(0)
    }

    fn backoff(&self, state: &Duration) -> Duration {
        *state
    }

    fn next_state(&self, state: &mut Duration) {
        *state += self.delta;
    }
}

/// Exponential backoff sleep strategy.
#[derive(Debug, Clone)]
pub struct ExponentialBackoff {
    /// The base of the exponentiation.
    pub base: u64,
    /// Retrieve a duration from a [`u64`].
    pub as_duration: fn(u64) -> Duration,
}

impl Default for ExponentialBackoff {
    fn default() -> Self {
        Self {
            base: 2,
            as_duration: Duration::from_secs,
        }
    }
}

impl SleepStrategy for ExponentialBackoff {
    type State = u32;

    fn new_state() -> u32 {
        0
    }

    fn backoff(&self, state: &u32) -> Duration {
        (self.as_duration)(self.base.saturating_pow(*state))
    }

    fn next_state(&self, state: &mut Self::State) {
        *state = state.saturating_add(1);
    }
}

/// A [`SleepStrategy`] adaptor, to run async tasks with custom
/// sleep durations.
#[repr(transparent)]
#[derive(Debug, Clone)]
pub struct Sleep<S> {
    /// The sleep strategy to use.
    pub strategy: S,
}

impl<S: SleepStrategy> Sleep<S> {
    /// Update the sleep strategy state, and sleep for the given backoff.
    async fn sleep_update(&self, state: &mut S::State) {
        self.strategy.next_state(state);
        sleep(self.strategy.backoff(state)).await;
    }

    /// Run a future as many times as `iter_times`
    /// yields a value, or break preemptively if
    /// the future returns with [`ControlFlow::Break`].
    async fn run_times<T, F, G>(
        &self,
        iter_times: impl Iterator<Item = ()>,
        mut future_gen: G,
    ) -> Result<T, Error>
    where
        G: FnMut() -> F,
        F: Future<Output = ControlFlow<T>>,
    {
        let mut state = S::new_state();
        for _ in iter_times {
            let fut = future_gen();
            match fut.await {
                ControlFlow::Continue(()) => {
                    self.sleep_update(&mut state).await;
                }
                ControlFlow::Break(ret) => return Ok(ret),
            }
        }
        Err(Error::MaxRetriesExceeded)
    }

    /// Execute a fallible task.
    ///
    /// Different retries will result in a sleep operation,
    /// with the current [`SleepStrategy`].
    #[inline]
    pub async fn run<T, F, G>(&self, future_gen: G) -> T
    where
        G: FnMut() -> F,
        F: Future<Output = ControlFlow<T>>,
    {
        match self.run_times(std::iter::repeat(()), future_gen).await {
            Ok(x) => x,
            _ => {
                // the iterator never returns `None`
                hints::cold();
                unreachable!();
            }
        }
    }

    /// Run a time constrained task until the given deadline.
    ///
    /// Different retries will result in a sleep operation,
    /// with the current [`SleepStrategy`].
    #[inline]
    pub async fn timeout<T, F, G>(
        &self,
        deadline: Instant,
        future_gen: G,
    ) -> Result<T, Error>
    where
        G: FnMut() -> F,
        F: Future<Output = ControlFlow<T>>,
    {
        internal_timeout_at(deadline, async move { self.run(future_gen).await })
            .await
            .map_err(|_| Error::Elapsed)
    }

    /// Retry running a fallible task for a limited number of times,
    /// until it succeeds or exhausts the maximum number of tries.
    ///
    /// Different retries will result in a sleep operation,
    /// with the current [`SleepStrategy`].
    #[inline]
    pub async fn retry<T, F, G>(
        &self,
        max_retries: usize,
        future_gen: G,
    ) -> Result<T, Error>
    where
        G: FnMut() -> F,
        F: Future<Output = ControlFlow<T>>,
    {
        self.run_times(std::iter::repeat(()).take(max_retries), future_gen)
            .await
    }
}

/// Pause the active task for the given duration.
#[inline]
pub async fn sleep(dur: Duration) {
    internal_sleep(dur).await;
}

#[cfg(target_family = "wasm")]
#[allow(missing_docs)]
mod internal {
    use std::future::Future;
    pub use std::time::Duration;

    pub use wasm_timer::Instant;
    use wasm_timer::{Delay, TryFutureExt};

    #[inline]
    pub(super) async fn internal_timeout_at<F: Future>(
        deadline: Instant,
        future: F,
    ) -> Result<F::Output, ()> {
        let run_future = async move {
            let value = future.await;
            Result::<_, std::io::Error>::Ok(value)
        };
        run_future.timeout_at(deadline).await.map_err(|_| ())
    }

    #[inline]
    pub(super) async fn internal_sleep(dur: Duration) {
        _ = Delay::new(dur).await;
    }
}

#[cfg(not(target_family = "wasm"))]
#[allow(missing_docs)]
mod internal {
    use std::future::Future;

    pub use tokio::time::{Duration, Instant};

    #[inline]
    pub(super) async fn internal_timeout_at<F: Future>(
        deadline: Instant,
        future: F,
    ) -> Result<F::Output, ()> {
        tokio::time::timeout_at(deadline, future)
            .await
            .map_err(|_| ())
    }

    #[inline]
    pub(super) async fn internal_sleep(dur: Duration) {
        tokio::time::sleep(dur).await;
    }
}

pub use internal::*;
