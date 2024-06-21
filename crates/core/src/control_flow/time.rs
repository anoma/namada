//! Time related logic for futures.

#![allow(clippy::arithmetic_side_effects)]

use std::future::Future;
use std::ops::ControlFlow;

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

    /// Map a function to the duration returned from a
    /// sleep strategy.
    fn map<M>(self, map: M) -> Map<Self, M>
    where
        M: Fn(Duration) -> Duration,
        Self: Sized,
    {
        Map {
            map,
            strategy: self,
        }
    }
}

/// Map a function to the duration returned from a
/// sleep strategy.
pub struct Map<S, M> {
    strategy: S,
    map: M,
}

impl<S, M> SleepStrategy for Map<S, M>
where
    S: SleepStrategy,
    M: Fn(Duration) -> Duration,
{
    type State = S::State;

    fn new_state() -> S::State {
        S::new_state()
    }

    #[inline]
    fn backoff(&self, state: &S::State) -> Duration {
        (self.map)(self.strategy.backoff(state))
    }

    #[inline]
    fn next_state(&self, state: &mut S::State) {
        self.strategy.next_state(state)
    }
}

/// Constant sleep strategy.
#[derive(Debug, Clone)]
pub struct Constant(pub Duration);

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
pub struct ExponentialBackoff<D> {
    /// The base of the exponentiation.
    pub base: u64,
    /// Retrieve a duration from a [`u64`].
    pub as_duration: D,
}

impl<D> SleepStrategy for ExponentialBackoff<D>
where
    D: Fn(u64) -> Duration,
{
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

/// Zero cost abstraction to check if we should exit
/// a running [`SleepStrategy`].
pub trait SleepRunUntil {
    /// The output type to return.
    type Output<T>;

    /// Exit with success, returning a value.
    ///
    /// Consumes the [`SleepRunUntil`] instance.
    fn success<T>(self, ret: T) -> Self::Output<T>;

    /// Exit with an error.
    ///
    /// Consumes the [`SleepRunUntil`] instance.
    fn error<T>(self) -> Self::Output<T>;

    /// Check if an error has occurred,
    /// prompting an early exit.
    fn poll_error(&mut self) -> bool;
}

/// Run a fallible task forever.
pub struct RunForever;

impl SleepRunUntil for RunForever {
    type Output<T> = T;

    #[inline]
    fn success<T>(self, ret: T) -> Self::Output<T> {
        ret
    }

    #[cold]
    fn error<T>(self) -> Self::Output<T> {
        unreachable!("Run forever never reaches an error")
    }

    #[inline]
    fn poll_error(&mut self) -> bool {
        false
    }
}

/// A [`SleepRunUntil`] implementation, for running a
/// fallible task a certain number of times before
/// ultimately giving up.
pub struct RunWithRetries {
    /// The number of times to run the fallible task.
    ///
    /// When the counter reaches zero, [`Sleep`] exits
    /// with an error.
    pub counter: usize,
}

impl SleepRunUntil for RunWithRetries {
    type Output<T> = Result<T, Error>;

    #[inline]
    fn success<T>(self, ret: T) -> Self::Output<T> {
        Ok(ret)
    }

    #[inline]
    fn error<T>(self) -> Self::Output<T> {
        Err(Error::MaxRetriesExceeded)
    }

    #[inline]
    fn poll_error(&mut self) -> bool {
        if self.counter == 0 {
            return true;
        }
        self.counter -= 1;
        false
    }
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
    pub async fn run_until<T, F, G, R>(
        &self,
        mut sleep_run: R,
        mut future_gen: G,
    ) -> R::Output<T>
    where
        R: SleepRunUntil,
        G: FnMut() -> F,
        F: Future<Output = ControlFlow<T>>,
    {
        let mut state = S::new_state();
        loop {
            if sleep_run.poll_error() {
                break sleep_run.error();
            }
            let fut = future_gen();
            match fut.await {
                ControlFlow::Continue(()) => {
                    self.sleep_update(&mut state).await;
                }
                ControlFlow::Break(ret) => break sleep_run.success(ret),
            }
        }
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
        self.run_until(RunForever, future_gen).await
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
        self.run_until(
            RunWithRetries {
                counter: max_retries,
            },
            future_gen,
        )
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

    pub use wasmtimer::std::Instant;
    use wasmtimer::tokio::{sleep, timeout_at};

    #[inline]
    pub(super) async fn internal_timeout_at<F: Future>(
        deadline: Instant,
        future: F,
    ) -> Result<F::Output, ()> {
        timeout_at(deadline, future).await.map_err(|_| ())
    }

    #[inline]
    pub(super) async fn internal_sleep(dur: Duration) {
        _ = sleep(dur).await;
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
