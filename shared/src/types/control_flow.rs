//! Control flow utilities.

pub mod time;

use std::future::Future;
use std::ops::ControlFlow;
use std::pin::Pin;
use std::task::{Context, Poll};

use futures::future::FutureExt;
#[cfg(any(unix, windows))]
use tokio::sync::oneshot;

/// A [`ControlFlow`] to control the halt status
/// of some execution context.
///
/// No return values are assumed to exist.
pub type Halt<T> = ControlFlow<(), T>;

/// Halt all execution.
pub const fn halt<T>() -> Halt<T> {
    ControlFlow::Break(())
}

/// Proceed execution.
pub const fn proceed<T>(value: T) -> Halt<T> {
    ControlFlow::Continue(value)
}

/// Halting abstraction to obtain [`ControlFlow`] actions.
pub trait TryHalt<T, E> {
    /// Possibly exit from some context, if we encounter an
    /// error. We may recover from said error.
    fn try_halt_or_recover<F>(self, handle_err: F) -> Halt<T>
    where
        F: FnMut(E) -> Halt<T>;

    /// Exit from some context, if we encounter an error.
    #[inline]
    fn try_halt<F>(self, mut handle_err: F) -> Halt<T>
    where
        Self: Sized,
        F: FnMut(E),
    {
        self.try_halt_or_recover(|e| {
            handle_err(e);
            halt()
        })
    }
}

impl<T, E> TryHalt<T, E> for Result<T, E> {
    #[inline]
    fn try_halt_or_recover<F>(self, mut handle_err: F) -> Halt<T>
    where
        F: FnMut(E) -> Halt<T>,
    {
        match self {
            Ok(x) => proceed(x),
            Err(e) => handle_err(e),
        }
    }
}

impl<L, R> TryHalt<R, L> for itertools::Either<L, R> {
    #[inline]
    fn try_halt_or_recover<F>(self, mut handle_err: F) -> Halt<R>
    where
        F: FnMut(L) -> Halt<R>,
    {
        match self {
            itertools::Either::Right(x) => proceed(x),
            itertools::Either::Left(e) => handle_err(e),
        }
    }
}

/// A shutdown signal receiver.
pub struct ShutdownSignal {
    #[cfg(not(any(unix, windows)))]
    _inner: (),
    #[cfg(any(unix, windows))]
    rx: oneshot::Receiver<()>,
}

#[cfg(any(unix, windows))]
impl Future for ShutdownSignal {
    type Output = ();

    #[inline]
    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<()> {
        self.rx.poll_unpin(cx).map(|_| ())
    }
}

#[cfg(not(any(unix, windows)))]
impl Future for ShutdownSignal {
    type Output = ();

    #[inline]
    fn poll(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<()> {
        Poll::Pending
    }
}

/// Install a shutdown signal handler, and retrieve the associated
/// signal's receiver.
pub fn install_shutdown_signal() -> ShutdownSignal {
    // #[cfg(target_family = "wasm")]
    // {
    //     compile_error!("WASM shutdown signal not supported");
    // }

    // on unix-like systems and windows, install a proper
    // OS signal based shutdown handler
    #[cfg(any(unix, windows))]
    {
        let (tx, rx) = oneshot::channel();
        tokio::spawn(async move {
            shutdown_send(tx).await;
        });
        ShutdownSignal { rx }
    }

    // on the remaining platforms, simply block forever
    #[cfg(not(any(unix, windows)))]
    {
        ShutdownSignal { _inner: () }
    }
}

#[cfg(unix)]
async fn shutdown_send(tx: oneshot::Sender<()>) {
    use tokio::signal::unix::{signal, SignalKind};
    let mut sigterm = signal(SignalKind::terminate()).unwrap();
    let mut sighup = signal(SignalKind::hangup()).unwrap();
    let mut sigpipe = signal(SignalKind::pipe()).unwrap();
    tokio::select! {
        signal = tokio::signal::ctrl_c() => {
            match signal {
                Ok(()) => tracing::info!("Received interrupt signal, exiting..."),
                Err(err) => tracing::error!("Failed to listen for CTRL+C signal: {err}"),
            }
        },
        signal = sigterm.recv() => {
            match signal {
                Some(()) => tracing::info!("Received termination signal, exiting..."),
                None => {
                    tracing::error!(
                        "Termination signal cannot be caught anymore, exiting..."
                    )
                }
            }
        },
        signal = sighup.recv() => {
            match signal {
                Some(()) => tracing::info!("Received hangup signal, exiting..."),
                None => tracing::error!("Hangup signal cannot be caught anymore, exiting..."),
            }
        },
        signal = sigpipe.recv() => {
            match signal {
                Some(()) => tracing::info!("Received pipe signal, exiting..."),
                None => tracing::error!("Pipe signal cannot be caught anymore, exiting..."),
            }
        },
    };
    if tx.send(()).is_err() {
        tracing::debug!("Shutdown signal receiver was dropped");
    }
}

#[cfg(windows)]
async fn shutdown_send(tx: oneshot::Sender<()>) {
    let mut sigbreak = tokio::signal::windows::ctrl_break().unwrap();
    tokio::select! {
        signal = tokio::signal::ctrl_c() => {
            match signal {
                Ok(()) => tracing::info!("Received interrupt signal, exiting..."),
                Err(err) => tracing::error!("Failed to listen for CTRL+C signal: {err}"),
            }
        },
        signal = sigbreak.recv() => {
            match signal {
                Some(()) => tracing::info!("Received break signal, exiting..."),
                None => tracing::error!("Break signal cannot be caught anymore, exiting..."),
            }
        },
    };
    if tx.send(()).is_err() {
        tracing::debug!("Shutdown signal receiver was dropped");
    }
}
