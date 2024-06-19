//! Control flow utilities.

pub mod time;

use std::future::Future;
use std::pin::Pin;
use std::task::{Context, Poll};

#[cfg(any(unix, windows))]
use futures::future::FutureExt;
#[cfg(any(unix, windows))]
use tokio::sync::oneshot;
use tokio::sync::oneshot::error::TryRecvError;

/// A shutdown signal receiver.
pub struct ShutdownSignal {
    #[cfg(not(any(unix, windows)))]
    _inner: (),
    #[cfg(any(unix, windows))]
    rx: oneshot::Receiver<()>,
}

impl ShutdownSignal {
    /// Checks if an interrupt signal was received.
    #[cfg(any(unix, windows))]
    pub fn received(&mut self) -> bool {
        match self.rx.try_recv() {
            Ok(_) => true,
            Err(TryRecvError::Empty) => false,
            Err(TryRecvError::Closed) => true,
        }
    }
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

/// A manually triggerable shutdown signal used for testing
#[cfg(any(test, feature = "testing"))]
pub fn testing_shutdown_signal() -> (oneshot::Sender<()>, ShutdownSignal) {
    let (tx, rx) = oneshot::channel();
    (tx, ShutdownSignal { rx })
}

/// Shutdown signal receiver
#[cfg(unix)]
pub async fn shutdown_send(tx: oneshot::Sender<()>) {
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

/// Shutdown signal receiver
#[cfg(windows)]
pub async fn shutdown_send(tx: oneshot::Sender<()>) {
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
