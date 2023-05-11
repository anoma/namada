//! Control flow utilities for client and ledger nodes.

pub mod timeouts;

use tokio::sync::oneshot;

/// Install a shutdown signal handler, and retrieve the associated
/// signal's receiver.
pub fn install_shutdown_signal() -> oneshot::Receiver<()> {
    let (tx, rx) = oneshot::channel();
    tokio::spawn(async move {
        shutdown_send(tx).await;
    });
    rx
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
    tx.send(())
        .expect("The oneshot receiver should still be alive");
}

#[cfg(windows)]
async fn shutdown_send(tx: oneshot::Sender<()>) {
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

#[cfg(not(any(unix, windows)))]
async fn shutdown_send(tx: oneshot::Sender<()>) {
    match tokio::signal::ctrl_c().await {
        Ok(()) => tracing::info!("Received interrupt signal, exiting..."),
        Err(err) => {
            tracing::error!("Failed to listen for CTRL+C signal: {err}")
        }
    }
    tx.send(())
        .expect("The oneshot receiver should still be alive");
}
