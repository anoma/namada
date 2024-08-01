//! Control flow utilities.

pub mod time;

/// Shutdown signal receiver.
pub trait ShutdownSignal {
    /// Wait until a shutdown signal is received.
    #[allow(async_fn_in_trait)]
    async fn wait_for_shutdown(&mut self);

    /// Check if the shutdown signal has been received.
    fn received(&mut self) -> bool;
}

#[cfg(not(target_family = "wasm"))]
mod non_wasm {
    use std::ops::Drop;
    use std::sync::atomic::{self, AtomicBool};

    use lazy_static::lazy_static;
    use tokio::sync::watch;

    use super::ShutdownSignal;

    struct InterruptChannel {
        sender: watch::Sender<bool>,
        receiver: watch::Receiver<bool>,
    }

    static LISTENING_TO_INTERRUPT_SIG: AtomicBool = AtomicBool::new(false);

    struct ListeningToInterruptGuard;

    impl Drop for ListeningToInterruptGuard {
        fn drop(&mut self) {
            LISTENING_TO_INTERRUPT_SIG.store(false, atomic::Ordering::SeqCst);
        }
    }

    lazy_static! {
        static ref SHUTDOWN_SIGNAL: InterruptChannel = {
            let (sender, receiver) = watch::channel(false);
            InterruptChannel { sender, receiver }
        };
    }

    /// Shutdown signal receiver.
    pub struct ShutdownSignalChan {
        pub(crate) rx: watch::Receiver<bool>,
    }

    impl ShutdownSignal for ShutdownSignalChan {
        async fn wait_for_shutdown(&mut self) {
            _ = self.rx.changed().await;
        }

        fn received(&mut self) -> bool {
            self.rx.has_changed().unwrap()
        }
    }

    /// Install a shutdown signal handler, and retrieve the associated
    /// signal's receiver.
    pub fn install_shutdown_signal() -> ShutdownSignalChan {
        if LISTENING_TO_INTERRUPT_SIG
            .compare_exchange(
                false,
                true,
                atomic::Ordering::SeqCst,
                atomic::Ordering::SeqCst,
            )
            .is_ok()
        {
            let guard = ListeningToInterruptGuard;

            tokio::spawn(async move {
                shutdown_send(guard).await;
            });
        }
        ShutdownSignalChan {
            rx: SHUTDOWN_SIGNAL.receiver.clone(),
        }
    }

    /// Shutdown signal receiver
    #[cfg(unix)]
    async fn shutdown_send(_guard: ListeningToInterruptGuard) {
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
        SHUTDOWN_SIGNAL.sender.send_replace(true);
    }

    /// Shutdown signal receiver
    #[cfg(windows)]
    async fn shutdown_send(_guard: ListeningToInterruptGuard) {
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
        SHUTDOWN_SIGNAL.sender.send_replace(true);
    }
}

#[cfg(not(target_family = "wasm"))]
pub use non_wasm::*;

#[cfg(any(test, feature = "testing"))]
pub mod testing {
    //! Control flow testing utilities.

    use tokio::sync::watch;

    use super::*;

    /// A manually triggerable shutdown signal used for testing
    pub fn shutdown_signal() -> (watch::Sender<bool>, ShutdownSignalChan) {
        let (tx, rx) = watch::channel(false);
        (tx, ShutdownSignalChan { rx })
    }
}
