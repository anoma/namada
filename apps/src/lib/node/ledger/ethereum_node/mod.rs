pub mod events;
pub mod oracle;
pub mod test_tools;
use std::ffi::OsString;

use thiserror::Error;
use tokio::sync::oneshot::{Receiver, Sender};

#[derive(Error, Debug)]
pub enum Error {
    #[error("Failed to start Ethereum fullnode: {0}")]
    StartUp(std::io::Error),
    #[error("{0}")]
    Runtime(String),
    #[error(
        "The receiver of the Ethereum relayer messages unexpectedly dropped"
    )]
    RelayerReceiverDropped,
    #[error("The Ethereum Oracle process unexpectedly stopped")]
    Oracle,
    #[error(
        "Could not read Ethereum network to connect to from env var: {0:?}"
    )]
    EthereumNetwork(OsString),
    #[error("Could not decode Ethereum event: {0}")]
    Decode(String),
}

pub type Result<T> = std::result::Result<T, Error>;

/// Monitor the Ethereum fullnode subprocess, returning only once it has
/// stopped running. If a signal is sent on `abort_recv`, the fullnode
/// subprocess will be killed.
pub async fn monitor(
    mut node: eth_fullnode::EthereumNode,
    abort_recv: Receiver<Sender<()>>,
) {
    tokio::select! {
        // wait for the Ethereum fullnode to naturally exit
        exit_status = node.wait() => {
            match exit_status {
                Ok(exit_status) => {
                    tracing::info!(%exit_status, "Ethereum fullnode exited");
                },
                Err(err) => {
                    tracing::warn!("Error while waiting for the Ethereum fullnode to exit: {}", err);
                    tracing::info!("Ensuring Ethereum fullnode is shut down...");
                    node.kill().await;
                },
            };
        },
        // wait for an abort signal
        resp_sender = abort_recv => {
            match resp_sender {
                Ok(resp_sender) => {
                    tracing::info!("Shutting down Ethereum fullnode...");
                    node.kill().await;
                    resp_sender.send(()).unwrap();
                },
                Err(err) => {
                    tracing::error!("The Ethereum abort sender has unexpectedly dropped: {}", err);
                    tracing::info!("Shutting down Ethereum fullnode...");
                    node.kill().await;
                }
            }
        }
    }
}

/// Tools for running a geth fullnode process
pub mod eth_fullnode {
    use std::io;
    use std::process::ExitStatus;
    use std::time::Duration;

    use tokio::process::{Child, Command};
    use tokio::task::LocalSet;
    use web30::client::Web3;

    use super::{Error, Result};

    /// A handle to a running geth process and a channel
    /// that indicates it should shut down if the oracle
    /// stops.
    pub struct EthereumNode {
        process: Child,
    }

    /// Read from environment variable which Ethereum
    /// network to connect to. Defaults to mainnet if
    /// no variable is set.
    ///
    /// Returns an error if the env var is defined but not
    /// a valid unicode
    fn get_eth_network() -> Result<Option<String>> {
        match std::env::var("ETHEREUM_NETWORK") {
            Ok(path) => {
                tracing::info!("Connecting to Ethereum network: {}", &path);
                Ok(Some(format!("--{}", path)))
            }
            Err(std::env::VarError::NotPresent) => {
                tracing::info!("Connecting to Ethereum mainnet");
                Ok(None)
            }
            Err(std::env::VarError::NotUnicode(msg)) => {
                Err(Error::EthereumNetwork(msg))
            }
        }
    }

    impl EthereumNode {
        /// Starts the geth process and returns a handle to it.
        ///
        /// First looks up which network to connect to from an env var.
        /// It then starts the process and waits for it to finish
        /// syncing.
        pub async fn new(url: &str) -> Result<EthereumNode> {
            // we have to start the node in a [`LocalSet`] due to the web30
            // crate
            LocalSet::new()
                .run_until(async move {
                    // the geth fullnode process
                    let network = get_eth_network()?;
                    let args = match &network {
                        Some(network) => {
                            vec![
                                "--syncmode",
                                "snap",
                                network.as_str(),
                                "--http",
                            ]
                        }
                        None => vec!["--syncmode", "snap", "--http"],
                    };
                    let ethereum_node = Command::new("geth")
                        .args(&args)
                        .kill_on_drop(true)
                        .spawn()
                        .map_err(Error::StartUp)?;
                    tracing::info!("Ethereum fullnode started");

                    // it takes a brief amount of time to open up the websocket
                    // on geth's end
                    const CLIENT_TIMEOUT: Duration = Duration::from_secs(5);
                    let client = Web3::new(url, CLIENT_TIMEOUT);

                    const SLEEP_DUR: Duration = Duration::from_secs(1);
                    tracing::info!(?url, "Checking Geth status");
                    loop {
                        if let Ok(false) = client.eth_syncing().await {
                            tracing::info!(?url, "Finished syncing");
                            break;
                        }
                        if let Err(error) = client.eth_syncing().await {
                            // This is very noisy and usually not interesting.
                            // Still can be very useful
                            tracing::debug!(
                                ?url,
                                ?error,
                                "Couldn't check Geth sync status"
                            );
                        }
                        tokio::time::sleep(SLEEP_DUR).await;
                    }

                    let node = Self {
                        process: ethereum_node,
                    };
                    Ok(node)
                })
                .await
        }

        /// Wait for the process to finish.
        pub async fn wait(&mut self) -> io::Result<ExitStatus> {
            self.process.wait().await
        }

        /// Stop the geth process
        pub async fn kill(&mut self) {
            self.process.kill().await.unwrap();
        }
    }
}
