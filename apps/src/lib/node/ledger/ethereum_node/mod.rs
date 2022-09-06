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

/// Monitor the Ethereum fullnode. If it stops or an abort
/// signal is sent, the subprocess is halted.
pub async fn monitor(
    ethereum_node: Subprocess,
    abort_recv: Receiver<Sender<()>>,
) -> Result<()> {
    match ethereum_node {
        Subprocess::Mock(node) => monitor_mock(node, abort_recv).await,
        Subprocess::Geth(node) => monitor_real(node, abort_recv).await,
    }
}

async fn monitor_real(
    mut ethereum_node: eth_fullnode::EthereumNode,
    abort_recv: Receiver<Sender<()>>,
) -> Result<()> {
    tokio::select! {
        // run the ethereum fullnode
        status = ethereum_node.wait() => status,
        // wait for an abort signal
        resp_sender = abort_recv => {
            match resp_sender {
                Ok(resp_sender) => {
                    tracing::info!("Shutting down Ethereum fullnode...");
                    ethereum_node.kill().await;
                    resp_sender.send(()).unwrap();
                },
                Err(err) => {
                    tracing::error!("The Ethereum abort sender has unexpectedly dropped: {}", err);
                    tracing::info!("Shutting down Ethereum fullnode...");
                    ethereum_node.kill().await;
                }
            }
            Ok(())
        }
    }
}

async fn monitor_mock(
    mut ethereum_node: test_tools::mock_eth_fullnode::EthereumNode,
    abort_recv: Receiver<Sender<()>>,
) -> Result<()> {
    tokio::select! {
        // run the ethereum fullnode
        status = ethereum_node.wait() => status,
        // wait for an abort signal
        resp_sender = abort_recv => {
            match resp_sender {
                Ok(resp_sender) => {
                    tracing::info!("Shutting down Ethereum fullnode...");
                    ethereum_node.kill().await;
                    resp_sender.send(()).unwrap();
                },
                Err(err) => {
                    tracing::error!("The Ethereum abort sender has unexpectedly dropped: {}", err);
                    tracing::info!("Shutting down Ethereum fullnode...");
                    ethereum_node.kill().await;
                }
            }
            Ok(())
        }
    }
}

/// Tools for running a geth fullnode process
pub mod eth_fullnode {
    use std::time::Duration;

    use tokio::process::{Child, Command};
    use tokio::sync::oneshot::error::TryRecvError;
    use tokio::sync::oneshot::{channel, Receiver, Sender};
    use tokio::task::LocalSet;
    use web30::client::Web3;

    use super::{Error, Result};

    /// A handle to a running geth process and a channel
    /// that indicates it should shut down if the oracle
    /// stops.
    pub struct EthereumNode {
        process: Child,
        abort_recv: Receiver<()>,
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
        /// Starts the geth process and returns a handle to it as well
        /// as an oracle that can relay data from geth to the ledger.
        ///
        /// First looks up which network to connect to from an env var.
        /// It then starts the process and waits for it to finish
        /// syncing.
        pub async fn new(url: &str) -> Result<(EthereumNode, Sender<()>)> {
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

                    let (abort_sender, receiver) = channel();
                    let node = Self {
                        process: ethereum_node,
                        abort_recv: receiver,
                    };
                    Ok((node, abort_sender))
                })
                .await
        }

        /// Wait for the process to finish or an abort message was
        /// received from the Oracle process. If either, return the
        /// status.
        pub async fn wait(&mut self) -> Result<()> {
            loop {
                match self.process.try_wait() {
                    Ok(Some(status)) => {
                        return if status.success() {
                            Ok(())
                        } else {
                            Err(Error::Runtime(status.to_string()))
                        };
                    }
                    Ok(None) => {}
                    Err(err) => return Err(Error::Runtime(err.to_string())),
                }
                match self.abort_recv.try_recv() {
                    Ok(()) => return Ok(()),
                    Err(TryRecvError::Empty) => {}
                    Err(TryRecvError::Closed) => return Err(Error::Oracle),
                }
            }
        }

        /// Stop the geth process
        pub async fn kill(&mut self) {
            self.process.kill().await.unwrap();
        }
    }
}

/// Starts an Ethereum fullnode in a subprocess and returns a handle for
/// monitoring it using [`monitor`], as well as a channel for halting it.
pub async fn start(url: &str, real: bool) -> Result<(Subprocess, Sender<()>)> {
    if real {
        let (node, sender) = eth_fullnode::EthereumNode::new(url).await?;
        Ok((Subprocess::Geth(node), sender))
    } else {
        let (node, sender) =
            test_tools::mock_eth_fullnode::EthereumNode::new().await?;
        Ok((Subprocess::Mock(node), sender))
    }
}

/// Represents a subprocess running an Ethereum full node
pub enum Subprocess {
    Mock(test_tools::mock_eth_fullnode::EthereumNode),
    Geth(eth_fullnode::EthereumNode),
}
