pub mod events;
pub mod test_tools;

use std::ffi::OsString;
use std::sync::Arc;

use events::{EthAddress, EthereumEvent};
use thiserror::Error;
use tokio::sync::Mutex;
use tokio::sync::mpsc::UnboundedSender;
use tokio::sync::oneshot::{channel, Receiver, Sender};
use tokio::task;
use web30::client::Web3;

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
    #[error("Web3 server unexpectedly stopped")]
    Web3Server,
    #[error(
        "Could not read Ethereum network to connect to from env var: {0:?}"
    )]
    EthereumNetwork(OsString),
    #[error("Could not decode Ethereum event: {0}")]
    Decode(String),
}

pub type Result<T> = std::result::Result<T, Error>;

/// Minimum number of confirmations needed to trust an Ethereum branch
const MIN_CONFIRMATIONS: u64 = 50;

/// Dummy addresses for smart contracts
const MINT_CONTRACT: EthAddress = EthAddress([0; 20]);
const GOVERNANCE_CONTRACT: EthAddress = EthAddress([1; 20]);

/// Run the Ethereum fullnode as well as a relayer
/// that sends RPC streams to the ledger. If either
/// stops or an abort signal is sent, these processes
/// are halted.
pub async fn run(
    url: &str,
    mut sender: UnboundedSender<EthereumEvent>,
    abort_recv: Receiver<Sender<()>>,
) -> Result<()> {
    // start up the ethereum node.
    let mut ethereum_node = EthereumNode::new(url).await?;
    let (shutdown_send, shutdown_recv) = tokio::sync::oneshot::channel();

    let (request, recv) = tokio::sync::mpsc::unbounded_channel();

    tokio::select! {
        // run the ethereum fullnode
        status = ethereum_node.wait() => status,
        // wait for an abort signal
        resp_sender = abort_recv => {
            match resp_sender {
                Ok(resp_sender) => {
                    tracing::info!("Shutting down Ethereum fullnode...");
                    shutdown_send.send(()).unwrap();
                    ethereum_node.kill().await;
                    resp_sender.send(()).unwrap();
                },
                Err(err) => {
                    tracing::error!("The Ethereum abort sender has unexpectedly dropped: {}", err);
                    tracing::info!("Shutting down Ethereum fullnode...");
                    shutdown_send.send(()).unwrap();
                    ethereum_node.kill().await;
                }
            }
            Ok(())
        }
        resp = toki
    }
}

#[cfg(feature = "eth-fullnode")]
/// Tools for running a geth fullnode process
pub mod eth_fullnode {
    use std::sync::Arc;

    use tokio::process::{Child, Command};
    use tokio::sync::Mutex;
    use web30::client::Web3;

    use super::{Error, Result};

    /// A handle to a running geth process
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
                Ok(Some(path))
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
            // the geth fullnode process
            let network = get_eth_network()?;
            let args = match &network {
                Some(network) => vec![
                    "--syncmode",
                    "snap",
                    network.as_str(),
                    "--ws",
                    "--ws.api",
                    "eth",
                ],
                None => vec!["--syncmode", "snap", "--ws", "--ws.api", "eth"],
            };
            let ethereum_node = Command::new("geth")
                .args(&args)
                .kill_on_drop(true)
                .spawn()
                .map_err(Error::StartUp)?;
            tracing::info!("Ethereum fullnode started");

            // it takes a brief amount of time to open up the websocket on
            // geth's end
            let client = Arc::new(Mutex::new(Web3::new(url, std::time::Duration::from_secs(5))));

            loop {
                match client.eth_syncing().await {
                    Ok(true) => {}
                    Ok(false) => {
                        tracing::info!("Finished syncing");
                        break;
                    }
                    Err(err) => {
                        tracing::error!(
                            "Encountered an error while syncing: {}",
                            err
                        );
                    }
                }
            }

            Ok(Self {
                process: ethereum_node,
            })
        }

        /// Wait for the process to finish. If it does,
        /// return the status.
        pub async fn wait(&mut self) -> Result<()> {
            match self.process.wait().await {
                Ok(status) => {
                    if status.success() {
                        Ok(())
                    } else {
                        Err(Error::Runtime(status.to_string()))
                    }
                }
                Err(err) => Err(Error::Runtime(err.to_string())),
            }
        }

        /// Stop the geth process
        pub async fn kill(&mut self) {
            self.process.kill().await.unwrap();
        }
    }
}

#[cfg(feature = "eth-fullnode")]
pub use eth_fullnode::EthereumNode;
#[cfg(not(feature = "eth-fullnode"))]
pub use test_tools::mock_eth_fullnode::EthereumNode;

/// Tools for polling the Geth fullnode asynchronously
#[cfg(feature = "eth-fullnode")]
pub mod ethereum_relayer {
    use events::{signatures, PendingEvent};
    use num256::Uint256;
    use tokio::sync::mpsc::{unbounded_channel, UnboundedSender, UnboundedReceiver};
    use web30::client::Web3;

    use super::*;

    /// Types of requests that can be sent to the Web3 server
    #[derive(Clone)]
    enum Web3Cmd {
        /// Requests the latest block seen by the full node
        LatestBlock,
        /// Find events with [`MIN_CONFIRMATIONS`] of confirmations
        /// and adds them to the pending queue
        FetchEvents{
            block_height: Uint256,
            signature: &'static str,
        },
        /// Request to shutdown the server
        Shutdown,
    }

    /// A request to the Web3 server. Includes the request body as well
    /// as a one shot channel to return the response
    struct Web3Request {
        /// Request body
        request: Web3Cmd,
        /// Channel for sending response
        reply: Sender<Web3Reply>
    }

    /// A reply from the Web3 server. A return value of None
    /// signifies a failure to connect to the underlying full node.
    enum Web3Reply {
        /// The latest block height
        LatestBlock(Option<Uint256>),
        /// A set of events from a block
        Events(Option<Vec<PendingEvent>>),
        /// Acknowledgment of shutdown
        Shutdown,
    }

    /// Runs a loop that receives requests from an inbound channel.
    /// These requests include a channel for sending replies.
    /// The server handles the request and sends a reply over the supplied
    /// channel.
    ///
    /// If any channel fails to send, the server shuts down.
    pub async fn web3_server(
        url: &str,
        mint_contract: EthAddress,
        governance_contract: EthAddress,
        mut channel: UnboundedReceiver<Web3Request>,
    ) {
        let client = Arc::new(Mutex::new(Web3::new(url, std::time::Duration::from_secs(3))));
        // If a none is received, the sending channel has hung up,
        // so the server stops.
        while let Some(
            Web3Request{
                request,
                reply
            }
        ) = channel.recv().await {
            // handle request by type
            if match request {
                Web3Cmd::LatestBlock => reply.send(
                    Web3Reply::LatestBlock(client
                        .lock()
                        .await
                        .eth_block_number()
                        .await
                        .ok())
                ),
                Web3Cmd::FetchEvents{block_height, signature} => {
                    let addr = match signatures::SigType::from(signature) {
                        signatures::SigType::Bridge => mint_contract.0.clone().into(),
                        signatures::SigType::Governance => governance_contract.0.clone().into(),
                    };
                    let events = client
                        .lock()
                        .await
                        .check_for_events(
                            block_height.clone(),
                            Some(block_height.clone()),
                            vec![addr],
                            vec![signature],
                        )
                        .await
                        .ok()
                        .map(|logs| {
                            logs.into_iter()
                                .filter_map(|log| {
                                    PendingEvent::decode(
                                        signature,
                                        block_height.clone(),
                                        log.data.0.as_slice(),
                                    ).ok()
                                })
                                .collect::<Vec<PendingEvent>>()}
                        );
                    reply.send(
                        Web3Reply::Events(events)
                    )
                }
                Web3Cmd::Shutdown => {
                    reply.send(Web3Reply::Shutdown);
                    // shutdown the server without waiting to see if
                    // reply sent successfully.
                    return ;
                }
            }.is_err() {
                // could not send reply because the receiver hung up,
                // so the server stops
                return;
            }
        }
    }

    /// Check which events in the queue have reached their
    /// required number of confirmations and send them
    /// to the ledger.
    ///
    /// If the ledger's receiver has dropped, this will
    /// propagate an error here.
    fn process_queue(
        latest_block: &Uint256,
        pending: &mut Vec<PendingEvent>,
        sender: &mut UnboundedSender<EthereumEvent>
    ) -> Result<()> {
        let mut pending_tmp: Vec<PendingEvent> = Vec::with_capacity(pending.len());
        std::mem::swap(&mut pending_tmp, pending);
        for item in pending_tmp.into_iter() {
            if item.is_confirmed(latest_block) {
                sender
                    .send(item.event)
                    .map(Error::RelayerReceiverDropped)?;
            } else {
                pending.push(item);
            }
        }
        Ok(())
    }

    /// Sends a request to the Web3 server and awaits a response. If the server has
    /// stopped, returns an error.
    fn process_request(request: &UnboundedSender<Web3Request>, cmd: Web3Cmd) -> Result<Web3Reply> {
        let (reply, mut recv) = channel();
        request.send(
            Web3Request {
                request: cmd,
                reply,
            }
        )
        .map_err(|_| Error::Web3Server)?;
        loop {
            match recv.try_recv() {
                Ok(reply) => return Ok(reply),
                Err(tokio::sync::oneshot::error::TryRecvError::Closed) => return Err(Error::Web3Server),
                _ => {}
            }
        }
    }

    /// Starts a Web3 server that allows this method to talk to the Ethereum
    /// full node.
    ///
    /// Continuously polls for events that are [`MIN_CONFIRMATIONS`] blocks old
    /// and when they have met their confirmation target, forwards them to the
    /// leder.
    ///
    /// On receiving a shutdown command, exit with an Ok(()). If the server shutsdown
    /// are the ledger hangs up its end of the channel, shuts down Anoma.
    pub async fn run_relayer(
        url: &str,
        mint_contract: EthAddress,
        governance_contract: EthAddress,
        mut sender: UnboundedSender<EthereumEvent>,
        mut shutdown: Receiver<()>,
    ) -> Result<()> {
        let (request, recv) = unbounded_channel();
        // start the server

        let mut latest_block: Uint256 = Default::default();
        let mut pending: Vec<PendingEvent> = Vec::new();
        // the main loop to watch for new events
        loop {
            // get the latest block height
            let height = loop {
                if let Web3Reply::LatestBlock(Some(height)) = process_request(&request, Web3Cmd::LatestBlock)? {
                    break height
                }
                if shutdown.try_recv().is_ok() {
                    let _ = process_request(&request, Web3Cmd::Shutdown);
                    return Ok(())
                }
            };
            latest_block = height;

            let block_to_check = latest_block.clone() - MIN_CONFIRMATIONS.into();
            // get events corresponding to each signature
            for sig in signatures::SIGNATURES {
                let mut events = loop {
                   let cmd = Web3Cmd::FetchEvents {
                       block_height: block_to_check.clone(),
                       signature: sig
                   };
                    if let Web3Reply::Events(Some(events)) = process_request(&request, cmd.clone())? {
                        break events;
                    }
                    if shutdown.try_recv().is_ok() {
                        let _ = process_request(&request, Web3Cmd::Shutdown);
                        return Ok(())
                    }
                };

                // add events to queue and forward to ledger if confirmed
                pending.append(&mut events);
                process_queue(&latest_block, &mut pending, &mut sender)?;
            }
        }
    }

}

#[cfg(feature = "eth-fullnode")]
pub use ethereum_relayer::{web3_server, run_relayer};
