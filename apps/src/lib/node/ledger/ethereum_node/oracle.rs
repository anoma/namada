use std::ops::Deref;

use num256::Uint256;
use tokio::sync::mpsc::UnboundedSender;
use tokio::sync::oneshot::Sender;
use web30::client::Web3;

use super::events::{signatures, EthAddress, EthereumEvent, PendingEvent};

/// Minimum number of confirmations needed to trust an Ethereum branch
pub(crate) const MIN_CONFIRMATIONS: u64 = 50;

/// Dummy addresses for smart contracts
const MINT_CONTRACT: EthAddress = EthAddress([0; 20]);
const GOVERNANCE_CONTRACT: EthAddress = EthAddress([1; 20]);

/// A client that can talk to geth and parse
/// and relay events relevant to Anoma to the
/// ledger process
pub(crate) struct Oracle {
    /// The client that talks to the Ethereum fullnode
    client: Web3,
    /// A channel for sending processed and confirmed
    /// events to the ledger process
    sender: UnboundedSender<EthereumEvent>,
    /// A channel to signal that the ledger should shut down
    /// because the Oracle has stopped
    abort: Option<Sender<()>>,
}

impl Deref for Oracle {
    type Target = Web3;

    fn deref(&self) -> &Self::Target {
        &self.client
    }
}

impl Drop for Oracle {
    fn drop(&mut self) {
        // send an abort signal to shut down the
        // rest of the ledger gracefully
        let abort = self.abort.take().unwrap();
        let _ = abort.send(());
    }
}

impl Oracle {
    /// Initialize a new [`Oracle`]
    pub fn new(url: &str, sender: UnboundedSender<EthereumEvent>, abort: Sender<()>) -> Self {
        Self {
            client: Web3::new(url, std::time::Duration::from_secs(30)),
            sender,
            abort: Some(abort),
        }
    }

    /// Send a series of [`EthereumEvent`]s to the Anoma
    /// ledger. Returns a boolean indicating that all sent
    /// successfully. If false is returned, the receiver
    /// has hung up.
    fn send(&self, events: Vec<EthereumEvent>) -> bool {
        events.into_iter()
            .map(|event| self.sender.send(event))
            .all(|res| res.is_ok())
    }

    /// Check if the receiver in the ledger has hung up.
    /// Used to help determine when to stop the oracle
    fn connected(&self) -> bool {
        !self.sender.is_closed()
    }
}

pub async fn run_oracle(url: &str, sender: UnboundedSender<EthereumEvent>, abort_sender: Sender<()>) {
    let oracle = Oracle::new(url, sender, abort_sender);
    // Initialize our local state. This includes
    // the latest block height seen and a queue of events
    // awaiting a certain number of confirmations
    let mut latest_block: Uint256 = Default::default();
    let mut pending: Vec<PendingEvent> = Vec::new();
    loop {
        // update the latest block height
        latest_block = loop {
            if let Ok(height) = oracle.eth_block_number().await {
                break height;
            }
            if !oracle.connected() {
                tracing::info!(
                    "Ethereum oracle could not send events to the ledger; \
                    the receiver has hung up. Shutting down"
                );
                return
            }
        };

        let block_to_check = latest_block.clone() - MIN_CONFIRMATIONS.into();
        // check for events with at least `[MIN_CONFIRMATIONS]` confirmations.
        for sig in signatures::SIGNATURES {
            let addr = match signatures::SigType::from(sig) {
                signatures::SigType::Bridge => {
                    MINT_CONTRACT.0.clone().into()
                }
                signatures::SigType::Governance => {
                    GOVERNANCE_CONTRACT.0.clone().into()
                }
            };
            // fetch the events for matching the given signature
            let mut events = loop {
                if let Ok(pending) = oracle.check_for_events(
                    block_to_check.clone(),
                    Some(block_to_check.clone()),
                    vec![addr],
                    vec![sig],
                )
                .await
                .map(|logs| {
                    logs.into_iter()
                        .filter_map(|log| {
                            PendingEvent::decode(
                                sig,
                                block_to_check.clone(),
                                log.data.0.as_slice(),
                            ).ok()
                        })
                        .collect::<Vec<PendingEvent>>()
                }) {
                    break pending;
                }
                if !oracle.connected() {
                    tracing::info!(
                        "Ethereum oracle could not send events to the ledger; \
                        the receiver has hung up. Shutting down"
                    );
                    return
                }
            };
            pending.append(&mut events);
            if !oracle.send(process_queue(&latest_block, &mut pending)) {
                tracing::info!(
                    "Ethereum oracle could not send events to the ledger; \
                     the receiver has hung up. Shutting down"
                );
                return
            }
        }
    }
}

/// Check which events in the queue have reached their
/// required number of confirmations and remove them
/// from the queue of pending events
fn process_queue(
    latest_block: &Uint256,
    pending: &mut Vec<PendingEvent>,
) -> Vec<EthereumEvent> {
    let mut pending_tmp: Vec<PendingEvent> =
        Vec::with_capacity(pending.len());
    std::mem::swap(&mut pending_tmp, pending);
    let mut confirmed = vec![];
    for item in pending_tmp.into_iter() {
        if item.is_confirmed(latest_block) {
           confirmed.push(item.event);
        } else {
            pending.push(item);
        }
    }
    confirmed
}
