use std::ops::Deref;
use std::time::Duration;

use clarity::Address;
use eyre::{eyre, Result};
use namada::types::ethereum_events::{EthAddress, EthereumEvent};
use num256::Uint256;
use tokio::sync::mpsc::Sender as BoundedSender;
use tokio::sync::oneshot::Sender;
use tokio::task::LocalSet;
#[cfg(not(test))]
use web30::client::Web3;

use super::events::{signatures, PendingEvent};
#[cfg(test)]
use super::test_tools::mock_web3_client::Web3;

/// Minimum number of confirmations needed to trust an Ethereum branch
pub(crate) const MIN_CONFIRMATIONS: u64 = 100;

/// Dummy addresses for smart contracts
// const MINT_CONTRACT: EthAddress = EthAddress([0; 20]);
const GOVERNANCE_CONTRACT: EthAddress = EthAddress([1; 20]);

/// The default amount of time the oracle will wait between processing blocks
const DEFAULT_BACKOFF: Duration = std::time::Duration::from_secs(1);

/// A client that can talk to geth and parse
/// and relay events relevant to Anoma to the
/// ledger process
pub struct Oracle {
    /// The client that talks to the Ethereum fullnode
    client: Web3,
    /// A channel for sending processed and confirmed
    /// events to the ledger process
    sender: BoundedSender<EthereumEvent>,
    /// A channel to signal that the ledger should shut down
    /// because the Oracle has stopped
    abort: Option<Sender<()>>,
    /// How long the oracle should wait between checking blocks
    backoff: Duration,
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
        match self.abort.take().unwrap().send(()) {
            Ok(()) => tracing::info!("Oracle sent abort signal"),
            Err(()) => {
                // this isn't necessarily an issue as the ledger may have shut
                // down first
                tracing::debug!(
                    "Oracle was unable to send an abort signal as the abort \
                     channel was already closed"
                )
            }
        };
    }
}

impl Oracle {
    /// Initialize a new [`Oracle`]
    pub fn new(
        url: &str,
        sender: BoundedSender<EthereumEvent>,
        abort: Sender<()>,
        backoff: Duration,
    ) -> Self {
        Self {
            client: Web3::new(url, std::time::Duration::from_secs(30)),
            sender,
            abort: Some(abort),
            backoff,
        }
    }

    /// Send a series of [`EthereumEvent`]s to the Anoma
    /// ledger. Returns a boolean indicating that all sent
    /// successfully. If false is returned, the receiver
    /// has hung up.
    ///
    /// N.B. this will block if the internal channel buffer
    /// is full.
    async fn send(&self, events: Vec<EthereumEvent>) -> bool {
        if self.sender.is_closed() {
            return false;
        }
        for event in events.into_iter() {
            if self.sender.send(event).await.is_err() {
                return false;
            }
        }
        true
    }

    async fn sleep(&self) {
        tokio::time::sleep(self.backoff).await;
    }
}

/// Set up an Oracle and run the process where the Oracle
/// processes and forwards Ethereum events to the ledger
pub fn run_oracle(
    url: impl AsRef<str>,
    sender: BoundedSender<EthereumEvent>,
    abort_sender: Sender<()>,
) -> tokio::task::JoinHandle<()> {
    let url = url.as_ref().to_owned();
    // we have to run the oracle in a [`LocalSet`] due to the web30
    // crate
    tokio::task::spawn_blocking(move || {
        let rt = tokio::runtime::Handle::current();
        rt.block_on(async move {
            LocalSet::new()
                .run_until(async move {
                    tracing::info!(?url, "Ethereum event oracle is starting");

                    let oracle = Oracle::new(
                        &url,
                        sender,
                        abort_sender,
                        DEFAULT_BACKOFF,
                    );
                    run_oracle_aux(oracle).await;

                    tracing::info!(
                        ?url,
                        "Ethereum event oracle is no longer running"
                    );
                })
                .await
        });
    })
}

/// Given an oracle, watch for new Ethereum events, processing
/// them into Anoma native types.
///
/// It also checks that once the specified number of confirmations
/// is reached, an event is forwarded to the ledger process
async fn run_oracle_aux(oracle: Oracle) {
    // Initialize a queue to keep events which are awaiting a certain number of
    // confirmations
    let mut pending: Vec<PendingEvent> = Vec::new();

    // TODO(namada#560): get the appropriate Ethereum block height to start
    // checking from rather than starting from zero every time
    let mut next_block_to_process: Uint256 = 0u8.into();

    loop {
        tracing::info!(
            ?next_block_to_process,
            "Checking Ethereum block for bridge events"
        );
        tokio::select! {
            result = process(&oracle, &mut pending, next_block_to_process.clone()) => {
                match result {
                    Ok(()) => next_block_to_process += 1u8.into(),
                    Err(error) => tracing::warn!(
                        ?error,
                        block = ?next_block_to_process,
                        "Error while trying to process Ethereum block"
                    ),
                }
            },
            _ = oracle.sender.closed() => {
                tracing::info!(
                    "Ethereum oracle can not send events to the ledger; the \
                    receiver has hung up. Shutting down"
                );
                break
            }
        };
        oracle.sleep().await;
    }
}

/// Checks if the given block has any events relating to the bridge, and if so,
/// sends them to the oracle's `sender` channel
async fn process(
    oracle: &Oracle,
    pending: &mut Vec<PendingEvent>,
    block_to_process: Uint256,
) -> Result<()> {
    // update the latest block height
    let latest_block = loop {
        let latest_block = match oracle.eth_block_number().await {
            Ok(height) => height,
            Err(error) => {
                return Err(eyre!(
                    "Couldn't get the latest synced Ethereum block height \
                     from the RPC endpoint: {error:?}",
                ));
            }
        };
        let minimum_latest_block =
            block_to_process.clone() + Uint256::from(MIN_CONFIRMATIONS);
        if minimum_latest_block > latest_block {
            tracing::debug!(
                ?block_to_process,
                ?latest_block,
                ?minimum_latest_block,
                "Waiting for enough Ethereum blocks to be synced"
            );
            // this isn't an error condition, so we continue in the loop here
            // with a back off
            oracle.sleep().await;
            continue;
        }
        break latest_block;
    };
    tracing::debug!(
        ?block_to_process,
        ?latest_block,
        "Got latest Ethereum block height"
    );
    // check for events with at least `[MIN_CONFIRMATIONS]`
    // confirmations.
    for sig in signatures::SIGNATURES {
        let addr: Address = match signatures::SigType::from(sig) {
            signatures::SigType::Bridge => MINT_CONTRACT.0.into(),
            signatures::SigType::Governance => GOVERNANCE_CONTRACT.0.into(),
        };
        tracing::debug!(
            ?block_to_process,
            ?addr,
            ?sig,
            "Checking for bridge events"
        );
        // fetch the events for matching the given signature
        let mut events = {
            let logs = match oracle
                .check_for_events(
                    block_to_process.clone(),
                    Some(block_to_process.clone()),
                    vec![addr],
                    vec![sig],
                )
                .await
            {
                Ok(logs) => logs,
                Err(error) => {
                    return Err(eyre!(
                        "Couldn't check for events ({sig} from {addr}) with \
                         the RPC endpoint: {error:?}",
                    ));
                }
            };
            if !logs.is_empty() {
                tracing::info!(
                    ?block_to_process,
                    ?addr,
                    ?sig,
                    n_events = logs.len(),
                    "Found bridge events in Ethereum block"
                )
            }
            logs.into_iter()
                .filter_map(|log| {
                    match PendingEvent::decode(
                        sig,
                        block_to_process.clone(),
                        log.data.0.as_slice(),
                    ) {
                        Ok(event) => Some(event),
                        Err(error) => {
                            tracing::error!(
                                ?error,
                                ?block_to_process,
                                ?addr,
                                ?sig,
                                "Couldn't decode event: {:#?}",
                                log
                            );
                            None
                        }
                    }
                })
                .collect()
        };
        pending.append(&mut events);
        if !pending.is_empty() {
            tracing::info!(
                ?block_to_process,
                ?addr,
                ?sig,
                pending = pending.len(),
                "There are Ethereum events pending"
            );
        }
        let confirmed = process_queue(&latest_block, pending);
        if !confirmed.is_empty() {
            tracing::info!(
                ?block_to_process,
                ?addr,
                ?sig,
                pending = pending.len(),
                confirmed = confirmed.len(),
                ?MIN_CONFIRMATIONS,
                "Some events that have reached the minimum number of \
                 confirmations and will be sent onwards"
            );
        }
        if !oracle.send(confirmed).await {
            return Err(eyre!(
                "Could not send all bridge events ({sig} from {addr}) to the \
                 shell"
            ));
        }
    }
    Ok(())
}

/// Check which events in the queue have reached their
/// required number of confirmations and remove them
/// from the queue of pending events
fn process_queue(
    latest_block: &Uint256,
    pending: &mut Vec<PendingEvent>,
) -> Vec<EthereumEvent> {
    let mut pending_tmp: Vec<PendingEvent> = Vec::with_capacity(pending.len());
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

#[cfg(test)]
mod test_oracle {
    use namada::types::ethereum_events::TransferToEthereum;
    use tokio::sync::oneshot::{channel, Receiver};
    use tokio::time::timeout;

    use super::*;
    use crate::node::ledger::ethereum_node::events::{
        ChangedContract, RawTransfersToEthereum,
    };
    use crate::node::ledger::ethereum_node::test_tools::mock_web3_client::{
        MockEventType, TestCmd, Web3,
    };

    /// The data returned from setting up a test
    struct TestPackage {
        oracle: Oracle,
        admin_channel: tokio::sync::mpsc::UnboundedSender<TestCmd>,
        eth_recv: tokio::sync::mpsc::Receiver<EthereumEvent>,
        blocks_processed_recv: tokio::sync::mpsc::UnboundedReceiver<Uint256>,
        abort_recv: Receiver<()>,
    }

    /// Set up an oracle with a mock web3 client that we can control
    fn setup() -> TestPackage {
        let (admin_channel, blocks_processed_recv, client) = Web3::setup();
        let (eth_sender, eth_receiver) = tokio::sync::mpsc::channel(1000);
        let (abort, abort_recv) = channel();
        TestPackage {
            oracle: Oracle {
                client,
                sender: eth_sender,
                abort: Some(abort),
                // backoff should be short for tests so that they run faster
                backoff: Duration::from_millis(5),
            },
            admin_channel,
            eth_recv: eth_receiver,
            blocks_processed_recv,
            abort_recv,
        }
    }

    /// Test that if the oracle shuts down, it
    /// sends a message to the fullnode to stop
    #[test]
    fn test_abort_send() {
        let TestPackage {
            oracle,
            mut abort_recv,
            ..
        } = setup();
        drop(oracle);
        assert!(abort_recv.try_recv().is_ok())
    }

    /// Test that if the fullnode stops, the oracle
    /// shuts down, even if the web3 client is unresponsive
    #[test]
    fn test_shutdown() {
        let TestPackage {
            oracle,
            eth_recv,
            admin_channel,
            ..
        } = setup();
        let oracle = std::thread::spawn(move || {
            tokio_test::block_on(run_oracle_aux(oracle));
        });
        admin_channel
            .send(TestCmd::Unresponsive)
            .expect("Test failed");
        drop(eth_recv);
        oracle.join().expect("Test failed");
    }

    /// Test that if no logs are received from the web3
    /// client, no events are sent out
    #[test]
    fn test_no_logs_no_op() {
        let TestPackage {
            oracle,
            mut eth_recv,
            admin_channel,
            blocks_processed_recv: _processed,
            ..
        } = setup();
        let oracle = std::thread::spawn(move || {
            tokio_test::block_on(run_oracle_aux(oracle));
        });
        admin_channel
            .send(TestCmd::NewHeight(Uint256::from(150u32)))
            .expect("Test failed");

        let mut time = std::time::Duration::from_secs(1);
        while time > std::time::Duration::from_millis(10) {
            assert!(eth_recv.try_recv().is_err());
            time -= std::time::Duration::from_millis(10);
        }
        drop(eth_recv);
        oracle.join().expect("Test failed");
    }

    /// Test that if a new block height doesn't increase,
    /// no events are sent out even if there are
    /// some in the logs.
    #[test]
    fn test_cant_get_new_height() {
        let TestPackage {
            oracle,
            mut eth_recv,
            admin_channel,
            blocks_processed_recv: _processed,
            ..
        } = setup();
        let oracle = std::thread::spawn(move || {
            tokio_test::block_on(run_oracle_aux(oracle));
        });
        // Increase height above [`MIN_CONFIRMATIONS`]
        admin_channel
            .send(TestCmd::NewHeight(100u32.into()))
            .expect("Test failed");

        let new_event = ChangedContract {
            name: "Test".to_string(),
            address: EthAddress([0; 20]),
        }
        .encode();
        let (sender, _) = channel();
        admin_channel
            .send(TestCmd::NewEvent {
                event_type: MockEventType::NewContract,
                data: new_event,
                height: 101,
                seen: sender,
            })
            .expect("Test failed");
        // since height is not updating, we should not receive events
        let mut time = std::time::Duration::from_secs(1);
        while time > std::time::Duration::from_millis(10) {
            assert!(eth_recv.try_recv().is_err());
            time -= std::time::Duration::from_millis(10);
        }
        drop(eth_recv);
        oracle.join().expect("Test failed");
    }

    /// Test that the oracle waits until new logs
    /// are received before sending them on.
    #[test]
    fn test_wait_on_new_logs() {
        let TestPackage {
            oracle,
            eth_recv,
            admin_channel,
            blocks_processed_recv: _processed,
            ..
        } = setup();
        let oracle = std::thread::spawn(move || {
            tokio_test::block_on(run_oracle_aux(oracle));
        });
        // Increase height above [`MIN_CONFIRMATIONS`]
        admin_channel
            .send(TestCmd::NewHeight(100u32.into()))
            .expect("Test failed");

        // set the oracle to be unresponsive
        admin_channel
            .send(TestCmd::Unresponsive)
            .expect("Test failed");
        // send a new event to the oracle
        let new_event = ChangedContract {
            name: "Test".to_string(),
            address: EthAddress([0; 20]),
        }
        .encode();
        let (sender, mut seen) = channel();
        admin_channel
            .send(TestCmd::NewEvent {
                event_type: MockEventType::NewContract,
                data: new_event,
                height: 150,
                seen: sender,
            })
            .expect("Test failed");
        // set the height high enough to emit the event
        admin_channel
            .send(TestCmd::NewHeight(Uint256::from(251u32)))
            .expect("Test failed");

        // the event should not be emitted even though the height is large
        // enough
        let mut time = std::time::Duration::from_secs(1);
        while time > std::time::Duration::from_millis(10) {
            assert!(seen.try_recv().is_err());
            time -= std::time::Duration::from_millis(10);
        }
        // check that when web3 becomes responsive, oracle sends event
        admin_channel.send(TestCmd::Normal).expect("Test failed");
        seen.blocking_recv().expect("Test failed");
        drop(eth_recv);
        oracle.join().expect("Test failed");
    }

    /// Test that events are only sent when they
    /// reach the required number of confirmations
    #[test]
    fn test_finality_gadget() {
        let TestPackage {
            oracle,
            mut eth_recv,
            admin_channel,
            blocks_processed_recv: _processed,
            ..
        } = setup();
        let oracle = std::thread::spawn(move || {
            tokio_test::block_on(run_oracle_aux(oracle));
        });
        // Increase height above [`MIN_CONFIRMATIONS`]
        admin_channel
            .send(TestCmd::NewHeight(100u32.into()))
            .expect("Test failed");

        // confirmed after 100 blocks
        let first_event = ChangedContract {
            name: "Test".to_string(),
            address: EthAddress([0; 20]),
        }
        .encode();

        // confirmed after 125 blocks
        let second_event = RawTransfersToEthereum {
            transfers: vec![TransferToEthereum {
                amount: Default::default(),
                asset: EthAddress([0; 20]),
                receiver: EthAddress([1; 20]),
            }],
            nonce: 1.into(),
            confirmations: 125,
        }
        .encode();

        // send in the events to the logs
        let (sender, seen_second) = channel();
        admin_channel
            .send(TestCmd::NewEvent {
                event_type: MockEventType::TransferToEthereum,
                data: second_event,
                height: 125,
                seen: sender,
            })
            .expect("Test failed");
        let (sender, _recv) = channel();
        admin_channel
            .send(TestCmd::NewEvent {
                event_type: MockEventType::NewContract,
                data: first_event,
                height: 100,
                seen: sender,
            })
            .expect("Test failed");

        // increase block height so first event is confirmed but second is
        // not.
        admin_channel
            .send(TestCmd::NewHeight(Uint256::from(200u32)))
            .expect("Test failed");
        // check the correct event is received
        let event = eth_recv.blocking_recv().expect("Test failed");
        if let EthereumEvent::NewContract { name, address } = event {
            assert_eq!(name.as_str(), "Test");
            assert_eq!(address, EthAddress([0; 20]));
        } else {
            panic!("Test failed, {:?}", event);
        }

        // check no other events are received
        let mut time = std::time::Duration::from_secs(1);
        while time > std::time::Duration::from_millis(10) {
            assert!(eth_recv.try_recv().is_err());
            time -= std::time::Duration::from_millis(10);
        }

        // increase block height so second event is emitted
        admin_channel
            .send(TestCmd::NewHeight(Uint256::from(225u32)))
            .expect("Test failed");
        // wait until event is emitted
        seen_second.blocking_recv().expect("Test failed");
        // increase block height so second event is confirmed
        admin_channel
            .send(TestCmd::NewHeight(Uint256::from(250u32)))
            .expect("Test failed");
        // check correct event is received
        let event = eth_recv.blocking_recv().expect("Test failed");
        if let EthereumEvent::TransfersToEthereum { mut transfers, .. } = event
        {
            assert_eq!(transfers.len(), 1);
            let transfer = transfers.remove(0);
            assert_eq!(
                transfer,
                TransferToEthereum {
                    amount: Default::default(),
                    asset: EthAddress([0; 20]),
                    receiver: EthAddress([1; 20]),
                }
            );
        } else {
            panic!("Test failed");
        }

        drop(eth_recv);
        oracle.join().expect("Test failed");
    }

    /// Test that Ethereum blocks are processed in sequence up to the latest
    /// block that has reached the minimum number of confirmations
    #[tokio::test]
    async fn test_blocks_checked_sequence() {
        let TestPackage {
            oracle,
            eth_recv,
            admin_channel,
            mut blocks_processed_recv,
            ..
        } = setup();
        let oracle = std::thread::spawn(move || {
            tokio_test::block_on(run_oracle_aux(oracle));
        });

        // set the height of the chain such that there are some blocks deep
        // enough to be considered confirmed by the oracle
        let confirmed_block_height = 9; // all blocks up to and including this block have enough confirmations
        let synced_block_height = MIN_CONFIRMATIONS + confirmed_block_height;
        for height in 0..synced_block_height + 1 {
            admin_channel
                .send(TestCmd::NewHeight(Uint256::from(height)))
                .expect("Test failed");
        }
        // check that the oracle indeed processes the confirmed blocks
        for height in 0u64..confirmed_block_height + 1 {
            let block_processed =
                timeout(Duration::from_secs(3), blocks_processed_recv.recv())
                    .await
                    .expect("Timed out waiting for block to be checked")
                    .unwrap();
            assert_eq!(block_processed, Uint256::from(height));
        }

        // check that the oracle hasn't yet checked any further blocks
        // TODO: check this in a deterministic way rather than just waiting a
        // bit
        assert!(
            timeout(Duration::from_secs(1), blocks_processed_recv.recv())
                .await
                .is_err()
        );

        // increase the height of the chain by one, and check that the oracle
        // processed the next confirmed block
        let synced_block_height = synced_block_height + 1;
        admin_channel
            .send(TestCmd::NewHeight(Uint256::from(synced_block_height)))
            .expect("Test failed");

        let block_processed =
            timeout(Duration::from_secs(3), blocks_processed_recv.recv())
                .await
                .expect("Timed out waiting for block to be checked")
                .unwrap();
        assert_eq!(block_processed, Uint256::from(confirmed_block_height + 1));

        drop(eth_recv);
        oracle.join().expect("Test failed");
    }

    /// Test that if the Ethereum RPC endpoint returns a latest block that is
    /// more than one block later than the previous latest block we received, we
    /// still check all the blocks in between
    #[tokio::test]
    async fn test_all_blocks_checked() {
        let TestPackage {
            oracle,
            eth_recv,
            admin_channel,
            mut blocks_processed_recv,
            ..
        } = setup();
        let oracle = std::thread::spawn(move || {
            tokio_test::block_on(run_oracle_aux(oracle));
        });

        let confirmed_block_height = 9; // all blocks up to and including this block have enough confirmations
        let synced_block_height = MIN_CONFIRMATIONS + confirmed_block_height;
        admin_channel
            .send(TestCmd::NewHeight(Uint256::from(synced_block_height)))
            .expect("Test failed");

        // check that the oracle has indeed processed the first `n` blocks, even
        // though the first latest block that the oracle received was not 0
        for height in 0u64..confirmed_block_height + 1 {
            let block_processed =
                timeout(Duration::from_secs(3), blocks_processed_recv.recv())
                    .await
                    .expect("Timed out waiting for block to be checked")
                    .unwrap();
            assert_eq!(block_processed, Uint256::from(height));
        }

        // the next time the oracle checks, the latest block will have increased
        // by more than one
        let difference = 10;
        let synced_block_height = synced_block_height + difference;
        admin_channel
            .send(TestCmd::NewHeight(Uint256::from(synced_block_height)))
            .expect("Test failed");

        // check that the oracle still checks the blocks inbetween
        for height in (confirmed_block_height + 1)
            ..(confirmed_block_height + difference + 1)
        {
            let block_processed =
                timeout(Duration::from_secs(3), blocks_processed_recv.recv())
                    .await
                    .expect("Timed out waiting for block to be checked")
                    .unwrap();
            assert_eq!(block_processed, Uint256::from(height));
        }

        drop(eth_recv);
        oracle.join().expect("Test failed");
    }
}
