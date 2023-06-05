pub mod events_endpoint;

#[cfg(test)]
pub mod mock_web3_client {
    use std::borrow::Cow;
    use std::fmt::Debug;
    use std::marker::PhantomData;
    use std::sync::{Arc, Mutex};

    use ethbridge_events::EventCodec;
    use num256::Uint256;
    use tokio::sync::mpsc::{
        unbounded_channel, UnboundedReceiver, UnboundedSender,
    };
    use tokio::sync::oneshot::Sender;
    use web30::types::Log;

    use super::super::super::ethereum_oracle::Error;
    use crate::node::ledger::ethereum_oracle::SyncStatus;

    /// Commands we can send to the mock client
    #[derive(Debug)]
    pub enum TestCmd {
        Normal,
        Unresponsive,
        NewHeight(Uint256),
        NewEvent {
            event_type: MockEventType,
            data: Vec<u8>,
            height: u32,
            seen: Sender<()>,
        },
    }

    /// The type of events supported
    pub type MockEventType = &'static str;

    /// A pointer to a mock Web3 client. The
    /// reason is for interior mutability.
    pub struct Web3(Arc<Mutex<Web3Client>>);

    /// Command sender for [`Web3`] instances.
    pub struct Web3Controller(Arc<Mutex<Web3Client>>);

    impl Web3Controller {
        /// Apply new oracle command.
        pub fn apply_cmd(&self, cmd: TestCmd) {
            let mut oracle = self.0.lock().unwrap();
            match cmd {
                TestCmd::Normal => oracle.active = true,
                TestCmd::Unresponsive => oracle.active = false,
                TestCmd::NewHeight(height) => {
                    oracle.latest_block_height = height
                }
                TestCmd::NewEvent {
                    event_type: ty,
                    data,
                    height,
                    seen,
                } => oracle.events.push((ty, data, height, seen)),
            }
        }
    }

    impl Clone for Web3Controller {
        #[inline]
        fn clone(&self) -> Self {
            Self(Arc::clone(&self.0))
        }
    }

    /// A mock of a web3 api client connected to an ethereum fullnode.
    /// It is not connected to a full node and is fully controllable
    /// via a channel to allow us to mock different behavior for
    /// testing purposes.
    pub struct Web3Client {
        active: bool,
        latest_block_height: Uint256,
        events: Vec<(MockEventType, Vec<u8>, u32, Sender<()>)>,
        blocks_processed: UnboundedSender<Uint256>,
        last_block_processed: Option<Uint256>,
    }

    impl Web3 {
        /// This method is part of the Web3 api we use,
        /// but is not meant to be used in tests
        #[allow(dead_code)]
        pub fn new(_: &str, _: std::time::Duration) -> Self {
            panic!(
                "Method is here for api completeness. It is not meant to be \
                 used in tests."
            )
        }

        /// Return a new client and a separate sender
        /// to send in admin commands
        pub fn setup() -> (UnboundedReceiver<Uint256>, Self) {
            let (block_processed_send, block_processed_recv) =
                unbounded_channel();
            (
                block_processed_recv,
                Self(Arc::new(Mutex::new(Web3Client {
                    active: true,
                    latest_block_height: Default::default(),
                    events: vec![],
                    blocks_processed: block_processed_send,
                    last_block_processed: None,
                }))),
            )
        }

        /// Get a new [`Web3Controller`] for the current oracle.
        pub fn controller(&self) -> Web3Controller {
            Web3Controller(Arc::clone(&self.0))
        }

        /// Gets the latest block number send in from the
        /// command channel if we have not set the client to
        /// act unresponsive.
        pub async fn eth_block_number(
            &self,
        ) -> std::result::Result<Uint256, Error> {
            Ok(self.0.lock().unwrap().latest_block_height.clone())
        }

        pub async fn syncing(&self) -> std::result::Result<SyncStatus, Error> {
            self.eth_block_number()
                .await
                .map(SyncStatus::AtHeight)
                .map_err(|_| Error::FallenBehind)
        }

        /// Gets the events (for the appropriate signature) that
        /// have been added from the command channel unless the
        /// client has not been set to act unresponsive.
        pub async fn check_for_events(
            &self,
            block_to_check: Uint256,
            _: Option<Uint256>,
            _: impl Debug,
            mut events: Vec<MockEventType>,
        ) -> eyre::Result<Vec<Log>> {
            let mut client = self.0.lock().unwrap();
            if client.active {
                let ty = events.remove(0);
                let mut logs = vec![];
                let mut events = vec![];
                std::mem::swap(&mut client.events, &mut events);
                for (event_ty, data, height, seen) in events.into_iter() {
                    if event_ty == ty && block_to_check >= Uint256::from(height)
                    {
                        seen.send(()).unwrap();
                        logs.push(Log {
                            data: data.into(),
                            ..Default::default()
                        });
                    } else {
                        client.events.push((event_ty, data, height, seen));
                    }
                }
                if client.last_block_processed.as_ref() < Some(&block_to_check)
                {
                    client
                        .blocks_processed
                        .send(block_to_check.clone())
                        .unwrap();
                    client.last_block_processed = Some(block_to_check);
                }
                Ok(logs)
            } else {
                Err(eyre::eyre!("Uh oh, I'm not responding"))
            }
        }
    }

    /// Get the signature of the given Ethereum event.
    pub fn event_signature<C>() -> &'static str
    where
        PhantomData<C>: EventCodec,
    {
        match PhantomData::<C>.event_signature() {
            Cow::Borrowed(s) => s,
            _ => unreachable!(
                "All Ethereum events should have a static ABI signature"
            ),
        }
    }
}
