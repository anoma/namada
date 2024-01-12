pub mod events_endpoint;

#[cfg(test)]
pub mod event_log {
    // praise be unto thee whom'st've read and understand this code
    // p.s.: https://medium.com/mycrypto/understanding-event-logs-on-the-ethereum-blockchain-f4ae7ba50378

    use ethbridge_bridge_events::{
        TransferToChainFilter, TransferToErcFilter, ValidatorSetUpdateFilter,
    };
    use namada::eth_bridge::ethers::abi::AbiEncode;
    use namada::eth_bridge::ethers::contract::EthEvent;

    /// Get an [`ethabi::RawLog`] from a given Ethereum event.
    pub trait GetLog {
        /// Return an [`ethabi::RawLog`].
        fn get_log(self) -> ethabi::RawLog;
    }

    impl GetLog for TransferToChainFilter {
        fn get_log(self) -> ethabi::RawLog {
            ethabi::RawLog {
                topics: vec![Self::signature()],
                data: self.encode(),
            }
        }
    }

    impl GetLog for TransferToErcFilter {
        fn get_log(self) -> ethabi::RawLog {
            ethabi::RawLog {
                topics: vec![Self::signature(), {
                    let mut buf = [0; 32];
                    self.nonce.to_big_endian(&mut buf);
                    ethabi::ethereum_types::H256(buf)
                }],
                data: (self.transfers, self.relayer_address).encode(),
            }
        }
    }

    impl GetLog for ValidatorSetUpdateFilter {
        fn get_log(self) -> ethabi::RawLog {
            ethabi::RawLog {
                topics: vec![Self::signature(), {
                    let mut buf = [0; 32];
                    self.validator_set_nonce.to_big_endian(&mut buf);
                    ethabi::ethereum_types::H256(buf)
                }],
                data: (
                    self.bridge_validator_set_hash,
                    self.governance_validator_set_hash,
                )
                    .encode(),
            }
        }
    }
}

#[cfg(any(test, feature = "testing"))]
pub mod mock_web3_client {
    use std::borrow::Cow;
    use std::fmt::Debug;
    use std::marker::PhantomData;
    use std::sync::{Arc, Mutex};

    use async_trait::async_trait;
    use ethabi::Address;
    use ethbridge_events::EventCodec;
    use namada::types::control_flow::time::{Duration, Instant};
    use namada::types::ethereum_structs::BlockHeight;
    use num256::Uint256;
    use tokio::sync::mpsc::{
        unbounded_channel, UnboundedReceiver, UnboundedSender,
    };
    use tokio::sync::oneshot::Sender;

    use super::super::super::ethereum_oracle::{Error, Oracle, RpcClient};
    use crate::node::ledger::ethereum_oracle::SyncStatus;

    /// Mock oracle used during unit tests.
    pub type TestOracle = Oracle<Web3Client>;

    /// Commands we can send to the mock client
    #[derive(Debug)]
    pub enum TestCmd {
        Normal,
        Unresponsive,
        NewHeight(Uint256),
        NewEvent {
            event_type: MockEventType,
            log: ethabi::RawLog,
            height: u32,
            seen: Sender<()>,
        },
    }

    /// The type of events supported
    pub type MockEventType = Cow<'static, str>;

    /// A pointer to a mock Web3 client. The
    /// reason is for interior mutability.
    pub struct Web3Client(Arc<Mutex<Web3ClientInner>>);

    /// Command sender for [`TestOracle`] instances.
    pub struct Web3Controller(Arc<Mutex<Web3ClientInner>>);

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
                    log,
                    height,
                    seen,
                } => oracle.events.push((ty, log, height, seen)),
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
    pub struct Web3ClientInner {
        active: bool,
        latest_block_height: Uint256,
        events: Vec<(MockEventType, ethabi::RawLog, u32, Sender<()>)>,
        blocks_processed: UnboundedSender<Uint256>,
        last_block_processed: Option<Uint256>,
    }

    #[async_trait(?Send)]
    impl RpcClient for Web3Client {
        type Log = ethabi::RawLog;

        #[cold]
        fn new_client(_: &str) -> Self
        where
            Self: Sized,
        {
            panic!(
                "Method is here for api completeness. It is not meant to be \
                 used in tests."
            )
        }

        async fn check_events_in_block(
            &self,
            block: BlockHeight,
            addr: Address,
            ty: &str,
        ) -> Result<Vec<Self::Log>, Error> {
            let block_to_check: Uint256 = block.into();
            let mut client = self.0.lock().unwrap();
            if client.active {
                let mut logs = vec![];
                let mut events = vec![];
                std::mem::swap(&mut client.events, &mut events);
                for (event_ty, log, height, seen) in events.into_iter() {
                    if event_ty == ty && block_to_check >= Uint256::from(height)
                    {
                        seen.send(()).unwrap();
                        logs.push(log);
                    } else {
                        client.events.push((event_ty, log, height, seen));
                    }
                }
                if client.last_block_processed.as_ref() < Some(&block_to_check)
                {
                    _ = client.blocks_processed.send(block_to_check.clone());
                    client.last_block_processed = Some(block_to_check);
                }
                Ok(logs)
            } else {
                tracing::debug!(
                    "No events to be processed by the Test Ethereum oracle, \
                     as it has been artificially set as unresponsive"
                );
                Err(Error::CheckEvents(
                    ty.into(),
                    addr,
                    "Test oracle is not responding".into(),
                ))
            }
        }

        async fn syncing(
            &self,
            _: Option<&BlockHeight>,
            _: Duration,
            _: Instant,
        ) -> Result<SyncStatus, Error> {
            let height = self.0.lock().unwrap().latest_block_height.clone();
            Ok(SyncStatus::AtHeight(height))
        }

        #[inline(always)]
        fn may_recover(&self, _: &Error) -> bool {
            true
        }
    }

    impl Web3Client {
        /// Return a new client and a separate sender
        /// to send in admin commands
        pub fn setup() -> (UnboundedReceiver<Uint256>, Self) {
            let (block_processed_send, block_processed_recv) =
                unbounded_channel();
            (
                block_processed_recv,
                Self(Arc::new(Mutex::new(Web3ClientInner {
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
    }

    /// Get the signature of the given Ethereum event.
    pub fn event_signature<C>() -> Cow<'static, str>
    where
        PhantomData<C>: EventCodec,
    {
        PhantomData::<C>.event_signature()
    }
}
