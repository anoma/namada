use super::*;

#[cfg(not(feature = "eth-fullnode"))]
/// tools for running a mock ethereum fullnode process
pub mod mock_eth_fullnode {
    use anoma::types::hash::Hash;
    use tokio::sync::mpsc::UnboundedSender;

    use super::Result;

    pub struct EthereumNode;

    impl EthereumNode {
        pub async fn new(_: &str) -> Result<EthereumNode> {
            Ok(Self {})
        }

        pub async fn wait(&mut self) -> Result<()> {
            std::future::pending().await
        }

        pub async fn kill(&mut self) {}
    }
}

#[cfg(not(feature = "eth-fullnode"))]
pub mod mock_web3_client {
    use std::fmt::Debug;
    use num256::Uint256;
    use tokio::sync::mpsc::{channel, Sender, Receiver};
    use web30::types::Log;

    use super::{Error, Result};
    use super::events::signatures::*;

    /// Commands we can send to the mock client
    pub enum TestCmd {
        Normal,
        Unresponsive,
        NewHeight(Uint256),
        NewEvent(MockEventType, Vec<u8>)
    }

    /// The type of events supported
    #[derive(PartialEq)]
    pub enum MockEventType {
        TransferToNamada,
        TransferToErc,
        ValSetUpdate,
        NewContract,
        UpgradedContract,
        BridgeWhitelist,
    }

    /// A mock of a web3 api connected to an ethereum fullnode.
    /// It is not connected to a full node and is fully controllable
    /// via a channel to allow us to mock different behavior for
    /// testing purposes.
    pub struct Web3 {
        cmd_channel: Receiver<TestCmd>,
        active: bool,
        latest_block_height: Uint256,
        events: Vec<(MockEventType, Vec<u8>)>
    }

    impl Web3 {
        /// Return a new client and a separate sender
        /// to send in admin commands
        pub fn new() -> (Sender<TestCmd>, Self) {
            // we can only send one command at a time.
            let (cmd_sender, cmd_channel) = channel(1);
            (
                cmd_sender,
                Self {
                    cmd_channel,
                    active: true,
                    latest_block_height: Default::default(),
                    events: vec![],
                }
            )
        }

        /// Check and apply new incoming commands
        fn check_cmd_channel(&mut self) {
            if let Ok(cmd) = self.cmd_channel.try_recv() {
                match cmd {
                    TestCmd::Normal => self.active = true,
                    TestCmd::Unresponsive => self.active = false,
                    TestCmd::NewHeight(height) => self.latest_block_height = height,
                    TestCmd::NewEvent(ty, data) => self.events.push((ty, data)),
                }
            }
        }

        /// Gets the latest block number send in from the
        /// command channel if we have not set the client to
        /// act unresponsive.
        pub async fn eth_block_number(&mut self) -> Result<Uint256> {
            self.check_cmd_channel();
            if self.active {
                Ok(self.latest_block_height.clone())
            } else {
                Err(Error::Runtime("Uh oh, I'm not responding".into()))
            }
        }

        /// Gets the events (for the appropriate signature) that
        /// have been added from the command channel unless the
        /// client has not been set to act unresponsive.
        pub async fn check_for_events(
            &mut self,
            _: Uint256,
            _: Option<Uint256>,
            _: impl Debug,
            mut events: Vec<&str>,
        ) -> Result<Vec<Log>> {
            self.check_cmd_channel();
            if self.active {
                let ty = match events.remove(0) {
                    TRANSFER_TO_NAMADA_SIG => MockEventType::TransferToNamada,
                    TRANSFER_TO_ERC_SIG => MockEventType::TransferToErc,
                    VALIDATOR_SET_UPDATE_SIG => MockEventType::ValSetUpdate,
                    NEW_CONTRACT_SIG => MockEventType::NewContract,
                    UPGRADED_CONTRACT_SIG => MockEventType::UpgradedContract,
                    UPDATE_BRIDGE_WHITELIST_SIG => MockEventType::BridgeWhitelist,
                    _ => return Ok(vec![])
                };
                let mut logs = vec![];
                let mut events = vec![];
                std::mem::swap(&mut self.events, &mut events);
                for (event_ty, data) in events.into_iter() {
                    if &event_ty == &ty {
                        logs.push(Log{
                            data: data.into(),
                            ..Default::default()
                        });
                    } else {
                        self.events.push((event_ty, data));
                    }
                }
                Ok(logs)
            } else {
                Err(Error::Runtime("Uh oh, I'm not responding".into()))
            }
        }
    }
}

