//! Functions to handle IBC modules

use std::collections::HashMap;
use std::str::FromStr;

use prost::Message;
use sha2::Digest;
use thiserror::Error;

use crate::ibc::applications::transfer::MODULE_ID_STR;
use crate::ibc::core::ics02_client::client_state::ClientState;
use crate::ibc::core::ics02_client::error::ClientError;
use crate::ibc::core::ics24_host::identifier::PortId;
use crate::ibc::core::ics26_routing::context::ModuleId;
use crate::ibc::core::{
    ContextError, ExecutionContext, Router, ValidationContext,
};
use crate::ibc::Height;
use crate::ibc_proto::google::protobuf::Any;
use crate::ledger::ibc::data::{
    Error as IbcDataError, FungibleTokenPacketData, IbcMessage, PacketAck,
    PacketReceipt,
};
use crate::ledger::ibc::storage;
use crate::ledger::storage_api;
use crate::tendermint::Time;
use crate::tendermint_proto::{Error as ProtoError, Protobuf};
use crate::types::address::{Address, InternalAddress};
use crate::types::ibc::IbcEvent as NamadaIbcEvent;
use crate::types::storage::{BlockHeight, Key};
use crate::types::time::Rfc3339String;
use crate::types::token::{self, Amount};

const COMMITMENT_PREFIX: &[u8] = b"ibc";

#[allow(missing_docs)]
#[derive(Error, Debug)]
pub enum Error {
    #[error("Invalid client error: {0}")]
    ClientId(Ics24Error),
    #[error("Invalid port error: {0}")]
    PortId(Ics24Error),
    #[error("Updating a client error: {0}")]
    ClientUpdate(String),
    #[error("IBC data error: {0}")]
    IbcData(IbcDataError),
    #[error("Decoding IBC data error: {0}")]
    Decoding(ProtoError),
    #[error("Client error: {0}")]
    Client(String),
    #[error("Connection error: {0}")]
    Connection(String),
    #[error("Channel error: {0}")]
    Channel(String),
    #[error("Counter error: {0}")]
    Counter(String),
    #[error("Sequence error: {0}")]
    Sequence(String),
    #[error("Time error: {0}")]
    Time(String),
    #[error("Invalid transfer message: {0}")]
    TransferMessage(token::TransferError),
    #[error("Sending a token error: {0}")]
    SendingToken(String),
    #[error("Receiving a token error: {0}")]
    ReceivingToken(String),
    #[error("IBC storage error: {0}")]
    IbcStorage(storage::Error),
}

// This is needed to use `ibc::Handler::Error` with `IbcActions` in
// `tx_prelude/src/ibc.rs`
impl From<Error> for storage_api::Error {
    fn from(err: Error) -> Self {
        storage_api::Error::new(err)
    }
}

/// IBC context trait to be implemented in integration that can read and write
pub trait IbcStorageContext {
    /// IBC action error
    type Error: From<Error>;

    /// Storage read prefix iterator
    type PrefixIter<'iter>
    where
        Self: 'iter;

    /// Read IBC-related data
    fn read(&self, key: &Key) -> Result<Option<Vec<u8>>, Self::Error>;

    /// Read IBC-related data with a prefix
    fn iter_prefix(
        &self,
        prefix: &Key,
    ) -> Result<Self::PrefixIter<'iter>, Self::Error>;

    /// next key value pair
    fn iter_next<'iter>(
        &'iter self,
        iter: &mut Self::PrefixIter<'iter>,
    ) -> Result<Option<(String, Vec<u8>)>, Self::Error>;

    /// Write IBC-related data
    fn write(
        &mut self,
        key: &Key,
        data: impl AsRef<[u8]>,
    ) -> Result<(), Self::Error>;

    /// Delete IBC-related data
    fn delete(&mut self, key: &Key) -> Result<(), Self::Error>;

    /// Emit an IBC event
    fn emit_ibc_event(
        &mut self,
        event: NamadaIbcEvent,
    ) -> Result<(), Self::Error>;

    /// Transfer token
    fn transfer_token(
        &mut self,
        src: &Key,
        dest: &Key,
        amount: Amount,
    ) -> Result<(), Self::Error>;

    /// Get the current height of this chain
    fn get_height(&self) -> Result<BlockHeight, Self::Error>;

    /// Get the current time of the tendermint header of this chain
    fn get_header_time(&self) -> Result<Rfc3339String, Self::Error>;
}

pub struct IbcActions<C>
where
    C: IbcStorageContext,
{
    ctx: C,
    modules: HashMap<ModuleId, &dyn Module>,
    ports: HashMap<PortId, ModuleId>,
}

impl<C> IbcActions<C>
where
    C: IbcStorageContext,
{
    pub fn new(ctx: C) -> Self {
        let mut modules = HashMap::new();
        let id = ModuleId::new(MODULE_ID_STR).expect("should be parsable");
        let module = TransferModule::new(&ctx);
        modules.insert(id, module);

        Self {
            ctx,
            modules,
            ports: HashMap::new(),
        }
    }
}

impl<C> Router for IbcActions<C>
where
    C: IbcStorageContext,
{
    fn get_route(&self, module_id: &ModuleId) -> Option<&dyn Module> {
        self.modules.get(module_id)
    }

    fn get_route_mut(
        &mut self,
        module_id: &ModuleId,
    ) -> Option<&mut dyn Module> {
        self.modules.get_mut(module_id)
    }

    fn has_route(&self, module_id: &ModuleId) -> bool {
        self.modules.contains_key(module_id)
    }

    fn lookup_module_by_port(&self, port_id: &PortId) -> Option<ModuleId> {
        self.ports.get(port_id).cloned()
    }
}

impl<C> ValidationContext for IbcActions<C>
where
    C: IbcStorageContext,
{
    fn client_state(
        &self,
        client_id: &ClientId,
    ) -> Result<Box<dyn ClientState>, ContextError> {
        let key = storage::client_state_key(&client_id);
        match self.read(&client_state_key) {
            Ok(Some(value)) => {
                let any = Any::decode(&value[..])
                    .map_err(ContextError::ClientError(ClientError::Decode))?;
                self.decode_client_state(any)
            }
            Ok(None) => {
                Err(ContextError::ClientError(ClientError::ClientNotFound {
                    client_id,
                }))
            }
            Err(e) => Err(ContextError::ClientError(ClientError::Other {
                description: format!(
                    "Reading the client state failed: ID {}, error {}",
                    client_id, e
                ),
            })),
        }
    }

    fn decode_client_state(
        &self,
        client_state: Any,
    ) -> Result<Box<dyn ClientState>, ContextError> {
        if let Ok(cs) = TmClientState::try_from(client_state.clone()) {
            return Ok(cs.into_box());
        }

        #[cfg(any(feature = "ibc-mocks-abcipp", feature = "ibc-mocks"))]
        if let Ok(cs) = MockClientState::try_from(client_state) {
            return Ok(cs.into_box());
        }

        Err(ContextError::ClientError(ClientError::ClientSpecific {
            description: format!("Unknown client state"),
        }))
    }

    fn consensus_state(
        &self,
        client_id: &ClientId,
        height: &Height,
    ) -> Result<Box<dyn ConsensusState>, ContextError> {
        let key = storage::consensus_state_key(client_id, height);
        match self.ctx.read(&key) {
            Ok(Some(value)) => {
                let any = Any::decode(&value[..])
                    .map_err(ContextError::ClientError(ClientError::Decode))?;
                decode_consensus_state(any)
            }
            Ok(None) => Err(ContextError::ClientError(
                ClientError::ConsensusStateNotFound { client_id, height },
            )),
            Err(e) => Err(ContextError::ClientError(ClientError::Other {
                description: format!(
                    "Reading the consensus state failed: ID {}, error {}",
                    client_id, e
                ),
            })),
        }
    }

    fn next_consensus_state(
        &self,
        client_id: &ClientId,
        height: &Height,
    ) -> Result<Option<Box<dyn ConsensusState>>, ContextError> {
        let prefix = storage::consensus_state_prefix(client_id);
        let mut iter = self.ctx.iter_prefix(&prefix).map_err(|e| {
            ContextError::ClientError(ClientError::Other {
                description: format!(
                    "Reading the consensus state failed: ID {}, height {}, \
                     error {}",
                    client_id, height, e
                ),
            })
        })?;
        let mut lowest_height_value = None;
        while let Some((key, value)) =
            self.ctx.iter_next(&mut iter).map_err(|e| {
                ContextError::ClientError(ClientError::Other {
                    description: format!(
                        "Iterating consensus states failed: ID {}, height {}, \
                         error {}",
                        client_id, height, e
                    ),
                })
            })?
        {
            let key = Key::parse(key).expect("the key should be parsable");
            let consensus_height = storage::consensus_height(&key)
                .expect("the key should have a height");
            if consensus_height > height {
                lowest_height_value = match lowest_height_value {
                    Some((lowest, _)) if consensus_height < lowest => {
                        Some((consensus_height, value))
                    }
                    Some(_) => continue,
                    None => Some((consensus_height, value)),
                };
            }
        }
        match lowest_height_value {
            Some((_, value)) => {
                let any = Any::decode(&value[..])
                    .map_err(ContextError::ClientError(ClientError::Decode))?;
                let cs = decode_consensus_state(any)?;
                Ok(Some(cs))
            }
            None => Ok(None),
        }
    }

    fn prev_consensus_state(
        &self,
        client_id: &ClientId,
        height: &Height,
    ) -> Result<Option<Box<dyn ConsensusState>>, ContextError> {
        let prefix = storage::consensus_state_prefix(client_id);
        let mut iter = self.ctx.iter_prefix(&prefix).map_err(
            ContextError::ClientError(ClientError::Other {
                description: format!(
                    "Reading the consensus state failed: ID {}, height {}, \
                     error {}",
                    client_id, height, e
                ),
            }),
        )?;
        let mut highest_height_value = None;
        while let Some((key, value)) =
            self.ctx.iter_next(&mut iter).map_err(|e| {
                ContextError::ClientError(ClientError::Other {
                    description: format!(
                        "Iterating consensus states failed: ID {}, height {}, \
                         error {}",
                        client_id, height, e
                    ),
                })
            })?
        {
            let key = Key::parse(key).expect("the key should be parsable");
            let consensus_height = storage::consensus_height(&key)
                .expect("the key should have the height");
            if consensus_height < height {
                highest_height_value = match highest_height_value {
                    Some((highest, _)) if consensus_height > highest => {
                        Some((consensus_height, value))
                    }
                    Some(_) => continue,
                    None => Some((consensus_height, value)),
                };
            }
        }
        match highest_height_value {
            Some((_, value)) => {
                let any = Any::decode(&value[..])
                    .map_err(ContextError::ClientError(ClientError::Decode))?;
                let cs = decode_consensus_state(any)?;
                Ok(Some(cs))
            }
            None => Ok(None),
        }
    }

    fn host_height(&self) -> Result<Height, ContextError> {
        let height = self.ctx.get_height().map_err(|e| {
            ContextError::ClientError(ClientError::Other {
                description: format!(
                    "getting the host height failed: error {}",
                    e
                ),
            })
        })?;
        // the revision number is always 0
        Height::new(0, height).map_err(ContextError::ClientError)
    }

    fn pending_host_consensus_state(
        &self,
    ) -> Result<Box<dyn ConsensusState>, ContextError> {
        let height = self.host_height()?;
        self.host_consensus_state(&height)
    }

    /// Returns the `ConsensusState` of the host (local) chain at a specific
    /// height.
    fn host_consensus_state(
        &self,
        height: &Height,
    ) -> Result<Box<dyn ConsensusState>, ContextError>;

    /// Returns a natural number, counting how many clients have been created
    /// thus far. The value of this counter should increase only via method
    /// `ClientKeeper::increase_client_counter`.
    fn client_counter(&self) -> Result<u64, ContextError>;

    /// Returns the ConnectionEnd for the given identifier `conn_id`.
    fn connection_end(
        &self,
        conn_id: &ConnectionId,
    ) -> Result<ConnectionEnd, ContextError>;

    /// Validates the `ClientState` of the client on the counterparty chain.
    fn validate_self_client(
        &self,
        counterparty_client_state: Any,
    ) -> Result<(), ConnectionError>;

    /// Returns the prefix that the local chain uses in the KV store.
    fn commitment_prefix(&self) -> CommitmentPrefix;

    /// Returns a counter on how many connections have been created thus far.
    fn connection_counter(&self) -> Result<u64, ContextError>;

    /// Returns the ChannelEnd for the given `port_id` and `chan_id`.
    fn channel_end(
        &self,
        port_channel_id: &(PortId, ChannelId),
    ) -> Result<ChannelEnd, ContextError>;

    fn connection_channels(
        &self,
        cid: &ConnectionId,
    ) -> Result<Vec<(PortId, ChannelId)>, ContextError>;

    fn get_next_sequence_send(
        &self,
        port_channel_id: &(PortId, ChannelId),
    ) -> Result<Sequence, ContextError>;

    fn get_next_sequence_recv(
        &self,
        port_channel_id: &(PortId, ChannelId),
    ) -> Result<Sequence, ContextError>;

    fn get_next_sequence_ack(
        &self,
        port_channel_id: &(PortId, ChannelId),
    ) -> Result<Sequence, ContextError>;

    fn get_packet_commitment(
        &self,
        key: &(PortId, ChannelId, Sequence),
    ) -> Result<PacketCommitment, ContextError>;

    fn get_packet_receipt(
        &self,
        key: &(PortId, ChannelId, Sequence),
    ) -> Result<Receipt, ContextError>;

    fn get_packet_acknowledgement(
        &self,
        key: &(PortId, ChannelId, Sequence),
    ) -> Result<AcknowledgementCommitment, ContextError>;

    /// A hashing function for packet commitments
    fn hash(&self, value: &[u8]) -> Vec<u8>;

    /// Returns the time when the client state for the given [`ClientId`] was
    /// updated with a header for the given [`Height`]
    fn client_update_time(
        &self,
        client_id: &ClientId,
        height: &Height,
    ) -> Result<Timestamp, ContextError>;

    /// Returns the height when the client state for the given [`ClientId`] was
    /// updated with a header for the given [`Height`]
    fn client_update_height(
        &self,
        client_id: &ClientId,
        height: &Height,
    ) -> Result<Height, ContextError>;

    /// Returns a counter on the number of channel ids have been created thus
    /// far. The value of this counter should increase only via method
    /// `ChannelKeeper::increase_channel_counter`.
    fn channel_counter(&self) -> Result<u64, ContextError>;

    /// Returns the maximum expected time per block
    fn max_expected_time_per_block(&self) -> Duration;
}

impl<C> ExecutionContext for IbcActions<C> where C: IbcStorageContext {}

/// Decode ConsensusState from Any
pub fn decode_consensus_state(
    consensus_state: Any,
) -> Result<Box<dyn ConsensusState>, ContextError> {
    if let Ok(cs) = TmConsensusState::try_from(consensus_state.clone()) {
        return Ok(cs.into_box());
    }

    #[cfg(any(feature = "ibc-mocks-abcipp", feature = "ibc-mocks"))]
    if let Ok(cs) = MockConsensusState::try_from(consensus_state) {
        return Ok(cs.into_box());
    }

    Err(ContextError::ClientError(ClientError::ClientSpecific {
        description: format!("Unknown consensus state"),
    }))
}

use crate::ibc::applications::transfer::TokenTransferContext;
use crate::ibc::core::ics26_routing::context::Module;

pub struct TransferModule<'a, C>
where
    C: IbcStorageContext,
{
    ctx: &'a C,
}

impl<'a> TransferModule<'a, C>
where
    C: IbcStorageContext,
{
    pub fn new(ctx: &C) -> Self {
        Self { ctx }
    }
}

impl Module for TransferModule {}

impl TokenTransferContext for TransferModule {}
