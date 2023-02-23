//! ExecutionContext implementation for IBC

use super::super::{IbcActions, IbcStorageContext};
use crate::ibc::core::ics02_client::client_state::ClientState;
use crate::ibc::core::ics02_client::client_type::ClientType;
use crate::ibc::core::ics02_client::consensus_state::ConsensusState;
use crate::ibc::core::ics02_client::error::ClientError;
use crate::ibc::core::ics03_connection::connection::ConnectionEnd;
use crate::ibc::core::ics03_connection::error::ConnectionError;
use crate::ibc::core::ics04_channel::channel::ChannelEnd;
use crate::ibc::core::ics04_channel::commitment::{
    AcknowledgementCommitment, PacketCommitment,
};
use crate::ibc::core::ics04_channel::packet::{Receipt, Sequence};
use crate::ibc::core::ics24_host::identifier::{
    ChannelId, ClientId, ConnectionId, PortId,
};
use crate::ibc::core::ics24_host::path::{
    ClientConnectionsPath, ClientConsensusStatePath, ClientStatePath,
    ClientTypePath, ConnectionsPath, Path,
};
use crate::ibc::core::{ContextError, ExecutionContext, ValidationContext};
use crate::ibc::timestamp::Timestamp;
use crate::ibc::Height;
use crate::ibc_proto::protobuf::Protobuf;
use crate::ledger::ibc::storage;
use crate::tendermint_proto::Protobuf as TmProtobuf;

impl<C> ExecutionContext for IbcActions<C>
where
    C: IbcStorageContext,
{
    fn store_client_type(
        &mut self,
        client_type_path: ClientTypePath,
        client_type: ClientType,
    ) -> Result<(), ContextError> {
        let path = Path::ClientType(client_type_path);
        let key = storage::ibc_key(path.to_string())
            .expect("Creating a key for the client state shouldn't fail");
        let bytes = client_type.as_str().as_bytes();
        self.ctx.write(&key, bytes).map_err(|e| {
            ContextError::ClientError(ClientError::Other {
                description: format!(
                    "Writing the client state failed: Key {}",
                    key
                ),
            })
        })
    }

    fn store_client_state(
        &mut self,
        client_state_path: ClientStatePath,
        client_state: Box<dyn ClientState>,
    ) -> Result<(), ContextError> {
        let path = Path::ClientState(client_state_path);
        let key = storage::ibc_key(path.to_string())
            .expect("Creating a key for the client state shouldn't fail");
        let bytes = client_state.encode_vec().expect("encoding shouldn't fail");
        self.ctx.write(&key, bytes).map_err(|e| {
            ContextError::ClientError(ClientError::Other {
                description: format!(
                    "Writing the client state failed: Key {}",
                    key
                ),
            })
        })
    }

    fn store_consensus_state(
        &mut self,
        consensus_state_path: ClientConsensusStatePath,
        consensus_state: Box<dyn ConsensusState>,
    ) -> Result<(), ContextError> {
        let path = Path::ClientConsensusState(consensus_state_path);
        let key = storage::ibc_key(path.to_string())
            .expect("Creating a key for the client state shouldn't fail");
        let bytes = consensus_state
            .encode_vec()
            .expect("encoding shouldn't fail");
        self.ctx.write(&key, bytes).map_err(|e| {
            ContextError::ClientError(ClientError::Other {
                description: format!(
                    "Writing the consensus state failed: Key {}",
                    key
                ),
            })
        })
    }

    fn increase_client_counter(&mut self) {
        let key = storage::client_counter_key();
        let count = self.client_counter().expect("read failed");
        self.ctx
            .write(&key, count.to_be_bytes())
            .expect("write failed");
    }

    fn store_update_time(
        &mut self,
        client_id: ClientId,
        height: Height,
        timestamp: Timestamp,
    ) -> Result<(), ContextError> {
        let key = storage::client_update_timestamp_key(&client_id);
        match timestamp.into_tm_time() {
            Some(time) => self
                .ctx
                .write(
                    &key,
                    time.encode_vec().expect("encoding shouldn't fail"),
                )
                .map_err(|e| {
                    ContextError::ClientError(ClientError::Other {
                        description: format!(
                            "Writing the consensus state failed: Key {}",
                            key
                        ),
                    })
                }),
            None => Err(ContextError::ClientError(ClientError::Other {
                description: format!(
                    "The client timestamp is invalid: ID {}",
                    client_id
                ),
            })),
        }
    }

    fn store_update_height(
        &mut self,
        client_id: ClientId,
        height: Height,
        host_height: Height,
    ) -> Result<(), ContextError> {
        let key = storage::client_update_height_key(&client_id);
        let bytes = height.encode_vec().expect("encoding shouldn't fail");
        self.ctx.write(&key, bytes).map_err(|e| {
            ContextError::ClientError(ClientError::Other {
                description: format!(
                    "Writing the consensus state failed: Key {}",
                    key
                ),
            })
        })
    }

    /// Stores the given connection_end at path
    fn store_connection(
        &mut self,
        connections_path: ConnectionsPath,
        connection_end: ConnectionEnd,
    ) -> Result<(), ContextError> {
        let path = Path::Connections(connections_path);
        let key = storage::ibc_key(path.to_string())
            .expect("Creating a key for the client state shouldn't fail");
        let bytes = connection_end
            .encode_vec()
            .expect("encoding shouldn't fail");
        self.ctx.write(&key, bytes).map_err(|e| {
            ContextError::ConnectionError(ConnectionError::Other {
                description: format!(
                    "Writing the consensus state failed: Key {}",
                    key
                ),
            })
        })
    }

    /// Stores the given connection_id at a path associated with the client_id.
    fn store_connection_to_client(
        &mut self,
        client_connections_path: ClientConnectionsPath,
        conn_id: ConnectionId,
    ) -> Result<(), ContextError> {
        let path = Path::ClientConnections(client_connections_path);
        let key = storage::ibc_key(path.to_string())
            .expect("Creating a key for the client state shouldn't fail");
        let list = match self.ctx.read(&key) {
            Ok(Some(value)) => {
                let list = String::from_utf8(value).map_err(|e| {
                    ContextError::ConnectionError(ConnectionError::Other {
                        description: format!(
                            "Decoding the list of connection IDs: Key {}, \
                             error {}",
                            key, e
                        ),
                    })
                })?;
                format!("{},{}", list, conn_id.to_string())
            }
            Ok(None) => conn_id.to_string(),
            Err(e) => {
                Err(ContextError::ConnectionError(ConnectionError::Other {
                    description: format!(
                        "Reading the list of connection IDs failed: Key {}",
                        key,
                    ),
                }))?
            }
        };
        let bytes = list.as_bytes();
        self.ctx.write(&key, bytes).map_err(|e| {
            ContextError::ConnectionError(ConnectionError::Other {
                description: format!(
                    "Writing the consensus state failed: Key {}",
                    key
                ),
            })
        })
    }

    /// Called upon connection identifier creation (Init or Try process).
    /// Increases the counter which keeps track of how many connections have
    /// been created. Should never fail.
    fn increase_connection_counter(&mut self);

    fn store_packet_commitment(
        &mut self,
        commitments_path: CommitmentsPath,
        commitment: PacketCommitment,
    ) -> Result<(), ContextError>;

    fn delete_packet_commitment(
        &mut self,
        key: CommitmentsPath,
    ) -> Result<(), ContextError>;

    fn store_packet_receipt(
        &mut self,
        path: ReceiptsPath,
        receipt: Receipt,
    ) -> Result<(), ContextError>;

    fn store_packet_acknowledgement(
        &mut self,
        key: (PortId, ChannelId, Sequence),
        ack_commitment: AcknowledgementCommitment,
    ) -> Result<(), ContextError>;

    fn delete_packet_acknowledgement(
        &mut self,
        key: (PortId, ChannelId, Sequence),
    ) -> Result<(), ContextError>;

    fn store_connection_channels(
        &mut self,
        conn_id: ConnectionId,
        port_channel_id: (PortId, ChannelId),
    ) -> Result<(), ContextError>;

    /// Stores the given channel_end at a path associated with the port_id and
    /// channel_id.
    fn store_channel(
        &mut self,
        port_channel_id: (PortId, ChannelId),
        channel_end: ChannelEnd,
    ) -> Result<(), ContextError>;

    fn store_next_sequence_send(
        &mut self,
        port_channel_id: (PortId, ChannelId),
        seq: Sequence,
    ) -> Result<(), ContextError>;

    fn store_next_sequence_recv(
        &mut self,
        port_channel_id: (PortId, ChannelId),
        seq: Sequence,
    ) -> Result<(), ContextError>;

    fn store_next_sequence_ack(
        &mut self,
        port_channel_id: (PortId, ChannelId),
        seq: Sequence,
    ) -> Result<(), ContextError>;

    /// Called upon channel identifier creation (Init or Try message
    /// processing). Increases the counter which keeps track of how many
    /// channels have been created. Should never fail.
    fn increase_channel_counter(&mut self);

    /// Ibc events
    fn emit_ibc_event(&mut self, event: IbcEvent);

    /// Logging facility
    fn log_message(&mut self, message: String);
}
