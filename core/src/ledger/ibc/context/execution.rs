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
use crate::ibc::core::ics04_channel::error::{ChannelError, PacketError};
use crate::ibc::core::ics04_channel::packet::{Receipt, Sequence};
use crate::ibc::core::ics24_host::identifier::{
    ChannelId, ClientId, ConnectionId, PortChannelId, PortId,
};
use crate::ibc::core::ics24_host::path::{
    ClientConnectionsPath, ClientConsensusStatePath, ClientStatePath,
    ClientTypePath, CommitmentsPath, ConnectionsPath, Path, ReceiptsPath,
};
use crate::ibc::core::{ContextError, ExecutionContext, ValidationContext};
use crate::ibc::events::IbcEvent;
use crate::ibc::timestamp::Timestamp;
use crate::ibc::Height;
use crate::ibc_proto::protobuf::Protobuf;
use crate::ledger::ibc::storage;
use crate::tendermint_proto::Protobuf as TmProtobuf;
use crate::types::storage::Key;

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
                    "Writing the connection end failed: Key {}",
                    key
                ),
            })
        })
    }

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
                            "Decoding the connection list failed: Key {}, \
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
                        "Reading the connection list of failed: Key {}",
                        key,
                    ),
                }))?
            }
        };
        let bytes = list.as_bytes();
        self.ctx.write(&key, bytes).map_err(|e| {
            ContextError::ConnectionError(ConnectionError::Other {
                description: format!(
                    "Writing the list of connection IDs failed: Key {}",
                    key
                ),
            })
        })
    }

    fn increase_connection_counter(&mut self) {
        let key = storage::connection_counter_key();
        self.increase_counter(&key)
            .expect("Error cannot be returned");
    }

    fn store_packet_commitment(
        &mut self,
        path: CommitmentsPath,
        commitment: PacketCommitment,
    ) -> Result<(), ContextError> {
        let path = Path::Commitments(path);
        let key = storage::ibc_key(path.to_string())
            .expect("Creating a key for the client state shouldn't fail");
        let bytes = commitment.into_vec();
        self.ctx.write(&key, bytes).map_err(|e| {
            ContextError::PacketError(PacketError::Channel(
                ChannelError::Other {
                    description: format!(
                        "Writing the packet commitment failed: Key {}",
                        key
                    ),
                },
            ))
        })
    }

    fn delete_packet_commitment(
        &mut self,
        path: CommitmentsPath,
    ) -> Result<(), ContextError> {
        let path = Path::Commitments(path);
        let key = storage::ibc_key(path.to_string())
            .expect("Creating a key for the client state shouldn't fail");
        self.ctx.delete(&key).map_err(|e| {
            ContextError::PacketError(PacketError::Channel(
                ChannelError::Other {
                    description: format!(
                        "Deleting the packet commitment failed: Key {}",
                        key
                    ),
                },
            ))
        })
    }

    fn store_packet_receipt(
        &mut self,
        path: ReceiptsPath,
        receipt: Receipt,
    ) -> Result<(), ContextError> {
        let path = Path::Receipts(path);
        let key = storage::ibc_key(path.to_string())
            .expect("Creating a key for the client state shouldn't fail");
        // the value is the same as ibc-go
        let bytes = &[1_u8];
        self.ctx.write(&key, bytes).map_err(|e| {
            ContextError::PacketError(PacketError::Channel(
                ChannelError::Other {
                    description: format!(
                        "Writing the receipt failed: Key {}",
                        key
                    ),
                },
            ))
        })
    }

    fn store_packet_acknowledgement(
        &mut self,
        key: (PortId, ChannelId, Sequence),
        ack_commitment: AcknowledgementCommitment,
    ) -> Result<(), ContextError> {
        let ack_key = storage::ack_key(&key.0, &key.1, key.2);
        let bytes = ack_commitment.into_vec();
        self.ctx.write(&ack_key, bytes).map_err(|e| {
            ContextError::PacketError(PacketError::Channel(
                ChannelError::Other {
                    description: format!(
                        "Writing the packet ack failed: Key {}",
                        ack_key
                    ),
                },
            ))
        })
    }

    fn delete_packet_acknowledgement(
        &mut self,
        key: (PortId, ChannelId, Sequence),
    ) -> Result<(), ContextError> {
        let ack_key = storage::ack_key(&key.0, &key.1, key.2);
        self.ctx.delete(&ack_key).map_err(|e| {
            ContextError::PacketError(PacketError::Channel(
                ChannelError::Other {
                    description: format!(
                        "Deleting the packet ack failed: Key {}",
                        ack_key
                    ),
                },
            ))
        })
    }

    fn store_connection_channels(
        &mut self,
        conn_id: ConnectionId,
        port_channel_id: (PortId, ChannelId),
    ) -> Result<(), ContextError> {
        let port_id = port_channel_id.0;
        let channel_id = port_channel_id.1;
        let key = storage::connection_channels_key(&conn_id);
        let mut list = self.connection_channels(&conn_id)?;
        list.push((port_id, channel_id));
        let bytes = list
            .iter()
            .fold("".to_string(), |acc, (p, c)| {
                format!("{},{}", acc, format!("{}/{}", p, c))
            })
            .as_bytes();
        self.ctx.write(&key, bytes).map_err(|e| {
            ContextError::ConnectionError(ConnectionError::Other {
                description: format!(
                    "Writing the port/channel list failed: Key {}",
                    key
                ),
            })
        })
    }

    fn store_channel(
        &mut self,
        port_channel_id: (PortId, ChannelId),
        channel_end: ChannelEnd,
    ) -> Result<(), ContextError> {
        let port_id = port_channel_id.0;
        let channel_id = port_channel_id.1;
        let port_channel_id =
            PortChannelId::new(channel_id.clone(), port_id.clone());
        let key = storage::channel_key(&port_channel_id);
        let bytes = channel_end.encode_vec().expect("encoding shouldn't fail");
        self.ctx.write(&key, bytes).map_err(|e| {
            ContextError::ChannelError(ChannelError::Other {
                description: format!(
                    "Writing the channel end failed: Key {}",
                    key
                ),
            })
        })
    }

    fn store_next_sequence_send(
        &mut self,
        port_channel_id: (PortId, ChannelId),
        seq: Sequence,
    ) -> Result<(), ContextError> {
        let port_id = port_channel_id.0;
        let channel_id = port_channel_id.1;
        let port_channel_id =
            PortChannelId::new(channel_id.clone(), port_id.clone());
        let key = storage::next_sequence_send_key(&port_channel_id);
        self.store_sequence(&key, seq)
    }

    fn store_next_sequence_recv(
        &mut self,
        port_channel_id: (PortId, ChannelId),
        seq: Sequence,
    ) -> Result<(), ContextError> {
        let port_id = port_channel_id.0;
        let channel_id = port_channel_id.1;
        let port_channel_id =
            PortChannelId::new(channel_id.clone(), port_id.clone());
        let key = storage::next_sequence_recv_key(&port_channel_id);
        self.store_sequence(&key, seq)
    }

    fn store_next_sequence_ack(
        &mut self,
        port_channel_id: (PortId, ChannelId),
        seq: Sequence,
    ) -> Result<(), ContextError> {
        let port_id = port_channel_id.0;
        let channel_id = port_channel_id.1;
        let port_channel_id =
            PortChannelId::new(channel_id.clone(), port_id.clone());
        let key = storage::next_sequence_ack_key(&port_channel_id);
        self.store_sequence(&key, seq)
    }

    fn increase_channel_counter(&mut self) {
        let key = storage::channel_counter_key();
        self.increase_counter(&key)
            .expect("Error cannot be returned");
    }

    fn emit_ibc_event(&mut self, event: IbcEvent) {
        let event = event.try_into().expect("The event should be converted");
        self.ctx
            .emit_ibc_event(event)
            .expect("Emitting an event shouldn't fail");
    }

    fn log_message(&mut self, message: String) {
        self.ctx.log_string(message)
    }
}

/// Helper functions
impl<C> IbcActions<C>
where
    C: IbcStorageContext,
{
    fn increase_counter(&self, key: &Key) -> Result<(), ContextError> {
        let count = self.read_counter(key)?;
        self.ctx
            .write(&key, &(count + 1).to_be_bytes())
            .map_err(|_| {
                ContextError::ClientError(ClientError::Other {
                    description: format!(
                        "Writing the counter failed: Key {}",
                        key
                    ),
                })
            })
    }

    fn store_sequence(
        &self,
        key: &Key,
        sequence: Sequence,
    ) -> Result<(), ContextError> {
        self.ctx
            .write(&key, &(u64::from(sequence) + 1).to_be_bytes())
            .map_err(|_| {
                ContextError::PacketError(PacketError::Channel(
                    ChannelError::Other {
                        description: format!(
                            "Writing the counter failed: Key {}",
                            key
                        ),
                    },
                ))
            })
    }
}
