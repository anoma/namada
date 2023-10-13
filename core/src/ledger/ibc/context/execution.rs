//! ExecutionContext implementation for IBC

use borsh::BorshDeserialize;
use borsh_ext::BorshSerializeExt;

use super::super::{IbcActions, IbcCommonContext};
use crate::ibc::core::events::IbcEvent;
use crate::ibc::core::ics02_client::client_state::ClientState;
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
use crate::ibc::core::ics24_host::identifier::{ClientId, ConnectionId};
use crate::ibc::core::ics24_host::path::{
    AckPath, ChannelEndPath, ClientConnectionPath, ClientConsensusStatePath,
    ClientStatePath, CommitmentPath, ConnectionPath, Path, ReceiptPath,
    SeqAckPath, SeqRecvPath, SeqSendPath,
};
use crate::ibc::core::timestamp::Timestamp;
use crate::ibc::core::{ContextError, ExecutionContext, ValidationContext};
use crate::ibc::Height;
use crate::ibc_proto::protobuf::Protobuf;
use crate::ledger::ibc::storage;
use crate::tendermint_proto::Protobuf as TmProtobuf;

impl<C> ExecutionContext for IbcActions<'_, C>
where
    C: IbcCommonContext,
{
    fn store_client_state(
        &mut self,
        client_state_path: ClientStatePath,
        client_state: Box<dyn ClientState>,
    ) -> Result<(), ContextError> {
        let path = Path::ClientState(client_state_path);
        let key = storage::ibc_key(path.to_string())
            .expect("Creating a key for the client state shouldn't fail");
        let bytes = client_state.encode_vec();
        self.ctx.borrow_mut().write(&key, bytes).map_err(|_| {
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
        let bytes = consensus_state.encode_vec();
        self.ctx.borrow_mut().write(&key, bytes).map_err(|_| {
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
            .borrow_mut()
            .write(&key, (count + 1).to_be_bytes().to_vec())
            .expect("write failed");
    }

    fn store_update_time(
        &mut self,
        client_id: ClientId,
        _height: Height,
        timestamp: Timestamp,
    ) -> Result<(), ContextError> {
        let key = storage::client_update_timestamp_key(&client_id);
        match timestamp.into_tm_time() {
            Some(time) => self
                .ctx
                .borrow_mut()
                .write(
                    &key,
                    time.encode_vec().expect("encoding shouldn't fail"),
                )
                .map_err(|_| {
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
        _height: Height,
        host_height: Height,
    ) -> Result<(), ContextError> {
        let key = storage::client_update_height_key(&client_id);
        let bytes = host_height.encode_vec();
        self.ctx.borrow_mut().write(&key, bytes).map_err(|_| {
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
        connection_path: &ConnectionPath,
        connection_end: ConnectionEnd,
    ) -> Result<(), ContextError> {
        let path = Path::Connection(connection_path.clone());
        let key = storage::ibc_key(path.to_string())
            .expect("Creating a key for the client state shouldn't fail");
        let bytes = connection_end.encode_vec();
        self.ctx.borrow_mut().write(&key, bytes).map_err(|_| {
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
        client_connection_path: &ClientConnectionPath,
        conn_id: ConnectionId,
    ) -> Result<(), ContextError> {
        let path = Path::ClientConnection(client_connection_path.clone());
        let key = storage::ibc_key(path.to_string())
            .expect("Creating a key for the client state shouldn't fail");
        let list = match self.ctx.borrow().read(&key) {
            Ok(Some(value)) => {
                let list = String::try_from_slice(&value).map_err(|e| {
                    ContextError::ConnectionError(ConnectionError::Other {
                        description: format!(
                            "Decoding the connection list failed: Key {}, \
                             error {}",
                            key, e
                        ),
                    })
                })?;
                format!("{},{}", list, conn_id)
            }
            Ok(None) => conn_id.to_string(),
            Err(_) => {
                Err(ContextError::ConnectionError(ConnectionError::Other {
                    description: format!(
                        "Reading the connection list of failed: Key {}",
                        key,
                    ),
                }))?
            }
        };
        let bytes = list.serialize_to_vec();
        self.ctx.borrow_mut().write(&key, bytes).map_err(|_| {
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
        self.ctx
            .borrow_mut()
            .increase_counter(&key)
            .expect("Error cannot be returned");
    }

    fn store_packet_commitment(
        &mut self,
        path: &CommitmentPath,
        commitment: PacketCommitment,
    ) -> Result<(), ContextError> {
        self.ctx
            .borrow_mut()
            .store_packet_commitment(path, commitment)
    }

    fn delete_packet_commitment(
        &mut self,
        path: &CommitmentPath,
    ) -> Result<(), ContextError> {
        let path = Path::Commitment(path.clone());
        let key = storage::ibc_key(path.to_string())
            .expect("Creating a key for the client state shouldn't fail");
        self.ctx.borrow_mut().delete(&key).map_err(|_| {
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
        path: &ReceiptPath,
        _receipt: Receipt,
    ) -> Result<(), ContextError> {
        let path = Path::Receipt(path.clone());
        let key = storage::ibc_key(path.to_string())
            .expect("Creating a key for the client state shouldn't fail");
        // the value is the same as ibc-go
        let bytes = [1_u8].to_vec();
        self.ctx.borrow_mut().write(&key, bytes).map_err(|_| {
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
        path: &AckPath,
        ack_commitment: AcknowledgementCommitment,
    ) -> Result<(), ContextError> {
        let path = Path::Ack(path.clone());
        let key = storage::ibc_key(path.to_string())
            .expect("Creating a key for the client state shouldn't fail");
        let bytes = ack_commitment.into_vec();
        self.ctx.borrow_mut().write(&key, bytes).map_err(|_| {
            ContextError::PacketError(PacketError::Channel(
                ChannelError::Other {
                    description: format!(
                        "Writing the packet ack failed: Key {}",
                        key
                    ),
                },
            ))
        })
    }

    fn delete_packet_acknowledgement(
        &mut self,
        path: &AckPath,
    ) -> Result<(), ContextError> {
        let path = Path::Ack(path.clone());
        let key = storage::ibc_key(path.to_string())
            .expect("Creating a key for the client state shouldn't fail");
        self.ctx.borrow_mut().delete(&key).map_err(|_| {
            ContextError::PacketError(PacketError::Channel(
                ChannelError::Other {
                    description: format!(
                        "Deleting the packet ack failed: Key {}",
                        key
                    ),
                },
            ))
        })
    }

    fn store_channel(
        &mut self,
        path: &ChannelEndPath,
        channel_end: ChannelEnd,
    ) -> Result<(), ContextError> {
        let path = Path::ChannelEnd(path.clone());
        let key = storage::ibc_key(path.to_string())
            .expect("Creating a key for the client state shouldn't fail");
        let bytes = channel_end.encode_vec();
        self.ctx.borrow_mut().write(&key, bytes).map_err(|_| {
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
        path: &SeqSendPath,
        seq: Sequence,
    ) -> Result<(), ContextError> {
        self.ctx.borrow_mut().store_next_sequence_send(path, seq)
    }

    fn store_next_sequence_recv(
        &mut self,
        path: &SeqRecvPath,
        seq: Sequence,
    ) -> Result<(), ContextError> {
        let path = Path::SeqRecv(path.clone());
        let key = storage::ibc_key(path.to_string())
            .expect("Creating a key for the client state shouldn't fail");
        self.ctx.borrow_mut().store_sequence(&key, seq)
    }

    fn store_next_sequence_ack(
        &mut self,
        path: &SeqAckPath,
        seq: Sequence,
    ) -> Result<(), ContextError> {
        let path = Path::SeqAck(path.clone());
        let key = storage::ibc_key(path.to_string())
            .expect("Creating a key for the client state shouldn't fail");
        self.ctx.borrow_mut().store_sequence(&key, seq)
    }

    fn increase_channel_counter(&mut self) {
        let key = storage::channel_counter_key();
        self.ctx
            .borrow_mut()
            .increase_counter(&key)
            .expect("Error cannot be returned");
    }

    fn emit_ibc_event(&mut self, event: IbcEvent) {
        let event = event.try_into().expect("The event should be converted");
        self.ctx
            .borrow_mut()
            .emit_ibc_event(event)
            .expect("Emitting an event shouldn't fail");
    }

    fn log_message(&mut self, message: String) {
        self.ctx.borrow_mut().log_string(message)
    }
}
