//! IbcCommonContext implementation for IBC

use core::time::Duration;

use prost::Message;
use sha2::Digest;

use super::storage::IbcStorageContext;
use crate::ibc::clients::ics07_tendermint::client_state::ClientState as TmClientState;
use crate::ibc::clients::ics07_tendermint::consensus_state::ConsensusState as TmConsensusState;
use crate::ibc::core::ics02_client::client_state::ClientState;
use crate::ibc::core::ics02_client::consensus_state::ConsensusState;
use crate::ibc::core::ics02_client::error::ClientError;
use crate::ibc::core::ics02_client::height::Height;
use crate::ibc::core::ics03_connection::connection::ConnectionEnd;
use crate::ibc::core::ics03_connection::error::ConnectionError;
use crate::ibc::core::ics04_channel::channel::ChannelEnd;
use crate::ibc::core::ics04_channel::commitment::{
    AcknowledgementCommitment, PacketCommitment,
};
use crate::ibc::core::ics04_channel::error::{ChannelError, PacketError};
use crate::ibc::core::ics04_channel::packet::{Receipt, Sequence};
use crate::ibc::core::ics04_channel::timeout::TimeoutHeight;
use crate::ibc::core::ics24_host::identifier::{
    ChannelId, ClientId, ConnectionId, PortId,
};
use crate::ibc::core::timestamp::Timestamp;
use crate::ibc::core::ContextError;
#[cfg(any(feature = "ibc-mocks-abcipp", feature = "ibc-mocks"))]
use crate::ibc::mock::client_state::MockClientState;
#[cfg(any(feature = "ibc-mocks-abcipp", feature = "ibc-mocks"))]
use crate::ibc::mock::consensus_state::MockConsensusState;
use crate::ibc_proto::google::protobuf::Any;
use crate::ibc_proto::protobuf::Protobuf;
use crate::ledger::ibc::storage;
use crate::ledger::parameters::storage::get_max_expected_time_per_block_key;
use crate::ledger::storage_api;
use crate::tendermint::Time as TmTime;
use crate::tendermint_proto::Protobuf as TmProtobuf;
use crate::types::storage::{BlockHeight, Key};
use crate::types::time::DurationSecs;

/// Result of IBC common function call
pub type Result<T> = std::result::Result<T, ContextError>;

/// Context to handle typical IBC data
pub trait IbcCommonContext: IbcStorageContext {
    /// Get the ClientState
    fn client_state(
        &self,
        client_id: &ClientId,
    ) -> Result<Box<dyn ClientState>> {
        let key = storage::client_state_key(client_id);
        match self.read_bytes(&key)? {
            Some(value) => {
                let any =
                    Any::decode(&value[..]).map_err(ClientError::Decode)?;
                self.decode_client_state(any)
            }
            None => Err(ClientError::ClientStateNotFound {
                client_id: client_id.clone(),
            }
            .into()),
        }
    }

    /// Store the ClientState
    fn store_client_state(
        &mut self,
        client_id: &ClientId,
        client_state: Box<dyn ClientState>,
    ) -> Result<()> {
        let key = storage::client_state_key(client_id);
        let bytes = client_state.encode_vec();
        self.write_bytes(&key, bytes).map_err(ContextError::from)
    }

    /// Decode ClientState from Any
    fn decode_client_state(
        &self,
        client_state: Any,
    ) -> Result<Box<dyn ClientState>> {
        #[cfg(any(feature = "ibc-mocks-abcipp", feature = "ibc-mocks"))]
        if let Ok(cs) = MockClientState::try_from(client_state.clone()) {
            return Ok(cs.into_box());
        }

        if let Ok(cs) = TmClientState::try_from(client_state) {
            return Ok(cs.into_box());
        }

        Err(ClientError::ClientSpecific {
            description: "Unknown client state".to_string(),
        }
        .into())
    }

    /// Get the ConsensusState
    fn consensus_state(
        &self,
        client_id: &ClientId,
        height: Height,
    ) -> Result<Box<dyn ConsensusState>> {
        let key = storage::consensus_state_key(client_id, height);
        match self.read_bytes(&key)? {
            Some(value) => {
                let any =
                    Any::decode(&value[..]).map_err(ClientError::Decode)?;
                self.decode_consensus_state(any)
            }
            None => Err(ClientError::ConsensusStateNotFound {
                client_id: client_id.clone(),
                height,
            }
            .into()),
        }
    }

    /// Store the ConsensusState
    fn store_consensus_state(
        &mut self,
        client_id: &ClientId,
        height: Height,
        consensus_state: Box<dyn ConsensusState>,
    ) -> Result<()> {
        let key = storage::consensus_state_key(client_id, height);
        let bytes = consensus_state.encode_vec();
        self.write_bytes(&key, bytes).map_err(ContextError::from)
    }

    /// Decode ConsensusState from Any
    fn decode_consensus_state(
        &self,
        consensus_state: Any,
    ) -> Result<Box<dyn ConsensusState>> {
        #[cfg(any(feature = "ibc-mocks-abcipp", feature = "ibc-mocks"))]
        if let Ok(cs) = MockConsensusState::try_from(consensus_state.clone()) {
            return Ok(cs.into_box());
        }

        if let Ok(cs) = TmConsensusState::try_from(consensus_state) {
            return Ok(cs.into_box());
        }

        Err(ClientError::ClientSpecific {
            description: "Unknown consensus state".to_string(),
        }
        .into())
    }

    /// Decode ConsensusState from bytes
    fn decode_consensus_state_value(
        &self,
        consensus_state: Vec<u8>,
    ) -> Result<Box<dyn ConsensusState>> {
        let any =
            Any::decode(&consensus_state[..]).map_err(ClientError::Decode)?;
        self.decode_consensus_state(any)
    }

    /// Get the client update time
    fn client_update_time(&self, client_id: &ClientId) -> Result<Timestamp> {
        let key = storage::client_update_timestamp_key(client_id);
        match self.read_bytes(&key)? {
            Some(value) => {
                let time = TmTime::decode_vec(&value).map_err(|_| {
                    ContextError::from(ClientError::Other {
                        description: format!(
                            "Decoding the client update time failed: ID \
                             {client_id}",
                        ),
                    })
                })?;
                Ok(time.into())
            }
            None => Err(ClientError::ClientSpecific {
                description: format!(
                    "The client update time doesn't exist: ID {client_id}",
                ),
            }
            .into()),
        }
    }

    /// Store the client update time
    fn store_update_time(
        &mut self,
        client_id: &ClientId,
        timestamp: Timestamp,
    ) -> Result<()> {
        let key = storage::client_update_timestamp_key(client_id);
        match timestamp.into_tm_time() {
            Some(time) => self
                .write_bytes(
                    &key,
                    time.encode_vec().expect("encoding shouldn't fail"),
                )
                .map_err(ContextError::from),
            None => Err(ContextError::ClientError(ClientError::Other {
                description: format!(
                    "The client timestamp is invalid: ID {client_id}",
                ),
            })),
        }
    }

    /// Get the client update height
    fn client_update_height(&self, client_id: &ClientId) -> Result<Height> {
        let key = storage::client_update_height_key(client_id);
        match self.read_bytes(&key)? {
            Some(value) => Height::decode_vec(&value).map_err(|_| {
                ClientError::Other {
                    description: format!(
                        "Decoding the client update height failed: ID \
                         {client_id}",
                    ),
                }
                .into()
            }),
            None => Err(ClientError::ClientSpecific {
                description: format!(
                    "The client update height doesn't exist: ID {client_id}",
                ),
            }
            .into()),
        }
    }

    /// Get the timestamp on this chain
    fn host_timestamp(&self) -> Result<Timestamp> {
        let height = self.get_block_height()?;
        let header = self.get_block_header(height)?.ok_or_else(|| {
            ContextError::from(ClientError::Other {
                description: "No host header".to_string(),
            })
        })?;
        let time = TmTime::try_from(header.time).map_err(|_| {
            ContextError::ClientError(ClientError::Other {
                description: "Converting to Tendermint time failed".to_string(),
            })
        })?;
        Ok(time.into())
    }

    /// Get the consensus state of this chain
    fn host_consensus_state(
        &self,
        height: &Height,
    ) -> Result<Box<dyn ConsensusState>> {
        let height = BlockHeight(height.revision_height());
        let header = self.get_block_header(height)?.ok_or_else(|| {
            ContextError::from(ClientError::Other {
                description: "No host header".to_string(),
            })
        })?;
        let commitment_root = header.hash.to_vec().into();
        let time = header
            .time
            .try_into()
            .expect("The time should be converted");
        let next_validators_hash = header
            .next_validators_hash
            .try_into()
            .expect("The hash should be converted");
        let consensus_state =
            TmConsensusState::new(commitment_root, time, next_validators_hash);
        Ok(consensus_state.into_box())
    }

    /// Get the max expected time per block
    fn max_expected_time_per_block(&self) -> Result<Duration> {
        let key = get_max_expected_time_per_block_key();
        match self.read::<DurationSecs>(&key)? {
            Some(duration) => Ok(duration.into()),
            None => unreachable!("The parameter should be initialized"),
        }
    }

    /// Store the client update height
    fn store_update_height(
        &mut self,
        client_id: &ClientId,
        host_height: Height,
    ) -> Result<()> {
        let key = storage::client_update_height_key(client_id);
        let bytes = host_height.encode_vec();
        self.write_bytes(&key, bytes).map_err(ContextError::from)
    }

    /// Get the ConnectionEnd
    fn connection_end(&self, conn_id: &ConnectionId) -> Result<ConnectionEnd> {
        let key = storage::connection_key(conn_id);
        match self.read_bytes(&key)? {
            Some(value) => ConnectionEnd::decode_vec(&value).map_err(|_| {
                ConnectionError::Other {
                    description: format!(
                        "Decoding the connection end failed: ID {conn_id}",
                    ),
                }
                .into()
            }),
            None => Err(ConnectionError::ConnectionNotFound {
                connection_id: conn_id.clone(),
            }
            .into()),
        }
    }

    /// Store the ConnectionEnd
    fn store_connection(
        &mut self,
        connection_id: &ConnectionId,
        connection_end: ConnectionEnd,
    ) -> Result<()> {
        let key = storage::connection_key(connection_id);
        let bytes = connection_end.encode_vec();
        self.write_bytes(&key, bytes).map_err(ContextError::from)
    }

    /// Append the connection ID to the connection list of the client
    fn append_connection(
        &mut self,
        client_id: &ClientId,
        conn_id: ConnectionId,
    ) -> Result<()> {
        let key = storage::client_connections_key(client_id);
        let list = match self.read::<String>(&key)? {
            Some(list) => format!("{list},{conn_id}"),
            None => conn_id.to_string(),
        };
        self.write(&key, list).map_err(ContextError::from)
    }

    /// Get the ChannelEnd
    fn channel_end(
        &self,
        port_id: &PortId,
        channel_id: &ChannelId,
    ) -> Result<ChannelEnd> {
        let key = storage::channel_key(port_id, channel_id);
        match self.read_bytes(&key)? {
            Some(value) => ChannelEnd::decode_vec(&value).map_err(|_| {
                ChannelError::Other {
                    description: format!(
                        "Decoding the channel end failed: Key {key}",
                    ),
                }
                .into()
            }),
            None => Err(ChannelError::ChannelNotFound {
                port_id: port_id.clone(),
                channel_id: channel_id.clone(),
            }
            .into()),
        }
    }

    /// Store the ChannelEnd
    fn store_channel(
        &mut self,
        port_id: &PortId,
        channel_id: &ChannelId,
        channel_end: ChannelEnd,
    ) -> Result<()> {
        let key = storage::channel_key(port_id, channel_id);
        let bytes = channel_end.encode_vec();
        self.write_bytes(&key, bytes).map_err(ContextError::from)
    }

    /// Get the NextSequenceSend
    fn get_next_sequence_send(
        &self,
        port_id: &PortId,
        channel_id: &ChannelId,
    ) -> Result<Sequence> {
        let key = storage::next_sequence_send_key(port_id, channel_id);
        self.read_sequence(&key)
    }

    /// Store the NextSequenceSend
    fn store_next_sequence_send(
        &mut self,
        port_id: &PortId,
        channel_id: &ChannelId,
        seq: Sequence,
    ) -> Result<()> {
        let key = storage::next_sequence_send_key(port_id, channel_id);
        self.store_sequence(&key, seq)
    }

    /// Get the NextSequenceRecv
    fn get_next_sequence_recv(
        &self,
        port_id: &PortId,
        channel_id: &ChannelId,
    ) -> Result<Sequence> {
        let key = storage::next_sequence_recv_key(port_id, channel_id);
        self.read_sequence(&key)
    }

    /// Store the NextSequenceRecv
    fn store_next_sequence_recv(
        &mut self,
        port_id: &PortId,
        channel_id: &ChannelId,
        seq: Sequence,
    ) -> Result<()> {
        let key = storage::next_sequence_recv_key(port_id, channel_id);
        self.store_sequence(&key, seq)
    }

    /// Get the NextSequenceAck
    fn get_next_sequence_ack(
        &self,
        port_id: &PortId,
        channel_id: &ChannelId,
    ) -> Result<Sequence> {
        let key = storage::next_sequence_ack_key(port_id, channel_id);
        self.read_sequence(&key)
    }

    /// Store the NextSequenceAck
    fn store_next_sequence_ack(
        &mut self,
        port_id: &PortId,
        channel_id: &ChannelId,
        seq: Sequence,
    ) -> Result<()> {
        let key = storage::next_sequence_ack_key(port_id, channel_id);
        self.store_sequence(&key, seq)
    }

    /// Read a sequence
    fn read_sequence(&self, key: &Key) -> Result<Sequence> {
        match self.read_bytes(key)? {
            Some(value) => {
                let value: [u8; 8] =
                    value.try_into().map_err(|_| ChannelError::Other {
                        description: format!(
                            "The sequence value wasn't u64: Key {key}",
                        ),
                    })?;
                Ok(u64::from_be_bytes(value).into())
            }
            // when the sequence has never been used, returns the initial value
            None => Ok(1.into()),
        }
    }

    /// Store the sequence
    fn store_sequence(&mut self, key: &Key, sequence: Sequence) -> Result<()> {
        let bytes = u64::from(sequence).to_be_bytes().to_vec();
        self.write_bytes(key, bytes).map_err(ContextError::from)
    }

    /// Calculate the hash
    fn hash(value: &[u8]) -> Vec<u8> {
        sha2::Sha256::digest(value).to_vec()
    }

    /// Calculate the packet commitment
    fn compute_packet_commitment(
        &self,
        packet_data: &[u8],
        timeout_height: &TimeoutHeight,
        timeout_timestamp: &Timestamp,
    ) -> PacketCommitment {
        let mut hash_input =
            timeout_timestamp.nanoseconds().to_be_bytes().to_vec();

        let revision_number =
            timeout_height.commitment_revision_number().to_be_bytes();
        hash_input.append(&mut revision_number.to_vec());

        let revision_height =
            timeout_height.commitment_revision_height().to_be_bytes();
        hash_input.append(&mut revision_height.to_vec());

        let packet_data_hash = Self::hash(packet_data);
        hash_input.append(&mut packet_data_hash.to_vec());

        Self::hash(&hash_input).into()
    }

    /// Get the packet commitment
    fn packet_commitment(
        &self,
        port_id: &PortId,
        channel_id: &ChannelId,
        sequence: Sequence,
    ) -> Result<PacketCommitment> {
        let key = storage::commitment_key(port_id, channel_id, sequence);
        match self.read_bytes(&key)? {
            Some(value) => Ok(value.into()),
            None => {
                Err(PacketError::PacketCommitmentNotFound { sequence }.into())
            }
        }
    }

    /// Store the packet commitment
    fn store_packet_commitment(
        &mut self,
        port_id: &PortId,
        channel_id: &ChannelId,
        sequence: Sequence,
        commitment: PacketCommitment,
    ) -> Result<()> {
        let key = storage::commitment_key(port_id, channel_id, sequence);
        let bytes = commitment.into_vec();
        self.write_bytes(&key, bytes).map_err(ContextError::from)
    }

    /// Delete the packet commitment
    fn delete_packet_commitment(
        &mut self,
        port_id: &PortId,
        channel_id: &ChannelId,
        sequence: Sequence,
    ) -> Result<()> {
        let key = storage::commitment_key(port_id, channel_id, sequence);
        self.delete(&key).map_err(ContextError::from)
    }

    /// Get the packet receipt
    fn packet_receipt(
        &self,
        port_id: &PortId,
        channel_id: &ChannelId,
        sequence: Sequence,
    ) -> Result<Receipt> {
        let key = storage::receipt_key(port_id, channel_id, sequence);
        match self.read_bytes(&key)? {
            Some(_) => Ok(Receipt::Ok),
            None => Err(PacketError::PacketReceiptNotFound { sequence }.into()),
        }
    }

    /// Store the packet receipt
    fn store_packet_receipt(
        &mut self,
        port_id: &PortId,
        channel_id: &ChannelId,
        sequence: Sequence,
    ) -> Result<()> {
        let key = storage::receipt_key(port_id, channel_id, sequence);
        // the value is the same as ibc-go
        let bytes = [1_u8].to_vec();
        self.write_bytes(&key, bytes).map_err(ContextError::from)
    }

    /// Get the packet acknowledgement
    fn packet_ack(
        &self,
        port_id: &PortId,
        channel_id: &ChannelId,
        sequence: Sequence,
    ) -> Result<AcknowledgementCommitment> {
        let key = storage::ack_key(port_id, channel_id, sequence);
        match self.read_bytes(&key)? {
            Some(value) => Ok(value.into()),
            None => {
                Err(PacketError::PacketAcknowledgementNotFound { sequence }
                    .into())
            }
        }
    }

    /// Store the packet acknowledgement
    fn store_packet_ack(
        &mut self,
        port_id: &PortId,
        channel_id: &ChannelId,
        sequence: Sequence,
        ack_commitment: AcknowledgementCommitment,
    ) -> Result<()> {
        let key = storage::ack_key(port_id, channel_id, sequence);
        let bytes = ack_commitment.into_vec();
        self.write_bytes(&key, bytes).map_err(ContextError::from)
    }

    /// Delete the packet acknowledgement
    fn delete_packet_ack(
        &mut self,
        port_id: &PortId,
        channel_id: &ChannelId,
        sequence: Sequence,
    ) -> Result<()> {
        let key = storage::ack_key(port_id, channel_id, sequence);
        self.delete(&key).map_err(ContextError::from)
    }

    /// Read a counter
    fn read_counter(&self, key: &Key) -> Result<u64> {
        match self.read_bytes(key)? {
            Some(value) => {
                let value: [u8; 8] =
                    value.try_into().map_err(|_| ClientError::Other {
                        description: format!(
                            "The counter value wasn't u64: Key {key}",
                        ),
                    })?;
                Ok(u64::from_be_bytes(value))
            }
            None => unreachable!("the counter should be initialized"),
        }
    }

    /// Increment the counter
    fn increment_counter(&mut self, key: &Key) -> Result<()> {
        let count = self.read_counter(key)?;
        let count =
            u64::checked_add(count, 1).ok_or_else(|| ClientError::Other {
                description: format!("The counter overflow: Key {key}"),
            })?;
        self.write_bytes(key, count.to_be_bytes())
            .map_err(ContextError::from)
    }

    /// Write the IBC denom. The given address could be a non-Namada token.
    fn store_ibc_denom(
        &mut self,
        addr: impl AsRef<str>,
        trace_hash: impl AsRef<str>,
        denom: impl AsRef<str>,
    ) -> Result<()> {
        let key = storage::ibc_denom_key(addr, trace_hash.as_ref());
        let has_key = self.has_key(&key).map_err(|_| ChannelError::Other {
            description: format!("Reading the IBC denom failed: Key {key}"),
        })?;
        if !has_key {
            self.write(&key, denom.as_ref()).map_err(|_| {
                ChannelError::Other {
                    description: format!(
                        "Writing the denom failed: Key {key}",
                    ),
                }
            })?;
        }
        Ok(())
    }
}

/// Convert `storage_api::Error` into `ContextError`.
/// It always returns `ClientError::Other` though the storage error could happen
/// in any storage access.
impl From<storage_api::Error> for ContextError {
    fn from(error: storage_api::Error) -> Self {
        ClientError::Other {
            description: format!("Storage error: {error}"),
        }
        .into()
    }
}
