//! IbcCommonContext implementation for IBC

use ibc::apps::nft_transfer::types::{PrefixedClassId, TokenId};
use ibc::clients::tendermint::consensus_state::ConsensusState as TmConsensusState;
use ibc::clients::tendermint::types::ConsensusState as TmConsensusStateType;
use ibc::core::channel::types::channel::ChannelEnd;
use ibc::core::channel::types::commitment::{
    AcknowledgementCommitment, PacketCommitment,
};
use ibc::core::channel::types::error::{ChannelError, PacketError};
use ibc::core::channel::types::packet::Receipt;
use ibc::core::client::types::error::ClientError;
use ibc::core::client::types::Height;
use ibc::core::connection::types::error::ConnectionError;
use ibc::core::connection::types::ConnectionEnd;
use ibc::core::handler::types::error::ContextError;
use ibc::core::host::types::identifiers::{
    ChannelId, ClientId, ConnectionId, PortId, Sequence,
};
use ibc::primitives::proto::{Any, Protobuf};
use ibc::primitives::Timestamp;
use namada_core::address::Address;
use namada_core::storage::{BlockHeight, Key};
use namada_core::tendermint::Time as TmTime;
use namada_state::{StorageError, StorageRead, StorageWrite};
use namada_token::storage_key::balance_key;
use namada_token::Amount;
use prost::Message;

use super::client::{AnyClientState, AnyConsensusState};
use super::storage::IbcStorageContext;
use crate::{storage, trace, NftClass, NftMetadata};

/// Result of IBC common function call
pub type Result<T> = std::result::Result<T, ContextError>;

/// Context to handle typical IBC data
pub trait IbcCommonContext: IbcStorageContext {
    /// Get the ClientState
    fn client_state(&self, client_id: &ClientId) -> Result<AnyClientState> {
        let key = storage::client_state_key(client_id);
        match self.storage().read_bytes(&key)? {
            Some(value) => Any::decode(&value[..])
                .map_err(|e| ClientError::Other {
                    description: e.to_string(),
                })?
                .try_into()
                .map_err(ContextError::from),
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
        client_state: AnyClientState,
    ) -> Result<()> {
        let key = storage::client_state_key(client_id);
        let bytes = Any::from(client_state).encode_to_vec();
        self.storage_mut()
            .write_bytes(&key, bytes)
            .map_err(ContextError::from)
    }

    /// Get the ConsensusState
    fn consensus_state(
        &self,
        client_id: &ClientId,
        height: Height,
    ) -> Result<AnyConsensusState> {
        let key = storage::consensus_state_key(client_id, height);
        match self.storage().read_bytes(&key)? {
            Some(value) => Any::decode(&value[..])
                .map_err(|e| ClientError::Other {
                    description: e.to_string(),
                })?
                .try_into()
                .map_err(ContextError::from),
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
        consensus_state: AnyConsensusState,
    ) -> Result<()> {
        let key = storage::consensus_state_key(client_id, height);
        let bytes = Any::from(consensus_state).encode_to_vec();
        self.storage_mut()
            .write_bytes(&key, bytes)
            .map_err(ContextError::from)
    }

    /// Delete the ConsensusState
    fn delete_consensus_state(
        &mut self,
        client_id: &ClientId,
        height: Height,
    ) -> Result<()> {
        let key = storage::consensus_state_key(client_id, height);
        self.storage_mut().delete(&key).map_err(ContextError::from)
    }

    /// Decode ConsensusState from bytes
    fn decode_consensus_state_value(
        &self,
        consensus_state: Vec<u8>,
    ) -> Result<AnyConsensusState> {
        Any::decode(&consensus_state[..])
            .map_err(|e| ClientError::Other {
                description: e.to_string(),
            })?
            .try_into()
            .map_err(ContextError::from)
    }

    /// Get heights of all consensus states
    fn consensus_state_heights(
        &self,
        client_id: &ClientId,
    ) -> Result<Vec<Height>> {
        let prefix = storage::consensus_state_prefix(client_id);
        let mut iter = self.storage().iter_prefix(&prefix)?;
        let mut heights = Vec::new();
        while let Some((key, _)) = self.storage().iter_next(&mut iter)? {
            let key = Key::parse(key).expect("the key should be parsable");
            let height = storage::consensus_height(&key).map_err(|e| {
                ClientError::Other {
                    description: e.to_string(),
                }
            })?;
            heights.push(height);
        }
        Ok(heights)
    }

    /// Get the next consensus state after the given height
    fn next_consensus_state(
        &self,
        client_id: &ClientId,
        height: &Height,
    ) -> Result<Option<AnyConsensusState>> {
        let prefix = storage::consensus_state_prefix(client_id);
        let mut iter = self.storage().iter_prefix(&prefix)?;
        let mut lowest_height_value = None;
        while let Some((key, value)) = self.storage().iter_next(&mut iter)? {
            let key = Key::parse(key).expect("the key should be parsable");
            let consensus_height = storage::consensus_height(&key)
                .expect("the key should have a height");
            if consensus_height > *height {
                lowest_height_value = match lowest_height_value {
                    Some((lowest, _)) if consensus_height < lowest => {
                        Some((consensus_height, value))
                    }
                    Some(_) => continue,
                    None => Some((consensus_height, value)),
                };
            }
        }
        lowest_height_value
            .map(|(_, value)| value.try_into().map_err(ContextError::from))
            .transpose()
    }

    /// Get the previous consensus state before the given height
    fn prev_consensus_state(
        &self,
        client_id: &ClientId,
        height: &Height,
    ) -> Result<Option<AnyConsensusState>> {
        let prefix = storage::consensus_state_prefix(client_id);
        // for iterator
        let mut iter = self.storage().iter_prefix(&prefix)?;
        let mut highest_height_value = None;
        while let Some((key, value)) = self.storage().iter_next(&mut iter)? {
            let key = Key::parse(key).expect("the key should be parsable");
            let consensus_height = storage::consensus_height(&key)
                .expect("the key should have the height");
            if consensus_height < *height {
                highest_height_value = match highest_height_value {
                    Some((highest, _)) if consensus_height > highest => {
                        Some((consensus_height, value))
                    }
                    Some(_) => continue,
                    None => Some((consensus_height, value)),
                };
            }
        }
        highest_height_value
            .map(|(_, value)| value.try_into().map_err(ContextError::from))
            .transpose()
    }

    /// Get the client update time
    fn client_update_meta(
        &self,
        client_id: &ClientId,
    ) -> Result<(Timestamp, Height)> {
        let key = storage::client_update_timestamp_key(client_id);
        let value = self.storage().read_bytes(&key)?.ok_or(
            ClientError::ClientSpecific {
                description: format!(
                    "The client update time doesn't exist: ID {client_id}",
                ),
            },
        )?;
        let time = TmTime::decode_vec(&value)
            .map_err(|_| ClientError::Other {
                description: format!(
                    "Decoding the client update time failed: ID {client_id}",
                ),
            })?
            .into();

        let key = storage::client_update_height_key(client_id);
        let value = self.storage().read_bytes(&key)?.ok_or({
            ClientError::ClientSpecific {
                description: format!(
                    "The client update height doesn't exist: ID {client_id}",
                ),
            }
        })?;
        let height = Height::decode_vec(&value).map_err(|_| {
            ContextError::ClientError(ClientError::Other {
                description: format!(
                    "Decoding the client update height failed: ID {client_id}",
                ),
            })
        })?;

        Ok((time, height))
    }

    /// Store the client update time and height
    fn store_update_meta(
        &mut self,
        client_id: &ClientId,
        host_timestamp: Timestamp,
        host_height: Height,
    ) -> Result<()> {
        let key = storage::client_update_timestamp_key(client_id);
        let time = host_timestamp.into_tm_time().ok_or(ClientError::Other {
            description: format!(
                "The client timestamp is invalid: ID {client_id}",
            ),
        })?;
        self.storage_mut()
            .write_bytes(&key, time.encode_vec())
            .map_err(ContextError::from)?;

        let key = storage::client_update_height_key(client_id);
        let bytes = host_height.encode_vec();
        self.storage_mut()
            .write_bytes(&key, bytes)
            .map_err(ContextError::from)
    }

    /// Delete the client update time and height
    fn delete_update_meta(&mut self, client_id: &ClientId) -> Result<()> {
        let key = storage::client_update_timestamp_key(client_id);
        self.storage_mut()
            .delete(&key)
            .map_err(ContextError::from)?;

        let key = storage::client_update_height_key(client_id);
        self.storage_mut().delete(&key).map_err(ContextError::from)
    }

    /// Get the timestamp on this chain
    fn host_timestamp(&self) -> Result<Timestamp> {
        let height = self.storage().get_block_height()?;
        let header = self
            .storage()
            .get_block_header(height)?
            .or({
                if height > BlockHeight::first() {
                    // When the latest header doesn't exist before
                    // `FinalizeBlock` phase, e.g. dry-run, use the previous
                    // header's time. It should be OK though the constraints
                    // become a bit stricter when checking timeouts.
                    self.storage()
                        .get_block_header(height.prev_height().unwrap())?
                } else {
                    None
                }
            })
            .ok_or_else(|| {
                ContextError::from(ClientError::Other {
                    description: "No host block header".to_string(),
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
    ) -> Result<AnyConsensusState> {
        let height = BlockHeight(height.revision_height());
        let header =
            self.storage().get_block_header(height)?.ok_or_else(|| {
                ContextError::from(ClientError::Other {
                    description: "No host header".to_string(),
                })
            })?;
        let commitment_root = header.hash.to_vec().into();
        let time = header
            .time
            .try_into()
            .expect("The time should be converted");
        let next_validators_hash = header.next_validators_hash.into();
        let consensus_state: TmConsensusState = TmConsensusStateType::new(
            commitment_root,
            time,
            next_validators_hash,
        )
        .into();
        Ok(consensus_state.into())
    }

    /// Get the ConnectionEnd
    fn connection_end(&self, conn_id: &ConnectionId) -> Result<ConnectionEnd> {
        let key = storage::connection_key(conn_id);
        let value = self.storage().read_bytes(&key)?.ok_or(
            ConnectionError::ConnectionNotFound {
                connection_id: conn_id.clone(),
            },
        )?;
        ConnectionEnd::decode_vec(&value).map_err(|_| {
            ConnectionError::Other {
                description: format!(
                    "Decoding the connection end failed: ID {conn_id}",
                ),
            }
            .into()
        })
    }

    /// Store the ConnectionEnd
    fn store_connection(
        &mut self,
        connection_id: &ConnectionId,
        connection_end: ConnectionEnd,
    ) -> Result<()> {
        let key = storage::connection_key(connection_id);
        let bytes = connection_end.encode_vec();
        self.storage_mut()
            .write_bytes(&key, bytes)
            .map_err(ContextError::from)
    }

    /// Append the connection ID to the connection list of the client
    fn append_connection(
        &mut self,
        client_id: &ClientId,
        conn_id: ConnectionId,
    ) -> Result<()> {
        let key = storage::client_connections_key(client_id);
        let list = match self.storage().read::<String>(&key)? {
            Some(list) => format!("{list},{conn_id}"),
            None => conn_id.to_string(),
        };
        self.storage_mut()
            .write(&key, list)
            .map_err(ContextError::from)
    }

    /// Get the ChannelEnd
    fn channel_end(
        &self,
        port_id: &PortId,
        channel_id: &ChannelId,
    ) -> Result<ChannelEnd> {
        let key = storage::channel_key(port_id, channel_id);
        let value = self.storage().read_bytes(&key)?.ok_or(
            ChannelError::ChannelNotFound {
                port_id: port_id.clone(),
                channel_id: channel_id.clone(),
            },
        )?;
        ChannelEnd::decode_vec(&value).map_err(|_| {
            ChannelError::Other {
                description: format!(
                    "Decoding the channel end failed: Key {key}",
                ),
            }
            .into()
        })
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
        self.storage_mut()
            .write_bytes(&key, bytes)
            .map_err(ContextError::from)
    }

    /// Get the NextSequenceSend
    fn get_next_sequence_send(
        &self,
        port_id: &PortId,
        channel_id: &ChannelId,
    ) -> Result<Sequence> {
        let key = storage::next_sequence_send_key(port_id, channel_id);
        read_sequence(self.storage(), &key).map_err(ContextError::from)
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
        read_sequence(self.storage(), &key).map_err(ContextError::from)
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
        read_sequence(self.storage(), &key).map_err(ContextError::from)
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

    /// Store the sequence
    fn store_sequence(&mut self, key: &Key, sequence: Sequence) -> Result<()> {
        let bytes = u64::from(sequence).to_be_bytes().to_vec();
        self.storage_mut()
            .write_bytes(key, bytes)
            .map_err(ContextError::from)
    }

    /// Get the packet commitment
    fn packet_commitment(
        &self,
        port_id: &PortId,
        channel_id: &ChannelId,
        sequence: Sequence,
    ) -> Result<PacketCommitment> {
        let key = storage::commitment_key(port_id, channel_id, sequence);
        match self.storage().read_bytes(&key)? {
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
        self.storage_mut()
            .write_bytes(&key, bytes)
            .map_err(ContextError::from)
    }

    /// Delete the packet commitment
    fn delete_packet_commitment(
        &mut self,
        port_id: &PortId,
        channel_id: &ChannelId,
        sequence: Sequence,
    ) -> Result<()> {
        let key = storage::commitment_key(port_id, channel_id, sequence);
        self.storage_mut().delete(&key).map_err(ContextError::from)
    }

    /// Get the packet receipt
    fn packet_receipt(
        &self,
        port_id: &PortId,
        channel_id: &ChannelId,
        sequence: Sequence,
    ) -> Result<Receipt> {
        let key = storage::receipt_key(port_id, channel_id, sequence);
        match self.storage().read_bytes(&key)? {
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
        self.storage_mut()
            .write_bytes(&key, bytes)
            .map_err(ContextError::from)
    }

    /// Get the packet acknowledgement
    fn packet_ack(
        &self,
        port_id: &PortId,
        channel_id: &ChannelId,
        sequence: Sequence,
    ) -> Result<AcknowledgementCommitment> {
        let key = storage::ack_key(port_id, channel_id, sequence);
        match self.storage().read_bytes(&key)? {
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
        self.storage_mut()
            .write_bytes(&key, bytes)
            .map_err(ContextError::from)
    }

    /// Delete the packet acknowledgement
    fn delete_packet_ack(
        &mut self,
        port_id: &PortId,
        channel_id: &ChannelId,
        sequence: Sequence,
    ) -> Result<()> {
        let key = storage::ack_key(port_id, channel_id, sequence);
        self.storage_mut().delete(&key).map_err(ContextError::from)
    }

    /// Read a counter
    fn read_counter(&self, key: &Key) -> Result<u64> {
        match self.storage().read::<u64>(key)? {
            Some(counter) => Ok(counter),
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
        self.storage_mut()
            .write(key, count)
            .map_err(ContextError::from)
    }

    /// Write the IBC trace. The given address could be a non-Namada token.
    fn store_ibc_trace(
        &mut self,
        addr: impl AsRef<str>,
        trace_hash: impl AsRef<str>,
        trace: impl AsRef<str>,
    ) -> Result<()> {
        let key = storage::ibc_trace_key(addr, trace_hash.as_ref());
        let has_key =
            self.storage()
                .has_key(&key)
                .map_err(|_| ChannelError::Other {
                    description: format!(
                        "Reading the IBC trace failed: Key {key}"
                    ),
                })?;
        if !has_key {
            self.storage_mut().write(&key, trace.as_ref()).map_err(|_| {
                ChannelError::Other {
                    description: format!(
                        "Writing the trace failed: Key {key}",
                    ),
                }
            })?;
        }
        Ok(())
    }

    /// Get the NFT class
    fn nft_class(
        &self,
        class_id: &PrefixedClassId,
    ) -> Result<Option<NftClass>> {
        let key = storage::nft_class_key(class_id);
        self.storage().read(&key).map_err(ContextError::from)
    }

    /// Store the NFT class
    fn store_nft_class(&mut self, class: NftClass) -> Result<()> {
        let key = storage::nft_class_key(&class.class_id);
        self.storage_mut()
            .write(&key, class)
            .map_err(ContextError::from)
    }

    /// Get the NFT metadata
    fn nft_metadata(
        &self,
        class_id: &PrefixedClassId,
        token_id: &TokenId,
    ) -> Result<Option<NftMetadata>> {
        let key = storage::nft_metadata_key(class_id, token_id);
        self.storage().read(&key).map_err(ContextError::from)
    }

    /// Store the NFT metadata
    fn store_nft_metadata(&mut self, metadata: NftMetadata) -> Result<()> {
        let key =
            storage::nft_metadata_key(&metadata.class_id, &metadata.token_id);
        self.storage_mut()
            .write(&key, metadata)
            .map_err(ContextError::from)
    }

    /// Return true if the NFT is owned by the owner
    fn is_nft_owned(
        &self,
        class_id: &PrefixedClassId,
        token_id: &TokenId,
        owner: &Address,
    ) -> Result<bool> {
        let ibc_token = trace::ibc_token_for_nft(class_id, token_id);
        let balance_key = balance_key(&ibc_token, owner);
        let amount = self.storage().read::<Amount>(&balance_key)?;
        Ok(amount == Some(Amount::from_u64(1)))
    }

    /// Read the mint amount of the given token
    fn mint_amount(&self, token: &Address) -> Result<Amount> {
        let key = storage::mint_amount_key(token);
        Ok(self.storage().read::<Amount>(&key)?.unwrap_or_default())
    }

    /// Write the mint amount of the given token
    fn store_mint_amount(
        &mut self,
        token: &Address,
        amount: Amount,
    ) -> Result<()> {
        let key = storage::mint_amount_key(token);
        self.storage_mut()
            .write(&key, amount)
            .map_err(ContextError::from)
    }

    /// Read the per-epoch deposit of the given token
    fn deposit(&self, token: &Address) -> Result<Amount> {
        let key = storage::deposit_key(token);
        Ok(self.storage().read::<Amount>(&key)?.unwrap_or_default())
    }

    /// Write the per-epoch deposit of the given token
    fn store_deposit(&mut self, token: &Address, amount: Amount) -> Result<()> {
        let key = storage::deposit_key(token);
        self.storage_mut()
            .write(&key, amount)
            .map_err(ContextError::from)
    }

    /// Read the per-epoch withdraw of the given token
    fn withdraw(&self, token: &Address) -> Result<Amount> {
        let key = storage::withdraw_key(token);
        Ok(self.storage().read::<Amount>(&key)?.unwrap_or_default())
    }

    /// Write the per-epoch withdraw of the given token
    fn store_withdraw(
        &mut self,
        token: &Address,
        amount: Amount,
    ) -> Result<()> {
        let key = storage::withdraw_key(token);
        self.storage_mut()
            .write(&key, amount)
            .map_err(ContextError::from)
    }
}

/// Read and decode the IBC sequence
pub fn read_sequence<S: StorageRead + ?Sized>(
    storage: &S,
    key: &Key,
) -> std::result::Result<Sequence, StorageError> {
    match storage.read_bytes(key)? {
        Some(value) => {
            let value: [u8; 8] = value.try_into().map_err(|_| {
                StorageError::new_alloc(format!(
                    "The sequence value wasn't u64: Key {key}",
                ))
            })?;
            Ok(u64::from_be_bytes(value).into())
        }
        // when the sequence has never been used, returns the initial value
        None => Ok(1.into()),
    }
}
