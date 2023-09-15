//! IbcCommonContext implementation for IBC

use borsh::BorshDeserialize;
use borsh_ext::BorshSerializeExt;
use prost::Message;
use sha2::Digest;

use super::storage::IbcStorageContext;
use crate::ibc::clients::ics07_tendermint::client_state::ClientState as TmClientState;
use crate::ibc::clients::ics07_tendermint::consensus_state::ConsensusState as TmConsensusState;
use crate::ibc::core::ics02_client::client_state::ClientState;
use crate::ibc::core::ics02_client::consensus_state::ConsensusState;
use crate::ibc::core::ics02_client::error::ClientError;
use crate::ibc::core::ics03_connection::connection::ConnectionEnd;
use crate::ibc::core::ics03_connection::error::ConnectionError;
use crate::ibc::core::ics04_channel::channel::ChannelEnd;
use crate::ibc::core::ics04_channel::commitment::PacketCommitment;
use crate::ibc::core::ics04_channel::error::{ChannelError, PacketError};
use crate::ibc::core::ics04_channel::packet::Sequence;
use crate::ibc::core::ics04_channel::timeout::TimeoutHeight;
use crate::ibc::core::ics24_host::identifier::{ClientId, ConnectionId};
use crate::ibc::core::ics24_host::path::{
    ChannelEndPath, ClientConsensusStatePath, CommitmentPath, Path, SeqSendPath,
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
use crate::types::address::Address;
use crate::types::storage::Key;
use crate::types::token;

/// Context to handle typical IBC data
pub trait IbcCommonContext: IbcStorageContext {
    /// Get the ClientState
    fn client_state(
        &self,
        client_id: &ClientId,
    ) -> Result<Box<dyn ClientState>, ContextError> {
        let key = storage::client_state_key(client_id);
        match self.read(&key) {
            Ok(Some(value)) => {
                let any = Any::decode(&value[..]).map_err(|e| {
                    ContextError::ClientError(ClientError::Decode(e))
                })?;
                self.decode_client_state(any)
            }
            Ok(None) => Err(ContextError::ClientError(
                ClientError::ClientStateNotFound {
                    client_id: client_id.clone(),
                },
            )),
            Err(_) => Err(ContextError::ClientError(ClientError::Other {
                description: format!(
                    "Reading the client state failed: ID {}",
                    client_id,
                ),
            })),
        }
    }

    /// Get the ConsensusState
    fn consensus_state(
        &self,
        client_cons_state_path: &ClientConsensusStatePath,
    ) -> Result<Box<dyn ConsensusState>, ContextError> {
        let path = Path::ClientConsensusState(client_cons_state_path.clone());
        let key = storage::ibc_key(path.to_string())
            .expect("Creating a key for the client state shouldn't fail");
        match self.read(&key) {
            Ok(Some(value)) => {
                let any = Any::decode(&value[..]).map_err(|e| {
                    ContextError::ClientError(ClientError::Decode(e))
                })?;
                self.decode_consensus_state(any)
            }
            Ok(None) => {
                let client_id = storage::client_id(&key).expect("invalid key");
                let height =
                    storage::consensus_height(&key).expect("invalid key");
                Err(ContextError::ClientError(
                    ClientError::ConsensusStateNotFound { client_id, height },
                ))
            }
            Err(_) => Err(ContextError::ClientError(ClientError::Other {
                description: format!(
                    "Reading the consensus state failed: Key {}",
                    key,
                ),
            })),
        }
    }

    /// Get the ConnectionEnd
    fn connection_end(
        &self,
        connection_id: &ConnectionId,
    ) -> Result<ConnectionEnd, ContextError> {
        let key = storage::connection_key(connection_id);
        match self.read(&key) {
            Ok(Some(value)) => {
                ConnectionEnd::decode_vec(&value).map_err(|_| {
                    ContextError::ConnectionError(ConnectionError::Other {
                        description: format!(
                            "Decoding the connection end failed: ID {}",
                            connection_id,
                        ),
                    })
                })
            }
            Ok(None) => Err(ContextError::ConnectionError(
                ConnectionError::ConnectionNotFound {
                    connection_id: connection_id.clone(),
                },
            )),
            Err(_) => {
                Err(ContextError::ConnectionError(ConnectionError::Other {
                    description: format!(
                        "Reading the connection end failed: ID {}",
                        connection_id,
                    ),
                }))
            }
        }
    }

    /// Get the ChannelEnd
    fn channel_end(
        &self,
        channel_end_path: &ChannelEndPath,
    ) -> Result<ChannelEnd, ContextError> {
        let path = Path::ChannelEnd(channel_end_path.clone());
        let key = storage::ibc_key(path.to_string())
            .expect("Creating a key for the client state shouldn't fail");
        match self.read(&key) {
            Ok(Some(value)) => ChannelEnd::decode_vec(&value).map_err(|_| {
                ContextError::ChannelError(ChannelError::Other {
                    description: format!(
                        "Decoding the channel end failed: Key {}",
                        key,
                    ),
                })
            }),
            Ok(None) => {
                let (port_id, channel_id) =
                    storage::port_channel_id(&key).expect("invalid key");
                Err(ContextError::ChannelError(ChannelError::ChannelNotFound {
                    channel_id,
                    port_id,
                }))
            }
            Err(_) => Err(ContextError::ChannelError(ChannelError::Other {
                description: format!(
                    "Reading the channel end failed: Key {}",
                    key,
                ),
            })),
        }
    }

    /// Get the NextSequenceSend
    fn get_next_sequence_send(
        &self,
        path: &SeqSendPath,
    ) -> Result<Sequence, ContextError> {
        let path = Path::SeqSend(path.clone());
        let key = storage::ibc_key(path.to_string())
            .expect("Creating a key for the client state shouldn't fail");
        self.read_sequence(&key)
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

    /// Decode ClientState from Any
    fn decode_client_state(
        &self,
        client_state: Any,
    ) -> Result<Box<dyn ClientState>, ContextError> {
        #[cfg(any(feature = "ibc-mocks-abcipp", feature = "ibc-mocks"))]
        if let Ok(cs) = MockClientState::try_from(client_state.clone()) {
            return Ok(cs.into_box());
        }

        if let Ok(cs) = TmClientState::try_from(client_state) {
            return Ok(cs.into_box());
        }

        Err(ContextError::ClientError(ClientError::ClientSpecific {
            description: "Unknown client state".to_string(),
        }))
    }

    /// Decode ConsensusState from Any
    fn decode_consensus_state(
        &self,
        consensus_state: Any,
    ) -> Result<Box<dyn ConsensusState>, ContextError> {
        #[cfg(any(feature = "ibc-mocks-abcipp", feature = "ibc-mocks"))]
        if let Ok(cs) = MockConsensusState::try_from(consensus_state.clone()) {
            return Ok(cs.into_box());
        }

        if let Ok(cs) = TmConsensusState::try_from(consensus_state) {
            return Ok(cs.into_box());
        }

        Err(ContextError::ClientError(ClientError::ClientSpecific {
            description: "Unknown consensus state".to_string(),
        }))
    }

    /// Read a counter
    fn read_counter(&self, key: &Key) -> Result<u64, ContextError> {
        match self.read(key) {
            Ok(Some(value)) => {
                let value: [u8; 8] = value.try_into().map_err(|_| {
                    ContextError::ClientError(ClientError::Other {
                        description: format!(
                            "The counter value wasn't u64: Key {}",
                            key
                        ),
                    })
                })?;
                Ok(u64::from_be_bytes(value))
            }
            Ok(None) => unreachable!("the counter should be initialized"),
            Err(_) => Err(ContextError::ClientError(ClientError::Other {
                description: format!("Reading the counter failed: Key {}", key),
            })),
        }
    }

    /// Read a sequence
    fn read_sequence(&self, key: &Key) -> Result<Sequence, ContextError> {
        match self.read(key) {
            Ok(Some(value)) => {
                let value: [u8; 8] = value.try_into().map_err(|_| {
                    ContextError::ChannelError(ChannelError::Other {
                        description: format!(
                            "The counter value wasn't u64: Key {}",
                            key
                        ),
                    })
                })?;
                Ok(u64::from_be_bytes(value).into())
            }
            // when the sequence has never been used, returns the initial value
            Ok(None) => Ok(1.into()),
            Err(_) => {
                let sequence = storage::port_channel_sequence_id(key)
                    .expect("The key should have sequence")
                    .2;
                Err(ContextError::ChannelError(ChannelError::Other {
                    description: format!(
                        "Reading the next sequence send failed: Sequence {}",
                        sequence
                    ),
                }))
            }
        }
    }

    /// Write the packet commitment
    fn store_packet_commitment(
        &mut self,
        path: &CommitmentPath,
        commitment: PacketCommitment,
    ) -> Result<(), ContextError> {
        let path = Path::Commitment(path.clone());
        let key = storage::ibc_key(path.to_string())
            .expect("Creating a key for the client state shouldn't fail");
        let bytes = commitment.into_vec();
        self.write(&key, bytes).map_err(|_| {
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

    /// Write the NextSequenceSend
    fn store_next_sequence_send(
        &mut self,
        path: &SeqSendPath,
        seq: Sequence,
    ) -> Result<(), ContextError> {
        let path = Path::SeqSend(path.clone());
        let key = storage::ibc_key(path.to_string())
            .expect("Creating a key for the client state shouldn't fail");
        self.store_sequence(&key, seq)
    }

    /// Increment and write the counter
    fn increase_counter(&mut self, key: &Key) -> Result<(), ContextError> {
        let count = self.read_counter(key)?;
        self.write(key, (count + 1).to_be_bytes().to_vec())
            .map_err(|_| {
                ContextError::ClientError(ClientError::Other {
                    description: format!(
                        "Writing the counter failed: Key {}",
                        key
                    ),
                })
            })
    }

    /// Write the sequence
    fn store_sequence(
        &mut self,
        key: &Key,
        sequence: Sequence,
    ) -> Result<(), ContextError> {
        self.write(key, u64::from(sequence).to_be_bytes().to_vec())
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

    /// Write the IBC denom
    fn store_ibc_denom(
        &mut self,
        trace_hash: impl AsRef<str>,
        denom: impl AsRef<str>,
    ) -> Result<(), ContextError> {
        let key = storage::ibc_denom_key(trace_hash.as_ref());
        let has_key = self.has_key(&key).map_err(|_| {
            ContextError::ChannelError(ChannelError::Other {
                description: format!(
                    "Reading the IBC denom failed: Key {}",
                    key
                ),
            })
        })?;
        if !has_key {
            let bytes = denom.as_ref().serialize_to_vec();
            self.write(&key, bytes).map_err(|_| {
                ContextError::ChannelError(ChannelError::Other {
                    description: format!(
                        "Writing the denom failed: Key {}",
                        key
                    ),
                })
            })?;
        }
        Ok(())
    }

    /// Read the token denom
    fn read_token_denom(
        &self,
        token: &Address,
    ) -> Result<Option<token::Denomination>, ContextError> {
        let key = token::denom_key(token);
        let bytes = self.read(&key).map_err(|_| {
            ContextError::ChannelError(ChannelError::Other {
                description: format!(
                    "Reading the token denom failed: Key {}",
                    key
                ),
            })
        })?;
        bytes
            .map(|b| token::Denomination::try_from_slice(&b))
            .transpose()
            .map_err(|_| {
                ContextError::ChannelError(ChannelError::Other {
                    description: format!(
                        "Decoding the token denom failed: Token {}",
                        token
                    ),
                })
            })
    }

    /// Write the IBC denom
    fn store_token_denom(
        &mut self,
        token: &Address,
    ) -> Result<(), ContextError> {
        let key = token::denom_key(token);
        let has_key = self.has_key(&key).map_err(|_| {
            ContextError::ChannelError(ChannelError::Other {
                description: format!(
                    "Reading the token denom failed: Key {}",
                    key
                ),
            })
        })?;
        if !has_key {
            // IBC denomination should be zero for U256
            let denom = token::Denomination::from(0);
            let bytes = denom.serialize_to_vec();
            self.write(&key, bytes).map_err(|_| {
                ContextError::ChannelError(ChannelError::Other {
                    description: format!(
                        "Writing the token denom failed: Key {}",
                        key
                    ),
                })
            })?;
        }
        Ok(())
    }
}
