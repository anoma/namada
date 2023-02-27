//! ValidationContext implementation for IBC

use core::str::FromStr;

use prost::Message;
use sha2::Digest;

use super::super::{IbcActions, IbcStorageContext};
use crate::ibc::clients::ics07_tendermint::client_state::ClientState as TmClientState;
use crate::ibc::clients::ics07_tendermint::consensus_state::ConsensusState as TmConsensusState;
use crate::ibc::core::ics02_client::client_state::{
    downcast_client_state, ClientState,
};
use crate::ibc::core::ics02_client::consensus_state::ConsensusState;
use crate::ibc::core::ics02_client::error::ClientError;
use crate::ibc::core::ics02_client::trust_threshold::TrustThreshold;
use crate::ibc::core::ics03_connection::connection::ConnectionEnd;
use crate::ibc::core::ics03_connection::error::ConnectionError;
use crate::ibc::core::ics04_channel::channel::ChannelEnd;
use crate::ibc::core::ics04_channel::commitment::{
    AcknowledgementCommitment, PacketCommitment,
};
use crate::ibc::core::ics04_channel::error::{ChannelError, PacketError};
use crate::ibc::core::ics04_channel::packet::{Receipt, Sequence};
use crate::ibc::core::ics23_commitment::commitment::CommitmentPrefix;
use crate::ibc::core::ics24_host::identifier::{
    ChannelId, ClientId, ConnectionId, PortId,
};
use crate::ibc::core::ics24_host::path::{
    AckPath, ChannelEndPath, ClientConsensusStatePath, CommitmentPath, Path,
    ReceiptPath, SeqAckPath, SeqRecvPath, SeqSendPath,
};
use crate::ibc::core::{ContextError, ValidationContext};
#[cfg(any(feature = "ibc-mocks-abcipp", feature = "ibc-mocks"))]
use crate::ibc::mock::client_state::MockClientState;
#[cfg(any(feature = "ibc-mocks-abcipp", feature = "ibc-mocks"))]
use crate::ibc::mock::consensus_state::MockConsensusState;
use crate::ibc::timestamp::Timestamp;
use crate::ibc::Height;
use crate::ibc_proto::google::protobuf::Any;
use crate::ibc_proto::protobuf::Protobuf;
use crate::ledger::ibc::storage;
use crate::ledger::parameters::storage::get_max_expected_time_per_block_key;
use crate::tendermint::Time as TmTime;
use crate::tendermint_proto::Protobuf as TmProtobuf;
use crate::types::storage::{BlockHeight, Key};
use crate::types::time::DurationSecs;

const COMMITMENT_PREFIX: &[u8] = b"ibc";

impl<C> ValidationContext for IbcActions<C>
where
    C: IbcStorageContext,
{
    fn client_state(
        &self,
        client_id: &ClientId,
    ) -> Result<Box<dyn ClientState>, ContextError> {
        let key = storage::client_state_key(&client_id);
        match self.ctx.read(&key) {
            Ok(Some(value)) => {
                let any = Any::decode(&value[..]).map_err(|e| {
                    ContextError::ClientError(ClientError::Decode(e))
                })?;
                self.decode_client_state(any)
            }
            Ok(None) => {
                Err(ContextError::ClientError(ClientError::ClientNotFound {
                    client_id: client_id.clone(),
                }))
            }
            Err(_) => Err(ContextError::ClientError(ClientError::Other {
                description: format!(
                    "Reading the client state failed: ID {}",
                    client_id,
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
        client_cons_state_path: &ClientConsensusStatePath,
    ) -> Result<Box<dyn ConsensusState>, ContextError> {
        let path = Path::ClientConsensusState(client_cons_state_path.clone());
        let key = storage::ibc_key(path.to_string())
            .expect("Creating a key for the client state shouldn't fail");
        match self.ctx.read(&key) {
            Ok(Some(value)) => {
                let any = Any::decode(&value[..]).map_err(|e| {
                    ContextError::ClientError(ClientError::Decode(e))
                })?;
                decode_consensus_state(any)
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

    fn next_consensus_state(
        &self,
        client_id: &ClientId,
        height: &Height,
    ) -> Result<Option<Box<dyn ConsensusState>>, ContextError> {
        let prefix = storage::consensus_state_prefix(client_id);
        let mut iter = self.ctx.iter_prefix(&prefix).map_err(|_| {
            ContextError::ClientError(ClientError::Other {
                description: format!(
                    "Reading the consensus state failed: ID {}, height {}",
                    client_id, height,
                ),
            })
        })?;
        let mut lowest_height_value = None;
        while let Some((key, value)) =
            self.ctx.iter_next(&mut iter).map_err(|_| {
                ContextError::ClientError(ClientError::Other {
                    description: format!(
                        "Iterating consensus states failed: ID {}, height {}",
                        client_id, height,
                    ),
                })
            })?
        {
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
        match lowest_height_value {
            Some((_, value)) => {
                let any = Any::decode(&value[..]).map_err(|e| {
                    ContextError::ClientError(ClientError::Decode(e))
                })?;
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
        let mut iter = self.ctx.iter_prefix(&prefix).map_err(|_| {
            ContextError::ClientError(ClientError::Other {
                description: format!(
                    "Reading the consensus state failed: ID {}, height {}",
                    client_id, height,
                ),
            })
        })?;
        let mut highest_height_value = None;
        while let Some((key, value)) =
            self.ctx.iter_next(&mut iter).map_err(|_| {
                ContextError::ClientError(ClientError::Other {
                    description: format!(
                        "Iterating consensus states failed: ID {}, height {}",
                        client_id, height,
                    ),
                })
            })?
        {
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
        match highest_height_value {
            Some((_, value)) => {
                let any = Any::decode(&value[..]).map_err(|e| {
                    ContextError::ClientError(ClientError::Decode(e))
                })?;
                let cs = decode_consensus_state(any)?;
                Ok(Some(cs))
            }
            None => Ok(None),
        }
    }

    fn host_height(&self) -> Result<Height, ContextError> {
        let height = self.ctx.get_height().map_err(|_| {
            ContextError::ClientError(ClientError::Other {
                description: "Getting the host height failed".to_string(),
            })
        })?;
        // the revision number is always 0
        Height::new(0, height.0).map_err(ContextError::ClientError)
    }

    fn host_timestamp(&self) -> Result<Timestamp, ContextError> {
        let height = self.host_height()?;
        let height = BlockHeight(height.revision_height());
        let header = self.ctx.get_header(height).map_err(|_| {
            ContextError::ClientError(ClientError::Other {
                description: "Getting the host header failed".to_string(),
            })
        })?;
        let time = TmTime::try_from(header.time).map_err(|_| {
            ContextError::ClientError(ClientError::Other {
                description: "Converting to Tenderming time failed".to_string(),
            })
        })?;
        Ok(time.into())
    }

    fn host_consensus_state(
        &self,
        height: &Height,
    ) -> Result<Box<dyn ConsensusState>, ContextError> {
        let height = BlockHeight(height.revision_height());
        let header = self.ctx.get_header(height).map_err(|_| {
            ContextError::ClientError(ClientError::Other {
                description: format!(
                    "Getting the header on this chain failed: Height {}",
                    height
                ),
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

    fn client_counter(&self) -> Result<u64, ContextError> {
        let key = storage::client_counter_key();
        self.read_counter(&key)
    }

    /// Returns the ConnectionEnd for the given identifier `conn_id`.
    fn connection_end(
        &self,
        connection_id: &ConnectionId,
    ) -> Result<ConnectionEnd, ContextError> {
        let key = storage::connection_key(&connection_id);
        match self.ctx.read(&key) {
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

    fn validate_self_client(
        &self,
        counterparty_client_state: Any,
    ) -> Result<(), ConnectionError> {
        // TODO: should return ContextError
        let client_state = self
            .decode_client_state(counterparty_client_state)
            .map_err(|_| ConnectionError::Other {
                description: "Decoding the client state failed".to_string(),
            })?;
        let client_state =
            downcast_client_state::<TmClientState>(client_state.as_ref())
                .ok_or_else(|| ConnectionError::Other {
                    description: "The client state is not for Tendermint"
                        .to_string(),
                })?;

        if client_state.is_frozen() {
            return Err(ConnectionError::Other {
                description: "The client is frozen".to_string(),
            });
        }

        let chain_id =
            self.ctx
                .get_chain_id()
                .map_err(|_| ConnectionError::Other {
                    description: "Getting the chain ID failed".to_string(),
                })?;
        if client_state.chain_id().to_string() != chain_id.to_string() {
            return Err(ConnectionError::Other {
                description: format!(
                    "The chain ID mismatched: in the client state {}",
                    client_state.chain_id()
                ),
            });
        }

        if client_state.chain_id().version() != 0 {
            return Err(ConnectionError::Other {
                description: format!(
                    "The chain ID revision is not zero: {}",
                    client_state.chain_id()
                ),
            });
        }

        let height =
            self.ctx.get_height().map_err(|_| ConnectionError::Other {
                description: "Getting the block height failed".to_string(),
            })?;
        if client_state.latest_height().revision_height() >= height.0 {
            return Err(ConnectionError::Other {
                description: format!(
                    "The height of the client state is higher: Client state \
                     height {}",
                    client_state.latest_height()
                ),
            });
        }

        // proof spec
        let proof_specs = self.ctx.get_proof_specs();
        if client_state.proof_specs != proof_specs.into() {
            return Err(ConnectionError::Other {
                description: "The proof specs mismatched".to_string(),
            });
        }

        let trust_level = client_state.trust_level.numerator()
            / client_state.trust_level.denominator();
        let min_level = TrustThreshold::ONE_THIRD;
        let min_level = min_level.numerator() / min_level.denominator();
        if trust_level < min_level {
            return Err(ConnectionError::Other {
                description: "The trust threshold is less 1/3".to_string(),
            });
        }

        Ok(())
    }

    fn commitment_prefix(&self) -> CommitmentPrefix {
        CommitmentPrefix::try_from(COMMITMENT_PREFIX.to_vec())
            .expect("the prefix should be parsable")
    }

    fn connection_counter(&self) -> Result<u64, ContextError> {
        let key = storage::connection_counter_key();
        self.read_counter(&key)
    }

    fn channel_end(
        &self,
        channel_end_path: &ChannelEndPath,
    ) -> Result<ChannelEnd, ContextError> {
        let path = Path::ChannelEnd(channel_end_path.clone());
        let key = storage::ibc_key(path.to_string())
            .expect("Creating a key for the client state shouldn't fail");
        match self.ctx.read(&key) {
            Ok(Some(value)) => ChannelEnd::decode_vec(&value).map_err(|_| {
                ContextError::ChannelError(ChannelError::Other {
                    description: format!(
                        "Decoding the channel end failed: Key {}",
                        key,
                    ),
                })
            }),
            Ok(None) => {
                let port_channel_id =
                    storage::port_channel_id(&key).expect("invalid key");
                Err(ContextError::ChannelError(ChannelError::ChannelNotFound {
                    channel_id: port_channel_id.channel_id,
                    port_id: port_channel_id.port_id,
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

    fn connection_channels(
        &self,
        conn_id: &ConnectionId,
    ) -> Result<Vec<(PortId, ChannelId)>, ContextError> {
        let key = storage::connection_channels_key(conn_id);
        match self.ctx.read(&key) {
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
                parse_port_channel_list(list)
            }
            Ok(None) => Ok(Vec::new()),
            Err(_) => {
                Err(ContextError::ConnectionError(ConnectionError::Other {
                    description: format!(
                        "Reading the port/channel list failed: Connection ID \
                         {},",
                        conn_id,
                    ),
                }))
            }
        }
    }

    fn get_next_sequence_send(
        &self,
        path: &SeqSendPath,
    ) -> Result<Sequence, ContextError> {
        let path = Path::SeqSend(path.clone());
        let key = storage::ibc_key(path.to_string())
            .expect("Creating a key for the client state shouldn't fail");
        self.read_sequence(&key)
    }

    fn get_next_sequence_recv(
        &self,
        path: &SeqRecvPath,
    ) -> Result<Sequence, ContextError> {
        let path = Path::SeqRecv(path.clone());
        let key = storage::ibc_key(path.to_string())
            .expect("Creating a key for the client state shouldn't fail");
        self.read_sequence(&key)
    }

    fn get_next_sequence_ack(
        &self,
        path: &SeqAckPath,
    ) -> Result<Sequence, ContextError> {
        let path = Path::SeqAck(path.clone());
        let key = storage::ibc_key(path.to_string())
            .expect("Creating a key for the client state shouldn't fail");
        self.read_sequence(&key)
    }

    fn get_packet_commitment(
        &self,
        path: &CommitmentPath,
    ) -> Result<PacketCommitment, ContextError> {
        let path = Path::Commitment(path.clone());
        let key = storage::ibc_key(path.to_string())
            .expect("Creating a key for the client state shouldn't fail");
        match self.ctx.read(&key) {
            Ok(Some(value)) => Ok(value.into()),
            Ok(None) => {
                let port_channel_sequence_id =
                    storage::port_channel_sequence_id(&key)
                        .expect("invalid key");
                Err(ContextError::PacketError(
                    PacketError::PacketCommitmentNotFound {
                        sequence: port_channel_sequence_id.2,
                    },
                ))
            }
            Err(_) => Err(ContextError::PacketError(PacketError::Channel(
                ChannelError::Other {
                    description: format!(
                        "Reading commitment failed: Key {}",
                        key,
                    ),
                },
            ))),
        }
    }

    fn get_packet_receipt(
        &self,
        path: &ReceiptPath,
    ) -> Result<Receipt, ContextError> {
        let path = Path::Receipt(path.clone());
        let key = storage::ibc_key(path.to_string())
            .expect("Creating a key for the client state shouldn't fail");
        match self.ctx.read(&key) {
            Ok(Some(_)) => Ok(Receipt::Ok),
            Ok(None) => {
                let port_channel_sequence_id =
                    storage::port_channel_sequence_id(&key)
                        .expect("invalid key");
                Err(ContextError::PacketError(
                    PacketError::PacketReceiptNotFound {
                        sequence: port_channel_sequence_id.2,
                    },
                ))
            }
            Err(_) => Err(ContextError::PacketError(PacketError::Channel(
                ChannelError::Other {
                    description: format!(
                        "Reading the receipt failed: Key {}",
                        key,
                    ),
                },
            ))),
        }
    }

    fn get_packet_acknowledgement(
        &self,
        path: &AckPath,
    ) -> Result<AcknowledgementCommitment, ContextError> {
        let path = Path::Ack(path.clone());
        let key = storage::ibc_key(path.to_string())
            .expect("Creating a key for the client state shouldn't fail");
        match self.ctx.read(&key) {
            Ok(Some(value)) => Ok(value.into()),
            Ok(None) => {
                let port_channel_sequence_id =
                    storage::port_channel_sequence_id(&key)
                        .expect("invalid key");
                Err(ContextError::PacketError(
                    PacketError::PacketAcknowledgementNotFound {
                        sequence: port_channel_sequence_id.2,
                    },
                ))
            }
            Err(_) => Err(ContextError::PacketError(PacketError::Channel(
                ChannelError::Other {
                    description: format!(
                        "Reading the ack commitment failed: Key {}",
                        key
                    ),
                },
            ))),
        }
    }

    fn hash(&self, value: &[u8]) -> Vec<u8> {
        sha2::Sha256::digest(&value).to_vec()
    }

    fn client_update_time(
        &self,
        client_id: &ClientId,
        _height: &Height,
    ) -> Result<Timestamp, ContextError> {
        let key = storage::client_update_timestamp_key(client_id);
        match self.ctx.read(&key) {
            Ok(Some(value)) => {
                let time = TmTime::decode_vec(&value).map_err(|_| {
                    ContextError::ClientError(ClientError::Other {
                        description: format!(
                            "Decoding the client update time failed: ID {}",
                            client_id
                        ),
                    })
                })?;
                Ok(time.into())
            }
            Ok(None) => {
                Err(ContextError::ClientError(ClientError::ClientSpecific {
                    description: format!(
                        "The client update time doesn't exist: ID {}",
                        client_id
                    ),
                }))
            }
            Err(_) => Err(ContextError::ClientError(ClientError::Other {
                description: format!(
                    "Reading the client update time failed: ID {}",
                    client_id,
                ),
            })),
        }
    }

    fn client_update_height(
        &self,
        client_id: &ClientId,
        _height: &Height,
    ) -> Result<Height, ContextError> {
        let key = storage::client_update_height_key(client_id);
        match self.ctx.read(&key) {
            Ok(Some(value)) => Height::decode_vec(&value).map_err(|e| {
                ContextError::ClientError(ClientError::Other {
                    description: format!(
                        "Decoding the height failed: Key {}, error {}",
                        key, e
                    ),
                })
            }),
            Ok(None) => {
                Err(ContextError::ClientError(ClientError::ClientSpecific {
                    description: format!(
                        "The client update height doesn't exist: ID {}",
                        client_id
                    ),
                }))
            }
            Err(_) => Err(ContextError::ClientError(ClientError::Other {
                description: format!(
                    "Reading the client update height failed: ID {}",
                    client_id,
                ),
            })),
        }
    }

    fn channel_counter(&self) -> Result<u64, ContextError> {
        let key = storage::channel_counter_key();
        self.read_counter(&key)
    }

    fn max_expected_time_per_block(&self) -> core::time::Duration {
        let key = get_max_expected_time_per_block_key();
        match self.ctx.read(&key) {
            Ok(Some(value)) => {
                crate::ledger::storage::types::decode::<DurationSecs>(&value)
                    .expect("Decoding max_expected_time_per_block failed")
                    .into()
            }
            _ => unreachable!("The parameter should be initialized"),
        }
    }
}

/// Helper functions
impl<C> IbcActions<C>
where
    C: IbcStorageContext,
{
    /// Read a counter
    pub fn read_counter(&self, key: &Key) -> Result<u64, ContextError> {
        match self.ctx.read(&key) {
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
    pub fn read_sequence(&self, key: &Key) -> Result<Sequence, ContextError> {
        match self.ctx.read(&key) {
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
                let sequence = storage::port_channel_sequence_id(&key)
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
}

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

/// Parse a port/channel list, e.g. "my-port/channel-0,my-port/channel-1"
fn parse_port_channel_list(
    list: impl AsRef<str>,
) -> Result<Vec<(PortId, ChannelId)>, ContextError> {
    let mut port_channel_list = Vec::new();
    for pair in list.as_ref().split(',') {
        let mut port_channel = pair.split('/');
        let port_id_str = port_channel.next().ok_or_else(|| {
            ContextError::ConnectionError(ConnectionError::Other {
                description: format!("No port ID in the entry: {}", pair),
            })
        })?;
        let port_id = PortId::from_str(port_id_str).map_err(|_| {
            ContextError::ConnectionError(ConnectionError::Other {
                description: format!(
                    "Parsing the port ID failed: {}",
                    port_id_str
                ),
            })
        })?;
        let channel_id_str = port_channel.next().ok_or_else(|| {
            ContextError::ConnectionError(ConnectionError::Other {
                description: format!("No channel ID in the entry: {}", pair),
            })
        })?;
        let channel_id = ChannelId::from_str(channel_id_str).map_err(|_| {
            ContextError::ConnectionError(ConnectionError::Other {
                description: format!(
                    "Parsing the channel ID failed: {}",
                    channel_id_str
                ),
            })
        })?;
        if port_channel.next().is_some() {
            return Err(ContextError::ConnectionError(
                ConnectionError::Other {
                    description: format!(
                        "The port/channel pair has an unexpected entry: {}",
                        pair
                    ),
                },
            ));
        }
        port_channel_list.push((port_id, channel_id));
    }
    Ok(port_channel_list)
}
