//! ValidationContext implementation for IBC

use prost::Message;
use sha2::Digest;

use super::{decode_consensus_state, IbcActions, IbcStorageContext};
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
    ChannelId, ClientId, ConnectionId, PortChannelId, PortId,
};
use crate::ibc::core::{ContextError, ValidationContext};
#[cfg(any(feature = "ibc-mocks-abcipp", feature = "ibc-mocks"))]
use crate::ibc::mock::client_state::MockClientState;
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
        client_id: &ClientId,
        height: &Height,
    ) -> Result<Box<dyn ConsensusState>, ContextError> {
        let key = storage::consensus_state_key(client_id, height.clone());
        match self.ctx.read(&key) {
            Ok(Some(value)) => {
                let any = Any::decode(&value[..]).map_err(|e| {
                    ContextError::ClientError(ClientError::Decode(e))
                })?;
                decode_consensus_state(any)
            }
            Ok(None) => Err(ContextError::ClientError(
                ClientError::ConsensusStateNotFound {
                    client_id: *client_id,
                    height: *height,
                },
            )),
            Err(_) => Err(ContextError::ClientError(ClientError::Other {
                description: format!(
                    "Reading the consensus state failed: ID {}",
                    client_id,
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
            self.ctx.iter_next(&mut iter).map_err(|e| {
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
                description: format!("Getting the host height failed",),
            })
        })?;
        // the revision number is always 0
        Height::new(0, height.0).map_err(ContextError::ClientError)
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
                    connection_id: *connection_id,
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
        // TODO: fix returned error to ContextError
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
        port_channel_id: &(PortId, ChannelId),
    ) -> Result<ChannelEnd, ContextError> {
        let port_id = port_channel_id.0;
        let channel_id = port_channel_id.1;
        let port_channel_id =
            PortChannelId::new(channel_id.clone(), port_id.clone());
        let key = storage::channel_key(&port_channel_id);
        match self.ctx.read(&key) {
            Ok(Some(value)) => ChannelEnd::decode_vec(&value).map_err(|_| {
                ContextError::ChannelError(ChannelError::Other {
                    description: format!(
                        "Decoding the channel end failed: Port ID {}, Channel \
                         ID {}",
                        port_id, channel_id,
                    ),
                })
            }),
            Ok(None) => {
                Err(ContextError::ChannelError(ChannelError::ChannelNotFound {
                    channel_id,
                    port_id,
                }))
            }
            Err(_) => Err(ContextError::ChannelError(ChannelError::Other {
                description: format!(
                    "Reading the channel end failed: Port ID {}, Channel ID {}",
                    port_id, channel_id,
                ),
            })),
        }
    }

    fn connection_channels(
        &self,
        cid: &ConnectionId,
    ) -> Result<Vec<(PortId, ChannelId)>, ContextError> {
        todo!("");
    }

    fn get_next_sequence_send(
        &self,
        port_channel_id: &(PortId, ChannelId),
    ) -> Result<Sequence, ContextError> {
        let port_id = port_channel_id.0;
        let channel_id = port_channel_id.1;
        let port_channel_id =
            PortChannelId::new(channel_id.clone(), port_id.clone());
        let key = storage::next_sequence_send_key(&port_channel_id);
        self.read_sequence(&key)
    }

    fn get_next_sequence_recv(
        &self,
        port_channel_id: &(PortId, ChannelId),
    ) -> Result<Sequence, ContextError> {
        let port_id = port_channel_id.0;
        let channel_id = port_channel_id.1;
        let port_channel_id =
            PortChannelId::new(channel_id.clone(), port_id.clone());
        let key = storage::next_sequence_recv_key(&port_channel_id);
        self.read_sequence(&key)
    }

    fn get_next_sequence_ack(
        &self,
        port_channel_id: &(PortId, ChannelId),
    ) -> Result<Sequence, ContextError> {
        let port_id = port_channel_id.0;
        let channel_id = port_channel_id.1;
        let port_channel_id =
            PortChannelId::new(channel_id.clone(), port_id.clone());
        let key = storage::next_sequence_ack_key(&port_channel_id);
        self.read_sequence(&key)
    }

    fn get_packet_commitment(
        &self,
        key: &(PortId, ChannelId, Sequence),
    ) -> Result<PacketCommitment, ContextError> {
        let commitment_key = storage::commitment_key(&key.0, &key.1, key.2);
        match self.ctx.read(&commitment_key) {
            Ok(Some(value)) => Ok(value.into()),
            Ok(None) => Err(ContextError::PacketError(
                PacketError::PacketCommitmentNotFound { sequence: key.2 },
            )),
            Err(e) => Err(ContextError::PacketError(PacketError::Channel(
                ChannelError::Other {
                    description: format!(
                        "Reading commitment failed: sequence {}",
                        key.2
                    ),
                },
            ))),
        }
    }

    fn get_packet_receipt(
        &self,
        key: &(PortId, ChannelId, Sequence),
    ) -> Result<Receipt, ContextError> {
        let receipt_key = storage::receipt_key(&key.0, &key.1, key.2);
        match self.ctx.read(&receipt_key) {
            Ok(Some(_)) => Ok(Receipt::Ok),
            Ok(None) => Err(ContextError::PacketError(
                PacketError::PacketReceiptNotFound { sequence: key.2 },
            )),
            Err(e) => Err(ContextError::PacketError(PacketError::Channel(
                ChannelError::Other {
                    description: format!(
                        "Reading the receipt failed: sequence {}",
                        key.2
                    ),
                },
            ))),
        }
    }

    fn get_packet_acknowledgement(
        &self,
        key: &(PortId, ChannelId, Sequence),
    ) -> Result<AcknowledgementCommitment, ContextError> {
        let ack_key = storage::ack_key(&key.0, &key.1, key.2);
        match self.ctx.read(&ack_key) {
            Ok(Some(value)) => Ok(value.into()),
            Ok(None) => Err(ContextError::PacketError(
                PacketError::PacketAcknowledgementNotFound { sequence: key.2 },
            )),
            Err(e) => Err(ContextError::PacketError(PacketError::Channel(
                ChannelError::Other {
                    description: format!(
                        "Reading the ack commitment failed: sequence {}",
                        key.2
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
        height: &Height,
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
            Err(e) => Err(ContextError::ClientError(ClientError::Other {
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
