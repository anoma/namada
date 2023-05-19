//! ValidationContext implementation for IBC

use prost::Message;

use super::super::{IbcActions, IbcCommonContext};
use crate::ibc::clients::ics07_tendermint::consensus_state::ConsensusState as TmConsensusState;
#[cfg(any(feature = "ibc-mocks-abcipp", feature = "ibc-mocks"))]
use crate::ibc::core::ics02_client::client_state::downcast_client_state;
use crate::ibc::core::ics02_client::client_state::ClientState;
use crate::ibc::core::ics02_client::consensus_state::ConsensusState;
use crate::ibc::core::ics02_client::error::ClientError;
use crate::ibc::core::ics03_connection::connection::ConnectionEnd;
use crate::ibc::core::ics04_channel::channel::ChannelEnd;
use crate::ibc::core::ics04_channel::commitment::{
    AcknowledgementCommitment, PacketCommitment,
};
use crate::ibc::core::ics04_channel::error::{ChannelError, PacketError};
use crate::ibc::core::ics04_channel::packet::{Receipt, Sequence};
use crate::ibc::core::ics23_commitment::commitment::CommitmentPrefix;
use crate::ibc::core::ics23_commitment::specs::ProofSpecs;
use crate::ibc::core::ics24_host::identifier::{
    ChainId, ClientId, ConnectionId,
};
use crate::ibc::core::ics24_host::path::{
    AckPath, ChannelEndPath, ClientConsensusStatePath, CommitmentPath, Path,
    ReceiptPath, SeqAckPath, SeqRecvPath, SeqSendPath,
};
use crate::ibc::core::{ContextError, ValidationContext};
use crate::ibc::hosts::tendermint::ValidateSelfClientContext;
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

impl<C> ValidationContext for IbcActions<'_, C>
where
    C: IbcCommonContext,
{
    fn client_state(
        &self,
        client_id: &ClientId,
    ) -> Result<Box<dyn ClientState>, ContextError> {
        self.ctx.borrow().client_state(client_id)
    }

    fn decode_client_state(
        &self,
        client_state: Any,
    ) -> Result<Box<dyn ClientState>, ContextError> {
        self.ctx.borrow().decode_client_state(client_state)
    }

    fn consensus_state(
        &self,
        client_cons_state_path: &ClientConsensusStatePath,
    ) -> Result<Box<dyn ConsensusState>, ContextError> {
        self.ctx.borrow().consensus_state(client_cons_state_path)
    }

    fn next_consensus_state(
        &self,
        client_id: &ClientId,
        height: &Height,
    ) -> Result<Option<Box<dyn ConsensusState>>, ContextError> {
        let prefix = storage::consensus_state_prefix(client_id);
        // for iterator
        let ctx = self.ctx.borrow();
        let mut iter = ctx.iter_prefix(&prefix).map_err(|_| {
            ContextError::ClientError(ClientError::Other {
                description: format!(
                    "Reading the consensus state failed: ID {}, height {}",
                    client_id, height,
                ),
            })
        })?;
        let mut lowest_height_value = None;
        while let Some((key, value)) =
            ctx.iter_next(&mut iter).map_err(|_| {
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
                let cs = self.ctx.borrow().decode_consensus_state(any)?;
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
        // for iterator
        let ctx = self.ctx.borrow();
        let mut iter = ctx.iter_prefix(&prefix).map_err(|_| {
            ContextError::ClientError(ClientError::Other {
                description: format!(
                    "Reading the consensus state failed: ID {}, height {}",
                    client_id, height,
                ),
            })
        })?;
        let mut highest_height_value = None;
        while let Some((key, value)) =
            ctx.iter_next(&mut iter).map_err(|_| {
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
                let cs = self.ctx.borrow().decode_consensus_state(any)?;
                Ok(Some(cs))
            }
            None => Ok(None),
        }
    }

    fn host_height(&self) -> Result<Height, ContextError> {
        let height = self.ctx.borrow().get_height().map_err(|_| {
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
        let header = self
            .ctx
            .borrow()
            .get_header(height)
            .map_err(|_| {
                ContextError::ClientError(ClientError::Other {
                    description: "Getting the host header failed".to_string(),
                })
            })?
            .ok_or_else(|| {
                ContextError::ClientError(ClientError::Other {
                    description: "No host header".to_string(),
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
        let header = self
            .ctx
            .borrow()
            .get_header(height)
            .map_err(|_| {
                ContextError::ClientError(ClientError::Other {
                    description: format!(
                        "Getting the header on this chain failed: Height {}",
                        height
                    ),
                })
            })?
            .ok_or_else(|| {
                ContextError::ClientError(ClientError::Other {
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

    fn client_counter(&self) -> Result<u64, ContextError> {
        let key = storage::client_counter_key();
        self.ctx.borrow().read_counter(&key)
    }

    fn connection_end(
        &self,
        connection_id: &ConnectionId,
    ) -> Result<ConnectionEnd, ContextError> {
        self.ctx.borrow().connection_end(connection_id)
    }

    fn validate_self_client(
        &self,
        counterparty_client_state: Any,
    ) -> Result<(), ContextError> {
        #[cfg(any(feature = "ibc-mocks-abcipp", feature = "ibc-mocks"))]
        {
            let client_state = self
                .decode_client_state(counterparty_client_state.clone())
                .map_err(|_| ClientError::Other {
                    description: "Decoding the client state failed".to_string(),
                })?;

            if let Some(_mock) =
                downcast_client_state::<MockClientState>(client_state.as_ref())
            {
                return Ok(());
            }
        }

        ValidateSelfClientContext::validate_self_tendermint_client(
            self,
            counterparty_client_state,
        )
    }

    fn commitment_prefix(&self) -> CommitmentPrefix {
        CommitmentPrefix::try_from(COMMITMENT_PREFIX.to_vec())
            .expect("the prefix should be parsable")
    }

    fn connection_counter(&self) -> Result<u64, ContextError> {
        let key = storage::connection_counter_key();
        self.ctx.borrow().read_counter(&key)
    }

    fn channel_end(
        &self,
        channel_end_path: &ChannelEndPath,
    ) -> Result<ChannelEnd, ContextError> {
        self.ctx.borrow().channel_end(channel_end_path)
    }

    fn get_next_sequence_send(
        &self,
        path: &SeqSendPath,
    ) -> Result<Sequence, ContextError> {
        self.ctx.borrow().get_next_sequence_send(path)
    }

    fn get_next_sequence_recv(
        &self,
        path: &SeqRecvPath,
    ) -> Result<Sequence, ContextError> {
        let path = Path::SeqRecv(path.clone());
        let key = storage::ibc_key(path.to_string())
            .expect("Creating a key for the client state shouldn't fail");
        self.ctx.borrow().read_sequence(&key)
    }

    fn get_next_sequence_ack(
        &self,
        path: &SeqAckPath,
    ) -> Result<Sequence, ContextError> {
        let path = Path::SeqAck(path.clone());
        let key = storage::ibc_key(path.to_string())
            .expect("Creating a key for the client state shouldn't fail");
        self.ctx.borrow().read_sequence(&key)
    }

    fn get_packet_commitment(
        &self,
        path: &CommitmentPath,
    ) -> Result<PacketCommitment, ContextError> {
        let path = Path::Commitment(path.clone());
        let key = storage::ibc_key(path.to_string())
            .expect("Creating a key for the client state shouldn't fail");
        match self.ctx.borrow().read(&key) {
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
        match self.ctx.borrow().read(&key) {
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
        match self.ctx.borrow().read(&key) {
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

    fn client_update_time(
        &self,
        client_id: &ClientId,
        _height: &Height,
    ) -> Result<Timestamp, ContextError> {
        let key = storage::client_update_timestamp_key(client_id);
        match self.ctx.borrow().read(&key) {
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
        match self.ctx.borrow().read(&key) {
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
        self.ctx.borrow().read_counter(&key)
    }

    fn max_expected_time_per_block(&self) -> core::time::Duration {
        let key = get_max_expected_time_per_block_key();
        match self.ctx.borrow().read(&key) {
            Ok(Some(value)) => {
                crate::ledger::storage::types::decode::<DurationSecs>(value)
                    .expect("Decoding max_expected_time_per_block failed")
                    .into()
            }
            _ => unreachable!("The parameter should be initialized"),
        }
    }
}

impl<C> ValidateSelfClientContext for IbcActions<'_, C>
where
    C: IbcCommonContext,
{
    fn chain_id(&self) -> &ChainId {
        &self.validation_params.chain_id
    }

    fn host_current_height(&self) -> Height {
        let height = self
            .ctx
            .borrow()
            .get_height()
            .expect("The height should exist");
        Height::new(0, height.0).expect("The conversion shouldn't fail")
    }

    fn proof_specs(&self) -> &ProofSpecs {
        &self.validation_params.proof_specs
    }

    fn unbonding_period(&self) -> core::time::Duration {
        self.validation_params.unbonding_period
    }

    /// Returns the host upgrade path. May be empty.
    fn upgrade_path(&self) -> &[String] {
        &self.validation_params.upgrade_path
    }
}
