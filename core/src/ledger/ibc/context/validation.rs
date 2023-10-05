//! ValidationContext implementation for IBC

use super::super::{IbcActions, IbcCommonContext};
use crate::ibc::core::ics02_client::client_state::ClientState;
use crate::ibc::core::ics02_client::consensus_state::ConsensusState;
use crate::ibc::core::ics03_connection::connection::ConnectionEnd;
use crate::ibc::core::ics04_channel::channel::ChannelEnd;
use crate::ibc::core::ics04_channel::commitment::{
    AcknowledgementCommitment, PacketCommitment,
};
use crate::ibc::core::ics04_channel::packet::{Receipt, Sequence};
use crate::ibc::core::ics23_commitment::commitment::CommitmentPrefix;
use crate::ibc::core::ics23_commitment::specs::ProofSpecs;
use crate::ibc::core::ics24_host::identifier::{
    ChainId, ClientId, ConnectionId,
};
use crate::ibc::core::ics24_host::path::{
    AckPath, ChannelEndPath, ClientConsensusStatePath, CommitmentPath,
    ReceiptPath, SeqAckPath, SeqRecvPath, SeqSendPath,
};
use crate::ibc::core::timestamp::Timestamp;
use crate::ibc::core::{ContextError, ValidationContext};
use crate::ibc::hosts::tendermint::ValidateSelfClientContext;
#[cfg(any(feature = "ibc-mocks-abcipp", feature = "ibc-mocks"))]
use crate::ibc::mock::client_state::MockClientState;
use crate::ibc::{Height, Signer};
use crate::ibc_proto::google::protobuf::Any;
use crate::ledger::ibc::storage;
use crate::types::storage::Key;

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
        let height = Height::new(
            client_cons_state_path.epoch,
            client_cons_state_path.height,
        )?;
        self.ctx
            .borrow()
            .consensus_state(&client_cons_state_path.client_id, height)
    }

    fn next_consensus_state(
        &self,
        client_id: &ClientId,
        height: &Height,
    ) -> Result<Option<Box<dyn ConsensusState>>, ContextError> {
        let prefix = storage::consensus_state_prefix(client_id);
        // or iterator
        let ctx = self.ctx.borrow();
        let mut iter = ctx.iter_prefix(&prefix)?;
        let mut lowest_height_value = None;
        while let Some((key, value)) = ctx.iter_next(&mut iter)? {
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
            .map(|(_, value)| ctx.decode_consensus_state_value(value))
            .transpose()
    }

    fn prev_consensus_state(
        &self,
        client_id: &ClientId,
        height: &Height,
    ) -> Result<Option<Box<dyn ConsensusState>>, ContextError> {
        let prefix = storage::consensus_state_prefix(client_id);
        // for iterator
        let ctx = self.ctx.borrow();
        let mut iter = ctx.iter_prefix(&prefix)?;
        let mut highest_height_value = None;
        while let Some((key, value)) = ctx.iter_next(&mut iter)? {
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
            .map(|(_, value)| ctx.decode_consensus_state_value(value))
            .transpose()
    }

    fn host_height(&self) -> Result<Height, ContextError> {
        let height = self.ctx.borrow().get_height()?;
        // the revision number is always 0
        Height::new(0, height.0).map_err(ContextError::ClientError)
    }

    fn host_timestamp(&self) -> Result<Timestamp, ContextError> {
        self.ctx.borrow().host_timestamp()
    }

    fn host_consensus_state(
        &self,
        height: &Height,
    ) -> Result<Box<dyn ConsensusState>, ContextError> {
        self.ctx.borrow().host_consensus_state(height)
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
            if MockClientState::try_from(counterparty_client_state.clone())
                .is_ok()
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
        path: &ChannelEndPath,
    ) -> Result<ChannelEnd, ContextError> {
        self.ctx.borrow().channel_end(&path.0, &path.1)
    }

    fn get_next_sequence_send(
        &self,
        path: &SeqSendPath,
    ) -> Result<Sequence, ContextError> {
        self.ctx.borrow().get_next_sequence_send(&path.0, &path.1)
    }

    fn get_next_sequence_recv(
        &self,
        path: &SeqRecvPath,
    ) -> Result<Sequence, ContextError> {
        self.ctx.borrow().get_next_sequence_recv(&path.0, &path.1)
    }

    fn get_next_sequence_ack(
        &self,
        path: &SeqAckPath,
    ) -> Result<Sequence, ContextError> {
        self.ctx.borrow().get_next_sequence_ack(&path.0, &path.1)
    }

    fn get_packet_commitment(
        &self,
        path: &CommitmentPath,
    ) -> Result<PacketCommitment, ContextError> {
        self.ctx.borrow().packet_commitment(
            &path.port_id,
            &path.channel_id,
            path.sequence,
        )
    }

    fn get_packet_receipt(
        &self,
        path: &ReceiptPath,
    ) -> Result<Receipt, ContextError> {
        self.ctx.borrow().packet_receipt(
            &path.port_id,
            &path.channel_id,
            path.sequence,
        )
    }

    fn get_packet_acknowledgement(
        &self,
        path: &AckPath,
    ) -> Result<AcknowledgementCommitment, ContextError> {
        self.ctx.borrow().packet_ack(
            &path.port_id,
            &path.channel_id,
            path.sequence,
        )
    }

    fn client_update_time(
        &self,
        client_id: &ClientId,
        _height: &Height,
    ) -> Result<Timestamp, ContextError> {
        self.ctx.borrow().client_update_time(client_id)
    }

    fn client_update_height(
        &self,
        client_id: &ClientId,
        _height: &Height,
    ) -> Result<Height, ContextError> {
        self.ctx.borrow().client_update_height(client_id)
    }

    fn channel_counter(&self) -> Result<u64, ContextError> {
        let key = storage::channel_counter_key();
        self.ctx.borrow().read_counter(&key)
    }

    fn max_expected_time_per_block(&self) -> core::time::Duration {
        self.ctx
            .borrow()
            .max_expected_time_per_block()
            .expect("Error cannot be returned")
    }

    fn validate_message_signer(
        &self,
        _signer: &Signer,
    ) -> Result<(), ContextError> {
        // The signer of a transaction should be validated
        Ok(())
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
