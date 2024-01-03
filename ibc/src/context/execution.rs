//! ExecutionContext implementation for IBC

use namada_core::ibc::core::channel::types::channel::ChannelEnd;
use namada_core::ibc::core::channel::types::commitment::{
    AcknowledgementCommitment, PacketCommitment,
};
use namada_core::ibc::core::channel::types::packet::Receipt;
use namada_core::ibc::core::client::context::ClientExecutionContext;
use namada_core::ibc::core::client::types::Height;
use namada_core::ibc::core::connection::types::ConnectionEnd;
use namada_core::ibc::core::handler::types::error::ContextError;
use namada_core::ibc::core::handler::types::events::IbcEvent;
use namada_core::ibc::core::host::types::identifiers::{
    ClientId, ConnectionId, Sequence,
};
use namada_core::ibc::core::host::types::path::{
    AckPath, ChannelEndPath, ClientConnectionPath, ClientConsensusStatePath,
    ClientStatePath, CommitmentPath, ConnectionPath, ReceiptPath, SeqAckPath,
    SeqRecvPath, SeqSendPath,
};
use namada_core::ibc::core::host::ExecutionContext;
use namada_core::ibc::primitives::Timestamp;

use super::client::{AnyClientState, AnyConsensusState};
use super::common::IbcCommonContext;
use super::IbcContext;
use crate::storage;

impl<C> ClientExecutionContext for IbcContext<C>
where
    C: IbcCommonContext,
{
    type AnyClientState = AnyClientState;
    type AnyConsensusState = AnyConsensusState;
    type V = Self;

    fn store_client_state(
        &mut self,
        client_state_path: ClientStatePath,
        client_state: Self::AnyClientState,
    ) -> Result<(), ContextError> {
        self.inner
            .borrow_mut()
            .store_client_state(&client_state_path.0, client_state)
    }

    fn store_consensus_state(
        &mut self,
        consensus_state_path: ClientConsensusStatePath,
        consensus_state: Self::AnyConsensusState,
    ) -> Result<(), ContextError> {
        let client_id = consensus_state_path.client_id;
        let height = Height::new(
            consensus_state_path.revision_number,
            consensus_state_path.revision_height,
        )?;
        self.inner.borrow_mut().store_consensus_state(
            &client_id,
            height,
            consensus_state,
        )
    }

    fn delete_consensus_state(
        &mut self,
        consensus_state_path: ClientConsensusStatePath,
    ) -> Result<(), ContextError> {
        let client_id = consensus_state_path.client_id;
        let height = Height::new(
            consensus_state_path.revision_number,
            consensus_state_path.revision_height,
        )?;
        self.inner
            .borrow_mut()
            .delete_consensus_state(&client_id, height)
    }

    fn store_update_time(
        &mut self,
        client_id: ClientId,
        _height: Height,
        timestamp: Timestamp,
    ) -> Result<(), ContextError> {
        self.inner
            .borrow_mut()
            .store_update_time(&client_id, timestamp)
    }

    fn store_update_height(
        &mut self,
        client_id: ClientId,
        _height: Height,
        host_height: Height,
    ) -> Result<(), ContextError> {
        self.inner
            .borrow_mut()
            .store_update_height(&client_id, host_height)
    }

    fn delete_update_time(
        &mut self,
        client_id: ClientId,
        _height: Height,
    ) -> Result<(), ContextError> {
        self.inner.borrow_mut().delete_update_time(&client_id)
    }

    fn delete_update_height(
        &mut self,
        client_id: ClientId,
        _height: Height,
    ) -> Result<(), ContextError> {
        self.inner.borrow_mut().delete_update_height(&client_id)
    }
}

impl<C> ExecutionContext for IbcContext<C>
where
    C: IbcCommonContext,
{
    fn get_client_execution_context(&mut self) -> &mut Self::E {
        self
    }

    fn increase_client_counter(&mut self) -> Result<(), ContextError> {
        let key = storage::client_counter_key();
        self.inner.borrow_mut().increment_counter(&key)
    }

    fn store_connection(
        &mut self,
        connection_path: &ConnectionPath,
        connection_end: ConnectionEnd,
    ) -> Result<(), ContextError> {
        self.inner
            .borrow_mut()
            .store_connection(&connection_path.0, connection_end)
    }

    fn store_connection_to_client(
        &mut self,
        client_connection_path: &ClientConnectionPath,
        conn_id: ConnectionId,
    ) -> Result<(), ContextError> {
        self.inner
            .borrow_mut()
            .append_connection(&client_connection_path.0, conn_id)
    }

    fn increase_connection_counter(&mut self) -> Result<(), ContextError> {
        let key = storage::connection_counter_key();
        self.inner.borrow_mut().increment_counter(&key)
    }

    fn store_packet_commitment(
        &mut self,
        path: &CommitmentPath,
        commitment: PacketCommitment,
    ) -> Result<(), ContextError> {
        self.inner.borrow_mut().store_packet_commitment(
            &path.port_id,
            &path.channel_id,
            path.sequence,
            commitment,
        )
    }

    fn delete_packet_commitment(
        &mut self,
        path: &CommitmentPath,
    ) -> Result<(), ContextError> {
        self.inner.borrow_mut().delete_packet_commitment(
            &path.port_id,
            &path.channel_id,
            path.sequence,
        )
    }

    fn store_packet_receipt(
        &mut self,
        path: &ReceiptPath,
        _receipt: Receipt,
    ) -> Result<(), ContextError> {
        self.inner.borrow_mut().store_packet_receipt(
            &path.port_id,
            &path.channel_id,
            path.sequence,
        )
    }

    fn store_packet_acknowledgement(
        &mut self,
        path: &AckPath,
        ack_commitment: AcknowledgementCommitment,
    ) -> Result<(), ContextError> {
        self.inner.borrow_mut().store_packet_ack(
            &path.port_id,
            &path.channel_id,
            path.sequence,
            ack_commitment,
        )
    }

    fn delete_packet_acknowledgement(
        &mut self,
        path: &AckPath,
    ) -> Result<(), ContextError> {
        self.inner.borrow_mut().delete_packet_ack(
            &path.port_id,
            &path.channel_id,
            path.sequence,
        )
    }

    fn store_channel(
        &mut self,
        path: &ChannelEndPath,
        channel_end: ChannelEnd,
    ) -> Result<(), ContextError> {
        self.inner
            .borrow_mut()
            .store_channel(&path.0, &path.1, channel_end)
    }

    fn store_next_sequence_send(
        &mut self,
        path: &SeqSendPath,
        seq: Sequence,
    ) -> Result<(), ContextError> {
        self.inner
            .borrow_mut()
            .store_next_sequence_send(&path.0, &path.1, seq)
    }

    fn store_next_sequence_recv(
        &mut self,
        path: &SeqRecvPath,
        seq: Sequence,
    ) -> Result<(), ContextError> {
        self.inner
            .borrow_mut()
            .store_next_sequence_recv(&path.0, &path.1, seq)
    }

    fn store_next_sequence_ack(
        &mut self,
        path: &SeqAckPath,
        seq: Sequence,
    ) -> Result<(), ContextError> {
        self.inner
            .borrow_mut()
            .store_next_sequence_ack(&path.0, &path.1, seq)
    }

    fn increase_channel_counter(&mut self) -> Result<(), ContextError> {
        let key = storage::channel_counter_key();
        self.inner.borrow_mut().increment_counter(&key)
    }

    fn emit_ibc_event(&mut self, event: IbcEvent) -> Result<(), ContextError> {
        let event = event.try_into().expect("The event should be converted");
        self.inner
            .borrow_mut()
            .emit_ibc_event(event)
            .map_err(ContextError::from)
    }

    fn log_message(&mut self, message: String) -> Result<(), ContextError> {
        self.inner.borrow().log_string(message);
        Ok(())
    }
}
