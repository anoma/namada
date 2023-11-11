//! ExecutionContext implementation for IBC

use super::super::{IbcActions, IbcCommonContext};
use crate::ibc::core::events::IbcEvent;
use crate::ibc::core::ics02_client::client_state::ClientState;
use crate::ibc::core::ics02_client::consensus_state::ConsensusState;
use crate::ibc::core::ics03_connection::connection::ConnectionEnd;
use crate::ibc::core::ics04_channel::channel::ChannelEnd;
use crate::ibc::core::ics04_channel::commitment::{
    AcknowledgementCommitment, PacketCommitment,
};
use crate::ibc::core::ics04_channel::packet::{Receipt, Sequence};
use crate::ibc::core::ics24_host::identifier::{ClientId, ConnectionId};
use crate::ibc::core::ics24_host::path::{
    AckPath, ChannelEndPath, ClientConnectionPath, ClientConsensusStatePath,
    ClientStatePath, CommitmentPath, ConnectionPath, ReceiptPath, SeqAckPath,
    SeqRecvPath, SeqSendPath,
};
use crate::ibc::core::timestamp::Timestamp;
use crate::ibc::core::{ContextError, ExecutionContext};
use crate::ibc::Height;
use crate::ledger::ibc::storage;

impl<C> ExecutionContext for IbcActions<'_, C>
where
    C: IbcCommonContext,
{
    fn store_client_state(
        &mut self,
        client_state_path: ClientStatePath,
        client_state: Box<dyn ClientState>,
    ) -> Result<(), ContextError> {
        self.ctx
            .borrow_mut()
            .store_client_state(&client_state_path.0, client_state)
    }

    fn store_consensus_state(
        &mut self,
        consensus_state_path: ClientConsensusStatePath,
        consensus_state: Box<dyn ConsensusState>,
    ) -> Result<(), ContextError> {
        let client_id = consensus_state_path.client_id;
        let height = Height::new(
            consensus_state_path.epoch,
            consensus_state_path.height,
        )?;
        self.ctx.borrow_mut().store_consensus_state(
            &client_id,
            height,
            consensus_state,
        )
    }

    fn increase_client_counter(&mut self) {
        let key = storage::client_counter_key();
        self.ctx
            .borrow_mut()
            .increment_counter(&key)
            .expect("Error cannot be returned");
    }

    fn store_update_time(
        &mut self,
        client_id: ClientId,
        _height: Height,
        timestamp: Timestamp,
    ) -> Result<(), ContextError> {
        self.ctx
            .borrow_mut()
            .store_update_time(&client_id, timestamp)
    }

    fn store_update_height(
        &mut self,
        client_id: ClientId,
        _height: Height,
        host_height: Height,
    ) -> Result<(), ContextError> {
        self.ctx
            .borrow_mut()
            .store_update_height(&client_id, host_height)
    }

    fn store_connection(
        &mut self,
        connection_path: &ConnectionPath,
        connection_end: ConnectionEnd,
    ) -> Result<(), ContextError> {
        self.ctx
            .borrow_mut()
            .store_connection(&connection_path.0, connection_end)
    }

    fn store_connection_to_client(
        &mut self,
        client_connection_path: &ClientConnectionPath,
        conn_id: ConnectionId,
    ) -> Result<(), ContextError> {
        self.ctx
            .borrow_mut()
            .append_connection(&client_connection_path.0, conn_id)
    }

    fn increase_connection_counter(&mut self) {
        let key = storage::connection_counter_key();
        self.ctx
            .borrow_mut()
            .increment_counter(&key)
            .expect("Error cannot be returned");
    }

    fn store_packet_commitment(
        &mut self,
        path: &CommitmentPath,
        commitment: PacketCommitment,
    ) -> Result<(), ContextError> {
        self.ctx.borrow_mut().store_packet_commitment(
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
        self.ctx.borrow_mut().delete_packet_commitment(
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
        self.ctx.borrow_mut().store_packet_receipt(
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
        self.ctx.borrow_mut().store_packet_ack(
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
        self.ctx.borrow_mut().delete_packet_ack(
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
        self.ctx
            .borrow_mut()
            .store_channel(&path.0, &path.1, channel_end)
    }

    fn store_next_sequence_send(
        &mut self,
        path: &SeqSendPath,
        seq: Sequence,
    ) -> Result<(), ContextError> {
        self.ctx
            .borrow_mut()
            .store_next_sequence_send(&path.0, &path.1, seq)
    }

    fn store_next_sequence_recv(
        &mut self,
        path: &SeqRecvPath,
        seq: Sequence,
    ) -> Result<(), ContextError> {
        self.ctx
            .borrow_mut()
            .store_next_sequence_recv(&path.0, &path.1, seq)
    }

    fn store_next_sequence_ack(
        &mut self,
        path: &SeqAckPath,
        seq: Sequence,
    ) -> Result<(), ContextError> {
        self.ctx
            .borrow_mut()
            .store_next_sequence_ack(&path.0, &path.1, seq)
    }

    fn increase_channel_counter(&mut self) {
        let key = storage::channel_counter_key();
        self.ctx
            .borrow_mut()
            .increment_counter(&key)
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
