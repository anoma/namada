//! IBC module for token transfer

use super::super::IbcStorageContext;
use crate::ibc::applications::transfer::context::{
    on_acknowledgement_packet, on_acknowledgement_packet_execute,
    on_acknowledgement_packet_validate, on_chan_close_confirm,
    on_chan_close_confirm_execute, on_chan_close_confirm_validate,
    on_chan_close_init, on_chan_close_init_execute,
    on_chan_close_init_validate, on_chan_open_ack, on_chan_open_ack_execute,
    on_chan_open_ack_validate, on_chan_open_confirm,
    on_chan_open_confirm_execute, on_chan_open_confirm_validate,
    on_chan_open_init, on_chan_open_init_execute, on_chan_open_init_validate,
    on_chan_open_try, on_chan_open_try_execute, on_chan_open_try_validate,
    on_recv_packet, on_recv_packet_execute, on_timeout_packet,
    on_timeout_packet_execute, on_timeout_packet_validate, BankKeeper,
    TokenTransferContext, TokenTransferKeeper, TokenTransferReader,
};
use crate::ibc::applications::transfer::error::TokenTransferError;
use crate::ibc::core::ics04_channel::channel::{Counterparty, Order};
use crate::ibc::core::ics04_channel::context::SendPacketReader;
use crate::ibc::core::ics04_channel::error::{ChannelError, PacketError};
use crate::ibc::core::ics04_channel::handler::ModuleExtras;
use crate::ibc::core::ics04_channel::msgs::acknowledgement::Acknowledgement;
use crate::ibc::core::ics04_channel::packet::Packet;
use crate::ibc::core::ics04_channel::Version;
use crate::ibc::core::ics24_host::identifier::{
    ChannelId, ConnectionId, PortId,
};
use crate::ibc::core::ics26_routing::context::{Module, ModuleOutputBuilder};
use crate::ibc::signer::Signer;

#[derive(Debug)]
pub struct TransferModule<C>
where
    C: IbcStorageContext + 'static,
{
    pub ctx: &'static C,
}

impl<C> Module for TransferModule<C>
where
    C: IbcStorageContext + Sync + core::fmt::Debug + 'static,
{
    #[allow(clippy::too_many_arguments)]
    fn on_chan_open_init_validate(
        &self,
        order: Order,
        connection_hops: &[ConnectionId],
        port_id: &PortId,
        channel_id: &ChannelId,
        counterparty: &Counterparty,
        version: &Version,
    ) -> Result<Version, ChannelError> {
        on_chan_open_init_validate(
            self,
            order,
            connection_hops,
            port_id,
            channel_id,
            counterparty,
            version,
        )
        .map_err(into_channel_error)?;
        Ok(version.clone())
    }

    #[allow(clippy::too_many_arguments)]
    fn on_chan_open_init_execute(
        &mut self,
        order: Order,
        connection_hops: &[ConnectionId],
        port_id: &PortId,
        channel_id: &ChannelId,
        counterparty: &Counterparty,
        version: &Version,
    ) -> Result<(ModuleExtras, Version), ChannelError> {
        on_chan_open_init_execute(
            self,
            order,
            connection_hops,
            port_id,
            channel_id,
            counterparty,
            version,
        )
        .map_err(into_channel_error)
    }

    #[allow(clippy::too_many_arguments)]
    fn on_chan_open_init(
        &mut self,
        order: Order,
        connection_hops: &[ConnectionId],
        port_id: &PortId,
        channel_id: &ChannelId,
        counterparty: &Counterparty,
        version: &Version,
    ) -> Result<(ModuleExtras, Version), ChannelError> {
        on_chan_open_init(
            self,
            order,
            connection_hops,
            port_id,
            channel_id,
            counterparty,
            version,
        )
        .map_err(into_channel_error)
    }

    #[allow(clippy::too_many_arguments)]
    fn on_chan_open_try_validate(
        &self,
        order: Order,
        connection_hops: &[ConnectionId],
        port_id: &PortId,
        channel_id: &ChannelId,
        counterparty: &Counterparty,
        counterparty_version: &Version,
    ) -> Result<Version, ChannelError> {
        on_chan_open_try_validate(
            self,
            order,
            connection_hops,
            port_id,
            channel_id,
            counterparty,
            counterparty_version,
        )
        .map_err(into_channel_error)?;
        Ok(counterparty_version.clone())
    }

    #[allow(clippy::too_many_arguments)]
    fn on_chan_open_try_execute(
        &mut self,
        order: Order,
        connection_hops: &[ConnectionId],
        port_id: &PortId,
        channel_id: &ChannelId,
        counterparty: &Counterparty,
        counterparty_version: &Version,
    ) -> Result<(ModuleExtras, Version), ChannelError> {
        on_chan_open_try_execute(
            self,
            order,
            connection_hops,
            port_id,
            channel_id,
            counterparty,
            counterparty_version,
        )
        .map_err(into_channel_error)
    }

    #[allow(clippy::too_many_arguments)]
    fn on_chan_open_try(
        &mut self,
        order: Order,
        connection_hops: &[ConnectionId],
        port_id: &PortId,
        channel_id: &ChannelId,
        counterparty: &Counterparty,
        counterparty_version: &Version,
    ) -> Result<(ModuleExtras, Version), ChannelError> {
        on_chan_open_try(
            self,
            order,
            connection_hops,
            port_id,
            channel_id,
            counterparty,
            counterparty_version,
        )
        .map_err(into_channel_error)
    }

    fn on_chan_open_ack_validate(
        &self,
        port_id: &PortId,
        channel_id: &ChannelId,
        counterparty_version: &Version,
    ) -> Result<(), ChannelError> {
        on_chan_open_ack_validate(
            self,
            port_id,
            channel_id,
            counterparty_version,
        )
        .map_err(into_channel_error)
    }

    fn on_chan_open_ack_execute(
        &mut self,
        port_id: &PortId,
        channel_id: &ChannelId,
        counterparty_version: &Version,
    ) -> Result<ModuleExtras, ChannelError> {
        on_chan_open_ack_execute(
            self,
            port_id,
            channel_id,
            counterparty_version,
        )
        .map_err(into_channel_error)
    }

    fn on_chan_open_ack(
        &mut self,
        port_id: &PortId,
        channel_id: &ChannelId,
        counterparty_version: &Version,
    ) -> Result<ModuleExtras, ChannelError> {
        on_chan_open_ack(self, port_id, channel_id, counterparty_version)
            .map_err(into_channel_error)
    }

    fn on_chan_open_confirm_validate(
        &self,
        port_id: &PortId,
        channel_id: &ChannelId,
    ) -> Result<(), ChannelError> {
        on_chan_open_confirm_validate(self, port_id, channel_id)
            .map_err(into_channel_error)
    }

    fn on_chan_open_confirm_execute(
        &mut self,
        port_id: &PortId,
        channel_id: &ChannelId,
    ) -> Result<ModuleExtras, ChannelError> {
        on_chan_open_confirm_execute(self, port_id, channel_id)
            .map_err(into_channel_error)
    }

    fn on_chan_open_confirm(
        &mut self,
        port_id: &PortId,
        channel_id: &ChannelId,
    ) -> Result<ModuleExtras, ChannelError> {
        on_chan_open_confirm(self, port_id, channel_id)
            .map_err(into_channel_error)
    }

    fn on_chan_close_init_validate(
        &self,
        port_id: &PortId,
        channel_id: &ChannelId,
    ) -> Result<(), ChannelError> {
        on_chan_close_init_validate(self, port_id, channel_id)
            .map_err(into_channel_error)
    }

    fn on_chan_close_init_execute(
        &mut self,
        port_id: &PortId,
        channel_id: &ChannelId,
    ) -> Result<ModuleExtras, ChannelError> {
        on_chan_close_init_execute(self, port_id, channel_id)
            .map_err(into_channel_error)
    }

    fn on_chan_close_init(
        &mut self,
        port_id: &PortId,
        channel_id: &ChannelId,
    ) -> Result<ModuleExtras, ChannelError> {
        on_chan_close_init(self, port_id, channel_id)
            .map_err(into_channel_error)
    }

    fn on_chan_close_confirm_validate(
        &self,
        port_id: &PortId,
        channel_id: &ChannelId,
    ) -> Result<(), ChannelError> {
        on_chan_close_confirm_validate(self, port_id, channel_id)
            .map_err(into_channel_error)
    }

    fn on_chan_close_confirm_execute(
        &mut self,
        port_id: &PortId,
        channel_id: &ChannelId,
    ) -> Result<ModuleExtras, ChannelError> {
        on_chan_close_confirm_execute(self, port_id, channel_id)
            .map_err(into_channel_error)
    }

    fn on_chan_close_confirm(
        &mut self,
        port_id: &PortId,
        channel_id: &ChannelId,
    ) -> Result<ModuleExtras, ChannelError> {
        on_chan_close_confirm(self, port_id, channel_id)
            .map_err(into_channel_error)
    }

    fn on_recv_packet_execute(
        &mut self,
        packet: &Packet,
        _relayer: &Signer,
    ) -> (ModuleExtras, Acknowledgement) {
        on_recv_packet_execute(self, packet)
    }

    fn on_recv_packet(
        &mut self,
        output: &mut ModuleOutputBuilder,
        packet: &Packet,
        relayer: &Signer,
    ) -> Acknowledgement {
        on_recv_packet(self, output, packet, relayer)
    }

    fn on_acknowledgement_packet_validate(
        &self,
        packet: &Packet,
        acknowledgement: &Acknowledgement,
        relayer: &Signer,
    ) -> Result<(), PacketError> {
        on_acknowledgement_packet_validate(
            self,
            packet,
            acknowledgement,
            relayer,
        )
        .map_err(into_packet_error)
    }

    fn on_acknowledgement_packet_execute(
        &mut self,
        packet: &Packet,
        acknowledgement: &Acknowledgement,
        relayer: &Signer,
    ) -> (ModuleExtras, Result<(), PacketError>) {
        let (extras, result) = on_acknowledgement_packet_execute(
            self,
            packet,
            acknowledgement,
            relayer,
        );
        (extras, result.map_err(into_packet_error))
    }

    fn on_acknowledgement_packet(
        &mut self,
        output: &mut ModuleOutputBuilder,
        packet: &Packet,
        acknowledgement: &Acknowledgement,
        relayer: &Signer,
    ) -> Result<(), PacketError> {
        on_acknowledgement_packet(
            self,
            output,
            packet,
            acknowledgement,
            relayer,
        )
        .map_err(into_packet_error)
    }

    fn on_timeout_packet_validate(
        &self,
        packet: &Packet,
        relayer: &Signer,
    ) -> Result<(), PacketError> {
        on_timeout_packet_validate(self, packet, relayer)
            .map_err(into_packet_error)
    }

    fn on_timeout_packet_execute(
        &mut self,
        packet: &Packet,
        relayer: &Signer,
    ) -> (ModuleExtras, Result<(), PacketError>) {
        let (extras, result) = on_timeout_packet_execute(self, packet, relayer);
        (extras, result.map_err(into_packet_error))
    }

    fn on_timeout_packet(
        &mut self,
        output: &mut ModuleOutputBuilder,
        packet: &Packet,
        relayer: &Signer,
    ) -> Result<(), PacketError> {
        on_timeout_packet(self, output, packet, relayer)
            .map_err(into_packet_error)
    }
}

impl<C> SendPacketReader for TransferModule<C> where C: IbcStorageContext {}

impl<C> TokenTransferReader for TransferModule<C> where C: IbcStorageContext {}

impl<C> BankKeeper for TransferModule<C> where C: IbcStorageContext {}

impl<C> TokenTransferKeeper for TransferModule<C> where C: IbcStorageContext {}

impl<C> TokenTransferContext for TransferModule<C> where C: IbcStorageContext {}

fn into_channel_error(error: TokenTransferError) -> ChannelError {
    ChannelError::AppModule {
        description: error.to_string(),
    }
}

fn into_packet_error(error: TokenTransferError) -> PacketError {
    PacketError::AppModule {
        description: error.to_string(),
    }
}
