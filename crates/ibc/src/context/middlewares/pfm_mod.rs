//! Implementation of Packet Forward Middleware on top of the ICS-20
//! [`TransferModule`].

use std::fmt::{Debug, Formatter};
use std::marker::PhantomData;

use ibc::apps::transfer::context::TokenTransferExecutionContext;
use ibc::apps::transfer::handler::{
    refund_packet_token_execute, send_transfer_execute,
};
use ibc::apps::transfer::types::msgs::transfer::MsgTransfer;
use ibc::apps::transfer::types::packet::PacketData;
use ibc::apps::transfer::types::{is_receiver_chain_source, TracePrefix};
use ibc::core::channel::handler::{
    commit_packet_acknowledgment, emit_packet_acknowledgement_event,
};
use ibc::core::channel::types::acknowledgement::Acknowledgement;
use ibc::core::channel::types::channel::{Counterparty, Order};
use ibc::core::channel::types::error::{ChannelError, PacketError};
use ibc::core::channel::types::packet::Packet;
use ibc::core::channel::types::timeout::TimeoutTimestamp;
use ibc::core::channel::types::Version;
use ibc::core::host::types::identifiers::{
    ChannelId, ConnectionId, PortId, Sequence,
};
use ibc::core::router::module::Module;
use ibc::core::router::types::module::ModuleExtras;
use ibc::primitives::Signer;
use ibc_middleware_module::MiddlewareModule;
use ibc_middleware_module_macros::from_middleware;
use ibc_middleware_packet_forward::{
    InFlightPacket, InFlightPacketKey, PfmContext,
};
use namada_core::address::{IBC as IBC_ADDRESS, MULTITOKEN};
use namada_state::{StorageRead, StorageWrite};

use crate::context::transfer_mod::TransferModule;
use crate::context::IbcContext;
use crate::storage::inflight_packet_key;
use crate::{Error, IbcCommonContext, IbcStorageContext, TokenTransferContext};

/// A wrapper around an IBC transfer module necessary to
/// build execution contexts. This allows us to implement
/// packet forward middleware on this struct.
pub struct PfmTransferModule<C, Params>
where
    C: IbcCommonContext + Debug,
{
    /// The main module
    pub transfer_module: TransferModule<C>,
    #[allow(missing_docs)]
    pub _phantom: PhantomData<Params>,
}

impl<C: IbcCommonContext + Debug, Params> Debug
    for PfmTransferModule<C, Params>
{
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.debug_struct(stringify!(PfmTransferModule))
            .field("transfer_module", &self.transfer_module)
            .finish_non_exhaustive()
    }
}

from_middleware! {
    impl<C, Params> Module for PfmTransferModule<C, Params>
    where
        C: IbcCommonContext + Debug,
}

impl<C, Params> MiddlewareModule for PfmTransferModule<C, Params>
where
    C: IbcCommonContext + Debug,
{
    type NextMiddleware = TransferModule<C>;

    fn next_middleware(&self) -> &Self::NextMiddleware {
        &self.transfer_module
    }

    fn next_middleware_mut(&mut self) -> &mut Self::NextMiddleware {
        &mut self.transfer_module
    }

    fn middleware_on_recv_packet_execute(
        &mut self,
        packet: &Packet,
        relayer: &Signer,
    ) -> (ModuleExtras, Option<Acknowledgement>) {
        let Ok(packet_data) =
            serde_json::from_slice::<PacketData>(&packet.data)
        else {
            return self
                .transfer_module
                .on_recv_packet_execute(packet, relayer);
        };

        if crate::is_packet_forward(&packet_data) {
            self.transfer_module.ctx.enable_parse_addr_as_governance();
            let ret =
                self.transfer_module.on_recv_packet_execute(packet, relayer);
            self.transfer_module.ctx.disable_parse_addr_as_governance();
            ret
        } else {
            self.transfer_module.on_recv_packet_execute(packet, relayer)
        }
    }
}

impl<C, Params> PfmContext for PfmTransferModule<C, Params>
where
    C: IbcCommonContext + Debug,
    Params: namada_systems::parameters::Read<<C as IbcStorageContext>::Storage>,
{
    type Error = crate::Error;

    fn send_transfer_execute(
        &mut self,
        msg: MsgTransfer,
    ) -> Result<Sequence, Self::Error> {
        let seq = self
            .transfer_module
            .ctx
            .inner
            .borrow()
            .get_next_sequence_send(&msg.port_id_on_a, &msg.chan_id_on_a)
            .map_err(|e| Error::Context(Box::new(e)))?;
        tracing::debug!(?seq, ?msg, "PFM send_transfer_execute");

        let mut ctx = IbcContext::<C, Params>::new(
            self.transfer_module.ctx.inner.clone(),
        );
        let mut token_transfer_ctx = TokenTransferContext::new(
            self.transfer_module.ctx.inner.clone(),
            Default::default(),
        );

        self.transfer_module.ctx.insert_verifier(&MULTITOKEN);

        send_transfer_execute(&mut ctx, &mut token_transfer_ctx, msg)
            .map_err(Error::TokenTransfer)?;

        Ok(seq)
    }

    fn receive_refund_execute(
        &mut self,
        packet: &Packet,
        data: PacketData,
    ) -> Result<(), Self::Error> {
        tracing::debug!(?packet, ?data, "PFM receive_refund_execute");
        let mut token_transfer_ctx = TokenTransferContext::new(
            self.transfer_module.ctx.inner.clone(),
            self.transfer_module.ctx.verifiers.clone(),
        );
        self.transfer_module.ctx.insert_verifier(&MULTITOKEN);
        refund_packet_token_execute(&mut token_transfer_ctx, packet, &data)
            .map_err(Error::TokenTransfer)
    }

    fn send_refund_execute(
        &mut self,
        msg: &InFlightPacket,
    ) -> Result<(), Self::Error> {
        tracing::debug!(?msg, "PFM send_refund_execute");

        let packet_data: PacketData = serde_json::from_slice(&msg.packet_data)
            .expect(
                "The in-flight packet data should have belonged to an ICS-20 \
                 packet",
            );

        let mut token_transfer_ctx = TokenTransferContext::new(
            self.transfer_module.ctx.inner.clone(),
            self.transfer_module.ctx.verifiers.clone(),
        );

        self.transfer_module.ctx.insert_verifier(&MULTITOKEN);

        if is_receiver_chain_source(
            msg.packet_src_port_id.clone(),
            msg.packet_src_channel_id.clone(),
            &packet_data.token.denom,
        ) {
            let coin = {
                let mut c = packet_data.token;
                c.denom.remove_trace_prefix(&TracePrefix::new(
                    msg.packet_src_port_id.clone(),
                    msg.packet_src_channel_id.clone(),
                ));
                c
            };

            token_transfer_ctx
                .escrow_coins_execute(
                    &IBC_ADDRESS,
                    &msg.refund_port_id,
                    &msg.refund_channel_id,
                    &coin,
                    &String::new().into(),
                )
                .map_err(Error::TokenTransfer)
        } else {
            let coin = {
                let mut c = packet_data.token;
                c.denom.add_trace_prefix(TracePrefix::new(
                    msg.refund_port_id.clone(),
                    msg.refund_channel_id.clone(),
                ));
                c
            };

            token_transfer_ctx
                .burn_coins_execute(&IBC_ADDRESS, &coin, &String::new().into())
                .map_err(Error::TokenTransfer)
        }
    }

    fn write_ack_and_events(
        &mut self,
        packet: &Packet,
        acknowledgement: &Acknowledgement,
    ) -> Result<(), Self::Error> {
        tracing::debug!(?packet, ?acknowledgement, "PFM write_ack_and_events");
        let mut ctx = IbcContext::<C, Params>::new(
            self.transfer_module.ctx.inner.clone(),
        );
        commit_packet_acknowledgment(&mut ctx, packet, acknowledgement)
            .map_err(|e| Error::Context(Box::new(e)))?;
        emit_packet_acknowledgement_event(
            &mut ctx,
            packet.clone(),
            acknowledgement.clone(),
        )
        .map_err(|e| Error::Context(Box::new(e)))
    }

    fn override_receiver(
        &self,
        _channel: &ChannelId,
        _original_sender: &Signer,
    ) -> Result<Signer, Self::Error> {
        Ok(IBC_ADDRESS.to_string().into())
    }

    #[allow(clippy::arithmetic_side_effects)]
    fn timeout_timestamp(
        &self,
        timeout_duration: dur::Duration,
    ) -> Result<TimeoutTimestamp, Self::Error> {
        let timestamp = self
            .transfer_module
            .ctx
            .inner
            .borrow()
            .host_timestamp()
            .map_err(|e| Error::Other(e.to_string()))?
            + timeout_duration.try_to_std().ok_or_else(|| {
                Error::Other(format!(
                    "Packet timeout duration is too large: {timeout_duration}"
                ))
            })?;
        let ts = timestamp
            .map(TimeoutTimestamp::At)
            .map_err(|e| Error::Other(e.to_string()))?;
        tracing::debug!(timeout_timestamp = ?ts, "PFM timeout_timestamp");
        Ok(ts)
    }

    fn store_inflight_packet(
        &mut self,
        key: InFlightPacketKey,
        inflight_packet: InFlightPacket,
    ) -> Result<(), Self::Error> {
        tracing::debug!(?key, ?inflight_packet, "PFM store_inflight_packet");
        let mut ctx = self.transfer_module.ctx.inner.borrow_mut();
        let key = inflight_packet_key(&key);
        ctx.storage_mut()
            .write(&key, inflight_packet)
            .map_err(Error::Storage)
    }

    fn retrieve_inflight_packet(
        &self,
        key: &InFlightPacketKey,
    ) -> Result<Option<InFlightPacket>, Self::Error> {
        let mut ctx = self.transfer_module.ctx.inner.borrow_mut();
        let key = inflight_packet_key(key);
        let packet = ctx.storage_mut().read(&key).map_err(Error::Storage);

        tracing::debug!(?key, ?packet, "PFM retrieve_inflight_packet");

        packet
    }

    fn delete_inflight_packet(
        &mut self,
        key: &InFlightPacketKey,
    ) -> Result<(), Self::Error> {
        tracing::debug!(?key, "PFM delete_inflight_packet");
        let mut ctx = self.transfer_module.ctx.inner.borrow_mut();
        let key = inflight_packet_key(key);
        ctx.storage_mut().delete(&key).map_err(Error::Storage)
    }
}
