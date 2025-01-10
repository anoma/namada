//! Implementation of Packet Forward Middleware on top of the ICS-20
//! [`TransferModule`].

use std::cell::RefCell;
use std::collections::BTreeSet;
use std::fmt::{Debug, Formatter};
use std::marker::PhantomData;
use std::rc::Rc;

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
use ibc::core::router::types::module::{ModuleExtras, ModuleId};
use ibc::primitives::Signer;
use ibc_middleware_packet_forward::{
    InFlightPacket, InFlightPacketKey, PacketForwardMiddleware, PfmContext,
};
use namada_core::address::{Address, IBC as IBC_ADDRESS, MULTITOKEN};
use namada_core::storage::{self, KeySeg};
use namada_state::{StorageRead, StorageWrite};

use crate::context::transfer_mod::TransferModule;
use crate::context::IbcContext;
use crate::{
    Error, IbcCommonContext, IbcStorageContext, ModuleWrapper,
    TokenTransferContext,
};

const MIDDLEWARES_SUBKEY: &str = "middleware";
const PFM_SUBKEY: &str = "pfm";

/// Get the Namada storage key associated to the provided `InFlightPacketKey`.
pub fn get_inflight_packet_key(
    inflight_packet_key: &InFlightPacketKey,
) -> storage::Key {
    let key: storage::Key = IBC_ADDRESS.to_db_key().into();
    key.with_segment(MIDDLEWARES_SUBKEY.to_string())
        .with_segment(PFM_SUBKEY.to_string())
        .with_segment(inflight_packet_key.port.to_string())
        .with_segment(inflight_packet_key.channel.to_string())
        .with_segment(inflight_packet_key.sequence.to_string())
}

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

impl<C, Params> PfmTransferModule<C, Params>
where
    C: IbcCommonContext + Debug,
{
    /// Create a new [`PfmTransferModule`]
    pub fn wrap(
        ctx: Rc<RefCell<C>>,
        verifiers: Rc<RefCell<BTreeSet<Address>>>,
    ) -> PacketForwardMiddleware<Self> {
        PacketForwardMiddleware::next(Self {
            transfer_module: TransferModule::new(ctx, verifiers),
            _phantom: Default::default(),
        })
    }
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

impl<C, Params> Module for PfmTransferModule<C, Params>
where
    C: IbcCommonContext + Debug,
{
    fn on_chan_open_init_validate(
        &self,
        order: Order,
        connection_hops: &[ConnectionId],
        port_id: &PortId,
        channel_id: &ChannelId,
        counterparty: &Counterparty,
        version: &Version,
    ) -> Result<Version, ChannelError> {
        self.transfer_module.on_chan_open_init_validate(
            order,
            connection_hops,
            port_id,
            channel_id,
            counterparty,
            version,
        )
    }

    fn on_chan_open_init_execute(
        &mut self,
        order: Order,
        connection_hops: &[ConnectionId],
        port_id: &PortId,
        channel_id: &ChannelId,
        counterparty: &Counterparty,
        version: &Version,
    ) -> Result<(ModuleExtras, Version), ChannelError> {
        self.transfer_module.on_chan_open_init_execute(
            order,
            connection_hops,
            port_id,
            channel_id,
            counterparty,
            version,
        )
    }

    fn on_chan_open_try_validate(
        &self,
        order: Order,
        connection_hops: &[ConnectionId],
        port_id: &PortId,
        channel_id: &ChannelId,
        counterparty: &Counterparty,
        counterparty_version: &Version,
    ) -> Result<Version, ChannelError> {
        self.transfer_module.on_chan_open_try_validate(
            order,
            connection_hops,
            port_id,
            channel_id,
            counterparty,
            counterparty_version,
        )
    }

    fn on_chan_open_try_execute(
        &mut self,
        order: Order,
        connection_hops: &[ConnectionId],
        port_id: &PortId,
        channel_id: &ChannelId,
        counterparty: &Counterparty,
        counterparty_version: &Version,
    ) -> Result<(ModuleExtras, Version), ChannelError> {
        self.transfer_module.on_chan_open_try_execute(
            order,
            connection_hops,
            port_id,
            channel_id,
            counterparty,
            counterparty_version,
        )
    }

    fn on_chan_open_ack_validate(
        &self,
        port_id: &PortId,
        channel_id: &ChannelId,
        counterparty_version: &Version,
    ) -> Result<(), ChannelError> {
        self.transfer_module.on_chan_open_ack_validate(
            port_id,
            channel_id,
            counterparty_version,
        )
    }

    fn on_chan_open_ack_execute(
        &mut self,
        port_id: &PortId,
        channel_id: &ChannelId,
        counterparty_version: &Version,
    ) -> Result<ModuleExtras, ChannelError> {
        self.transfer_module.on_chan_open_ack_execute(
            port_id,
            channel_id,
            counterparty_version,
        )
    }

    fn on_chan_open_confirm_validate(
        &self,
        port_id: &PortId,
        channel_id: &ChannelId,
    ) -> Result<(), ChannelError> {
        self.transfer_module
            .on_chan_open_confirm_validate(port_id, channel_id)
    }

    fn on_chan_open_confirm_execute(
        &mut self,
        port_id: &PortId,
        channel_id: &ChannelId,
    ) -> Result<ModuleExtras, ChannelError> {
        self.transfer_module
            .on_chan_open_confirm_execute(port_id, channel_id)
    }

    fn on_chan_close_init_validate(
        &self,
        port_id: &PortId,
        channel_id: &ChannelId,
    ) -> Result<(), ChannelError> {
        self.transfer_module
            .on_chan_close_init_validate(port_id, channel_id)
    }

    fn on_chan_close_init_execute(
        &mut self,
        port_id: &PortId,
        channel_id: &ChannelId,
    ) -> Result<ModuleExtras, ChannelError> {
        self.transfer_module
            .on_chan_close_init_execute(port_id, channel_id)
    }

    fn on_chan_close_confirm_validate(
        &self,
        port_id: &PortId,
        channel_id: &ChannelId,
    ) -> Result<(), ChannelError> {
        self.transfer_module
            .on_chan_close_confirm_validate(port_id, channel_id)
    }

    fn on_chan_close_confirm_execute(
        &mut self,
        port_id: &PortId,
        channel_id: &ChannelId,
    ) -> Result<ModuleExtras, ChannelError> {
        self.transfer_module
            .on_chan_close_confirm_execute(port_id, channel_id)
    }

    fn on_recv_packet_execute(
        &mut self,
        packet: &Packet,
        relayer: &Signer,
    ) -> (ModuleExtras, Option<Acknowledgement>) {
        self.transfer_module.on_recv_packet_execute(packet, relayer)
    }

    fn on_acknowledgement_packet_validate(
        &self,
        packet: &Packet,
        acknowledgement: &Acknowledgement,
        relayer: &Signer,
    ) -> Result<(), PacketError> {
        self.transfer_module.on_acknowledgement_packet_validate(
            packet,
            acknowledgement,
            relayer,
        )
    }

    fn on_acknowledgement_packet_execute(
        &mut self,
        packet: &Packet,
        acknowledgement: &Acknowledgement,
        relayer: &Signer,
    ) -> (ModuleExtras, Result<(), PacketError>) {
        self.transfer_module.on_acknowledgement_packet_execute(
            packet,
            acknowledgement,
            relayer,
        )
    }

    fn on_timeout_packet_validate(
        &self,
        packet: &Packet,
        relayer: &Signer,
    ) -> Result<(), PacketError> {
        self.transfer_module
            .on_timeout_packet_validate(packet, relayer)
    }

    fn on_timeout_packet_execute(
        &mut self,
        packet: &Packet,
        relayer: &Signer,
    ) -> (ModuleExtras, Result<(), PacketError>) {
        self.transfer_module
            .on_timeout_packet_execute(packet, relayer)
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
        let key = get_inflight_packet_key(&key);
        ctx.storage_mut()
            .write(&key, inflight_packet)
            .map_err(Error::Storage)
    }

    fn retrieve_inflight_packet(
        &self,
        key: &InFlightPacketKey,
    ) -> Result<Option<InFlightPacket>, Self::Error> {
        let mut ctx = self.transfer_module.ctx.inner.borrow_mut();
        let key = get_inflight_packet_key(key);
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
        let key = get_inflight_packet_key(key);
        ctx.storage_mut().delete(&key).map_err(Error::Storage)
    }
}

impl<T> ModuleWrapper for PacketForwardMiddleware<T>
where
    T: Module + PfmContext,
{
    fn as_module(&self) -> &dyn Module {
        self
    }

    fn as_module_mut(&mut self) -> &mut dyn Module {
        self
    }

    fn module_id(&self) -> ModuleId {
        ModuleId::new(ibc::apps::transfer::types::MODULE_ID_STR.to_string())
    }

    fn port_id(&self) -> PortId {
        PortId::transfer()
    }
}
