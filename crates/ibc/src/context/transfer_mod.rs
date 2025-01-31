//! IBC module for token transfer

use std::cell::RefCell;
use std::collections::BTreeSet;
use std::fmt::Debug;
use std::marker::PhantomData;
use std::rc::Rc;

use ibc::apps::transfer::context::TokenTransferValidationContext;
use ibc::apps::transfer::module::{
    on_acknowledgement_packet_execute, on_acknowledgement_packet_validate,
    on_chan_close_confirm_execute, on_chan_close_confirm_validate,
    on_chan_close_init_execute, on_chan_close_init_validate,
    on_chan_open_ack_execute, on_chan_open_ack_validate,
    on_chan_open_confirm_execute, on_chan_open_confirm_validate,
    on_chan_open_init_execute, on_chan_open_init_validate,
    on_chan_open_try_execute, on_chan_open_try_validate,
    on_recv_packet_execute, on_timeout_packet_execute,
    on_timeout_packet_validate,
};
use ibc::apps::transfer::types::error::TokenTransferError;
use ibc::apps::transfer::types::MODULE_ID_STR;
use ibc::core::channel::types::acknowledgement::{
    Acknowledgement, AcknowledgementStatus,
};
use ibc::core::channel::types::channel::{Counterparty, Order};
use ibc::core::channel::types::error::{ChannelError, PacketError};
use ibc::core::channel::types::packet::Packet;
use ibc::core::channel::types::Version;
use ibc::core::host::types::identifiers::{ChannelId, ConnectionId, PortId};
use ibc::core::router::module::Module;
use ibc::core::router::types::module::{ModuleExtras, ModuleId};
use ibc::primitives::Signer;
use namada_core::address::Address;

use crate::{
    try_replace_sender_for_shielded_refund, IbcCommonContext,
    IbcStorageContext, TokenTransferContext,
};

/// IBC module wrapper for getting the reference of the module
pub trait ModuleWrapper: Module {
    /// Reference of the module
    fn as_module(&self) -> &dyn Module;

    /// Mutable reference of the module
    fn as_module_mut(&mut self) -> &mut dyn Module;

    /// Get the module ID
    fn module_id(&self) -> ModuleId;

    /// Get the port ID
    fn port_id(&self) -> PortId;
}

/// IBC module for token transfer
#[derive(Debug)]
pub struct TransferModule<C, Params>
where
    C: IbcCommonContext,
{
    /// IBC actions
    pub ctx: TokenTransferContext<C>,
    _marker: PhantomData<Params>,
}

impl<C, Params> TransferModule<C, Params>
where
    C: IbcCommonContext,
    Params: namada_systems::parameters::Read<<C as IbcStorageContext>::Storage>,
{
    /// Make a new module
    pub fn new(
        ctx: Rc<RefCell<C>>,
        verifiers: Rc<RefCell<BTreeSet<Address>>>,
    ) -> Self {
        Self {
            ctx: TokenTransferContext::new(ctx, verifiers),
            _marker: PhantomData,
        }
    }
}

impl<C, Params> ModuleWrapper for TransferModule<C, Params>
where
    C: IbcCommonContext + Debug,
    Params: namada_systems::parameters::Read<<C as IbcStorageContext>::Storage>
        + Debug,
{
    fn as_module(&self) -> &dyn Module {
        self
    }

    fn as_module_mut(&mut self) -> &mut dyn Module {
        self
    }

    fn module_id(&self) -> ModuleId {
        ModuleId::new(MODULE_ID_STR.to_string())
    }

    fn port_id(&self) -> PortId {
        self.ctx.get_port().expect("The port ID should be set")
    }
}

impl<C, Params> Module for TransferModule<C, Params>
where
    C: IbcCommonContext + Debug,
    Params: namada_systems::parameters::Read<<C as IbcStorageContext>::Storage>
        + Debug,
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
            &self.ctx,
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
            &mut self.ctx,
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
            &self.ctx,
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
            &mut self.ctx,
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
            &self.ctx,
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
            &mut self.ctx,
            port_id,
            channel_id,
            counterparty_version,
        )
        .map_err(into_channel_error)
    }

    fn on_chan_open_confirm_validate(
        &self,
        port_id: &PortId,
        channel_id: &ChannelId,
    ) -> Result<(), ChannelError> {
        on_chan_open_confirm_validate(&self.ctx, port_id, channel_id)
            .map_err(into_channel_error)
    }

    fn on_chan_open_confirm_execute(
        &mut self,
        port_id: &PortId,
        channel_id: &ChannelId,
    ) -> Result<ModuleExtras, ChannelError> {
        on_chan_open_confirm_execute(&mut self.ctx, port_id, channel_id)
            .map_err(into_channel_error)
    }

    fn on_chan_close_init_validate(
        &self,
        port_id: &PortId,
        channel_id: &ChannelId,
    ) -> Result<(), ChannelError> {
        on_chan_close_init_validate(&self.ctx, port_id, channel_id)
            .map_err(into_channel_error)
    }

    fn on_chan_close_init_execute(
        &mut self,
        port_id: &PortId,
        channel_id: &ChannelId,
    ) -> Result<ModuleExtras, ChannelError> {
        on_chan_close_init_execute(&mut self.ctx, port_id, channel_id)
            .map_err(into_channel_error)
    }

    fn on_chan_close_confirm_validate(
        &self,
        port_id: &PortId,
        channel_id: &ChannelId,
    ) -> Result<(), ChannelError> {
        on_chan_close_confirm_validate(&self.ctx, port_id, channel_id)
            .map_err(into_channel_error)
    }

    fn on_chan_close_confirm_execute(
        &mut self,
        port_id: &PortId,
        channel_id: &ChannelId,
    ) -> Result<ModuleExtras, ChannelError> {
        on_chan_close_confirm_execute(&mut self.ctx, port_id, channel_id)
            .map_err(into_channel_error)
    }

    fn on_recv_packet_execute(
        &mut self,
        packet: &Packet,
        _relayer: &Signer,
    ) -> (ModuleExtras, Option<Acknowledgement>) {
        on_recv_packet_execute(&mut self.ctx, packet)
    }

    fn on_acknowledgement_packet_validate(
        &self,
        packet: &Packet,
        acknowledgement: &Acknowledgement,
        relayer: &Signer,
    ) -> Result<(), PacketError> {
        on_acknowledgement_packet_validate(
            &self.ctx,
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
        let updated_packet = serde_json::from_slice::<AcknowledgementStatus>(
            acknowledgement.as_ref(),
        )
        .ok()
        .and_then(|ack| {
            if ack.is_successful() {
                return None;
            }
            try_replace_sender_for_shielded_refund::<
                <C as IbcStorageContext>::Storage,
                Params,
            >(self.ctx.inner.borrow().storage(), packet)
        });

        let (extras, result) = match updated_packet {
            Some(packet) => on_acknowledgement_packet_execute(
                &mut self.ctx,
                &packet,
                acknowledgement,
                relayer,
            ),
            None => on_acknowledgement_packet_execute(
                &mut self.ctx,
                packet,
                acknowledgement,
                relayer,
            ),
        };
        (extras, result.map_err(into_packet_error))
    }

    fn on_timeout_packet_validate(
        &self,
        packet: &Packet,
        relayer: &Signer,
    ) -> Result<(), PacketError> {
        on_timeout_packet_validate(&self.ctx, packet, relayer)
            .map_err(into_packet_error)
    }

    fn on_timeout_packet_execute(
        &mut self,
        packet: &Packet,
        relayer: &Signer,
    ) -> (ModuleExtras, Result<(), PacketError>) {
        let updated_packet =
            try_replace_sender_for_shielded_refund::<
                <C as IbcStorageContext>::Storage,
                Params,
            >(self.ctx.inner.borrow().storage(), packet);

        let (extras, result) = if let Some(packet) = updated_packet {
            on_timeout_packet_execute(&mut self.ctx, &packet, relayer)
        } else {
            on_timeout_packet_execute(&mut self.ctx, packet, relayer)
        };
        (extras, result.map_err(into_packet_error))
    }
}

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

/// Helpers for testing
#[cfg(any(test, feature = "testing"))]
pub mod testing {
    use std::str::FromStr;

    use ibc::apps::transfer::types::{ack_success_b64, PORT_ID_STR};
    use ibc::core::channel::types::acknowledgement::AcknowledgementStatus;

    use super::*;

    /// Dummy IBC module for token transfer
    #[derive(Debug)]
    pub struct DummyTransferModule {}

    impl ModuleWrapper for DummyTransferModule {
        fn as_module(&self) -> &dyn Module {
            self
        }

        fn as_module_mut(&mut self) -> &mut dyn Module {
            self
        }

        fn module_id(&self) -> ModuleId {
            ModuleId::new(MODULE_ID_STR.to_string())
        }

        fn port_id(&self) -> PortId {
            PortId::from_str(PORT_ID_STR).unwrap()
        }
    }

    impl Module for DummyTransferModule {
        #[allow(clippy::too_many_arguments)]
        fn on_chan_open_init_validate(
            &self,
            _order: Order,
            _connection_hops: &[ConnectionId],
            _port_id: &PortId,
            _channel_id: &ChannelId,
            _counterparty: &Counterparty,
            version: &Version,
        ) -> Result<Version, ChannelError> {
            Ok(version.clone())
        }

        #[allow(clippy::too_many_arguments)]
        fn on_chan_open_init_execute(
            &mut self,
            _order: Order,
            _connection_hops: &[ConnectionId],
            _port_id: &PortId,
            _channel_id: &ChannelId,
            _counterparty: &Counterparty,
            version: &Version,
        ) -> Result<(ModuleExtras, Version), ChannelError> {
            Ok((ModuleExtras::empty(), version.clone()))
        }

        #[allow(clippy::too_many_arguments)]
        fn on_chan_open_try_validate(
            &self,
            _order: Order,
            _connection_hops: &[ConnectionId],
            _port_id: &PortId,
            _channel_id: &ChannelId,
            _counterparty: &Counterparty,
            counterparty_version: &Version,
        ) -> Result<Version, ChannelError> {
            Ok(counterparty_version.clone())
        }

        #[allow(clippy::too_many_arguments)]
        fn on_chan_open_try_execute(
            &mut self,
            _order: Order,
            _connection_hops: &[ConnectionId],
            _port_id: &PortId,
            _channel_id: &ChannelId,
            _counterparty: &Counterparty,
            counterparty_version: &Version,
        ) -> Result<(ModuleExtras, Version), ChannelError> {
            Ok((ModuleExtras::empty(), counterparty_version.clone()))
        }

        fn on_chan_open_ack_validate(
            &self,
            _port_id: &PortId,
            _channel_id: &ChannelId,
            _counterparty_version: &Version,
        ) -> Result<(), ChannelError> {
            Ok(())
        }

        fn on_chan_open_ack_execute(
            &mut self,
            _port_id: &PortId,
            _channel_id: &ChannelId,
            _counterparty_version: &Version,
        ) -> Result<ModuleExtras, ChannelError> {
            Ok(ModuleExtras::empty())
        }

        fn on_chan_open_confirm_validate(
            &self,
            _port_id: &PortId,
            _channel_id: &ChannelId,
        ) -> Result<(), ChannelError> {
            Ok(())
        }

        fn on_chan_open_confirm_execute(
            &mut self,
            _port_id: &PortId,
            _channel_id: &ChannelId,
        ) -> Result<ModuleExtras, ChannelError> {
            Ok(ModuleExtras::empty())
        }

        fn on_chan_close_init_validate(
            &self,
            _port_id: &PortId,
            _channel_id: &ChannelId,
        ) -> Result<(), ChannelError> {
            Ok(())
        }

        fn on_chan_close_init_execute(
            &mut self,
            _port_id: &PortId,
            _channel_id: &ChannelId,
        ) -> Result<ModuleExtras, ChannelError> {
            Ok(ModuleExtras::empty())
        }

        fn on_chan_close_confirm_validate(
            &self,
            _port_id: &PortId,
            _channel_id: &ChannelId,
        ) -> Result<(), ChannelError> {
            Ok(())
        }

        fn on_chan_close_confirm_execute(
            &mut self,
            _port_id: &PortId,
            _channel_id: &ChannelId,
        ) -> Result<ModuleExtras, ChannelError> {
            Ok(ModuleExtras::empty())
        }

        fn on_recv_packet_execute(
            &mut self,
            _packet: &Packet,
            _relayer: &Signer,
        ) -> (ModuleExtras, Option<Acknowledgement>) {
            (
                ModuleExtras::empty(),
                Some(AcknowledgementStatus::success(ack_success_b64()).into()),
            )
        }

        fn on_acknowledgement_packet_validate(
            &self,
            _packet: &Packet,
            _acknowledgement: &Acknowledgement,
            _relayer: &Signer,
        ) -> Result<(), PacketError> {
            Ok(())
        }

        fn on_acknowledgement_packet_execute(
            &mut self,
            _packet: &Packet,
            _acknowledgement: &Acknowledgement,
            _relayer: &Signer,
        ) -> (ModuleExtras, Result<(), PacketError>) {
            (ModuleExtras::empty(), Ok(()))
        }

        fn on_timeout_packet_validate(
            &self,
            _packet: &Packet,
            _relayer: &Signer,
        ) -> Result<(), PacketError> {
            Ok(())
        }

        fn on_timeout_packet_execute(
            &mut self,
            _packet: &Packet,
            _relayer: &Signer,
        ) -> (ModuleExtras, Result<(), PacketError>) {
            (ModuleExtras::empty(), Ok(()))
        }
    }
}
