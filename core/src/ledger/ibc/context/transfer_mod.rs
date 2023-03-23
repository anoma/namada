//! IBC module for token transfer

use std::cell::RefCell;
use std::fmt::Debug;
use std::rc::Rc;
use std::str::FromStr;

use super::common::IbcCommonContext;
use crate::ibc::applications::transfer::coin::PrefixedCoin;
use crate::ibc::applications::transfer::context::{
    on_acknowledgement_packet_execute, on_acknowledgement_packet_validate,
    on_chan_close_confirm_execute, on_chan_close_confirm_validate,
    on_chan_close_init_execute, on_chan_close_init_validate,
    on_chan_open_ack_execute, on_chan_open_ack_validate,
    on_chan_open_confirm_execute, on_chan_open_confirm_validate,
    on_chan_open_init_execute, on_chan_open_init_validate,
    on_chan_open_try_execute, on_chan_open_try_validate,
    on_recv_packet_execute, on_timeout_packet_execute,
    on_timeout_packet_validate, TokenTransferExecutionContext,
    TokenTransferValidationContext,
};
use crate::ibc::applications::transfer::denom::PrefixedDenom;
use crate::ibc::applications::transfer::error::TokenTransferError;
use crate::ibc::applications::transfer::MODULE_ID_STR;
use crate::ibc::core::ics02_client::client_state::ClientState;
use crate::ibc::core::ics02_client::consensus_state::ConsensusState;
use crate::ibc::core::ics03_connection::connection::ConnectionEnd;
use crate::ibc::core::ics04_channel::channel::{
    ChannelEnd, Counterparty, Order,
};
use crate::ibc::core::ics04_channel::commitment::PacketCommitment;
use crate::ibc::core::ics04_channel::context::{
    SendPacketExecutionContext, SendPacketValidationContext,
};
use crate::ibc::core::ics04_channel::error::{ChannelError, PacketError};
use crate::ibc::core::ics04_channel::handler::ModuleExtras;
use crate::ibc::core::ics04_channel::msgs::acknowledgement::Acknowledgement;
use crate::ibc::core::ics04_channel::packet::{Packet, Sequence};
use crate::ibc::core::ics04_channel::Version;
use crate::ibc::core::ics24_host::identifier::{
    ChannelId, ClientId, ConnectionId, PortId,
};
use crate::ibc::core::ics24_host::path::{
    ChannelEndPath, ClientConsensusStatePath, CommitmentPath, SeqSendPath,
};
use crate::ibc::core::ics26_routing::context::{Module, ModuleId};
use crate::ibc::core::ContextError;
use crate::ibc::events::IbcEvent;
use crate::ibc::signer::Signer;
use crate::ledger::ibc::storage;
use crate::types::address::{Address, InternalAddress};
use crate::types::token;

/// IBC module wrapper for getting the reference of the module
pub trait ModuleWrapper: Module {
    /// Reference of the module
    fn as_module(&self) -> &dyn Module;

    /// Mutable reference of the module
    fn as_module_mut(&mut self) -> &mut dyn Module;
}

/// IBC module for token transfer
#[derive(Debug)]
pub struct TransferModule<C>
where
    C: IbcCommonContext,
{
    /// IBC actions
    pub ctx: Rc<RefCell<C>>,
}

impl<C> TransferModule<C>
where
    C: IbcCommonContext,
{
    /// Make a new module
    pub fn new(ctx: Rc<RefCell<C>>) -> Self {
        Self { ctx }
    }

    /// Get the module ID
    pub fn module_id(&self) -> ModuleId {
        ModuleId::from_str(MODULE_ID_STR).expect("should be parsable")
    }
}

impl<C> ModuleWrapper for TransferModule<C>
where
    C: IbcCommonContext + Debug,
{
    fn as_module(&self) -> &dyn Module {
        self
    }

    fn as_module_mut(&mut self) -> &mut dyn Module {
        self
    }
}

impl<C> Module for TransferModule<C>
where
    C: IbcCommonContext + Debug,
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

    fn on_recv_packet_execute(
        &mut self,
        packet: &Packet,
        _relayer: &Signer,
    ) -> (ModuleExtras, Acknowledgement) {
        on_recv_packet_execute(self, packet)
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
}

impl<C> SendPacketValidationContext for TransferModule<C>
where
    C: IbcCommonContext,
{
    fn channel_end(
        &self,
        channel_end_path: &ChannelEndPath,
    ) -> Result<ChannelEnd, ContextError> {
        self.ctx.borrow().channel_end(channel_end_path)
    }

    fn connection_end(
        &self,
        connection_id: &ConnectionId,
    ) -> Result<ConnectionEnd, ContextError> {
        self.ctx.borrow().connection_end(connection_id)
    }

    fn client_state(
        &self,
        client_id: &ClientId,
    ) -> Result<Box<dyn ClientState>, ContextError> {
        self.ctx.borrow().client_state(client_id)
    }

    fn client_consensus_state(
        &self,
        client_cons_state_path: &ClientConsensusStatePath,
    ) -> Result<Box<dyn ConsensusState>, ContextError> {
        self.ctx.borrow().consensus_state(client_cons_state_path)
    }

    fn get_next_sequence_send(
        &self,
        seq_send_path: &SeqSendPath,
    ) -> Result<Sequence, ContextError> {
        self.ctx.borrow().get_next_sequence_send(seq_send_path)
    }
}

impl<C> TokenTransferValidationContext for TransferModule<C>
where
    C: IbcCommonContext,
{
    type AccountId = Address;

    fn get_port(&self) -> Result<PortId, TokenTransferError> {
        Ok(PortId::transfer())
    }

    fn get_escrow_account(
        &self,
        _port_id: &PortId,
        _channel_id: &ChannelId,
    ) -> Result<Self::AccountId, TokenTransferError> {
        Ok(Address::Internal(InternalAddress::IbcEscrow))
    }

    fn can_send_coins(&self) -> Result<(), TokenTransferError> {
        Ok(())
    }

    fn can_receive_coins(&self) -> Result<(), TokenTransferError> {
        Ok(())
    }

    fn send_coins_validate(
        &self,
        _from: &Self::AccountId,
        _to: &Self::AccountId,
        _coin: &PrefixedCoin,
    ) -> Result<(), TokenTransferError> {
        // validated by IBC token VP
        Ok(())
    }

    fn mint_coins_validate(
        &self,
        _account: &Self::AccountId,
        _coin: &PrefixedCoin,
    ) -> Result<(), TokenTransferError> {
        // validated by IBC token VP
        Ok(())
    }

    fn burn_coins_validate(
        &self,
        _account: &Self::AccountId,
        _coin: &PrefixedCoin,
    ) -> Result<(), TokenTransferError> {
        // validated by IBC token VP
        Ok(())
    }

    fn denom_hash_string(&self, denom: &PrefixedDenom) -> Option<String> {
        Some(storage::calc_hash(denom.to_string()))
    }
}

impl<C> TokenTransferExecutionContext for TransferModule<C>
where
    C: IbcCommonContext,
{
    fn send_coins_execute(
        &mut self,
        from: &Self::AccountId,
        to: &Self::AccountId,
        coin: &PrefixedCoin,
    ) -> Result<(), TokenTransferError> {
        // Assumes that the coin denom is prefixed with "port-id/channel-id" or
        // has no prefix
        let (token, amount) = get_token_amount(coin)?;

        let src = if coin.denom.trace_path.is_empty()
            || *from == Address::Internal(InternalAddress::IbcEscrow)
            || *from == Address::Internal(InternalAddress::IbcMint)
        {
            token::balance_key(&token, from)
        } else {
            let prefix = storage::ibc_token_prefix(coin.denom.to_string())
                .map_err(|_| TokenTransferError::InvalidCoin {
                    coin: coin.to_string(),
                })?;
            token::multitoken_balance_key(&prefix, from)
        };

        let dest = if coin.denom.trace_path.is_empty()
            || *to == Address::Internal(InternalAddress::IbcEscrow)
            || *to == Address::Internal(InternalAddress::IbcBurn)
        {
            token::balance_key(&token, to)
        } else {
            let prefix = storage::ibc_token_prefix(coin.denom.to_string())
                .map_err(|_| TokenTransferError::InvalidCoin {
                    coin: coin.to_string(),
                })?;
            token::multitoken_balance_key(&prefix, to)
        };

        self.ctx
            .borrow_mut()
            .transfer_token(&src, &dest, amount)
            .map_err(|_| {
                TokenTransferError::ContextError(ContextError::ChannelError(
                    ChannelError::Other {
                        description: format!(
                            "Sending a coin failed: from {}, to {}, amount {}",
                            src, dest, amount
                        ),
                    },
                ))
            })
    }

    fn mint_coins_execute(
        &mut self,
        account: &Self::AccountId,
        coin: &PrefixedCoin,
    ) -> Result<(), TokenTransferError> {
        let (token, amount) = get_token_amount(coin)?;

        let src = token::balance_key(
            &token,
            &Address::Internal(InternalAddress::IbcMint),
        );

        let dest = if coin.denom.trace_path.is_empty() {
            token::balance_key(&token, account)
        } else {
            let prefix = storage::ibc_token_prefix(coin.denom.to_string())
                .map_err(|_| TokenTransferError::InvalidCoin {
                    coin: coin.to_string(),
                })?;
            token::multitoken_balance_key(&prefix, account)
        };

        self.ctx
            .borrow_mut()
            .transfer_token(&src, &dest, amount)
            .map_err(|_| {
                TokenTransferError::ContextError(ContextError::ChannelError(
                    ChannelError::Other {
                        description: format!(
                            "Sending a coin failed: from {}, to {}, amount {}",
                            src, dest, amount
                        ),
                    },
                ))
            })
    }

    fn burn_coins_execute(
        &mut self,
        account: &Self::AccountId,
        coin: &PrefixedCoin,
    ) -> Result<(), TokenTransferError> {
        let (token, amount) = get_token_amount(coin)?;

        let src = if coin.denom.trace_path.is_empty() {
            token::balance_key(&token, account)
        } else {
            let prefix = storage::ibc_token_prefix(coin.denom.to_string())
                .map_err(|_| TokenTransferError::InvalidCoin {
                    coin: coin.to_string(),
                })?;
            token::multitoken_balance_key(&prefix, account)
        };

        let dest = token::balance_key(
            &token,
            &Address::Internal(InternalAddress::IbcBurn),
        );

        self.ctx
            .borrow_mut()
            .transfer_token(&src, &dest, amount)
            .map_err(|_| {
                TokenTransferError::ContextError(ContextError::ChannelError(
                    ChannelError::Other {
                        description: format!(
                            "Sending a coin failed: from {}, to {}, amount {}",
                            src, dest, amount
                        ),
                    },
                ))
            })
    }
}

impl<C> SendPacketExecutionContext for TransferModule<C>
where
    C: IbcCommonContext,
{
    fn store_next_sequence_send(
        &mut self,
        seq_send_path: &SeqSendPath,
        seq: Sequence,
    ) -> Result<(), ContextError> {
        self.ctx
            .borrow_mut()
            .store_next_sequence_send(seq_send_path, seq)
    }

    fn store_packet_commitment(
        &mut self,
        commitment_path: &CommitmentPath,
        commitment: PacketCommitment,
    ) -> Result<(), ContextError> {
        self.ctx
            .borrow_mut()
            .store_packet_commitment(commitment_path, commitment)
    }

    fn emit_ibc_event(&mut self, event: IbcEvent) {
        let event = event.try_into().expect("IBC event conversion failed");
        self.ctx
            .borrow_mut()
            .emit_ibc_event(event)
            .expect("Emitting an IBC event failed")
    }

    fn log_message(&mut self, message: String) {
        self.ctx.borrow_mut().log_string(message)
    }
}

/// Get the token address and the amount from PrefixedCoin
fn get_token_amount(
    coin: &PrefixedCoin,
) -> Result<(Address, token::Amount), TokenTransferError> {
    let token =
        Address::decode(coin.denom.base_denom.as_str()).map_err(|_| {
            TokenTransferError::InvalidCoin {
                coin: coin.denom.base_denom.to_string(),
            }
        })?;

    let amount = coin.amount.try_into().map_err(|_| {
        TokenTransferError::InvalidCoin {
            coin: coin.to_string(),
        }
    })?;

    Ok((token, amount))
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
    use super::*;
    use crate::ibc::applications::transfer::acknowledgement::TokenTransferAcknowledgement;

    /// Dummy IBC module for token transfer
    #[derive(Debug)]
    pub struct DummyTransferModule {}

    impl DummyTransferModule {
        /// Get the module ID
        pub fn module_id(&self) -> ModuleId {
            ModuleId::from_str(MODULE_ID_STR).expect("should be parsable")
        }
    }

    impl ModuleWrapper for DummyTransferModule {
        fn as_module(&self) -> &dyn Module {
            self
        }

        fn as_module_mut(&mut self) -> &mut dyn Module {
            self
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
        ) -> (ModuleExtras, Acknowledgement) {
            let transfer_ack = TokenTransferAcknowledgement::success();
            (ModuleExtras::empty(), transfer_ack.into())
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
