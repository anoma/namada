//! IBC module for token transfer

use std::fmt::Debug;
use std::str::FromStr;

use super::super::{IbcActions, IbcStorageContext};
use crate::ibc::applications::transfer::coin::PrefixedCoin;
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
use crate::ibc::core::ics04_channel::context::SendPacketReader;
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
use crate::ibc::core::ics26_routing::context::{
    Module, ModuleId, ModuleOutputBuilder,
};
use crate::ibc::core::{ContextError, ExecutionContext, ValidationContext};
use crate::ibc::signer::Signer;
use crate::ledger::ibc::storage;
use crate::types::address::{Address, InternalAddress};
use crate::types::token;

/// IBC module for token transfer
#[derive(Debug)]
pub struct TransferModule<C>
where
    C: IbcStorageContext + 'static,
{
    /// IBC actions
    pub ctx: &'static mut IbcActions<C>,
}

impl<C> TransferModule<C>
where
    C: IbcStorageContext + 'static,
{
    /// Make a new module
    pub fn new(ctx: &'static mut IbcActions<C>) -> Self {
        Self { ctx }
    }

    /// Get the module ID
    pub fn module_id(&self) -> ModuleId {
        ModuleId::from_str(MODULE_ID_STR).expect("should be parsable")
    }
}

impl<C> Module for TransferModule<C>
where
    C: IbcStorageContext + Debug + 'static,
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

impl<C> SendPacketReader for TransferModule<C>
where
    C: IbcStorageContext,
{
    fn channel_end(
        &self,
        channel_end_path: &ChannelEndPath,
    ) -> Result<ChannelEnd, ContextError> {
        ValidationContext::channel_end(self.ctx, channel_end_path)
    }

    fn connection_end(
        &self,
        connection_id: &ConnectionId,
    ) -> Result<ConnectionEnd, ContextError> {
        ValidationContext::connection_end(self.ctx, connection_id)
    }

    fn client_state(
        &self,
        client_id: &ClientId,
    ) -> Result<Box<dyn ClientState>, ContextError> {
        ValidationContext::client_state(self.ctx, client_id)
    }

    fn client_consensus_state(
        &self,
        client_cons_state_path: &ClientConsensusStatePath,
    ) -> Result<Box<dyn ConsensusState>, ContextError> {
        ValidationContext::consensus_state(self.ctx, client_cons_state_path)
    }

    fn get_next_sequence_send(
        &self,
        seq_send_path: &SeqSendPath,
    ) -> Result<Sequence, ContextError> {
        ValidationContext::get_next_sequence_send(self.ctx, seq_send_path)
    }

    fn hash(&self, value: &[u8]) -> Vec<u8> {
        ValidationContext::hash(self.ctx, value)
    }
}

impl<C> TokenTransferReader for TransferModule<C>
where
    C: IbcStorageContext,
{
    type AccountId = Address;

    fn get_port(&self) -> Result<PortId, TokenTransferError> {
        Ok(PortId::transfer())
    }

    fn get_channel_escrow_address(
        &self,
        _port_id: &PortId,
        _channel_id: &ChannelId,
    ) -> Result<Self::AccountId, TokenTransferError> {
        Ok(Address::Internal(InternalAddress::IbcEscrow))
    }

    fn is_send_enabled(&self) -> bool {
        true
    }

    fn is_receive_enabled(&self) -> bool {
        true
    }

    fn denom_hash_string(&self, denom: &PrefixedDenom) -> Option<String> {
        Some(storage::calc_hash(denom.to_string()))
    }
}

impl<C> BankKeeper for TransferModule<C>
where
    C: IbcStorageContext,
{
    type AccountId = Address;

    fn send_coins(
        &mut self,
        from: &Self::AccountId,
        to: &Self::AccountId,
        coin: &PrefixedCoin,
    ) -> Result<(), TokenTransferError> {
        // Assumes that the coin denom is prefixed with "port-id/channel-id" or
        // has no prefix

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

        let src = if coin.denom.trace_path.is_empty()
            || *from == Address::Internal(InternalAddress::IbcMint)
        {
            token::balance_key(&token, from)
        } else {
            let sub_prefix = storage::ibc_token_prefix(coin.denom.to_string())
                .map_err(|_| TokenTransferError::InvalidCoin {
                    coin: coin.to_string(),
                })?;
            let prefix = token::multitoken_balance_prefix(&token, &sub_prefix);
            token::multitoken_balance_key(&prefix, from)
        };

        let dest = token::balance_key(&token, to);

        self.ctx
            .ctx
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

    fn mint_coins(
        &mut self,
        account: &Self::AccountId,
        coin: &PrefixedCoin,
    ) -> Result<(), TokenTransferError> {
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

        let src = token::balance_key(
            &token,
            &Address::Internal(InternalAddress::IbcMint),
        );

        let dest = if coin.denom.trace_path.is_empty() {
            token::balance_key(&token, account)
        } else {
            let sub_prefix = storage::ibc_token_prefix(coin.denom.to_string())
                .map_err(|_| TokenTransferError::InvalidCoin {
                    coin: coin.to_string(),
                })?;
            let prefix = token::multitoken_balance_prefix(&token, &sub_prefix);
            token::multitoken_balance_key(&prefix, account)
        };

        self.ctx
            .ctx
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

    fn burn_coins(
        &mut self,
        account: &Self::AccountId,
        coin: &PrefixedCoin,
    ) -> Result<(), TokenTransferError> {
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

        let src = if coin.denom.trace_path.is_empty() {
            token::balance_key(&token, account)
        } else {
            let sub_prefix = storage::ibc_token_prefix(coin.denom.to_string())
                .map_err(|_| TokenTransferError::InvalidCoin {
                    coin: coin.to_string(),
                })?;
            let prefix = token::multitoken_balance_prefix(&token, &sub_prefix);
            token::multitoken_balance_key(&prefix, account)
        };

        let dest = token::balance_key(
            &token,
            &Address::Internal(InternalAddress::IbcBurn),
        );

        self.ctx
            .ctx
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

impl<C> TokenTransferKeeper for TransferModule<C>
where
    C: IbcStorageContext,
{
    fn store_packet_commitment(
        &mut self,
        port_id: PortId,
        channel_id: ChannelId,
        sequence: Sequence,
        commitment: PacketCommitment,
    ) -> Result<(), ContextError> {
        let path = CommitmentPath {
            port_id,
            channel_id,
            sequence,
        };
        self.ctx.store_packet_commitment(&path, commitment)
    }

    fn store_next_sequence_send(
        &mut self,
        port_id: PortId,
        channel_id: ChannelId,
        seq: Sequence,
    ) -> Result<(), ContextError> {
        let path = SeqSendPath(port_id, channel_id);
        self.ctx.store_next_sequence_send(&path, seq)
    }
}

impl<C> TokenTransferContext for TransferModule<C>
where
    C: IbcStorageContext,
{
    type AccountId = Address;
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
