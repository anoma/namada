//! IBC library code

pub mod context;
pub mod storage;

use std::cell::RefCell;
use std::fmt::Debug;
use std::rc::Rc;
use std::str::FromStr;

use borsh::BorshDeserialize;
pub use context::common::IbcCommonContext;
use context::router::IbcRouter;
pub use context::storage::{IbcStorageContext, ProofSpec};
pub use context::token_transfer::TokenTransferContext;
pub use context::transfer_mod::{ModuleWrapper, TransferModule};
use context::IbcContext;
pub use context::ValidationParams;
use prost::Message;
use thiserror::Error;

use crate::ibc::apps::transfer::handler::{
    send_transfer_execute, send_transfer_validate,
};
use crate::ibc::apps::transfer::types::error::TokenTransferError;
use crate::ibc::apps::transfer::types::msgs::transfer::MsgTransfer;
use crate::ibc::apps::transfer::types::{
    is_receiver_chain_source, PrefixedDenom, TracePrefix,
};
use crate::ibc::core::channel::types::msgs::PacketMsg;
use crate::ibc::core::entrypoint::{execute, validate};
use crate::ibc::core::handler::types::error::ContextError;
use crate::ibc::core::handler::types::msgs::MsgEnvelope;
use crate::ibc::core::host::types::error::IdentifierError;
use crate::ibc::core::host::types::identifiers::{ChannelId, PortId};
use crate::ibc::core::router::types::error::RouterError;
use crate::ibc::core::router::types::module::ModuleId;
use crate::ibc::primitives::proto::Any;
use crate::types::address::{Address, MASP};
use crate::types::ibc::{
    get_shielded_transfer, is_ibc_denom, MsgShieldedTransfer,
    EVENT_TYPE_DENOM_TRACE, EVENT_TYPE_PACKET,
};
use crate::types::masp::PaymentAddress;

#[allow(missing_docs)]
#[derive(Error, Debug)]
pub enum Error {
    #[error("Decoding IBC data error")]
    DecodingData,
    #[error("Decoding message error: {0}")]
    DecodingMessage(RouterError),
    #[error("IBC context error: {0}")]
    Context(Box<ContextError>),
    #[error("IBC token transfer error: {0}")]
    TokenTransfer(TokenTransferError),
    #[error("Denom error: {0}")]
    Denom(String),
    #[error("Invalid chain ID: {0}")]
    ChainId(IdentifierError),
    #[error("Handling MASP transaction error: {0}")]
    MaspTx(String),
}

/// IBC actions to handle IBC operations
#[derive(Debug)]
pub struct IbcActions<'a, C>
where
    C: IbcCommonContext,
{
    ctx: IbcContext<C>,
    router: IbcRouter<'a>,
}

impl<'a, C> IbcActions<'a, C>
where
    C: IbcCommonContext + Debug,
{
    /// Make new IBC actions
    pub fn new(ctx: Rc<RefCell<C>>) -> Self {
        Self {
            ctx: IbcContext::new(ctx),
            router: IbcRouter::new(),
        }
    }

    /// Add TokenTransfer route
    pub fn add_transfer_module(
        &mut self,
        module_id: ModuleId,
        module: impl ModuleWrapper + 'a,
    ) {
        self.router.add_transfer_module(module_id, module)
    }

    /// Set the validation parameters
    pub fn set_validation_params(&mut self, params: ValidationParams) {
        self.ctx.validation_params = params;
    }

    /// Execute according to the message in an IBC transaction or VP
    pub fn execute(&mut self, tx_data: &[u8]) -> Result<(), Error> {
        let message = decode_message(tx_data)?;
        match &message {
            IbcMessage::Transfer(msg) => {
                let mut token_transfer_ctx =
                    TokenTransferContext::new(self.ctx.inner.clone());
                send_transfer_execute(
                    &mut self.ctx,
                    &mut token_transfer_ctx,
                    msg.clone(),
                )
                .map_err(Error::TokenTransfer)
            }
            IbcMessage::ShieldedTransfer(msg) => {
                let mut token_transfer_ctx =
                    TokenTransferContext::new(self.ctx.inner.clone());
                send_transfer_execute(
                    &mut self.ctx,
                    &mut token_transfer_ctx,
                    msg.message.clone(),
                )
                .map_err(Error::TokenTransfer)?;
                self.handle_masp_tx(message)
            }
            IbcMessage::Envelope(envelope) => {
                execute(&mut self.ctx, &mut self.router, envelope.clone())
                    .map_err(|e| Error::Context(Box::new(e)))?;
                // the current ibc-rs execution doesn't store the denom for the
                // token hash when transfer with MsgRecvPacket
                self.store_denom(&envelope)?;
                // For receiving the token to a shielded address
                self.handle_masp_tx(message)
            }
        }
    }

    /// Store the denom when transfer with MsgRecvPacket
    fn store_denom(&mut self, envelope: &MsgEnvelope) -> Result<(), Error> {
        if let MsgEnvelope::Packet(PacketMsg::Recv(_)) = envelope {
            if let Some((trace_hash, ibc_denom, receiver)) =
                self.get_minted_token_info()?
            {
                // If the denomination trace event has the trace hash and
                // the IBC denom, a token has been minted. The raw IBC denom
                // including the port ID, the channel ID and the base token
                // is stored to be restored from the trace hash. The amount
                // denomination is also set for the minting.
                self.ctx
                    .inner
                    .borrow_mut()
                    .store_ibc_denom(&receiver, &trace_hash, &ibc_denom)
                    .map_err(|e| {
                        Error::Denom(format!(
                            "Writing the IBC denom failed: {}",
                            e
                        ))
                    })?;
                if let Some((_, base_token)) = is_ibc_denom(&ibc_denom) {
                    self.ctx
                        .inner
                        .borrow_mut()
                        .store_ibc_denom(base_token, trace_hash, &ibc_denom)
                        .map_err(|e| {
                            Error::Denom(format!(
                                "Writing the IBC denom failed: {}",
                                e
                            ))
                        })?;
                }
            }
        }
        Ok(())
    }

    /// Get the minted IBC denom, the trace hash, and the receiver from IBC
    /// events
    fn get_minted_token_info(
        &self,
    ) -> Result<Option<(String, String, String)>, Error> {
        let receive_event = self
            .ctx
            .inner
            .borrow()
            .get_ibc_events(EVENT_TYPE_PACKET)
            .map_err(|_| {
                Error::Denom("Reading the IBC event failed".to_string())
            })?;
        // The receiving event should be only one in the single IBC transaction
        let receiver = match receive_event
            .first()
            .as_ref()
            .and_then(|event| event.attributes.get("receiver"))
        {
            // Check the receiver address
            Some(receiver) => Some(
                Address::decode(receiver)
                    .or_else(|_| {
                        // Replace it with MASP address when the receiver is a
                        // payment address
                        PaymentAddress::from_str(receiver).map(|_| MASP)
                    })
                    .map_err(|_| {
                        Error::Denom(format!(
                            "Decoding the receiver address failed: {:?}",
                            receive_event
                        ))
                    })?
                    .to_string(),
            ),
            None => None,
        };
        let denom_event = self
            .ctx
            .inner
            .borrow()
            .get_ibc_events(EVENT_TYPE_DENOM_TRACE)
            .map_err(|_| {
                Error::Denom("Reading the IBC event failed".to_string())
            })?;
        // The denom event should be only one in the single IBC transaction
        Ok(denom_event.first().as_ref().and_then(|event| {
            let trace_hash = event.attributes.get("trace_hash").cloned()?;
            let denom = event.attributes.get("denom").cloned()?;
            Some((trace_hash, denom, receiver?))
        }))
    }

    /// Validate according to the message in IBC VP
    pub fn validate(&self, tx_data: &[u8]) -> Result<(), Error> {
        let message = decode_message(tx_data)?;
        match message {
            IbcMessage::Transfer(msg) => {
                let token_transfer_ctx =
                    TokenTransferContext::new(self.ctx.inner.clone());
                send_transfer_validate(&self.ctx, &token_transfer_ctx, msg)
                    .map_err(Error::TokenTransfer)
            }
            IbcMessage::ShieldedTransfer(msg) => {
                let token_transfer_ctx =
                    TokenTransferContext::new(self.ctx.inner.clone());
                send_transfer_validate(
                    &self.ctx,
                    &token_transfer_ctx,
                    msg.message,
                )
                .map_err(Error::TokenTransfer)
            }
            IbcMessage::Envelope(envelope) => {
                validate(&self.ctx, &self.router, envelope)
                    .map_err(|e| Error::Context(Box::new(e)))
            }
        }
    }

    /// Handle the MASP transaction if needed
    fn handle_masp_tx(&mut self, message: IbcMessage) -> Result<(), Error> {
        let shielded_transfer = match message {
            IbcMessage::Envelope(MsgEnvelope::Packet(PacketMsg::Recv(_))) => {
                let event = self
                    .ctx
                    .inner
                    .borrow()
                    .get_ibc_events(EVENT_TYPE_PACKET)
                    .map_err(|_| {
                        Error::MaspTx(
                            "Reading the IBC event failed".to_string(),
                        )
                    })?;
                // The receiving event should be only one in the single IBC
                // transaction
                match event.first() {
                    Some(event) => get_shielded_transfer(event)
                        .map_err(|e| Error::MaspTx(e.to_string()))?,
                    None => return Ok(()),
                }
            }
            IbcMessage::ShieldedTransfer(msg) => Some(msg.shielded_transfer),
            _ => return Ok(()),
        };
        if let Some(shielded_transfer) = shielded_transfer {
            self.ctx
                .inner
                .borrow_mut()
                .handle_masp_tx(&shielded_transfer)
                .map_err(|_| {
                    Error::MaspTx("Writing MASP components failed".to_string())
                })?;
        }
        Ok(())
    }
}

enum IbcMessage {
    Envelope(MsgEnvelope),
    Transfer(MsgTransfer),
    ShieldedTransfer(MsgShieldedTransfer),
}

fn decode_message(tx_data: &[u8]) -> Result<IbcMessage, Error> {
    // ibc-rs message
    if let Ok(any_msg) = Any::decode(tx_data) {
        if let Ok(transfer_msg) = MsgTransfer::try_from(any_msg.clone()) {
            return Ok(IbcMessage::Transfer(transfer_msg));
        }
        if let Ok(envelope) = MsgEnvelope::try_from(any_msg) {
            return Ok(IbcMessage::Envelope(envelope));
        }
    }

    // Message with Transfer for the shielded transfer
    if let Ok(msg) = MsgShieldedTransfer::try_from_slice(tx_data) {
        return Ok(IbcMessage::ShieldedTransfer(msg));
    }

    Err(Error::DecodingData)
}

/// Get the IbcToken from the source/destination ports and channels
pub fn received_ibc_token(
    ibc_denom: &PrefixedDenom,
    src_port_id: &PortId,
    src_channel_id: &ChannelId,
    dest_port_id: &PortId,
    dest_channel_id: &ChannelId,
) -> Result<Address, Error> {
    let mut ibc_denom = ibc_denom.clone();
    if is_receiver_chain_source(
        src_port_id.clone(),
        src_channel_id.clone(),
        &ibc_denom,
    ) {
        let prefix =
            TracePrefix::new(src_port_id.clone(), src_channel_id.clone());
        ibc_denom.remove_trace_prefix(&prefix);
    } else {
        let prefix =
            TracePrefix::new(dest_port_id.clone(), dest_channel_id.clone());
        ibc_denom.add_trace_prefix(prefix);
    }
    Ok(storage::ibc_token(ibc_denom.to_string()))
}
