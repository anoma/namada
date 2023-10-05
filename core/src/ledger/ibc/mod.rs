//! IBC library code

pub mod context;
pub mod storage;

use std::cell::RefCell;
use std::collections::HashMap;
use std::fmt::Debug;
use std::rc::Rc;
use std::str::FromStr;
use std::time::Duration;

pub use context::common::IbcCommonContext;
pub use context::storage::{IbcStorageContext, ProofSpec};
pub use context::transfer_mod::{ModuleWrapper, TransferModule};
use prost::Message;
use thiserror::Error;

use crate::ibc::applications::transfer::error::TokenTransferError;
use crate::ibc::applications::transfer::msgs::transfer::MsgTransfer;
use crate::ibc::applications::transfer::{
    is_receiver_chain_source, send_transfer_execute, send_transfer_validate,
    PrefixedDenom, TracePrefix,
};
use crate::ibc::core::ics04_channel::msgs::PacketMsg;
use crate::ibc::core::ics23_commitment::specs::ProofSpecs;
use crate::ibc::core::ics24_host::identifier::{
    ChainId as IbcChainId, ChannelId, PortId,
};
use crate::ibc::core::router::{Module, ModuleId, Router};
use crate::ibc::core::{execute, validate, MsgEnvelope, RouterError};
use crate::ibc_proto::google::protobuf::Any;
use crate::types::address::{masp, Address};
use crate::types::chain::ChainId;
use crate::types::ibc::{
    get_shielded_transfer, is_ibc_denom, EVENT_TYPE_DENOM_TRACE,
    EVENT_TYPE_PACKET,
};
use crate::types::masp::PaymentAddress;

#[allow(missing_docs)]
#[derive(Error, Debug)]
pub enum Error {
    #[error("Decoding IBC data error: {0}")]
    DecodingData(prost::DecodeError),
    #[error("Decoding message error: {0}")]
    DecodingMessage(RouterError),
    #[error("IBC storage error: {0}")]
    IbcStorage(storage::Error),
    #[error("IBC execution error: {0}")]
    Execution(RouterError),
    #[error("IBC token transfer error: {0}")]
    TokenTransfer(TokenTransferError),
    #[error("IBC validation error: {0}")]
    Validation(RouterError),
    #[error("IBC module doesn't exist")]
    NoModule,
    #[error("Denom error: {0}")]
    Denom(String),
    #[error("Invalid chain ID: {0}")]
    ChainId(ChainId),
    #[error("Handling MASP transaction error: {0}")]
    MaspTx(String),
}

/// IBC actions to handle IBC operations
#[derive(Debug)]
pub struct IbcActions<'a, C>
where
    C: IbcCommonContext,
{
    ctx: Rc<RefCell<C>>,
    modules: HashMap<ModuleId, Rc<dyn ModuleWrapper + 'a>>,
    ports: HashMap<PortId, ModuleId>,
    validation_params: ValidationParams,
}

impl<'a, C> IbcActions<'a, C>
where
    C: IbcCommonContext + Debug,
{
    /// Make new IBC actions
    pub fn new(ctx: Rc<RefCell<C>>) -> Self {
        Self {
            ctx,
            modules: HashMap::new(),
            ports: HashMap::new(),
            validation_params: ValidationParams::default(),
        }
    }

    /// Set the validation parameters
    pub fn set_validation_params(&mut self, params: ValidationParams) {
        self.validation_params = params;
    }

    /// Add TokenTransfer route
    pub fn add_transfer_route(
        &mut self,
        module_id: ModuleId,
        module: impl ModuleWrapper + 'a,
    ) {
        self.modules.insert(module_id.clone(), Rc::new(module));
        self.ports.insert(PortId::transfer(), module_id);
    }

    fn get_route_by_port(&self, port_id: &PortId) -> Option<&dyn Module> {
        self.lookup_module_by_port(port_id)
            .and_then(|id| self.get_route(&id))
    }

    fn get_route_mut_by_port(
        &mut self,
        port_id: &PortId,
    ) -> Option<&mut dyn Module> {
        self.lookup_module_by_port(port_id)
            .and_then(|id| self.get_route_mut(&id))
    }

    /// Execute according to the message in an IBC transaction or VP
    pub fn execute(&mut self, tx_data: &[u8]) -> Result<(), Error> {
        let any_msg = Any::decode(tx_data).map_err(Error::DecodingData)?;
        match MsgTransfer::try_from(any_msg.clone()) {
            Ok(msg) => {
                let port_id = msg.port_id_on_a.clone();
                match self.get_route_mut_by_port(&port_id) {
                    Some(_module) => {
                        let mut module = TransferModule::new(self.ctx.clone());
                        send_transfer_execute(&mut module, msg)
                            .map_err(Error::TokenTransfer)
                    }
                    None => Err(Error::NoModule),
                }
            }
            Err(_) => {
                let envelope =
                    MsgEnvelope::try_from(any_msg).map_err(Error::Execution)?;
                execute(self, envelope.clone()).map_err(Error::Execution)?;
                // For receiving the token to a shielded address
                self.handle_masp_tx(&envelope)?;
                // the current ibc-rs execution doesn't store the denom for the
                // token hash when transfer with MsgRecvPacket
                self.store_denom(&envelope)
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
                        PaymentAddress::from_str(receiver).map(|_| masp())
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
        let any_msg = Any::decode(tx_data).map_err(Error::DecodingData)?;
        match MsgTransfer::try_from(any_msg.clone()) {
            Ok(msg) => {
                let port_id = msg.port_id_on_a.clone();
                match self.get_route_by_port(&port_id) {
                    Some(_module) => {
                        let module = TransferModule::new(self.ctx.clone());
                        send_transfer_validate(&module, msg)
                            .map_err(Error::TokenTransfer)
                    }
                    None => Err(Error::NoModule),
                }
            }
            Err(_) => {
                let envelope = MsgEnvelope::try_from(any_msg)
                    .map_err(Error::Validation)?;
                validate(self, envelope).map_err(Error::Validation)
            }
        }
    }

    /// Handle the MASP transaction if needed
    fn handle_masp_tx(&mut self, envelope: &MsgEnvelope) -> Result<(), Error> {
        let shielded_transfer = match envelope {
            MsgEnvelope::Packet(PacketMsg::Recv(_)) => {
                let event = self
                    .ctx
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
            _ => return Ok(()),
        };
        if let Some(shielded_transfer) = shielded_transfer {
            self.ctx
                .borrow_mut()
                .handle_masp_tx(&shielded_transfer)
                .map_err(|_| {
                    Error::MaspTx("Writing MASP components failed".to_string())
                })?;
        }
        Ok(())
    }
}

#[derive(Debug, Default)]
/// Parameters for validation
pub struct ValidationParams {
    /// Chain ID
    pub chain_id: IbcChainId,
    /// IBC proof specs
    pub proof_specs: ProofSpecs,
    /// Unbonding period
    pub unbonding_period: Duration,
    /// Upgrade path
    pub upgrade_path: Vec<String>,
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
