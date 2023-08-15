//! IBC library code

pub mod context;
pub mod storage;

use std::cell::RefCell;
use std::collections::HashMap;
use std::fmt::Debug;
use std::rc::Rc;
use std::time::Duration;

pub use context::common::IbcCommonContext;
pub use context::storage::{IbcStorageContext, ProofSpec};
pub use context::transfer_mod::{ModuleWrapper, TransferModule};
use prost::Message;
use thiserror::Error;

use crate::ibc::applications::transfer::denom::TracePrefix;
use crate::ibc::applications::transfer::error::TokenTransferError;
use crate::ibc::applications::transfer::msgs::transfer::MsgTransfer;
use crate::ibc::applications::transfer::packet::PacketData;
use crate::ibc::applications::transfer::{
    send_transfer_execute, send_transfer_validate,
};
use crate::ibc::core::ics04_channel::msgs::PacketMsg;
use crate::ibc::core::ics23_commitment::specs::ProofSpecs;
use crate::ibc::core::ics24_host::identifier::{ChainId as IbcChainId, PortId};
use crate::ibc::core::router::{Module, ModuleId, Router};
use crate::ibc::core::{execute, validate, MsgEnvelope, RouterError};
use crate::ibc_proto::google::protobuf::Any;
use crate::types::chain::ChainId;

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
                // the current ibc-rs execution doesn't store the denom for the
                // token hash when transfer with MsgRecvPacket
                self.store_denom(envelope)
            }
        }
    }

    /// Store the denom when transfer with MsgRecvPacket
    fn store_denom(&mut self, envelope: MsgEnvelope) -> Result<(), Error> {
        match envelope {
            MsgEnvelope::Packet(PacketMsg::Recv(msg)) => {
                let data = match serde_json::from_slice::<PacketData>(
                    &msg.packet.data,
                ) {
                    Ok(data) => data,
                    // not token transfer data
                    Err(_) => return Ok(()),
                };
                let prefix = TracePrefix::new(
                    msg.packet.port_id_on_b.clone(),
                    msg.packet.chan_id_on_b,
                );
                let mut coin = data.token;
                coin.denom.add_trace_prefix(prefix);
                let trace_hash = storage::calc_hash(coin.denom.to_string());
                self.ctx
                    .borrow_mut()
                    .store_denom(trace_hash, coin.denom)
                    .map_err(|e| {
                        Error::Denom(format!("Write the denom failed: {}", e))
                    })
            }
            // other messages
            _ => Ok(()),
        }
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
