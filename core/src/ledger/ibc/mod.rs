//! IBC library code

pub mod context;
pub mod storage;

use std::cell::RefCell;
use std::collections::HashMap;
use std::fmt::Debug;
use std::rc::Rc;

pub use context::common::IbcCommonContext;
pub use context::storage::{IbcStorageContext, ProofSpec};
pub use context::transfer_mod::{ModuleWrapper, TransferModule};
use prost::Message;
use thiserror::Error;

use crate::ibc::applications::transfer::denom::TracePrefix;
use crate::ibc::applications::transfer::error::TokenTransferError;
use crate::ibc::applications::transfer::msgs::transfer::{
    MsgTransfer, TYPE_URL as MSG_TRANSFER_TYPE_URL,
};
use crate::ibc::applications::transfer::packet::PacketData;
use crate::ibc::applications::transfer::relay::send_transfer::{
    send_transfer_execute, send_transfer_validate,
};
use crate::ibc::core::context::Router;
use crate::ibc::core::ics04_channel::msgs::PacketMsg;
use crate::ibc::core::ics24_host::identifier::PortId;
use crate::ibc::core::ics26_routing::context::{Module, ModuleId};
use crate::ibc::core::ics26_routing::error::RouterError;
use crate::ibc::core::ics26_routing::msgs::MsgEnvelope;
use crate::ibc::core::{execute, validate};
use crate::ibc_proto::google::protobuf::Any;

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
}

/// IBC actions to handle IBC operations
#[derive(Debug)]
pub struct IbcActions<C>
where
    C: IbcCommonContext,
{
    ctx: Rc<RefCell<C>>,
    modules: HashMap<ModuleId, Rc<dyn ModuleWrapper>>,
    ports: HashMap<PortId, ModuleId>,
}

impl<C> IbcActions<C>
where
    C: IbcCommonContext + Debug,
{
    /// Make new IBC actions
    pub fn new(ctx: Rc<RefCell<C>>) -> Self {
        Self {
            ctx,
            modules: HashMap::new(),
            ports: HashMap::new(),
        }
    }

    /// Add TokenTransfer route
    pub fn add_transfer_route(
        &mut self,
        module_id: ModuleId,
        module: impl ModuleWrapper,
    ) {
        self.modules.insert(module_id.clone(), Rc::new(module));
        self.ports.insert(PortId::transfer(), module_id);
    }

    fn get_route_by_port(&self, port_id: &PortId) -> Option<&dyn Module> {
        self.lookup_module_by_port(&port_id)
            .and_then(|id| self.get_route(&id))
    }

    fn get_route_mut_by_port(
        &mut self,
        port_id: &PortId,
    ) -> Option<&mut dyn Module> {
        self.lookup_module_by_port(&port_id)
            .and_then(|id| self.get_route_mut(&id))
    }

    /// Execute according to the message in an IBC transaction or VP
    pub fn execute(&mut self, tx_data: &[u8]) -> Result<(), Error> {
        let msg = Any::decode(&tx_data[..]).map_err(Error::DecodingData)?;
        match msg.type_url.as_str() {
            MSG_TRANSFER_TYPE_URL => {
                let msg =
                    MsgTransfer::try_from(msg).map_err(Error::TokenTransfer)?;
                let port_id = msg.port_on_a.clone();
                match self.get_route_mut_by_port(&port_id) {
                    Some(_module) => {
                        let mut module = TransferModule::new(self.ctx.clone());
                        // restore the denom if it is hashed
                        let msg = self.restore_denom(msg)?;
                        send_transfer_execute(&mut module, msg)
                            .map_err(Error::TokenTransfer)
                    }
                    None => Err(Error::NoModule),
                }
            }
            _ => {
                execute(self, msg.clone()).map_err(Error::Execution)?;
                // the current ibc-rs execution doesn't store the denom for the
                // token hash when transfer with MsgRecvPacket
                self.store_denom(msg)
            }
        }
    }

    /// Restore the denom when it is hashed, i.e. the denom is `ibc/{hash}`.
    fn restore_denom(&self, msg: MsgTransfer) -> Result<MsgTransfer, Error> {
        let mut msg = msg;
        // lookup the original denom with the IBC token hash
        if let Some(token_hash) =
            storage::token_hash_from_denom(&msg.token.denom).map_err(|e| {
                Error::Denom(format!("Invalid denom: error {}", e))
            })?
        {
            let denom_key = storage::ibc_denom_key(token_hash);
            let denom = match self.ctx.borrow().read(&denom_key) {
                Ok(Some(v)) => String::from_utf8(v).map_err(|e| {
                    Error::Denom(format!(
                        "Decoding the denom string failed: {}",
                        e
                    ))
                })?,
                _ => {
                    return Err(Error::Denom(format!(
                        "No original denom: denom_key {}",
                        denom_key
                    )));
                }
            };
            msg.token.denom = denom;
        }
        Ok(msg)
    }

    /// Store the denom when transfer with MsgRecvPacket
    fn store_denom(&mut self, msg: Any) -> Result<(), Error> {
        let envelope = MsgEnvelope::try_from(msg).map_err(|e| {
            Error::Denom(format!("Decoding the message failed: {}", e))
        })?;
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
                    msg.packet.port_on_b.clone(),
                    msg.packet.chan_on_b.clone(),
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
        let msg = Any::decode(&tx_data[..]).map_err(Error::DecodingData)?;
        match msg.type_url.as_str() {
            MSG_TRANSFER_TYPE_URL => {
                let msg =
                    MsgTransfer::try_from(msg).map_err(Error::TokenTransfer)?;
                let port_id = msg.port_on_a.clone();
                match self.get_route_by_port(&port_id) {
                    Some(_module) => {
                        let module = TransferModule::new(self.ctx.clone());
                        // restore the denom if it is hashed
                        let msg = self.restore_denom(msg)?;
                        send_transfer_validate(&module, msg)
                            .map_err(Error::TokenTransfer)
                    }
                    None => Err(Error::NoModule),
                }
            }
            _ => validate(self, msg).map_err(Error::Validation),
        }
    }
}
