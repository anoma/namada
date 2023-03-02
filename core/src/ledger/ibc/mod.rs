//! IBC library code

mod context;
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

use crate::ibc::applications::transfer::error::TokenTransferError;
use crate::ibc::applications::transfer::msgs::transfer::{
    MsgTransfer, TYPE_URL as MSG_TRANSFER_TYPE_URL,
};
use crate::ibc::applications::transfer::relay::send_transfer::{
    send_transfer_execute, send_transfer_validate,
};
use crate::ibc::core::context::Router;
use crate::ibc::core::ics24_host::identifier::PortId;
use crate::ibc::core::ics26_routing::context::{Module, ModuleId};
use crate::ibc::core::ics26_routing::error::RouterError;
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
    #[error("IBC module doesn't exist")]
    NoModule,
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

    /// Add a route to IBC actions
    pub fn add_route(
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
                        send_transfer_execute(&mut module, msg)
                            .map_err(Error::TokenTransfer)
                    }
                    None => Err(Error::NoModule),
                }
            }
            _ => {
                execute(self, msg).map_err(Error::Execution)?;
                // TODO store the denom when MsgRecvPacket
                Ok(())
            }
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
                        send_transfer_validate(&module, msg)
                            .map_err(Error::TokenTransfer)
                    }
                    None => Err(Error::NoModule),
                }
            }
            _ => validate(self, msg).map_err(Error::Execution),
        }
    }
}
