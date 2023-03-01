//! IBC library code

mod context;
pub mod storage;

use std::collections::HashMap;
use std::fmt::Debug;

pub use context::storage::{IbcStorageContext, ProofSpec};
pub use context::transfer_mod::TransferModule;
use prost::Message;
use thiserror::Error;

use crate::ibc::applications::transfer::error::TokenTransferError;
use crate::ibc::applications::transfer::msgs::transfer::{
    MsgTransfer, TYPE_URL as MSG_TRANSFER_TYPE_URL,
};
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
}

/// IBC actions to handle IBC operations
#[derive(Debug)]
pub struct IbcActions<'a, C>
where
    C: IbcStorageContext,
{
    ctx: &'a mut C,
    modules: HashMap<ModuleId, Box<dyn Module>>,
    ports: HashMap<PortId, ModuleId>,
}

impl<'a, C> IbcActions<'a, C>
where
    C: IbcStorageContext + Debug,
{
    /// Make new IBC actions
    pub fn new(ctx: &'a mut C) -> Self {
        Self {
            ctx,
            modules: HashMap::new(),
            ports: HashMap::new(),
        }
    }

    /// Add a route to IBC actions
    pub fn add_route(&mut self, module_id: ModuleId, module: impl Module) {
        self.modules
            .insert(module_id.clone(), Box::new(module) as Box<dyn Module>);
        self.ports.insert(PortId::transfer(), module_id);
    }

    /// Execute according to the message in an IBC transaction or VP
    pub fn execute(&mut self, tx_data: &[u8]) -> Result<(), Error> {
        let msg = Any::decode(&tx_data[..]).map_err(Error::DecodingData)?;
        match msg.type_url.as_str() {
            MSG_TRANSFER_TYPE_URL => {
                let _msg =
                    MsgTransfer::try_from(msg).map_err(Error::TokenTransfer)?;
                // TODO: call send_transfer(...)
                // TODO: write results and emit the event
                Ok(())
            }
            _ => execute(self, msg).map_err(Error::Execution),
        }
    }

    /// Validate according to the message in IBC VP
    pub fn validate(&self, tx_data: &[u8]) -> Result<(), Error> {
        let msg = Any::decode(&tx_data[..]).map_err(Error::DecodingData)?;
        match msg.type_url.as_str() {
            MSG_TRANSFER_TYPE_URL => {
                let _msg =
                    MsgTransfer::try_from(msg).map_err(Error::TokenTransfer)?;
                // TODO: validate transfer and a sent packet
                Ok(())
            }
            _ => validate(self, msg).map_err(Error::Execution),
        }
    }
}
