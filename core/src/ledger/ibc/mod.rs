//! IBC library code

mod context;
pub mod storage;
mod transfer_mod;

use std::collections::HashMap;
use std::str::FromStr;

use context::storage::IbcStorageContext;
use prost::Message;
use thiserror::Error;
use transfer_mod::TransferModule;

use crate::ibc::applications::transfer::error::TokenTransferError;
use crate::ibc::applications::transfer::msgs::transfer::{
    MsgTransfer, TYPE_URL,
};
use crate::ibc::applications::transfer::MODULE_ID_STR;
use crate::ibc::core::ics24_host::identifier::PortId;
use crate::ibc::core::ics26_routing::context::{Module, ModuleId};
use crate::ibc::core::ics26_routing::error::RouterError;
use crate::ibc::core::ics26_routing::msgs::MsgEnvelope;
use crate::ibc::core::{ExecutionContext, ValidationContext};
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

pub struct IbcActions<C>
where
    C: IbcStorageContext + 'static,
{
    ctx: &'static C,
    modules: HashMap<ModuleId, Box<dyn Module>>,
    ports: HashMap<PortId, ModuleId>,
}

impl<C> IbcActions<C>
where
    C: IbcStorageContext + Sync + core::fmt::Debug,
{
    pub fn new(ctx: &C) -> Self {
        let mut modules = HashMap::new();
        let id = ModuleId::from_str(MODULE_ID_STR).expect("should be parsable");
        let module = TransferModule { ctx };
        modules.insert(id, Box::new(module) as Box<dyn Module>);

        Self {
            ctx,
            modules,
            ports: HashMap::new(),
        }
    }

    /// Execute according to the message in an IBC transaction or VP
    pub fn execute(&mut self, tx_data: &Vec<u8>) -> Result<(), Error> {
        let msg = Any::decode(&tx_data[..]).map_err(Error::DecodingData)?;
        match msg.type_url.as_str() {
            TYPE_URL => {
                let msg =
                    MsgTransfer::try_from(msg).map_err(Error::TokenTransfer)?;
                // TODO: call send_transfer(...)
                // TODO: write results and emit the event
                Ok(())
            }
            _ => {
                let envelope = MsgEnvelope::try_from(msg)
                    .map_err(Error::DecodingMessage)?;
                ExecutionContext::execute(self, envelope)
                    .map_err(Error::Execution)
            }
        }
    }

    /// Validate according to the message in IBC VP
    pub fn validate(&self, tx_data: &Vec<u8>) -> Result<(), Error> {
        let msg = Any::decode(&tx_data[..]).map_err(Error::DecodingData)?;
        match msg.type_url.as_str() {
            TYPE_URL => {
                let msg =
                    MsgTransfer::try_from(msg).map_err(Error::TokenTransfer)?;
                // TODO: validate transfer and a sent packet
                Ok(())
            }
            _ => {
                let envelope = MsgEnvelope::try_from(msg)
                    .map_err(Error::DecodingMessage)?;
                ValidationContext::validate(self, envelope)
                    .map_err(Error::Execution)
            }
        }
    }
}
