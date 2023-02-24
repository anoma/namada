//! IBC library code

mod context;
pub mod storage;

use std::collections::HashMap;
use std::str::FromStr;

use context::storage::IbcStorageContext;
use context::transfer_mod::TransferModule;
use prost::Message;
use thiserror::Error;

use crate::ibc::applications::transfer::error::TokenTransferError;
use crate::ibc::applications::transfer::msgs::transfer::{
    MsgTransfer, TYPE_URL,
};
use crate::ibc::applications::transfer::MODULE_ID_STR;
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

#[derive(Debug)]
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
        let mut actions = Self {
            ctx,
            modules: HashMap::new(),
            ports: HashMap::new(),
        };
        let module_id =
            ModuleId::from_str(MODULE_ID_STR).expect("should be parsable");
        let module = TransferModule { ctx: &actions };
        actions
            .modules
            .insert(module_id.clone(), Box::new(module) as Box<dyn Module>);
        actions.ports.insert(PortId::transfer(), module_id);

        actions
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
            _ => execute(self, msg).map_err(Error::Execution),
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
            _ => validate(self, msg).map_err(Error::Execution),
        }
    }
}
