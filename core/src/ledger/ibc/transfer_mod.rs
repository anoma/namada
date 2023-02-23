//! IBC module for token transfer

use super::IbcStorageContext;
use crate::ibc::applications::transfer::context::{
    BankKeeper, TokenTransferContext, TokenTransferKeeper, TokenTransferReader,
};
use crate::ibc::core::ics04_channel::context::SendPacketReader;
use crate::ibc::core::ics26_routing::context::Module;

#[derive(Debug)]
pub struct TransferModule<C>
where
    C: IbcStorageContext + 'static,
{
    pub ctx: &'static C,
}

impl<C> Module for TransferModule<C> where
    C: IbcStorageContext + Sync + core::fmt::Debug + 'static
{
}

impl<C> SendPacketReader for TransferModule<C> where C: IbcStorageContext {}

impl<C> TokenTransferReader for TransferModule<C> where C: IbcStorageContext {}

impl<C> BankKeeper for TransferModule<C> where C: IbcStorageContext {}

impl<C> TokenTransferKeeper for TransferModule<C> where C: IbcStorageContext {}

impl<C> TokenTransferContext for TransferModule<C> where C: IbcStorageContext {}
