//! Middleware entry points on Namada.

use std::cell::RefCell;
use std::collections::BTreeSet;
use std::fmt::Debug;
use std::marker::PhantomData;
use std::rc::Rc;

use ibc_middleware_packet_forward::PacketForwardMiddleware;
use namada_core::address::Address;

use crate::context::pfm_mod::PfmTransferModule;
use crate::context::transfer_mod::TransferModule;
use crate::{IbcCommonContext, IbcStorageContext};

/// The stack of middlewares of the transfer module.
pub type TransferMiddlewares<C, Params> =
    PacketForwardMiddleware<PfmTransferModule<C, Params>>;

/// Create a new instance of [`TransferMiddlewares`]
pub fn create_transfer_middlewares<C, Params>(
    ctx: Rc<RefCell<C>>,
    verifiers: Rc<RefCell<BTreeSet<Address>>>,
) -> TransferMiddlewares<C, Params>
where
    C: IbcCommonContext + Debug,
    Params: namada_systems::parameters::Read<<C as IbcStorageContext>::Storage>,
{
    PacketForwardMiddleware::next(PfmTransferModule {
        transfer_module: TransferModule::new(ctx, verifiers),
        _phantom: PhantomData,
    })
}
