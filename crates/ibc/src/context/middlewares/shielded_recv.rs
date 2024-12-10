//! This middleware is to handle automatically shielding the results of a
//! shielded swap.
//!
//! Since we do not know the resulting amount of assets from the swap ahead of
//! time, we cannot create a MASP note at the onset. We instead, create a note
//! for the minimum amount, which will be shielded. All assets exceeding the
//! minimum amount will be transferred to an overflow address specified by
//! the user.

use std::cell::RefCell;
use std::collections::BTreeSet;
use std::fmt::{Debug, Formatter};
use std::rc::Rc;

use ibc::apps::transfer::context::TokenTransferExecutionContext;
use ibc::apps::transfer::types::packet::PacketData;
use ibc::apps::transfer::types::{Amount, Coin, PrefixedDenom};
use ibc::core::channel::types::acknowledgement::{
    Acknowledgement, AcknowledgementStatus, StatusValue as AckStatusValue,
};
use ibc::core::channel::types::channel::{Counterparty, Order};
use ibc::core::channel::types::error::{ChannelError, PacketError};
use ibc::core::channel::types::packet::Packet;
use ibc::core::channel::types::Version;
use ibc::core::host::types::identifiers::{ChannelId, ConnectionId, PortId};
use ibc::core::router::module::Module;
use ibc::core::router::types::module::ModuleExtras;
use ibc::primitives::Signer;
use ibc_middleware_module::MiddlewareModule;
use ibc_middleware_module_macros::from_middleware;
use ibc_middleware_overflow_receive::OverflowRecvContext;
use ibc_middleware_packet_forward::PacketForwardMiddleware;
use namada_core::address::{Address, MASP};
use namada_core::token;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

use crate::context::middlewares::pfm_mod::PfmTransferModule;
use crate::{Error, IbcCommonContext, IbcStorageContext, TokenTransferContext};

/// A middleware for handling IBC pockets received
/// after a shielded swap. The minimum amount will
/// be shielded and the rest placed in an overflow
/// account.
pub struct ShieldedRecvModule<C, Params>
where
    C: IbcCommonContext + Debug,
    Params: namada_systems::parameters::Read<<C as IbcStorageContext>::Storage>,
{
    /// The next middleware module
    pub next: PacketForwardMiddleware<PfmTransferModule<C, Params>>,
}

impl<C, Params> ShieldedRecvModule<C, Params>
where
    C: IbcCommonContext + Debug,
    Params: namada_systems::parameters::Read<<C as IbcStorageContext>::Storage>,
{
    fn get_ctx(&self) -> Rc<RefCell<C>> {
        self.next.next().transfer_module.ctx.inner.clone()
    }

    fn get_verifiers(&self) -> Rc<RefCell<BTreeSet<Address>>> {
        self.next.next().transfer_module.ctx.verifiers.clone()
    }
}

impl<C, Params> Debug for ShieldedRecvModule<C, Params>
where
    C: IbcCommonContext + Debug,
    Params: namada_systems::parameters::Read<<C as IbcStorageContext>::Storage>,
{
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.debug_struct(stringify!(ShieldedRecvModule))
            .field("next", &self.next)
            .finish()
    }
}

from_middleware! {
    impl<C, Params> Module for ShieldedRecvModule<C, Params>
    where
        C: IbcCommonContext + Debug,
        Params: namada_systems::parameters::Read<<C as IbcStorageContext>::Storage>,
}

impl<C, Params> MiddlewareModule for ShieldedRecvModule<C, Params>
where
    C: IbcCommonContext + Debug,
    Params: namada_systems::parameters::Read<<C as IbcStorageContext>::Storage>,
{
    type NextMiddleware = PacketForwardMiddleware<PfmTransferModule<C, Params>>;

    fn next_middleware(&self) -> &Self::NextMiddleware {
        &self.next
    }

    fn next_middleware_mut(&mut self) -> &mut Self::NextMiddleware {
        &mut self.next
    }

    fn middleware_on_recv_packet_execute(
        &mut self,
        packet: &Packet,
        relayer: &Signer,
    ) -> (ModuleExtras, Option<Acknowledgement>) {
        let Ok(data) = serde_json::from_slice::<PacketData>(&packet.data)
        else {
            // NB: this isn't an ICS-20 packet
            return self.next.on_recv_packet_execute(packet, relayer);
        };
        if serde_json::from_str::<PacketMetadata>(data.memo.as_ref()).is_err() {
            // NB: this isn't a shielded recv packet
            return self.next.on_recv_packet_execute(packet, relayer);
        }

        if data.receiver.as_ref() != MASP.to_string() {
            let ack = AcknowledgementStatus::error(
                AckStatusValue::new(format!(
                    "Shielded receive error: Address {:?} is not the MASP",
                    data.receiver.as_ref()
                ))
                .expect("Ack is not empty"),
            );
            return (ModuleExtras::empty(), Some(ack.into()));
        }

        self.next.on_recv_packet_execute(packet, relayer)
    }
}

#[derive(Serialize, Deserialize)]
/// The overflow address and amount to deposit therein
pub struct ShieldedRecvMetadata {
    overflow_receiver: Signer,
    target_amount: Amount,
}

/// Metadata of a shielded recv packet.
#[derive(Serialize, Deserialize)]
pub struct PacketMetadata {
    shielded_recv: ShieldedRecvMetadata,
}

impl PacketMetadata {
    /// Create a new [`PacketMetadata`] instance.
    pub fn new(receiver: Address, amount: token::Amount) -> Self {
        Self {
            shielded_recv: ShieldedRecvMetadata {
                overflow_receiver: receiver.to_string().into(),
                target_amount: amount.into(),
            },
        }
    }
}

impl ibc_middleware_overflow_receive::PacketMetadata for PacketMetadata {
    type AccountId = Signer;
    type Amount = Amount;

    fn is_overflow_receive_msg(msg: &Map<String, Value>) -> bool {
        msg.contains_key("shielded_recv")
    }

    fn strip_middleware_msg(
        mut json_obj_memo: Map<String, Value>,
    ) -> Map<String, Value> {
        json_obj_memo.remove("shielded_recv");
        json_obj_memo
    }

    fn overflow_receiver(&self) -> &Signer {
        &self.shielded_recv.overflow_receiver
    }

    fn target_amount(&self) -> &Amount {
        &self.shielded_recv.target_amount
    }
}

impl<C, Params> OverflowRecvContext for ShieldedRecvModule<C, Params>
where
    C: IbcCommonContext + Debug,
    Params: namada_systems::parameters::Read<<C as IbcStorageContext>::Storage>,
{
    type Error = Error;
    type PacketMetadata = PacketMetadata;

    fn mint_coins_execute(
        &mut self,
        receiver: &Signer,
        coin: &Coin<PrefixedDenom>,
    ) -> Result<(), Self::Error> {
        let ctx = self.get_ctx();
        let verifiers = self.get_verifiers();
        let mut token_transfer_context =
            TokenTransferContext::new(ctx, verifiers);
        let receiver = Address::decode(receiver)
            .map_err(|e| Error::Other(e.to_string()))?;
        token_transfer_context
            .mint_coins_execute(&receiver, coin)
            .map_err(Error::TokenTransfer)
    }

    fn unescrow_coins_execute(
        &mut self,
        receiver: &Signer,
        port: &PortId,
        channel: &ChannelId,
        coin: &Coin<PrefixedDenom>,
    ) -> Result<(), Self::Error> {
        let ctx = self.get_ctx();
        let verifiers = self.get_verifiers();
        let mut token_transfer_context =
            TokenTransferContext::new(ctx, verifiers);
        let receiver = Address::decode(receiver)
            .map_err(|e| Error::Other(e.to_string()))?;
        token_transfer_context
            .unescrow_coins_execute(&receiver, port, channel, coin)
            .map_err(Error::TokenTransfer)
    }
}
