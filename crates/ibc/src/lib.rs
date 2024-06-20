//! IBC library code

#![doc(html_favicon_url = "https://dev.namada.net/master/favicon.png")]
#![doc(html_logo_url = "https://dev.namada.net/master/rustdoc-logo.png")]
#![deny(rustdoc::broken_intra_doc_links)]
#![deny(rustdoc::private_intra_doc_links)]
#![warn(
    missing_docs,
    rust_2018_idioms,
    clippy::cast_sign_loss,
    clippy::cast_possible_truncation,
    clippy::cast_possible_wrap,
    clippy::cast_lossless,
    clippy::arithmetic_side_effects,
    clippy::dbg_macro,
    clippy::print_stdout,
    clippy::print_stderr
)]

mod actions;
pub mod context;
pub mod event;
mod msg;
mod nft;
pub mod parameters;
pub mod storage;

use std::cell::RefCell;
use std::collections::BTreeSet;
use std::fmt::Debug;
use std::rc::Rc;
use std::str::FromStr;

pub use actions::transfer_over_ibc;
use borsh::BorshDeserialize;
pub use context::common::IbcCommonContext;
pub use context::nft_transfer::NftTransferContext;
pub use context::nft_transfer_mod::NftTransferModule;
use context::router::IbcRouter;
pub use context::storage::{IbcStorageContext, ProofSpec};
pub use context::token_transfer::TokenTransferContext;
pub use context::transfer_mod::{ModuleWrapper, TransferModule};
use context::IbcContext;
pub use context::ValidationParams;
use ibc::apps::nft_transfer::handler::{
    send_nft_transfer_execute, send_nft_transfer_validate,
};
use ibc::apps::nft_transfer::types::error::NftTransferError;
use ibc::apps::nft_transfer::types::packet::PacketData as NftPacketData;
use ibc::apps::nft_transfer::types::{
    ack_success_b64, is_receiver_chain_source as is_nft_receiver_chain_source,
    PrefixedClassId, TokenId, TracePath as NftTracePath,
    TracePrefix as NftTracePrefix,
};
use ibc::apps::transfer::handler::{
    send_transfer_execute, send_transfer_validate,
};
use ibc::apps::transfer::types::error::TokenTransferError;
use ibc::apps::transfer::types::packet::PacketData;
use ibc::apps::transfer::types::{
    is_receiver_chain_source, PrefixedDenom, TracePath, TracePrefix,
};
use ibc::core::channel::types::acknowledgement::{
    Acknowledgement, AcknowledgementStatus,
};
use ibc::core::channel::types::commitment::compute_ack_commitment;
use ibc::core::channel::types::msgs::{
    MsgRecvPacket as IbcMsgRecvPacket, PacketMsg,
};
use ibc::core::channel::types::packet::Packet;
use ibc::core::entrypoint::{execute, validate};
use ibc::core::handler::types::error::ContextError;
use ibc::core::handler::types::events::Error as RawIbcEventError;
use ibc::core::handler::types::msgs::MsgEnvelope;
use ibc::core::host::types::error::IdentifierError;
use ibc::core::host::types::identifiers::{ChannelId, PortId};
use ibc::core::router::types::error::RouterError;
use ibc::primitives::proto::Any;
pub use ibc::*;
pub use msg::*;
use namada_core::address::{self, Address};
use namada_core::uint::Uint;
use namada_token::{Amount, ShieldingTransfer};
pub use nft::*;
use prost::Message;
use thiserror::Error;

use crate::storage::ibc_token;

/// The event type defined in ibc-rs for receiving a token
pub const EVENT_TYPE_PACKET: &str = "fungible_token_packet";
/// The event type defined in ibc-rs for receiving an NFT
pub const EVENT_TYPE_NFT_PACKET: &str = "non_fungible_token_packet";
/// The escrow address for IBC transfer
pub const IBC_ESCROW_ADDRESS: Address = address::IBC;

#[allow(missing_docs)]
#[derive(Error, Debug)]
pub enum Error {
    #[error("IBC event error: {0}")]
    IbcEvent(RawIbcEventError),
    #[error("Decoding IBC data error")]
    DecodingData,
    #[error("Decoding message error: {0}")]
    DecodingMessage(RouterError),
    #[error("IBC context error: {0}")]
    Context(Box<ContextError>),
    #[error("IBC token transfer error: {0}")]
    TokenTransfer(TokenTransferError),
    #[error("IBC NFT transfer error: {0}")]
    NftTransfer(NftTransferError),
    #[error("Trace error: {0}")]
    Trace(String),
    #[error("Invalid chain ID: {0}")]
    ChainId(IdentifierError),
    #[error("Verifier insertion error: {0}")]
    Verifier(namada_storage::Error),
    #[error("Invalid ShieldingTransfer")]
    ShieldingTransfer,
}

/// IBC actions to handle IBC operations
#[derive(Debug)]
pub struct IbcActions<'a, C>
where
    C: IbcCommonContext,
{
    ctx: IbcContext<C>,
    router: IbcRouter<'a>,
    verifiers: Rc<RefCell<BTreeSet<Address>>>,
}

impl<'a, C> IbcActions<'a, C>
where
    C: IbcCommonContext + Debug,
{
    /// Make new IBC actions
    pub fn new(
        ctx: Rc<RefCell<C>>,
        verifiers: Rc<RefCell<BTreeSet<Address>>>,
    ) -> Self {
        Self {
            ctx: IbcContext::new(ctx),
            router: IbcRouter::new(),
            verifiers,
        }
    }

    /// Add a transfer module to the router
    pub fn add_transfer_module(&mut self, module: impl ModuleWrapper + 'a) {
        self.router.add_transfer_module(module)
    }

    /// Set the validation parameters
    pub fn set_validation_params(&mut self, params: ValidationParams) {
        self.ctx.validation_params = params;
    }

    /// Execute according to the message in an IBC transaction or VP
    pub fn execute(
        &mut self,
        tx_data: &[u8],
    ) -> Result<Option<ShieldingTransfer>, Error> {
        let message = decode_message(tx_data)?;
        match &message {
            IbcMessage::Transfer(msg) => {
                let mut token_transfer_ctx = TokenTransferContext::new(
                    self.ctx.inner.clone(),
                    self.verifiers.clone(),
                );
                self.insert_verifiers()?;
                send_transfer_execute(
                    &mut self.ctx,
                    &mut token_transfer_ctx,
                    msg.message.clone(),
                )
                .map_err(Error::TokenTransfer)?;
                Ok(msg.transfer.clone())
            }
            IbcMessage::NftTransfer(msg) => {
                let mut nft_transfer_ctx =
                    NftTransferContext::new(self.ctx.inner.clone());
                send_nft_transfer_execute(
                    &mut self.ctx,
                    &mut nft_transfer_ctx,
                    msg.message.clone(),
                )
                .map_err(Error::NftTransfer)?;
                Ok(msg.transfer.clone())
            }
            IbcMessage::RecvPacket(msg) => {
                let envelope =
                    MsgEnvelope::Packet(PacketMsg::Recv(msg.message.clone()));
                execute(&mut self.ctx, &mut self.router, envelope)
                    .map_err(|e| Error::Context(Box::new(e)))?;
                let transfer = if self.is_receiving_success(&msg.message)? {
                    // For receiving the token to a shielded address
                    msg.transfer.clone()
                } else {
                    None
                };
                Ok(transfer)
            }
            IbcMessage::AckPacket(msg) => {
                let envelope =
                    MsgEnvelope::Packet(PacketMsg::Ack(msg.message.clone()));
                execute(&mut self.ctx, &mut self.router, envelope)
                    .map_err(|e| Error::Context(Box::new(e)))?;
                let transfer =
                    if !is_ack_successful(&msg.message.acknowledgement)? {
                        // For refunding the token to a shielded address
                        msg.transfer.clone()
                    } else {
                        None
                    };
                Ok(transfer)
            }
            IbcMessage::Timeout(msg) => {
                let envelope = MsgEnvelope::Packet(PacketMsg::Timeout(
                    msg.message.clone(),
                ));
                execute(&mut self.ctx, &mut self.router, envelope)
                    .map_err(|e| Error::Context(Box::new(e)))?;
                Ok(msg.transfer.clone())
            }
            IbcMessage::Envelope(envelope) => {
                execute(&mut self.ctx, &mut self.router, *envelope.clone())
                    .map_err(|e| Error::Context(Box::new(e)))?;
                Ok(None)
            }
        }
    }

    /// Check the result of receiving the packet by checking the packet
    /// acknowledgement
    fn is_receiving_success(
        &self,
        msg: &IbcMsgRecvPacket,
    ) -> Result<bool, Error> {
        let packet_ack = self
            .ctx
            .inner
            .borrow()
            .packet_ack(
                &msg.packet.port_id_on_b,
                &msg.packet.chan_id_on_b,
                msg.packet.seq_on_a,
            )
            .map_err(|e| Error::Context(Box::new(e)))?;
        let success_ack_commitment = compute_ack_commitment(
            &AcknowledgementStatus::success(ack_success_b64()).into(),
        );
        Ok(packet_ack == success_ack_commitment)
    }

    /// Validate according to the message in IBC VP
    pub fn validate(&self, tx_data: &[u8]) -> Result<(), Error> {
        // Use an empty verifiers set placeholder for validation, this is only
        // needed in actual txs to addresses whose VPs should be triggered
        let verifiers = Rc::new(RefCell::new(BTreeSet::<Address>::new()));

        let message = decode_message(tx_data)?;
        match message {
            IbcMessage::Transfer(msg) => {
                let token_transfer_ctx = TokenTransferContext::new(
                    self.ctx.inner.clone(),
                    verifiers.clone(),
                );
                self.insert_verifiers()?;
                send_transfer_validate(
                    &self.ctx,
                    &token_transfer_ctx,
                    msg.message,
                )
                .map_err(Error::TokenTransfer)
            }
            IbcMessage::NftTransfer(msg) => {
                let nft_transfer_ctx =
                    NftTransferContext::new(self.ctx.inner.clone());
                send_nft_transfer_validate(
                    &self.ctx,
                    &nft_transfer_ctx,
                    msg.message,
                )
                .map_err(Error::NftTransfer)
            }
            IbcMessage::RecvPacket(msg) => {
                if let Some(shielding_transfer) = &msg.transfer {
                    self.validate_shielding_transfer(
                        shielding_transfer,
                        &msg.message.packet,
                        false,
                    )?;
                }
                validate(
                    &self.ctx,
                    &self.router,
                    MsgEnvelope::Packet(PacketMsg::Recv(msg.message)),
                )
                .map_err(|e| Error::Context(Box::new(e)))
            }
            IbcMessage::AckPacket(msg) => {
                if let Some(shielding_transfer) = &msg.transfer {
                    self.validate_shielding_transfer(
                        shielding_transfer,
                        &msg.message.packet,
                        true,
                    )?;
                }
                validate(
                    &self.ctx,
                    &self.router,
                    MsgEnvelope::Packet(PacketMsg::Ack(msg.message)),
                )
                .map_err(|e| Error::Context(Box::new(e)))
            }
            IbcMessage::Timeout(msg) => {
                if let Some(shielding_transfer) = &msg.transfer {
                    self.validate_shielding_transfer(
                        shielding_transfer,
                        &msg.message.packet,
                        true,
                    )?;
                }
                validate(
                    &self.ctx,
                    &self.router,
                    MsgEnvelope::Packet(PacketMsg::Timeout(msg.message)),
                )
                .map_err(|e| Error::Context(Box::new(e)))
            }
            IbcMessage::Envelope(envelope) => {
                validate(&self.ctx, &self.router, *envelope)
                    .map_err(|e| Error::Context(Box::new(e)))
            }
        }
    }

    fn insert_verifiers(&self) -> Result<(), Error> {
        let mut ctx = self.ctx.inner.borrow_mut();
        for verifier in self.verifiers.borrow().iter() {
            ctx.insert_verifier(verifier).map_err(Error::Verifier)?;
        }
        Ok(())
    }

    fn validate_shielding_transfer(
        &self,
        shielding_transfer: &ShieldingTransfer,
        packet: &Packet,
        is_sender: bool,
    ) -> Result<(), Error> {
        if shielding_transfer.source != IBC_ESCROW_ADDRESS {
            return Err(Error::ShieldingTransfer);
        }

        let my_port_id = if is_sender {
            &packet.port_id_on_a
        } else {
            &packet.port_id_on_b
        };
        let (ibc_trace, amount) = if *my_port_id == PortId::transfer() {
            let packet_data = serde_json::from_slice::<PacketData>(
                &packet.data,
            )
            .map_err(|e| {
                Error::TokenTransfer(TokenTransferError::Other(format!(
                    "Decoding the packet data failed: {e}"
                )))
            })?;
            let ibc_denom = packet_data.token.denom.to_string();
            let uint_amount =
                Uint(primitive_types::U256::from(packet_data.token.amount).0);
            // amount should be canonical
            let amount = Amount::from_uint(uint_amount, 0).map_err(|e| {
                Error::TokenTransfer(TokenTransferError::Other(format!(
                    "Invalid amount: {}, error {e}",
                    packet_data.token.amount
                )))
            })?;
            (ibc_denom, amount)
        } else {
            let packet_data = serde_json::from_slice::<NftPacketData>(
                &packet.data,
            )
            .map_err(|e| {
                Error::TokenTransfer(TokenTransferError::Other(format!(
                    "Decoding the packet data failed: {e}"
                )))
            })?;
            let ibc_trace = format!(
                "{}/{}",
                &packet_data.class_id,
                packet_data
                    .token_ids
                    .0
                    .first()
                    .expect("TokenID should exist"),
            );
            (ibc_trace, Amount::from_u64(1))
        };

        let ibc_token = if is_sender {
            if ibc_trace.contains('/') {
                ibc_token(&ibc_trace)
            } else {
                Address::decode(&ibc_trace).map_err(|e| {
                    Error::TokenTransfer(TokenTransferError::Other(format!(
                        "Invalid IBC trace: {e}"
                    )))
                })?
            }
        } else {
            received_ibc_token(
                &ibc_trace,
                &packet.port_id_on_a,
                &packet.chan_id_on_a,
                &packet.port_id_on_b,
                &packet.chan_id_on_b,
            )?
        };

        if shielding_transfer.token != ibc_token
            || shielding_transfer.amount != amount.into()
        {
            return Err(Error::ShieldingTransfer);
        }

        Ok(())
    }
}

fn is_ack_successful(ack: &Acknowledgement) -> Result<bool, Error> {
    let acknowledgement = serde_json::from_slice::<AcknowledgementStatus>(
        ack.as_ref(),
    )
    .map_err(|e| {
        Error::TokenTransfer(TokenTransferError::Other(format!(
            "Decoding the acknowledgement failed: {e}"
        )))
    })?;
    Ok(acknowledgement.is_successful())
}

/// Tries to decode transaction data to an `IbcMessage`
pub fn decode_message(tx_data: &[u8]) -> Result<IbcMessage, Error> {
    // ibc-rs message
    if let Ok(any_msg) = Any::decode(tx_data) {
        if let Ok(envelope) = MsgEnvelope::try_from(any_msg) {
            return Ok(IbcMessage::Envelope(Box::new(envelope)));
        }
    }

    // Transfer message with `IbcShieldedTransfer`
    if let Ok(msg) = MsgTransfer::try_from_slice(tx_data) {
        return Ok(IbcMessage::Transfer(msg));
    }

    // NFT transfer message with `IbcShieldedTransfer`
    if let Ok(msg) = MsgNftTransfer::try_from_slice(tx_data) {
        return Ok(IbcMessage::NftTransfer(msg));
    }

    // Receiving packet message with `IbcShieldedTransfer`
    if let Ok(msg) = MsgRecvPacket::try_from_slice(tx_data) {
        return Ok(IbcMessage::RecvPacket(msg));
    }

    // Acknowledge packet message with `IbcShieldedTransfer`
    if let Ok(msg) = MsgAcknowledgement::try_from_slice(tx_data) {
        return Ok(IbcMessage::AckPacket(msg));
    }
    // Timeout packet message with `IbcShieldedTransfer`
    if let Ok(msg) = MsgTimeout::try_from_slice(tx_data) {
        return Ok(IbcMessage::Timeout(msg));
    }

    Err(Error::DecodingData)
}

fn received_ibc_trace(
    base_trace: impl AsRef<str>,
    src_port_id: &PortId,
    src_channel_id: &ChannelId,
    dest_port_id: &PortId,
    dest_channel_id: &ChannelId,
) -> Result<String, Error> {
    if *dest_port_id == PortId::transfer() {
        let mut prefixed_denom =
            base_trace.as_ref().parse().map_err(Error::TokenTransfer)?;
        if is_receiver_chain_source(
            src_port_id.clone(),
            src_channel_id.clone(),
            &prefixed_denom,
        ) {
            let prefix =
                TracePrefix::new(src_port_id.clone(), src_channel_id.clone());
            prefixed_denom.remove_trace_prefix(&prefix);
        } else {
            let prefix =
                TracePrefix::new(dest_port_id.clone(), dest_channel_id.clone());
            prefixed_denom.add_trace_prefix(prefix);
        }
        return Ok(prefixed_denom.to_string());
    }

    if let Some((trace_path, base_class_id, token_id)) =
        is_nft_trace(&base_trace)
    {
        let mut class_id = PrefixedClassId {
            trace_path,
            base_class_id: base_class_id.parse().map_err(Error::NftTransfer)?,
        };
        if is_nft_receiver_chain_source(
            src_port_id.clone(),
            src_channel_id.clone(),
            &class_id,
        ) {
            let prefix = NftTracePrefix::new(
                src_port_id.clone(),
                src_channel_id.clone(),
            );
            class_id.remove_trace_prefix(&prefix);
        } else {
            let prefix = NftTracePrefix::new(
                dest_port_id.clone(),
                dest_channel_id.clone(),
            );
            class_id.add_trace_prefix(prefix);
        }
        let token_id: TokenId = token_id.parse().map_err(Error::NftTransfer)?;
        return Ok(format!("{class_id}/{token_id}"));
    }

    Err(Error::Trace(format!(
        "Invalid IBC trace: {}",
        base_trace.as_ref()
    )))
}

/// Get the IbcToken from the source/destination ports and channels
pub fn received_ibc_token(
    ibc_denom: impl AsRef<str>,
    src_port_id: &PortId,
    src_channel_id: &ChannelId,
    dest_port_id: &PortId,
    dest_channel_id: &ChannelId,
) -> Result<Address, Error> {
    let ibc_trace = received_ibc_trace(
        ibc_denom,
        src_port_id,
        src_channel_id,
        dest_port_id,
        dest_channel_id,
    )?;
    if ibc_trace.contains('/') {
        Ok(storage::ibc_token(ibc_trace))
    } else {
        Address::decode(ibc_trace)
            .map_err(|e| Error::Trace(format!("Invalid base token: {e}")))
    }
}

/// Returns the trace path and the token string if the denom is an IBC
/// denom.
pub fn is_ibc_denom(denom: impl AsRef<str>) -> Option<(TracePath, String)> {
    let prefixed_denom = PrefixedDenom::from_str(denom.as_ref()).ok()?;
    let base_denom = prefixed_denom.base_denom.to_string();
    if prefixed_denom.trace_path.is_empty() || base_denom.contains('/') {
        // The denom is just a token or an NFT trace
        return None;
    }
    // The base token isn't decoded because it could be non Namada token
    Some((prefixed_denom.trace_path, base_denom))
}

/// Returns the trace path and the token string if the trace is an NFT one
pub fn is_nft_trace(
    trace: impl AsRef<str>,
) -> Option<(NftTracePath, String, String)> {
    // The trace should be {port}/{channel}/.../{class_id}/{token_id}
    if let Some((class_id, token_id)) = trace.as_ref().rsplit_once('/') {
        let prefixed_class_id = PrefixedClassId::from_str(class_id).ok()?;
        // The base token isn't decoded because it could be non Namada token
        Some((
            prefixed_class_id.trace_path,
            prefixed_class_id.base_class_id.to_string(),
            token_id.to_string(),
        ))
    } else {
        None
    }
}

#[cfg(any(test, feature = "testing"))]
/// Testing helpers ans strategies for IBC
pub mod testing {
    use std::str::FromStr;

    use ibc::apps::transfer::types::msgs::transfer::MsgTransfer;
    use ibc::apps::transfer::types::packet::PacketData;
    use ibc::apps::transfer::types::{
        Amount, BaseDenom, Memo, PrefixedCoin, PrefixedDenom, TracePath,
        TracePrefix,
    };
    use ibc::core::channel::types::timeout::TimeoutHeight;
    use ibc::core::client::types::Height;
    use ibc::core::host::types::identifiers::{ChannelId, PortId};
    use ibc::core::primitives::Signer;
    use ibc::primitives::proto::Any;
    use ibc::primitives::{Timestamp, ToProto};
    use proptest::prelude::{Just, Strategy};
    use proptest::{collection, prop_compose, prop_oneof};

    prop_compose! {
        /// Generate an arbitrary port ID
        pub fn arb_ibc_port_id()(id in "[a-zA-Z0-9_+.\\-\\[\\]#<>]{2,128}") -> PortId {
            PortId::new(id).expect("generated invalid port ID")
        }
    }

    prop_compose! {
        /// Generate an arbitrary channel ID
        pub fn arb_ibc_channel_id()(id: u64) -> ChannelId {
            ChannelId::new(id)
        }
    }

    prop_compose! {
        /// Generate an arbitrary IBC height
        pub fn arb_ibc_height()(
            revision_number: u64,
            revision_height in 1u64..,
        ) -> Height {
            Height::new(revision_number, revision_height)
                .expect("generated invalid IBC height")
        }
    }

    /// Generate arbitrary timeout data
    pub fn arb_ibc_timeout_data() -> impl Strategy<Value = TimeoutHeight> {
        prop_oneof![
            arb_ibc_height().prop_map(TimeoutHeight::At),
            Just(TimeoutHeight::Never),
        ]
    }

    prop_compose! {
        /// Generate an arbitrary IBC timestamp
        pub fn arb_ibc_timestamp()(nanoseconds: u64) -> Timestamp {
            Timestamp::from_nanoseconds(nanoseconds).expect("generated invalid IBC timestamp")
        }
    }

    prop_compose! {
        /// Generate an arbitrary IBC memo
        pub fn arb_ibc_memo()(memo in "[a-zA-Z0-9_]*") -> Memo {
            memo.into()
        }
    }

    prop_compose! {
        /// Generate an arbitrary IBC memo
        pub fn arb_ibc_signer()(signer in "[a-zA-Z0-9_]*") -> Signer {
            signer.into()
        }
    }

    prop_compose! {
        /// Generate an arbitrary IBC trace prefix
        pub fn arb_ibc_trace_prefix()(
            port_id in arb_ibc_port_id(),
            channel_id in arb_ibc_channel_id(),
        ) -> TracePrefix {
            TracePrefix::new(port_id, channel_id)
        }
    }

    prop_compose! {
        /// Generate an arbitrary IBC trace path
        pub fn arb_ibc_trace_path()(path in collection::vec(arb_ibc_trace_prefix(), 0..10)) -> TracePath {
            TracePath::from(path)
        }
    }

    prop_compose! {
        /// Generate an arbitrary IBC base denomination
        pub fn arb_ibc_base_denom()(base_denom in "[a-zA-Z0-9_]+") -> BaseDenom {
            BaseDenom::from_str(&base_denom).expect("generated invalid IBC base denomination")
        }
    }

    prop_compose! {
        /// Generate an arbitrary IBC prefixed denomination
        pub fn arb_ibc_prefixed_denom()(
            trace_path in arb_ibc_trace_path(),
            base_denom in arb_ibc_base_denom(),
        ) -> PrefixedDenom {
            PrefixedDenom {
                trace_path,
                base_denom,
            }
        }
    }

    prop_compose! {
        /// Generate an arbitrary IBC amount
        pub fn arb_ibc_amount()(value: [u64; 4]) -> Amount {
            value.into()
        }
    }

    prop_compose! {
        /// Generate an arbitrary prefixed coin
        pub fn arb_ibc_prefixed_coin()(
            denom in arb_ibc_prefixed_denom(),
            amount in arb_ibc_amount(),
        ) -> PrefixedCoin {
            PrefixedCoin {
                denom,
                amount,
            }
        }
    }

    prop_compose! {
        /// Generate arbitrary packet data
        pub fn arb_ibc_packet_data()(
            token in arb_ibc_prefixed_coin(),
            sender in arb_ibc_signer(),
            receiver in arb_ibc_signer(),
            memo in arb_ibc_memo(),
        ) -> PacketData {
            PacketData {
                token,
                sender,
                receiver,
                memo,
            }
        }
    }

    prop_compose! {
        /// Generate an arbitrary IBC transfer message
        pub fn arb_ibc_msg_transfer()(
            port_id_on_a in arb_ibc_port_id(),
            chan_id_on_a in arb_ibc_channel_id(),
            packet_data in arb_ibc_packet_data(),
            timeout_height_on_b in arb_ibc_timeout_data(),
            timeout_timestamp_on_b in arb_ibc_timestamp(),
        ) -> MsgTransfer {
            MsgTransfer {
                port_id_on_a,
                chan_id_on_a,
                packet_data,
                timeout_height_on_b,
                timeout_timestamp_on_b,
            }
        }
    }

    prop_compose! {
        /// Generate an arbitrary IBC any object
        pub fn arb_ibc_any()(msg_transfer in arb_ibc_msg_transfer()) -> Any {
            msg_transfer.to_any()
        }
    }
}
