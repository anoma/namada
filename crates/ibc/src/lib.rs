//! IBC library code

mod actions;
pub mod context;
pub mod storage;

use std::cell::RefCell;
use std::fmt::Debug;
use std::rc::Rc;
use std::str::FromStr;

pub use actions::{transfer_over_ibc, CompatibleIbcTxHostEnvState};
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
use namada_core::address::{Address, MASP};
use namada_core::ibc::apps::nft_transfer::handler::{
    send_nft_transfer_execute, send_nft_transfer_validate,
};
use namada_core::ibc::apps::nft_transfer::types::error::NftTransferError;
use namada_core::ibc::apps::nft_transfer::types::packet::PacketData as NftPacketData;
use namada_core::ibc::apps::nft_transfer::types::{
    is_receiver_chain_source as is_nft_receiver_chain_source, PrefixedClassId,
    TokenId, TracePrefix as NftTracePrefix,
};
use namada_core::ibc::apps::transfer::handler::{
    send_transfer_execute, send_transfer_validate,
};
use namada_core::ibc::apps::transfer::types::error::TokenTransferError;
use namada_core::ibc::apps::transfer::types::packet::PacketData;
use namada_core::ibc::apps::transfer::types::{
    is_receiver_chain_source, TracePrefix,
};
use namada_core::ibc::core::channel::types::acknowledgement::{
    Acknowledgement, AcknowledgementStatus,
};
use namada_core::ibc::core::channel::types::msgs::{
    MsgRecvPacket as IbcMsgRecvPacket, PacketMsg,
};
use namada_core::ibc::core::entrypoint::{execute, validate};
use namada_core::ibc::core::handler::types::error::ContextError;
use namada_core::ibc::core::handler::types::msgs::MsgEnvelope;
use namada_core::ibc::core::host::types::error::IdentifierError;
use namada_core::ibc::core::host::types::identifiers::{ChannelId, PortId};
use namada_core::ibc::core::router::types::error::RouterError;
use namada_core::ibc::primitives::proto::Any;
pub use namada_core::ibc::*;
use namada_core::masp::PaymentAddress;
use prost::Message;
use thiserror::Error;

#[allow(missing_docs)]
#[derive(Error, Debug)]
pub enum Error {
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
    #[error("Handling MASP transaction error: {0}")]
    MaspTx(String),
}

/// IBC actions to handle IBC operations
#[derive(Debug)]
pub struct IbcActions<'a, C>
where
    C: IbcCommonContext,
{
    ctx: IbcContext<C>,
    router: IbcRouter<'a>,
}

impl<'a, C> IbcActions<'a, C>
where
    C: IbcCommonContext + Debug,
{
    /// Make new IBC actions
    pub fn new(ctx: Rc<RefCell<C>>) -> Self {
        Self {
            ctx: IbcContext::new(ctx),
            router: IbcRouter::new(),
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
    pub fn execute(&mut self, tx_data: &[u8]) -> Result<(), Error> {
        let message = decode_message(tx_data)?;
        match &message {
            IbcMessage::Transfer(msg) => {
                let mut token_transfer_ctx =
                    TokenTransferContext::new(self.ctx.inner.clone());
                send_transfer_execute(
                    &mut self.ctx,
                    &mut token_transfer_ctx,
                    msg.message.clone(),
                )
                .map_err(Error::TokenTransfer)?;
                match &msg.shielded_transfer {
                    Some(shielded_transfer) => {
                        self.handle_masp_tx(shielded_transfer)
                    }
                    None => Ok(()),
                }
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
                match &msg.shielded_transfer {
                    Some(shielded_transfer) => {
                        self.handle_masp_tx(shielded_transfer)
                    }
                    None => Ok(()),
                }
            }
            IbcMessage::RecvPacket(msg) => {
                let envelope =
                    MsgEnvelope::Packet(PacketMsg::Recv(msg.message.clone()));
                execute(&mut self.ctx, &mut self.router, envelope)
                    .map_err(|e| Error::Context(Box::new(e)))?;
                if self.is_receiving_success()? {
                    // the current ibc-rs execution doesn't store the denom
                    // for the token hash when transfer with MsgRecvPacket
                    self.store_trace(&msg.message)?;
                    // For receiving the token to a shielded address
                    if let Some(shielded_transfer) = &msg.shielded_transfer {
                        self.handle_masp_tx(shielded_transfer)?;
                    }
                }
                Ok(())
            }
            IbcMessage::AckPacket(msg) => {
                let envelope =
                    MsgEnvelope::Packet(PacketMsg::Ack(msg.message.clone()));
                execute(&mut self.ctx, &mut self.router, envelope)
                    .map_err(|e| Error::Context(Box::new(e)))?;
                if !is_ack_successful(&msg.message.acknowledgement)? {
                    // For refunding the token to a shielded address
                    if let Some(shielded_transfer) = &msg.shielded_transfer {
                        self.handle_masp_tx(shielded_transfer)?;
                    }
                }
                Ok(())
            }
            IbcMessage::Timeout(msg) => {
                let envelope = MsgEnvelope::Packet(PacketMsg::Timeout(
                    msg.message.clone(),
                ));
                execute(&mut self.ctx, &mut self.router, envelope)
                    .map_err(|e| Error::Context(Box::new(e)))?;
                // For refunding the token to a shielded address
                if let Some(shielded_transfer) = &msg.shielded_transfer {
                    self.handle_masp_tx(shielded_transfer)?;
                }
                Ok(())
            }
            IbcMessage::Envelope(envelope) => {
                execute(&mut self.ctx, &mut self.router, *envelope.clone())
                    .map_err(|e| Error::Context(Box::new(e)))?;
                if let MsgEnvelope::Packet(PacketMsg::Recv(msg)) = &**envelope {
                    if self.is_receiving_success()? {
                        // the current ibc-rs execution doesn't store the denom
                        // for the token hash when transfer with MsgRecvPacket
                        self.store_trace(msg)?;
                    }
                }
                Ok(())
            }
        }
    }

    /// Store the trace path when transfer with MsgRecvPacket
    fn store_trace(&mut self, msg: &IbcMsgRecvPacket) -> Result<(), Error> {
        // Get the IBC trace, and the receiver from the packet data
        let minted_token_info = if let Ok(data) =
            serde_json::from_slice::<PacketData>(&msg.packet.data)
        {
            let ibc_denom = received_ibc_trace(
                data.token.denom.to_string(),
                &msg.packet.port_id_on_a,
                &msg.packet.chan_id_on_a,
                &msg.packet.port_id_on_b,
                &msg.packet.chan_id_on_b,
            )?;
            if !ibc_denom.contains('/') {
                // Skip to store it because the token has been redeemed
                return Ok(());
            }
            let receiver =
                if PaymentAddress::from_str(data.receiver.as_ref()).is_ok() {
                    MASP.to_string()
                } else {
                    data.receiver.to_string()
                };
            Some((vec![ibc_denom], receiver))
        } else if let Ok(data) =
            serde_json::from_slice::<NftPacketData>(&msg.packet.data)
        {
            let ibc_traces: Result<Vec<String>, _> = data
                .token_ids
                .0
                .iter()
                .map(|id| {
                    let trace = format!("{}/{id}", data.class_id);
                    received_ibc_trace(
                        trace,
                        &msg.packet.port_id_on_a,
                        &msg.packet.chan_id_on_a,
                        &msg.packet.port_id_on_b,
                        &msg.packet.chan_id_on_b,
                    )
                })
                .collect();
            let receiver =
                if PaymentAddress::from_str(data.receiver.as_ref()).is_ok() {
                    MASP.to_string()
                } else {
                    data.receiver.to_string()
                };
            Some((ibc_traces?, receiver))
        } else {
            None
        };

        if let Some((ibc_traces, receiver)) = minted_token_info {
            // If the trace event has the trace hash and the IBC denom or NFT
            // IDs, a token has been minted. The raw IBC trace including the
            // port ID, the channel ID and the base token is stored to be
            // restored from the trace hash.
            for ibc_trace in ibc_traces {
                let trace_hash = storage::calc_hash(&ibc_trace);
                self.ctx
                    .inner
                    .borrow_mut()
                    .store_ibc_trace(&receiver, &trace_hash, &ibc_trace)
                    .map_err(|e| {
                        Error::Trace(format!(
                            "Writing the IBC trace failed: {}",
                            e
                        ))
                    })?;
                let base_token = if let Some((_, base_token)) =
                    is_ibc_denom(&ibc_trace)
                {
                    base_token
                } else if let Some((_, _, token_id)) = is_nft_trace(&ibc_trace)
                {
                    token_id
                } else {
                    // non-prefixed denom
                    continue;
                };
                self.ctx
                    .inner
                    .borrow_mut()
                    .store_ibc_trace(base_token, trace_hash, &ibc_trace)
                    .map_err(|e| {
                        Error::Trace(format!(
                            "Writing the IBC trace failed: {}",
                            e
                        ))
                    })?;
            }
        }
        Ok(())
    }

    /// Check the result of receiving the packet from IBC events
    fn is_receiving_success(&self) -> Result<bool, Error> {
        let mut receive_event = self
            .ctx
            .inner
            .borrow()
            .get_ibc_events(EVENT_TYPE_PACKET)
            .map_err(|_| {
                Error::Trace("Reading the IBC event failed".to_string())
            })?;
        if receive_event.is_empty() {
            // check the packet is for an NFT
            receive_event = self
                .ctx
                .inner
                .borrow()
                .get_ibc_events(EVENT_TYPE_NFT_PACKET)
                .map_err(|_| {
                    Error::Trace("Reading the IBC event failed".to_string())
                })?;
        }
        match receive_event
            .first()
            .as_ref()
            .and_then(|event| event.attributes.get(EVENT_ATTRIBUTE_SUCCESS))
        {
            Some(success) if success == EVENT_VALUE_SUCCESS => Ok(true),
            _ => Ok(false),
        }
    }

    /// Validate according to the message in IBC VP
    pub fn validate(&self, tx_data: &[u8]) -> Result<(), Error> {
        let message = decode_message(tx_data)?;
        match message {
            IbcMessage::Transfer(msg) => {
                let token_transfer_ctx =
                    TokenTransferContext::new(self.ctx.inner.clone());
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
            IbcMessage::RecvPacket(msg) => validate(
                &self.ctx,
                &self.router,
                MsgEnvelope::Packet(PacketMsg::Recv(msg.message)),
            )
            .map_err(|e| Error::Context(Box::new(e))),
            IbcMessage::AckPacket(msg) => validate(
                &self.ctx,
                &self.router,
                MsgEnvelope::Packet(PacketMsg::Ack(msg.message)),
            )
            .map_err(|e| Error::Context(Box::new(e))),
            IbcMessage::Timeout(msg) => validate(
                &self.ctx,
                &self.router,
                MsgEnvelope::Packet(PacketMsg::Timeout(msg.message)),
            )
            .map_err(|e| Error::Context(Box::new(e))),
            IbcMessage::Envelope(envelope) => {
                validate(&self.ctx, &self.router, *envelope)
                    .map_err(|e| Error::Context(Box::new(e)))
            }
        }
    }

    /// Handle the MASP transaction if needed
    fn handle_masp_tx(
        &mut self,
        shielded_transfer: &IbcShieldedTransfer,
    ) -> Result<(), Error> {
        self.ctx
            .inner
            .borrow_mut()
            .handle_masp_tx(
                &shielded_transfer.masp_tx,
                shielded_transfer.transfer.key.as_deref(),
            )
            .map_err(|_| {
                Error::MaspTx("Writing MASP components failed".to_string())
            })
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
