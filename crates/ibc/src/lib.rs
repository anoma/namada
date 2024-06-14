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
pub mod trace;
pub mod vp;

use std::cell::RefCell;
use std::collections::BTreeSet;
use std::fmt::Debug;
use std::rc::Rc;

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
use ibc::apps::nft_transfer::types::msgs::transfer::MsgTransfer as IbcMsgNftTransfer;
use ibc::apps::nft_transfer::types::{
    ack_success_b64, is_receiver_chain_source as is_nft_receiver_chain_source,
    PrefixedClassId, TokenId, TracePrefix as NftTracePrefix,
};
use ibc::apps::transfer::handler::{
    send_transfer_execute, send_transfer_validate,
};
use ibc::apps::transfer::types::error::TokenTransferError;
use ibc::apps::transfer::types::msgs::transfer::MsgTransfer as IbcMsgTransfer;
use ibc::apps::transfer::types::{is_receiver_chain_source, TracePrefix};
use ibc::core::channel::types::acknowledgement::{
    Acknowledgement, AcknowledgementStatus,
};
use ibc::core::channel::types::commitment::compute_ack_commitment;
use ibc::core::channel::types::msgs::{
    MsgRecvPacket as IbcMsgRecvPacket, PacketMsg,
};
use ibc::core::entrypoint::{execute, validate};
use ibc::core::handler::types::error::ContextError;
use ibc::core::handler::types::events::Error as RawIbcEventError;
use ibc::core::handler::types::msgs::MsgEnvelope;
use ibc::core::host::types::error::IdentifierError;
use ibc::core::host::types::identifiers::{ChannelId, PortId, Sequence};
use ibc::core::router::types::error::RouterError;
use ibc::primitives::proto::Any;
pub use ibc::*;
use masp_primitives::transaction::Transaction as MaspTransaction;
pub use msg::*;
use namada_core::address::{self, Address};
use namada_core::arith::checked;
use namada_core::token::Amount;
use namada_events::EmitEvents;
use namada_state::{
    DBIter, Key, State, StorageError, StorageHasher, StorageRead, StorageWrite,
    WlState, DB,
};
use namada_token::Transfer;
pub use nft::*;
use prost::Message;
use thiserror::Error;

use crate::storage::{
    channel_counter_key, client_counter_key, connection_counter_key,
    deposit_prefix, withdraw_prefix,
};

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
    ) -> Result<(Option<Transfer>, Option<MaspTransaction>), Error> {
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
                Ok((msg.transfer.clone(), None))
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
                Ok((msg.transfer.clone(), None))
            }
            IbcMessage::Envelope(envelope) => {
                execute(&mut self.ctx, &mut self.router, *envelope.clone())
                    .map_err(|e| Error::Context(Box::new(e)))?;
                // Extract MASP tx from the memo in the packet if needed
                let masp_tx = match &**envelope {
                    MsgEnvelope::Packet(packet_msg) => {
                        match packet_msg {
                            PacketMsg::Recv(msg) => {
                                if self.is_receiving_success(msg)? {
                                    extract_masp_tx_from_packet(
                                        &msg.packet,
                                        false,
                                    )
                                } else {
                                    None
                                }
                            }
                            PacketMsg::Ack(msg) => {
                                if is_ack_successful(&msg.acknowledgement)? {
                                    // No refund
                                    None
                                } else {
                                    extract_masp_tx_from_packet(
                                        &msg.packet,
                                        true,
                                    )
                                }
                            }
                            PacketMsg::Timeout(msg) => {
                                extract_masp_tx_from_packet(&msg.packet, true)
                            }
                            _ => None,
                        }
                    }
                    _ => None,
                };
                Ok((None, masp_tx))
            }
        }
    }

    /// Check the result of receiving the packet by checking the packet
    /// acknowledgement
    pub fn is_receiving_success(
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
        if let Ok(envelope) = MsgEnvelope::try_from(any_msg.clone()) {
            return Ok(IbcMessage::Envelope(Box::new(envelope)));
        }
        if let Ok(message) = IbcMsgTransfer::try_from(any_msg.clone()) {
            let msg = MsgTransfer {
                message,
                transfer: None,
            };
            return Ok(IbcMessage::Transfer(msg));
        }
        if let Ok(message) = IbcMsgNftTransfer::try_from(any_msg) {
            let msg = MsgNftTransfer {
                message,
                transfer: None,
            };
            return Ok(IbcMessage::NftTransfer(msg));
        }
    }

    // Transfer message with `ShieldingTransfer`
    if let Ok(msg) = MsgTransfer::try_from_slice(tx_data) {
        return Ok(IbcMessage::Transfer(msg));
    }

    // NFT transfer message with `ShieldingTransfer`
    if let Ok(msg) = MsgNftTransfer::try_from_slice(tx_data) {
        return Ok(IbcMessage::NftTransfer(msg));
    }

    Err(Error::DecodingData)
}

/// Return the last sequence send
pub fn get_last_sequence_send<S: StorageRead>(
    storage: &S,
    port_id: &PortId,
    channel_id: &ChannelId,
) -> Result<Sequence, StorageError> {
    let seq_key = storage::next_sequence_send_key(port_id, channel_id);
    let next_seq: u64 =
        context::common::read_sequence(storage, &seq_key)?.into();
    if next_seq <= 1 {
        // No transfer heppened
        return Err(StorageError::new_alloc(format!(
            "No IBC transfer happened: Port ID {port_id}, Channel ID \
             {channel_id}",
        )));
    }
    Ok(checked!(next_seq - 1)?.into())
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
        trace::is_nft_trace(&base_trace)
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
    trace::convert_to_address(ibc_trace)
        .map_err(|e| Error::Trace(format!("Invalid base token: {e}")))
}

/// Initialize storage in the genesis block.
pub fn init_genesis_storage<S>(storage: &mut S)
where
    S: State,
{
    // In ibc-go, u64 like a counter is encoded with big-endian:
    // https://github.com/cosmos/ibc-go/blob/89ffaafb5956a5ea606e1f1bf249c880bea802ed/modules/core/04-channel/keeper/keeper.go#L115

    let init_value = 0_u64;

    // the client counter
    let key = client_counter_key();
    storage
        .write(&key, init_value)
        .expect("Unable to write the initial client counter");

    // the connection counter
    let key = connection_counter_key();
    storage
        .write(&key, init_value)
        .expect("Unable to write the initial connection counter");

    // the channel counter
    let key = channel_counter_key();
    storage
        .write(&key, init_value)
        .expect("Unable to write the initial channel counter");
}

/// Update IBC-related data when finalizing block
pub fn finalize_block<D, H>(
    state: &mut WlState<D, H>,
    _events: &mut impl EmitEvents,
    is_new_epoch: bool,
) -> Result<(), StorageError>
where
    D: 'static + DB + for<'iter> DBIter<'iter> + Sync,
    H: 'static + StorageHasher + Sync,
{
    if is_new_epoch {
        clear_throughputs(state)?;
    }
    Ok(())
}

/// Clear the per-epoch throughputs (deposit and withdraw)
fn clear_throughputs<D, H>(
    state: &mut WlState<D, H>,
) -> Result<(), StorageError>
where
    D: 'static + DB + for<'iter> DBIter<'iter> + Sync,
    H: 'static + StorageHasher + Sync,
{
    for prefix in [deposit_prefix(), withdraw_prefix()] {
        let keys: Vec<Key> = state
            .iter_prefix(&prefix)?
            .map(|(key, _, _)| {
                Key::parse(key).expect("The key should be parsable")
            })
            .collect();
        for key in keys {
            state.write(&key, Amount::from(0))?;
        }
    }

    Ok(())
}

#[cfg(any(test, feature = "testing"))]
/// Testing helpers ans strategies for IBC
pub mod testing {
    use std::str::FromStr;

    use ibc::apps::nft_transfer::types::msgs::transfer::MsgTransfer as MsgNftTransfer;
    use ibc::apps::nft_transfer::types::packet::PacketData as NftPacketData;
    use ibc::apps::nft_transfer::types::{
        ClassData, ClassId, ClassUri, Memo as NftMemo, PrefixedClassId,
        TokenData, TokenId, TokenIds, TokenUri,
    };
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
    use proptest::{collection, option, prop_compose, prop_oneof};

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
        /// Generate an arbitrary IBC NFT memo
        pub fn arb_ibc_nft_memo()(memo in "[a-zA-Z0-9_]*") -> NftMemo {
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
        /// Generate an arbitrary IBC token ID
        pub fn arb_ibc_token_id()(token_id in "[a-zA-Z0-9_]+") -> TokenId {
            TokenId::from_str(&token_id).expect("generated invalid IBC token ID")
        }
    }

    prop_compose! {
        /// Generate an arbitrary IBC token ID vector
        pub fn arb_ibc_token_ids()(token_ids in collection::vec(arb_ibc_token_id(), 1..10)) -> TokenIds {
            TokenIds(token_ids)
        }
    }

    prop_compose! {
        /// Generate arbitrary IBC class data
        pub fn arb_ibc_class_data()(class_data in "[a-zA-Z0-9_]*") -> ClassData {
            ClassData::from_str(&class_data).expect("generated invalid IBC class data")
        }
    }

    prop_compose! {
        /// Generate an arbitrary IBC class ID
        pub fn arb_ibc_class_id()(token_id in "[a-zA-Z0-9_]+") -> ClassId {
            ClassId::from_str(&token_id).expect("generated invalid IBC class ID")
        }
    }

    prop_compose! {
        /// Generate an arbitrary IBC prefixed class ID
        pub fn arb_ibc_prefixed_class_id()(
            trace_path in arb_ibc_trace_path(),
            base_class_id in arb_ibc_class_id(),
        ) -> PrefixedClassId {
            PrefixedClassId {
                trace_path,
                base_class_id,
            }
        }
    }

    prop_compose! {
        /// Generate arbitrary IBC token data
        pub fn arb_ibc_token_data()(
            token_data in "[a-zA-Z0-9_]*",
        ) -> TokenData {
            TokenData::from_str(&token_data).expect("generated invalid IBC token data")
        }
    }

    // An arbitrary URI for the tests. Generating random URIs would not increase
    // test coverage since they are encoded as length-prefixed strings.
    const ARBITRARY_URI: &str = "https://namada.net/#ibc-interoperability";

    prop_compose! {
        /// Generate arbitrary NFT packet data
        pub fn arb_ibc_nft_packet_data()(
            token_ids in arb_ibc_token_ids(),
            token_uri in Just(TokenUri::from_str(ARBITRARY_URI).unwrap()),
        )(
            sender in arb_ibc_signer(),
            receiver in arb_ibc_signer(),
            memo in option::of(arb_ibc_nft_memo()),
            class_data in option::of(arb_ibc_class_data()),
            class_id in arb_ibc_prefixed_class_id(),
            class_uri in option::of(Just(ClassUri::from_str(ARBITRARY_URI).unwrap())),
            token_uris in option::of(collection::vec(Just(token_uri), token_ids.0.len())),
            token_data in option::of(collection::vec(arb_ibc_token_data(), token_ids.0.len())),
            token_ids in Just(token_ids),
        ) -> NftPacketData {
            NftPacketData {
                token_ids,
                sender,
                receiver,
                memo,
                class_data,
                class_id,
                class_uri,
                token_uris,
                token_data,
            }
        }
    }

    prop_compose! {
        /// Generate an arbitrary IBC NFT transfer message
        pub fn arb_ibc_msg_nft_transfer()(
            port_id_on_a in arb_ibc_port_id(),
            chan_id_on_a in arb_ibc_channel_id(),
            packet_data in arb_ibc_nft_packet_data(),
            timeout_height_on_b in arb_ibc_timeout_data(),
            timeout_timestamp_on_b in arb_ibc_timestamp(),
        ) -> MsgNftTransfer {
            MsgNftTransfer {
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
        pub fn arb_ibc_any()(any in prop_oneof![
            arb_ibc_msg_transfer().prop_map(|x| x.to_any()),
            arb_ibc_msg_nft_transfer().prop_map(|x| x.to_any()),
        ]) -> Any {
            any
        }
    }
}
