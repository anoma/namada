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
mod protocol;
pub mod storage;
pub mod trace;
pub mod vp;

use std::fmt::Debug;
use std::marker::PhantomData;

pub use actions::*;
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
use ibc::apps::nft_transfer::types::error::NftTransferError;
use ibc::apps::nft_transfer::types::{
    is_receiver_chain_source as is_nft_receiver_chain_source, PrefixedClassId,
    TokenId, TracePrefix as NftTracePrefix,
};
use ibc::apps::transfer::types::error::TokenTransferError;
use ibc::apps::transfer::types::{is_receiver_chain_source, TracePrefix};
use ibc::core::channel::types::msgs::PacketMsg;
use ibc::core::channel::types::packet::Packet;
use ibc::core::handler::types::error::ContextError;
use ibc::core::handler::types::events::Error as RawIbcEventError;
use ibc::core::handler::types::msgs::MsgEnvelope;
use ibc::core::host::types::error::IdentifierError;
use ibc::core::host::types::identifiers::{ChannelId, PortId};
use ibc::core::router::types::error::RouterError;
pub use ibc::*;
use masp_primitives::transaction::Transaction as MaspTransaction;
pub use msg::*;
use namada_core::address::{self, Address};
use namada_core::arith::{checked, CheckedAdd, CheckedSub};
pub use namada_core::ibc::*;
use namada_core::masp::{addr_taddr, ibc_taddr, MaspEpoch, TAddrData};
use namada_core::masp_primitives::transaction::components::ValueSum;
use namada_core::token::Amount;
use namada_events::EmitEvents;
use namada_state::{
    DBIter, Error as StorageError, Key, Result as StorageResult, ResultExt,
    State, StorageHasher, StorageRead, StorageWrite, WlState, DB,
};
use namada_systems::ibc::ChangedBalances;
pub use nft::*;
pub use protocol::transfer_over_ibc;
use thiserror::Error;
use trace::{
    convert_to_address,
    is_receiver_chain_source as is_receiver_chain_source_str,
    is_sender_chain_source,
};

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
/// The commitment prefix for the ICS23 commitment proof
pub const COMMITMENT_PREFIX: &str = "ibc";

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
    Verifier(StorageError),
    #[error("Storage read/write error: {0}")]
    Storage(StorageError),
    #[error("IBC error: {0}")]
    Other(String),
}

impl From<Error> for StorageError {
    fn from(value: Error) -> Self {
        StorageError::new(value)
    }
}

/// IBC storage `Keys/Read/Write` implementation
#[derive(Debug)]
pub struct Store<S>(PhantomData<S>);

impl<S> namada_systems::ibc::Read<S> for Store<S>
where
    S: StorageRead,
{
    fn try_extract_masp_tx_from_envelope<Transfer: BorshDeserialize>(
        tx_data: &[u8],
    ) -> StorageResult<Option<masp_primitives::transaction::Transaction>> {
        let msg = decode_message::<Transfer>(tx_data)
            .into_storage_result()
            .ok();
        let tx = if let Some(IbcMessage::Envelope(ref envelope)) = msg {
            extract_masp_tx_from_envelope(envelope)
        } else {
            None
        };
        Ok(tx)
    }

    fn try_get_refund_masp_tx<Transfer: BorshDeserialize>(
        storage: &S,
        tx_data: &[u8],
        masp_epoch: MaspEpoch,
    ) -> StorageResult<Option<MaspTransaction>> {
        // refund only when ack or timeout in an IBC envelope message
        let Some(IbcMessage::Envelope(envelope)) =
            decode_message::<Transfer>(tx_data)
                .into_storage_result()
                .ok()
        else {
            return Ok(None);
        };

        let Some((port_id, channel_id, sequence)) =
            packet_info_from_envelope(&envelope)
        else {
            return Ok(None);
        };

        let key = storage::refund_masp_tx_key(
            port_id, channel_id, sequence, masp_epoch,
        );
        storage.read(&key)
    }

    fn apply_ibc_packet<Transfer: BorshDeserialize>(
        tx_data: &[u8],
        accum: ChangedBalances,
    ) -> StorageResult<ChangedBalances> {
        let msg = decode_message::<Transfer>(tx_data)
            .into_storage_result()
            .ok();
        match msg {
            None => Ok(accum),
            // This event is emitted on the sender
            Some(IbcMessage::Transfer(msg)) => {
                // Get the packet commitment from post-storage that corresponds
                // to this event
                let ibc_transfer = IbcTransferInfo::try_from(msg.message)?;
                apply_transfer_msg(accum, ibc_transfer)
            }
            Some(IbcMessage::NftTransfer(msg)) => {
                let ibc_transfer = IbcTransferInfo::try_from(msg.message)?;
                apply_transfer_msg(accum, ibc_transfer)
            }
            Some(IbcMessage::Envelope(envelope)) => match *envelope {
                MsgEnvelope::Packet(PacketMsg::Recv(msg)) => {
                    apply_recv_msg(accum, &msg.packet)
                }
                MsgEnvelope::Packet(PacketMsg::Ack(msg)) => {
                    apply_refund_msg(accum, &msg.packet)
                }
                MsgEnvelope::Packet(PacketMsg::Timeout(msg)) => {
                    apply_refund_msg(accum, &msg.packet)
                }
                _ => Ok(accum),
            },
        }
    }
}

// Apply the given transfer message to the changed balances structure
fn apply_transfer_msg(
    mut accum: ChangedBalances,
    ibc_transfer: IbcTransferInfo,
) -> StorageResult<ChangedBalances> {
    let IbcTransferInfo {
        ibc_traces,
        src_port_id,
        src_channel_id,
        amount,
        receiver,
    } = ibc_transfer;

    let addr = TAddrData::Ibc(receiver.clone());
    let receiver = ibc_taddr(receiver);
    accum.decoder.insert(receiver, addr);
    for ibc_trace in &ibc_traces {
        let token = convert_to_address(ibc_trace).into_storage_result()?;
        let delta = ValueSum::from_pair(token, amount);
        // If there is a transfer to the IBC account, then deduplicate the
        // balance increase since we already account for it below
        if is_sender_chain_source(ibc_trace, &src_port_id, &src_channel_id) {
            let ibc_taddr = addr_taddr(address::IBC);
            let post_entry = accum
                .post
                .get(&ibc_taddr)
                .cloned()
                .unwrap_or(ValueSum::zero());
            accum.post.insert(
                ibc_taddr,
                checked!(post_entry - &delta).map_err(StorageError::new)?,
            );
        }
        // Record an increase to the balance of a specific IBC receiver
        let post_entry = accum
            .post
            .get(&receiver)
            .cloned()
            .unwrap_or(ValueSum::zero());
        accum.post.insert(
            receiver,
            checked!(post_entry + &delta).map_err(StorageError::new)?,
        );
    }

    Ok(accum)
}

// Apply the given write acknowledge to the changed balances structure
fn apply_recv_msg(
    mut accum: ChangedBalances,
    packet: &Packet,
) -> StorageResult<ChangedBalances> {
    let recv_info =
        recv_info_from_packet(packet, false).map_err(StorageError::new)?;
    let addr = TAddrData::Ibc(recv_info.receiver.clone());
    accum.decoder.insert(ibc_taddr(recv_info.receiver), addr);
    for ibc_trace in recv_info.ibc_traces {
        // Only artificially increase the IBC internal address pre-balance
        // if receiving involves minting. We do not do this in the unescrow
        // case since the pre-balance already accounts for the amount being
        // received.
        if !is_receiver_chain_source_str(
            &ibc_trace,
            &packet.port_id_on_a,
            &packet.chan_id_on_a,
        ) {
            // Get the received token
            let token = received_ibc_token(
                ibc_trace,
                &packet.port_id_on_a,
                &packet.chan_id_on_a,
                &packet.port_id_on_b,
                &packet.chan_id_on_b,
            )
            .into_storage_result()?;
            let delta = ValueSum::from_pair(token.clone(), recv_info.amount);
            // Enable funds to be taken from the IBC internal
            // address and be deposited elsewhere
            // Required for the IBC internal Address to release
            // funds
            let ibc_taddr = addr_taddr(address::IBC);
            let pre_entry = accum
                .pre
                .get(&ibc_taddr)
                .cloned()
                .unwrap_or(ValueSum::zero());
            accum.pre.insert(
                ibc_taddr,
                checked!(pre_entry + &delta).map_err(StorageError::new)?,
            );
        }
    }
    Ok(accum)
}

// Apply a refund to the changed balances structure
fn apply_refund_msg(
    mut accum: ChangedBalances,
    packet: &Packet,
) -> StorageResult<ChangedBalances> {
    let refund_info =
        recv_info_from_packet(packet, true).map_err(StorageError::new)?;
    // Shielded refund only happens if MsgAcknowledgement or MsgTimeout is
    // successful
    for ibc_trace in &refund_info.ibc_traces {
        // If there is a transfer to the IBC account, then deduplicate the
        // balance increase since we already account for it below
        let token = convert_to_address(ibc_trace).into_storage_result()?;
        let delta = ValueSum::from_pair(token, refund_info.amount);
        if !is_sender_chain_source(
            ibc_trace,
            &packet.port_id_on_a,
            &packet.chan_id_on_a,
        ) {
            // Enable funds to be taken from the IBC internal address and be
            // deposited elsewhere
            // Required for the IBC internal address to release funds
            let ibc_taddr = addr_taddr(address::IBC);
            let pre_entry = accum
                .pre
                .get(&ibc_taddr)
                .cloned()
                .unwrap_or(ValueSum::zero());
            accum.pre.insert(
                ibc_taddr,
                checked!(pre_entry + &delta).map_err(StorageError::new)?,
            );
        }
    }
    Ok(accum)
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
    use ibc::core::channel::types::timeout::{TimeoutHeight, TimeoutTimestamp};
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
        pub fn arb_ibc_timestamp()(nanoseconds: u64) -> TimeoutTimestamp {
            TimeoutTimestamp::At(Timestamp::from_nanoseconds(nanoseconds))
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
        pub fn arb_ibc_token_ids()(token_ids in collection::hash_set(arb_ibc_token_id().prop_map(|x| x.to_string()), 1..10)) -> TokenIds {
            TokenIds::try_from(token_ids.into_iter().collect::<Vec<_>>()).expect("generated invalid IBC token ID vector")
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
