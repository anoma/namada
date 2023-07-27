//! IBC token transfer validation as a native validity predicate

use std::collections::{BTreeSet, HashMap, HashSet};

use borsh::BorshDeserialize;
use prost::Message;
use thiserror::Error;

use crate::ibc::applications::transfer::coin::PrefixedCoin;
use crate::ibc::applications::transfer::error::TokenTransferError;
use crate::ibc::applications::transfer::msgs::transfer::{
    MsgTransfer, TYPE_URL as MSG_TRANSFER_TYPE_URL,
};
use crate::ibc::applications::transfer::packet::PacketData;
use crate::ibc::applications::transfer::{
    is_receiver_chain_source, is_sender_chain_source,
};
use crate::ibc::core::ics04_channel::msgs::PacketMsg;
use crate::ibc::core::ics04_channel::packet::Packet;
use crate::ibc::core::ics26_routing::error::RouterError;
use crate::ibc::core::ics26_routing::msgs::MsgEnvelope;
use crate::ibc_proto::google::protobuf::Any;
use crate::ledger::ibc::storage as ibc_storage;
use crate::ledger::native_vp::{self, Ctx, NativeVp, VpEnv};
use crate::ledger::storage::{self as ledger_storage, StorageHasher};
use crate::proto::Tx;
use crate::types::address::{Address, InternalAddress};
use crate::types::storage::Key;
use crate::types::token::{self, Amount, AmountParseError};
use crate::vm::WasmCacheAccess;

#[allow(missing_docs)]
#[derive(Error, Debug)]
pub enum Error {
    #[error("Native VP error: {0}")]
    NativeVpError(native_vp::Error),
    #[error("IBC message error: {0}")]
    IbcMessage(RouterError),
    #[error("Invalid message")]
    InvalidMessage,
    #[error("Parsing amount error: {0}")]
    Amount(AmountParseError),
    #[error("Decoding error: {0}")]
    Decoding(std::io::Error),
    #[error("Decoding IBC data error: {0}")]
    DecodingIbcData(prost::DecodeError),
    #[error("Decoding PacketData error: {0}")]
    DecodingPacketData(serde_json::Error),
    #[error("IBC message is required as transaction data")]
    NoTxData,
    #[error("Invalid denom: {0}")]
    Denom(String),
    #[error("Invalid MsgTransfer: {0}")]
    MsgTransfer(TokenTransferError),
    #[error("Invalid token transfer: {0}")]
    TokenTransfer(String),
}

/// Result for IBC token VP
pub type Result<T> = std::result::Result<T, Error>;

/// IBC token VP to validate the transfer for an IBC-specific account. The
/// account is a sub-prefixed account with an IBC token hash, or a normal
/// account for `IbcEscrow`, `IbcBurn`, or `IbcMint`.
pub struct IbcToken<'a, DB, H, CA>
where
    DB: ledger_storage::DB + for<'iter> ledger_storage::DBIter<'iter>,
    H: StorageHasher,
    CA: 'static + WasmCacheAccess,
{
    /// Context to interact with the host structures.
    pub ctx: Ctx<'a, DB, H, CA>,
}

impl<'a, DB, H, CA> NativeVp for IbcToken<'a, DB, H, CA>
where
    DB: 'static + ledger_storage::DB + for<'iter> ledger_storage::DBIter<'iter>,
    H: 'static + StorageHasher,
    CA: 'static + WasmCacheAccess,
{
    type Error = Error;

    fn validate_tx(
        &self,
        tx_data: &Tx,
        keys_changed: &BTreeSet<Key>,
        _verifiers: &BTreeSet<Address>,
    ) -> Result<bool> {
        let signed = tx_data;
        let tx_data = signed.data().ok_or(Error::NoTxData)?;

        // Check the non-onwer balance updates
        let ibc_keys_changed: HashSet<Key> = keys_changed
            .iter()
            .filter(|k| {
                matches!(
                    token::is_any_token_balance_key(k),
                    Some([
                        _,
                        Address::Internal(
                            InternalAddress::IbcEscrow
                                | InternalAddress::IbcBurn
                                | InternalAddress::IbcMint
                        )
                    ])
                )
            })
            .cloned()
            .collect();
        if ibc_keys_changed.is_empty() {
            // some multitoken balances are changed
            let mut changes = HashMap::new();
            for key in keys_changed {
                if let Some((sub_prefix, _)) =
                    token::is_any_multitoken_balance_key(key)
                {
                    if !ibc_storage::is_ibc_sub_prefix(&sub_prefix) {
                        continue;
                    }
                    let pre: token::Amount =
                        self.ctx.read_pre(key)?.unwrap_or_default();
                    let post: token::Amount =
                        self.ctx.read_post(key)?.unwrap_or_default();
                    let this_change = post.change() - pre.change();
                    let change: token::Change =
                        changes.get(&sub_prefix).cloned().unwrap_or_default();
                    changes.insert(sub_prefix, change + this_change);
                }
            }
            if changes.iter().all(|(_, c)| c.is_zero()) {
                return Ok(true);
            } else {
                return Err(Error::TokenTransfer(
                    "Invalid transfer between different origin accounts"
                        .to_owned(),
                ));
            }
        } else if ibc_keys_changed.len() > 1 {
            // a transaction can update at most 1 special IBC account for now
            return Err(Error::TokenTransfer(
                "Invalid transfer for multiple non-owner balances".to_owned(),
            ));
        }

        // Check the message
        let ibc_msg =
            Any::decode(&tx_data[..]).map_err(Error::DecodingIbcData)?;
        match ibc_msg.type_url.as_str() {
            MSG_TRANSFER_TYPE_URL => {
                let msg = MsgTransfer::try_from(ibc_msg)
                    .map_err(Error::MsgTransfer)?;
                self.validate_sending_token(&msg)
            }
            _ => {
                let envelope: MsgEnvelope =
                    ibc_msg.try_into().map_err(Error::IbcMessage)?;
                match envelope {
                    MsgEnvelope::Packet(PacketMsg::Recv(msg)) => {
                        self.validate_receiving_token(&msg.packet)
                    }
                    MsgEnvelope::Packet(PacketMsg::Ack(msg)) => {
                        self.validate_refunding_token(&msg.packet)
                    }
                    MsgEnvelope::Packet(PacketMsg::Timeout(msg)) => {
                        self.validate_refunding_token(&msg.packet)
                    }
                    MsgEnvelope::Packet(PacketMsg::TimeoutOnClose(msg)) => {
                        self.validate_refunding_token(&msg.packet)
                    }
                    _ => Err(Error::InvalidMessage),
                }
            }
        }
    }
}

impl<'a, DB, H, CA> IbcToken<'a, DB, H, CA>
where
    DB: 'static + ledger_storage::DB + for<'iter> ledger_storage::DBIter<'iter>,
    H: 'static + StorageHasher,
    CA: 'static + WasmCacheAccess,
{
    fn validate_sending_token(&self, msg: &MsgTransfer) -> Result<bool> {
        let mut coin = msg.token.clone();
        // lookup the original denom with the IBC token hash
        if let Some(token_hash) =
            ibc_storage::token_hash_from_denom(&coin.denom).map_err(|e| {
                Error::Denom(format!("Invalid denom: error {}", e))
            })?
        {
            let denom_key = ibc_storage::ibc_denom_key(token_hash);
            coin.denom = match self.ctx.read_bytes_pre(&denom_key) {
                Ok(Some(v)) => String::from_utf8(v).map_err(|e| {
                    Error::Denom(format!(
                        "Decoding the denom string failed: {}",
                        e
                    ))
                })?,
                _ => {
                    return Err(Error::Denom(format!(
                        "No original denom: denom_key {}",
                        denom_key
                    )));
                }
            };
        }
        let coin = PrefixedCoin::try_from(coin).map_err(Error::MsgTransfer)?;
        let token = ibc_storage::token(coin.denom.to_string())
            .map_err(|e| Error::Denom(e.to_string()))?;
        let amount = Amount::try_from(coin.amount).map_err(Error::Amount)?;

        // check the denomination field
        let change = if is_sender_chain_source(
            msg.port_id_on_a.clone(),
            msg.chan_id_on_a.clone(),
            &coin.denom,
        ) {
            // source zone
            // check the amount of the token has been escrowed
            let target_key = token::balance_key(
                &token,
                &Address::Internal(InternalAddress::IbcEscrow),
            );
            let pre =
                try_decode_token_amount(self.ctx.read_bytes_pre(&target_key)?)?
                    .unwrap_or_default();
            let post = try_decode_token_amount(
                self.ctx.read_bytes_post(&target_key)?,
            )?
            .unwrap_or_default();
            post.change() - pre.change()
        } else {
            // sink zone
            // check the amount of the token has been burned
            let target_key = token::balance_key(
                &token,
                &Address::Internal(InternalAddress::IbcBurn),
            );
            let post = try_decode_token_amount(
                self.ctx.read_bytes_temp(&target_key)?,
            )?
            .unwrap_or_default();
            // the previous balance of the burn address should be zero
            post.change()
        };

        if change == amount.change() {
            Ok(true)
        } else {
            Err(Error::TokenTransfer(format!(
                "Sending the token is invalid: coin {}",
                coin,
            )))
        }
    }

    fn validate_receiving_token(&self, packet: &Packet) -> Result<bool> {
        let data = serde_json::from_slice::<PacketData>(&packet.data)
            .map_err(Error::DecodingPacketData)?;
        let token = ibc_storage::token(data.token.denom.to_string())
            .map_err(|e| Error::Denom(e.to_string()))?;
        let amount =
            Amount::try_from(data.token.amount).map_err(Error::Amount)?;

        let change = if is_receiver_chain_source(
            packet.port_id_on_a.clone(),
            packet.chan_id_on_a.clone(),
            &data.token.denom,
        ) {
            // this chain is the source
            // check the amount of the token has been unescrowed
            let source_key = token::balance_key(
                &token,
                &Address::Internal(InternalAddress::IbcEscrow),
            );
            let pre =
                try_decode_token_amount(self.ctx.read_bytes_pre(&source_key)?)?
                    .unwrap_or_default();
            let post = try_decode_token_amount(
                self.ctx.read_bytes_post(&source_key)?,
            )?
            .unwrap_or_default();
            pre.change() - post.change()
        } else {
            // the sender is the source
            // check the amount of the token has been minted
            let source_key = token::balance_key(
                &token,
                &Address::Internal(InternalAddress::IbcMint),
            );
            let post = try_decode_token_amount(
                self.ctx.read_bytes_temp(&source_key)?,
            )?
            .unwrap_or_default();
            // the previous balance of the mint address should be the maximum
            Amount::max_signed().change() - post.change()
        };

        if change == amount.change() {
            Ok(true)
        } else {
            Err(Error::TokenTransfer(format!(
                "Receivinging the token is invalid: coin {}",
                data.token
            )))
        }
    }

    fn validate_refunding_token(&self, packet: &Packet) -> Result<bool> {
        let data = serde_json::from_slice::<PacketData>(&packet.data)
            .map_err(Error::DecodingPacketData)?;
        let token = ibc_storage::token(data.token.denom.to_string())
            .map_err(|e| Error::Denom(e.to_string()))?;
        let amount =
            Amount::try_from(data.token.amount).map_err(Error::Amount)?;

        // check the denom field
        let change = if is_sender_chain_source(
            packet.port_id_on_a.clone(),
            packet.chan_id_on_a.clone(),
            &data.token.denom,
        ) {
            // source zone: unescrow the token for the refund
            let source_key = token::balance_key(
                &token,
                &Address::Internal(InternalAddress::IbcEscrow),
            );
            let pre =
                try_decode_token_amount(self.ctx.read_bytes_pre(&source_key)?)?
                    .unwrap_or_default();
            let post = try_decode_token_amount(
                self.ctx.read_bytes_post(&source_key)?,
            )?
            .unwrap_or_default();
            pre.change() - post.change()
        } else {
            // sink zone: mint the token for the refund
            let source_key = token::balance_key(
                &token,
                &Address::Internal(InternalAddress::IbcMint),
            );
            let post = try_decode_token_amount(
                self.ctx.read_bytes_temp(&source_key)?,
            )?
            .unwrap_or_default();
            // the previous balance of the mint address should be the maximum
            Amount::max_signed().change() - post.change()
        };

        if change == amount.change() {
            Ok(true)
        } else {
            Err(Error::TokenTransfer(format!(
                "Refunding the token is invalid: coin {}",
                data.token,
            )))
        }
    }
}

impl From<native_vp::Error> for Error {
    fn from(err: native_vp::Error) -> Self {
        Self::NativeVpError(err)
    }
}

fn try_decode_token_amount(
    bytes: Option<Vec<u8>>,
) -> Result<Option<token::Amount>> {
    if let Some(bytes) = bytes {
        let tokens = Amount::try_from_slice(&bytes).map_err(Error::Decoding)?;
        return Ok(Some(tokens));
    }
    Ok(None)
}
