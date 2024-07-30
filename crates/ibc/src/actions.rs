//! Implementation of `IbcActions` with the protocol storage

use std::cell::RefCell;
use std::collections::BTreeSet;
use std::rc::Rc;

use ibc::apps::transfer::types::msgs::transfer::MsgTransfer as IbcMsgTransfer;
use ibc::apps::transfer::types::packet::PacketData;
use ibc::apps::transfer::types::PrefixedCoin;
use ibc::core::channel::types::timeout::TimeoutHeight;
use namada_core::address::Address;
use namada_core::borsh::BorshSerializeExt;
use namada_core::tendermint::Time as TmTime;
use namada_core::token::Amount;
use namada_events::EmitEvents;
use namada_governance::storage::proposal::PGFIbcTarget;
use namada_parameters::read_epoch_duration_parameter;
use namada_state::{
    Epochs, ResultExt, State, StorageError, StorageRead, StorageResult,
    StorageWrite,
};
use namada_token as token;

use crate::event::IbcEvent;
use crate::{
    storage as ibc_storage, IbcActions, IbcCommonContext, IbcStorageContext,
    MsgTransfer,
};

/// IBC protocol context
#[derive(Debug)]
pub struct IbcProtocolContext<'a, S> {
    state: &'a mut S,
}

impl<S> StorageRead for IbcProtocolContext<'_, S>
where
    S: State,
{
    type PrefixIter<'iter> = <S as StorageRead>::PrefixIter<'iter> where Self: 'iter;

    fn read_bytes(
        &self,
        key: &namada_storage::Key,
    ) -> StorageResult<Option<Vec<u8>>> {
        self.state.read_bytes(key)
    }

    fn has_key(&self, key: &namada_storage::Key) -> StorageResult<bool> {
        self.state.has_key(key)
    }

    fn iter_prefix<'iter>(
        &'iter self,
        prefix: &namada_storage::Key,
    ) -> StorageResult<Self::PrefixIter<'iter>> {
        self.state.iter_prefix(prefix)
    }

    fn iter_next<'iter>(
        &'iter self,
        iter: &mut Self::PrefixIter<'iter>,
    ) -> StorageResult<Option<(String, Vec<u8>)>> {
        self.state.iter_next(iter)
    }

    fn get_chain_id(&self) -> StorageResult<String> {
        self.state.get_chain_id()
    }

    fn get_block_height(&self) -> StorageResult<namada_storage::BlockHeight> {
        self.state.get_block_height()
    }

    fn get_block_header(
        &self,
        height: namada_storage::BlockHeight,
    ) -> StorageResult<Option<namada_storage::Header>> {
        StorageRead::get_block_header(self.state, height)
    }

    fn get_block_epoch(&self) -> StorageResult<namada_storage::Epoch> {
        self.state.get_block_epoch()
    }

    fn get_pred_epochs(&self) -> StorageResult<Epochs> {
        self.state.get_pred_epochs()
    }

    fn get_tx_index(&self) -> StorageResult<namada_storage::TxIndex> {
        self.state.get_tx_index()
    }

    fn get_native_token(&self) -> StorageResult<Address> {
        self.state.get_native_token()
    }
}

impl<S> StorageWrite for IbcProtocolContext<'_, S>
where
    S: State,
{
    fn write_bytes(
        &mut self,
        key: &namada_storage::Key,
        val: impl AsRef<[u8]>,
    ) -> StorageResult<()> {
        self.state.write_bytes(key, val)
    }

    fn delete(&mut self, key: &namada_storage::Key) -> StorageResult<()> {
        self.state.delete(key)
    }
}

impl<S> IbcStorageContext for IbcProtocolContext<'_, S>
where
    S: State + EmitEvents,
{
    type Storage = Self;

    fn storage(&self) -> &Self::Storage {
        self
    }

    fn storage_mut(&mut self) -> &mut Self::Storage {
        self
    }

    fn emit_ibc_event(&mut self, event: IbcEvent) -> Result<(), StorageError> {
        // There's no gas cost for protocol, we can ignore result
        self.state.write_log_mut().emit_event(event);
        Ok(())
    }

    /// Transfer token
    fn transfer_token(
        &mut self,
        src: &Address,
        dest: &Address,
        token: &Address,
        amount: Amount,
    ) -> Result<(), StorageError> {
        token::transfer(self.state, token, src, dest, amount)
    }

    /// Mint token
    fn mint_token(
        &mut self,
        target: &Address,
        token: &Address,
        amount: Amount,
    ) -> Result<(), StorageError> {
        ibc_storage::mint_tokens(self.state, target, token, amount)
    }

    /// Burn token
    fn burn_token(
        &mut self,
        target: &Address,
        token: &Address,
        amount: Amount,
    ) -> Result<(), StorageError> {
        ibc_storage::burn_tokens(self.state, target, token, amount)
    }

    fn insert_verifier(
        &mut self,
        _verifier: &Address,
    ) -> Result<(), StorageError> {
        Ok(())
    }

    fn log_string(&self, message: String) {
        tracing::trace!(message);
    }
}

impl<S> IbcCommonContext for IbcProtocolContext<'_, S> where
    S: State + EmitEvents
{
}

/// Transfer tokens over IBC
pub fn transfer_over_ibc<S>(
    state: &mut S,
    token: &Address,
    source: &Address,
    target: &PGFIbcTarget,
) -> StorageResult<()>
where
    S: State + EmitEvents,
{
    let token = PrefixedCoin {
        denom: token.to_string().parse().expect("invalid token"),
        amount: target.amount.into(),
    };
    let packet_data = PacketData {
        token,
        sender: source.to_string().into(),
        receiver: target.target.clone().into(),
        memo: String::default().into(),
    };
    #[allow(clippy::arithmetic_side_effects)]
    let timeout_timestamp = state
        .in_mem()
        .header
        .as_ref()
        .expect("The header should exist")
        .time
        + read_epoch_duration_parameter(state)?.min_duration;
    let timeout_timestamp =
        TmTime::try_from(timeout_timestamp).into_storage_result()?;
    let message = IbcMsgTransfer {
        port_id_on_a: target.port_id.clone(),
        chan_id_on_a: target.channel_id.clone(),
        packet_data,
        timeout_height_on_b: TimeoutHeight::Never,
        timeout_timestamp_on_b: timeout_timestamp.into(),
    };
    let data = MsgTransfer {
        message,
        transfer: None,
    }
    .serialize_to_vec();

    let ctx = IbcProtocolContext { state };

    // Use an empty verifiers set placeholder for validation, this is only
    // needed in txs and not protocol
    let verifiers = Rc::new(RefCell::new(BTreeSet::<Address>::new()));
    let mut actions = IbcActions::new(Rc::new(RefCell::new(ctx)), verifiers);
    actions.execute(&data).into_storage_result()?;

    Ok(())
}
