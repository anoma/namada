//! Implementation of `IbcActions` with the protocol storage

use std::cell::RefCell;
use std::rc::Rc;

use namada_core::address::{Address, InternalAddress};
use namada_core::ibc::apps::transfer::types::msgs::transfer::MsgTransfer;
use namada_core::ibc::apps::transfer::types::packet::PacketData;
use namada_core::ibc::apps::transfer::types::PrefixedCoin;
use namada_core::ibc::core::channel::types::timeout::TimeoutHeight;
use namada_core::ibc::primitives::Msg;
use namada_core::ibc::IbcEvent;
use namada_core::tendermint::Time as TmTime;
use namada_core::token::DenominatedAmount;
use namada_governance::storage::proposal::PGFIbcTarget;
use namada_parameters::read_epoch_duration_parameter;
use namada_state::write_log::WriteLog;
use namada_state::{
    DBIter, Epochs, InMemory, ResultExt, State, StateRead, StorageError,
    StorageHasher, StorageRead, StorageResult, StorageWrite, TxHostEnvState,
    WlState, DB,
};
use namada_token as token;

use crate::{IbcActions, IbcCommonContext, IbcStorageContext};

/// IBC protocol context
#[derive(Debug)]
pub struct IbcProtocolContext<'a, S>
where
    S: State,
{
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

    fn get_block_hash(&self) -> StorageResult<namada_storage::BlockHash> {
        self.state.get_block_hash()
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

/// Temporary wrapper to have gas cost compatible with v0.31.6.
// TODO: Delete this wrapper and use `TxHostEnvState` directly in a breaking
// release. Differs in `iter_next`.
#[derive(Debug)]
pub struct CompatibleIbcTxHostEnvState<'a, D, H>(pub TxHostEnvState<'a, D, H>)
where
    D: DB + for<'iter> DBIter<'iter>,
    H: StorageHasher;

impl<D, H> StorageRead for CompatibleIbcTxHostEnvState<'_, D, H>
where
    D: DB + for<'iter> DBIter<'iter> + 'static,
    H: StorageHasher + 'static,
{
    type PrefixIter<'iter> = namada_state::PrefixIter<'iter, D> where Self: 'iter;

    fn read_bytes(
        &self,
        key: &namada_storage::Key,
    ) -> StorageResult<Option<Vec<u8>>> {
        self.0.read_bytes(key)
    }

    fn has_key(&self, key: &namada_storage::Key) -> StorageResult<bool> {
        self.0.has_key(key)
    }

    fn iter_prefix<'iter>(
        &'iter self,
        prefix: &namada_storage::Key,
    ) -> StorageResult<Self::PrefixIter<'iter>> {
        let (iter, gas) = namada_state::iter_prefix_post(
            self.0.write_log(),
            self.0.db(),
            prefix,
        );
        self.0.charge_gas(gas).into_storage_result()?;
        Ok(iter)
    }

    fn iter_next<'iter>(
        &'iter self,
        iter: &mut Self::PrefixIter<'iter>,
    ) -> StorageResult<Option<(String, Vec<u8>)>> {
        use namada_state::write_log;
        let write_log = self.0.write_log();
        for (key, val, iter_gas) in iter.by_ref() {
            let (log_val, log_gas) = write_log.read(
                &namada_storage::Key::parse(key.clone())
                    .into_storage_result()?,
            );
            self.0
                .charge_gas(iter_gas + log_gas)
                .into_storage_result()?;
            match log_val {
                Some(write_log::StorageModification::Write { ref value }) => {
                    return Ok(Some((key, value.clone())));
                }
                Some(&write_log::StorageModification::Delete) => {
                    // check the next because the key has already deleted
                    continue;
                }
                Some(&write_log::StorageModification::InitAccount {
                    ..
                }) => {
                    // a VP of a new account doesn't need to be iterated
                    continue;
                }
                Some(write_log::StorageModification::Temp { ref value }) => {
                    return Ok(Some((key, value.clone())));
                }
                None => {
                    return Ok(Some((key, val)));
                }
            }
        }
        Ok(None)
    }

    fn get_chain_id(&self) -> StorageResult<String> {
        self.0.get_chain_id()
    }

    fn get_block_height(&self) -> StorageResult<namada_storage::BlockHeight> {
        self.0.get_block_height()
    }

    fn get_block_header(
        &self,
        height: namada_storage::BlockHeight,
    ) -> StorageResult<Option<namada_storage::Header>> {
        StorageRead::get_block_header(&self.0, height)
    }

    fn get_block_hash(&self) -> StorageResult<namada_storage::BlockHash> {
        self.0.get_block_hash()
    }

    fn get_block_epoch(&self) -> StorageResult<namada_storage::Epoch> {
        self.0.get_block_epoch()
    }

    fn get_pred_epochs(&self) -> StorageResult<Epochs> {
        self.0.get_pred_epochs()
    }

    fn get_tx_index(&self) -> StorageResult<namada_storage::TxIndex> {
        self.0.get_tx_index()
    }

    fn get_native_token(&self) -> StorageResult<Address> {
        self.0.get_native_token()
    }
}

impl<D, H> StorageWrite for CompatibleIbcTxHostEnvState<'_, D, H>
where
    D: DB + for<'iter> DBIter<'iter> + 'static,
    H: StorageHasher + 'static,
{
    fn write_bytes(
        &mut self,
        key: &namada_storage::Key,
        val: impl AsRef<[u8]>,
    ) -> StorageResult<()> {
        self.0.write_bytes(key, val)
    }

    fn delete(&mut self, key: &namada_storage::Key) -> StorageResult<()> {
        self.0.delete(key)
    }
}

impl<D, H> StateRead for CompatibleIbcTxHostEnvState<'_, D, H>
where
    D: DB + for<'iter> DBIter<'iter> + 'static,
    H: StorageHasher + 'static,
{
    type D = D;
    type H = H;

    fn write_log(&self) -> &WriteLog {
        self.0.write_log
    }

    fn db(&self) -> &D {
        self.0.db()
    }

    fn in_mem(&self) -> &InMemory<Self::H> {
        self.0.in_mem()
    }

    fn charge_gas(&self, gas: u64) -> namada_state::Result<()> {
        self.0.charge_gas(gas)
    }
}

impl<D, H> State for CompatibleIbcTxHostEnvState<'_, D, H>
where
    D: 'static + DB + for<'iter> DBIter<'iter>,
    H: 'static + StorageHasher,
{
    fn write_log_mut(&mut self) -> &mut WriteLog {
        self.0.write_log_mut()
    }

    fn split_borrow(
        &mut self,
    ) -> (&mut WriteLog, &InMemory<Self::H>, &Self::D) {
        self.0.split_borrow()
    }
}

impl<D, H> IbcStorageContext for CompatibleIbcTxHostEnvState<'_, D, H>
where
    D: 'static + DB + for<'iter> DBIter<'iter>,
    H: 'static + StorageHasher,
{
    fn emit_ibc_event(&mut self, event: IbcEvent) -> Result<(), StorageError> {
        let gas = self.write_log_mut().emit_ibc_event(event);
        self.charge_gas(gas).into_storage_result()?;
        Ok(())
    }

    fn get_ibc_events(
        &self,
        event_type: impl AsRef<str>,
    ) -> Result<Vec<IbcEvent>, StorageError> {
        Ok(self
            .write_log()
            .get_ibc_events()
            .iter()
            .filter(|event| event.event_type == event_type.as_ref())
            .cloned()
            .collect())
    }

    fn transfer_token(
        &mut self,
        src: &Address,
        dest: &Address,
        token: &Address,
        amount: DenominatedAmount,
    ) -> Result<(), StorageError> {
        token::transfer(self, token, src, dest, amount.amount())
    }

    fn handle_masp_tx(
        &mut self,
        shielded: &masp_primitives::transaction::Transaction,
        pin_key: Option<&str>,
    ) -> Result<(), StorageError> {
        namada_token::utils::handle_masp_tx(self, shielded, pin_key)?;
        namada_token::utils::update_note_commitment_tree(self, shielded)
    }

    fn mint_token(
        &mut self,
        target: &Address,
        token: &Address,
        amount: DenominatedAmount,
    ) -> Result<(), StorageError> {
        token::credit_tokens(self, token, target, amount.amount())?;
        let minter_key = token::storage_key::minter_key(token);
        self.write(&minter_key, Address::Internal(InternalAddress::Ibc))
    }

    fn burn_token(
        &mut self,
        target: &Address,
        token: &Address,
        amount: DenominatedAmount,
    ) -> Result<(), StorageError> {
        token::burn_tokens(self, token, target, amount.amount())
    }

    fn log_string(&self, message: String) {
        tracing::trace!(message);
    }
}

impl<D, H> IbcCommonContext for CompatibleIbcTxHostEnvState<'_, D, H>
where
    D: 'static + DB + for<'iter> DBIter<'iter>,
    H: 'static + StorageHasher,
{
}

impl<S> IbcStorageContext for IbcProtocolContext<'_, S>
where
    S: State,
{
    fn emit_ibc_event(&mut self, event: IbcEvent) -> Result<(), StorageError> {
        self.state.write_log_mut().emit_ibc_event(event);
        Ok(())
    }

    /// Get IBC events
    fn get_ibc_events(
        &self,
        event_type: impl AsRef<str>,
    ) -> Result<Vec<IbcEvent>, StorageError> {
        Ok(self
            .state
            .write_log()
            .get_ibc_events()
            .iter()
            .filter(|event| event.event_type == event_type.as_ref())
            .cloned()
            .collect())
    }

    /// Transfer token
    fn transfer_token(
        &mut self,
        src: &Address,
        dest: &Address,
        token: &Address,
        amount: DenominatedAmount,
    ) -> Result<(), StorageError> {
        token::transfer(self.state, token, src, dest, amount.amount())
    }

    /// Handle masp tx
    fn handle_masp_tx(
        &mut self,
        _shielded: &masp_primitives::transaction::Transaction,
        _pin_key: Option<&str>,
    ) -> Result<(), StorageError> {
        unimplemented!("No MASP transfer in an IBC protocol transaction")
    }

    /// Mint token
    fn mint_token(
        &mut self,
        target: &Address,
        token: &Address,
        amount: DenominatedAmount,
    ) -> Result<(), StorageError> {
        token::credit_tokens(self.state, token, target, amount.amount())?;
        let minter_key = token::storage_key::minter_key(token);
        self.state
            .write(&minter_key, Address::Internal(InternalAddress::Ibc))
    }

    /// Burn token
    fn burn_token(
        &mut self,
        target: &Address,
        token: &Address,
        amount: DenominatedAmount,
    ) -> Result<(), StorageError> {
        token::burn_tokens(self.state, token, target, amount.amount())
    }

    fn log_string(&self, message: String) {
        tracing::trace!(message);
    }
}

impl<S> IbcCommonContext for IbcProtocolContext<'_, S> where S: State {}

/// Transfer tokens over IBC
pub fn transfer_over_ibc<D, H>(
    state: &mut WlState<D, H>,
    token: &Address,
    source: &Address,
    target: &PGFIbcTarget,
) -> StorageResult<()>
where
    D: DB + for<'iter> DBIter<'iter> + 'static,
    H: StorageHasher + 'static,
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
    let timeout_timestamp = state
        .in_mem()
        .header
        .as_ref()
        .expect("The header should exist")
        .time
        + read_epoch_duration_parameter(state)?.min_duration;
    let timeout_timestamp =
        TmTime::try_from(timeout_timestamp).into_storage_result()?;
    let ibc_message = MsgTransfer {
        port_id_on_a: target.port_id.clone(),
        chan_id_on_a: target.channel_id.clone(),
        packet_data,
        timeout_height_on_b: TimeoutHeight::Never,
        timeout_timestamp_on_b: timeout_timestamp.into(),
    };
    let any_msg = ibc_message.to_any();
    let mut data = vec![];
    prost::Message::encode(&any_msg, &mut data).into_storage_result()?;

    let ctx = IbcProtocolContext { state };
    let mut actions = IbcActions::new(Rc::new(RefCell::new(ctx)));
    actions.execute(&data).into_storage_result()
}
