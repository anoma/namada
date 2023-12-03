//! Implementation of `IbcActions` with the protocol storage

use std::cell::RefCell;
use std::rc::Rc;

use namada::core::ledger::governance::storage::proposal::PGFIbcTarget;
use namada::core::ledger::ibc::{
    IbcActions, IbcCommonContext, IbcStorageContext,
};
use namada::core::ledger::storage_api::Error;
use namada::ibc::applications::transfer::msgs::transfer::MsgTransfer;
use namada::ibc::applications::transfer::packet::PacketData;
use namada::ibc::applications::transfer::PrefixedCoin;
use namada::ibc::core::ics04_channel::timeout::TimeoutHeight;
use namada::ibc::core::Msg;
use namada::ledger::parameters::read_epoch_duration_parameter;
use namada::ledger::storage::wl_storage::WriteLogAndStorage;
use namada::ledger::storage::write_log::WriteLog;
use namada::ledger::storage::{DBIter, Storage, StorageHasher, WlStorage, DB};
use namada::ledger::storage_api::{self, token, ResultExt, StorageWrite};
use namada::tendermint::Time as TmTime;
use namada::types::address::{Address, InternalAddress};
use namada::types::hash::Hash;
use namada::types::ibc::{IbcEvent, IbcShieldedTransfer};
use namada::types::time::DateTimeUtc;
use namada::types::token::DenominatedAmount;

#[derive(Debug)]
pub struct IbcProtocolContext<'a, D, H>
where
    D: DB + for<'iter> DBIter<'iter>,
    H: StorageHasher,
{
    wl_storage: &'a mut WlStorage<D, H>,
}

impl<D, H> WriteLogAndStorage for IbcProtocolContext<'_, D, H>
where
    D: DB + for<'iter> DBIter<'iter>,
    H: StorageHasher,
{
    type D = D;
    type H = H;

    fn write_log(&self) -> &WriteLog {
        self.wl_storage.write_log()
    }

    fn write_log_mut(&mut self) -> &mut WriteLog {
        self.wl_storage.write_log_mut()
    }

    fn storage(&self) -> &Storage<D, H> {
        self.wl_storage.storage()
    }

    fn split_borrow(&mut self) -> (&mut WriteLog, &Storage<D, H>) {
        self.wl_storage.split_borrow()
    }

    fn write_tx_hash(
        &mut self,
        hash: Hash,
    ) -> namada::ledger::storage::write_log::Result<()> {
        self.wl_storage.write_tx_hash(hash)
    }
}

impl<D, H> IbcStorageContext for IbcProtocolContext<'_, D, H>
where
    D: DB + for<'iter> DBIter<'iter> + 'static,
    H: StorageHasher + 'static,
{
    fn emit_ibc_event(&mut self, event: IbcEvent) -> Result<(), Error> {
        self.wl_storage.write_log.emit_ibc_event(event);
        Ok(())
    }

    /// Get IBC events
    fn get_ibc_events(
        &self,
        event_type: impl AsRef<str>,
    ) -> Result<Vec<IbcEvent>, Error> {
        Ok(self
            .wl_storage
            .write_log
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
    ) -> Result<(), Error> {
        token::transfer(self, token, src, dest, amount.amount)
    }

    /// Handle masp tx
    fn handle_masp_tx(
        &mut self,
        _shielded: &IbcShieldedTransfer,
    ) -> Result<(), Error> {
        unimplemented!("No MASP transfer in an IBC protocol transaction")
    }

    /// Mint token
    fn mint_token(
        &mut self,
        target: &Address,
        token: &Address,
        amount: DenominatedAmount,
    ) -> Result<(), Error> {
        token::credit_tokens(self.wl_storage, token, target, amount.amount)?;
        let minter_key = token::minter_key(token);
        self.wl_storage
            .write(&minter_key, Address::Internal(InternalAddress::Ibc))
    }

    /// Burn token
    fn burn_token(
        &mut self,
        target: &Address,
        token: &Address,
        amount: DenominatedAmount,
    ) -> Result<(), Error> {
        token::burn(self.wl_storage, token, target, amount.amount)
    }

    fn log_string(&self, message: String) {
        tracing::trace!(message);
    }
}

impl<D, H> IbcCommonContext for IbcProtocolContext<'_, D, H>
where
    D: DB + for<'iter> DBIter<'iter> + 'static,
    H: StorageHasher + 'static,
{
}

pub fn transfer_over_ibc<D, H>(
    wl_storage: &mut WlStorage<D, H>,
    token: &Address,
    source: &Address,
    target: &PGFIbcTarget,
) -> storage_api::Result<()>
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
    let timeout_timestamp = DateTimeUtc::now()
        + read_epoch_duration_parameter(wl_storage)?.min_duration;
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

    let ctx = IbcProtocolContext { wl_storage };
    let mut actions = IbcActions::new(Rc::new(RefCell::new(ctx)));
    actions.execute(&data).into_storage_result()
}
