use std::cell::RefCell;

use namada_core::validity_predicate::VpSentinel;
use namada_gas::{GasMetering, TxGasMeter, VpGasMeter};
use namada_tx::data::TxSentinel;

use crate::in_memory::InMemory;
use crate::write_log::WriteLog;
use crate::{DBIter, Error, Result, State, StateRead, StorageHasher, DB};

// State with mutable write log and gas metering for tx host env.
#[derive(Debug)]
pub struct TxHostEnvState<'a, D, H>
where
    D: DB + for<'iter> DBIter<'iter>,
    H: StorageHasher,
{
    /// Write log
    pub write_log: &'a mut WriteLog,
    // DB
    pub db: &'a D,
    /// State
    pub in_mem: &'a InMemory<H>,
    /// Tx gas meter
    pub gas_meter: &'a RefCell<TxGasMeter>,
    /// Errors sentinel
    pub sentinel: &'a RefCell<TxSentinel>,
}

// Read-only state with gas metering for VP host env.
#[derive(Debug)]
pub struct VpHostEnvState<'a, D, H>
where
    D: DB + for<'iter> DBIter<'iter>,
    H: StorageHasher,
{
    /// Write log
    pub write_log: &'a WriteLog,
    // DB
    pub db: &'a D,
    /// State
    pub in_mem: &'a InMemory<H>,
    /// VP gas meter
    pub gas_meter: &'a RefCell<VpGasMeter>,
    /// Errors sentinel
    pub sentinel: &'a RefCell<VpSentinel>,
}

impl<D, H> StateRead for TxHostEnvState<'_, D, H>
where
    D: 'static + DB + for<'iter> DBIter<'iter>,
    H: 'static + StorageHasher,
{
    type D = D;
    type H = H;

    fn write_log(&self) -> &WriteLog {
        self.write_log
    }

    fn db(&self) -> &D {
        self.db
    }

    fn in_mem(&self) -> &InMemory<Self::H> {
        self.in_mem
    }

    fn charge_gas(&self, gas: u64) -> Result<()> {
        self.gas_meter.borrow_mut().consume(gas).map_err(|err| {
            self.sentinel.borrow_mut().set_out_of_gas();
            tracing::info!(
                "Stopping transaction execution because of gas error: {}",
                err
            );
            Error::Gas(err)
        })
    }
}

impl<D, H> State for TxHostEnvState<'_, D, H>
where
    D: 'static + DB + for<'iter> DBIter<'iter>,
    H: 'static + StorageHasher,
{
    fn write_log_mut(&mut self) -> &mut WriteLog {
        self.write_log
    }

    fn split_borrow(
        &mut self,
    ) -> (&mut WriteLog, &InMemory<Self::H>, &Self::D) {
        (self.write_log, (self.in_mem), (self.db))
    }
}

impl<D, H> StateRead for VpHostEnvState<'_, D, H>
where
    D: 'static + DB + for<'iter> DBIter<'iter>,
    H: 'static + StorageHasher,
{
    type D = D;
    type H = H;

    fn write_log(&self) -> &WriteLog {
        self.write_log
    }

    fn db(&self) -> &D {
        self.db
    }

    fn in_mem(&self) -> &InMemory<Self::H> {
        self.in_mem
    }

    fn charge_gas(&self, gas: u64) -> Result<()> {
        self.gas_meter.borrow_mut().consume(gas).map_err(|err| {
            self.sentinel.borrow_mut().set_out_of_gas();
            tracing::info!(
                "Stopping VP execution because of gas error: {}",
                err
            );
            Error::Gas(err)
        })
    }
}
