//! The ledger's protocol

use std::collections::{HashMap, HashSet};
use std::fmt;
use std::ops::Add;

use anoma::proto::types::Tx;
use anoma_shared::types::{Address, Key};
use prost::Message;
use rayon::iter::{IntoParallelRefIterator, ParallelIterator};
use thiserror::Error;

use crate::shell::gas::{self, BlockGasMeter, VpGasMeter};
use crate::shell::storage;
use crate::shell::storage::PersistentStorage;
use crate::vm;
use crate::vm::host_env::write_log::WriteLog;
use crate::vm::{TxRunner, VpRunner};

#[derive(Error, Debug)]
pub enum Error {
    #[error("Storage error: {0}")]
    StorageError(storage::Error),
    #[error("Error decoding a transaction from bytes: {0}")]
    TxDecodingError(prost::DecodeError),
    #[error("Transaction runner error: {0}")]
    TxRunnerError(vm::Error),
    #[error("Gas error: {0}")]
    GasError(gas::Error),
    #[error("Error executing VP for addresses: {0:?}")]
    VpExecutionError(HashSet<Address>),
    #[error("Transaction gas overflow")]
    GasOverflow,
}

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Clone, Debug)]
pub struct VpsGas {
    max: u64,
    rest: Vec<u64>,
}

impl Default for VpsGas {
    fn default() -> Self {
        Self {
            max: 0,
            rest: Vec::new(),
        }
    }
}

#[derive(Clone, Debug)]
pub struct VpsResult {
    pub accepted_vps: HashSet<Address>,
    pub rejected_vps: HashSet<Address>,
    pub changed_keys: Vec<Key>,
    pub gas_used: VpsGas,
    pub have_error: bool,
}

impl VpsGas {
    fn merge(&mut self, other: &mut VpsGas, initial_gas: u64) -> Result<()> {
        if other.max > self.max {
            self.rest.push(self.max);
            self.max = other.max;
        } else {
            self.rest.push(other.max);
            self.rest.append(&mut other.rest);
        }

        let parallel_gas: u64 = (self.rest.clone().iter().sum::<u64>() as f64
            * VpGasMeter::parallel_fee())
            as u64;

        if self.max.add(initial_gas).add(parallel_gas)
            > VpGasMeter::transaction_gas_limit()
        {
            return Err(Error::GasOverflow);
        }
        Ok(())
    }
}

impl VpsResult {
    pub fn new(
        accepted_vps: HashSet<Address>,
        rejected_vps: HashSet<Address>,
        changed_keys: Vec<Key>,
        gas_used: VpsGas,
        have_error: bool,
    ) -> Self {
        Self {
            accepted_vps,
            rejected_vps,
            changed_keys,
            gas_used,
            have_error,
        }
    }
}

impl fmt::Display for VpsResult {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "Vps -> accepted: {:?}. rejected: {:?}, keys: {:?}, error: {:}",
            self.accepted_vps,
            self.rejected_vps,
            self.changed_keys,
            self.have_error
        )
    }
}

impl Default for VpsResult {
    fn default() -> Self {
        Self {
            accepted_vps: HashSet::default(),
            rejected_vps: HashSet::default(),
            changed_keys: Vec::default(),
            gas_used: VpsGas::default(),
            have_error: false,
        }
    }
}

#[derive(Clone, Debug)]
pub struct TxResult {
    pub gas_used: u64,
    pub vps: VpsResult,
    pub valid: bool,
}

impl TxResult {
    pub fn new(gas: Result<u64>, vps: VpsResult) -> Self {
        let mut tx_result = TxResult {
            gas_used: gas.unwrap_or(0),
            vps,
            valid: false,
        };
        tx_result.valid = tx_result.is_tx_correct();
        tx_result
    }

    pub fn is_tx_correct(&self) -> bool {
        self.vps.rejected_vps.is_empty()
    }
}

impl fmt::Display for TxResult {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "Transaction is {}. Gas used: {}, vps: {}",
            if self.valid { "valid" } else { "invalid" },
            self.gas_used,
            self.vps.to_string(),
        )
    }
}

fn get_verifiers(
    write_log: &WriteLog,
    verifiers: &HashSet<Address>,
) -> HashMap<Address, Vec<Key>> {
    let mut verifiers =
        verifiers.iter().fold(HashMap::new(), |mut acc, addr| {
            acc.insert(addr.clone(), vec![]);
            acc
        });
    // get changed keys grouped by the address
    for key in write_log.get_changed_keys() {
        for addr in &key.find_addresses() {
            match verifiers.get_mut(&addr) {
                Some(keys) => keys.push(key.clone()),
                None => {
                    verifiers.insert(addr.clone(), vec![key.clone()]);
                }
            }
        }
    }
    // The new accounts should be validated by every verifier's VP
    for key in write_log.get_initialized_accounts() {
        for (_verifier, keys) in verifiers.iter_mut() {
            keys.push(key.clone());
        }
    }
    verifiers
}

pub fn run_tx(
    tx_bytes: &[u8],
    block_gas_meter: &mut BlockGasMeter,
    write_log: &mut WriteLog,
    storage: &PersistentStorage,
) -> Result<TxResult> {
    block_gas_meter
        .add_base_transaction_fee(tx_bytes.len())
        .map_err(Error::GasError)?;

    let tx = Tx::decode(tx_bytes).map_err(Error::TxDecodingError)?;

    // Execute the transaction code
    let verifiers = execute_tx(&tx, storage, block_gas_meter, write_log)?;

    let vps_result =
        check_vps(&tx, storage, block_gas_meter, write_log, &verifiers)?;

    let gas = block_gas_meter
        .finalize_transaction()
        .map_err(Error::GasError);

    Ok(TxResult::new(gas, vps_result))
}

fn check_vps(
    tx: &Tx,
    storage: &PersistentStorage,
    gas_meter: &mut BlockGasMeter,
    write_log: &mut WriteLog,
    verifiers: &HashSet<Address>,
) -> Result<VpsResult> {
    let verifiers = get_verifiers(write_log, verifiers);

    let tx_data = tx.data.clone().unwrap_or_default();
    let tx_code = tx.code.clone();

    let verifiers_vps: Vec<(Address, Vec<Key>, Vec<u8>)> = verifiers
        .iter()
        .map(|(addr, keys)| {
            let vp = storage
                .validity_predicate(&addr)
                .map_err(Error::StorageError)?;

            gas_meter
                .add_compiling_fee(vp.len())
                .map_err(Error::GasError)?;

            Ok((addr.clone(), keys.clone(), vp))
        })
        .collect::<std::result::Result<_, _>>()?;

    let initial_gas = gas_meter.get_current_transaction_gas();

    let mut vps_result = run_vps(
        verifiers_vps,
        tx_data,
        tx_code,
        storage,
        write_log,
        initial_gas,
    )?;

    gas_meter
        .add(vps_result.gas_used.max)
        .map_err(Error::GasError)?;
    gas_meter
        .add_parallel_fee(&mut vps_result.gas_used.rest)
        .map_err(Error::GasError)?;

    Ok(vps_result)
}

fn execute_tx(
    tx: &Tx,
    storage: &PersistentStorage,
    gas_meter: &mut BlockGasMeter,
    write_log: &mut WriteLog,
) -> Result<HashSet<Address>> {
    let tx_code = tx.code.clone();
    gas_meter
        .add_compiling_fee(tx_code.len())
        .map_err(Error::GasError)?;
    let tx_data = tx.data.clone().unwrap_or_default();
    let mut verifiers = HashSet::new();

    let tx_runner = TxRunner::new();

    tx_runner
        .run(
            storage,
            write_log,
            &mut verifiers,
            gas_meter,
            tx_code,
            tx_data,
        )
        .map_err(Error::TxRunnerError)?;

    Ok(verifiers)
}

fn run_vps(
    verifiers: Vec<(Address, Vec<Key>, Vec<u8>)>,
    tx_data: Vec<u8>,
    tx_code: Vec<u8>,
    storage: &PersistentStorage,
    write_log: &mut WriteLog,
    initial_gas: u64,
) -> Result<VpsResult> {
    let addresses = verifiers
        .iter()
        .map(|(addr, _, _)| addr)
        .collect::<HashSet<_>>();

    verifiers
        .par_iter()
        .try_fold(VpsResult::default, |result, (addr, keys, vp)| {
            run_vp(
                result,
                tx_data.clone(),
                tx_code.clone(),
                storage,
                write_log,
                addresses.clone(),
                &mut VpGasMeter::new(initial_gas),
                (addr, keys, vp),
            )
        })
        .try_reduce(VpsResult::default, |a, b| {
            merge_vp_results(a, b, initial_gas)
        })
}

fn merge_vp_results(
    a: VpsResult,
    mut b: VpsResult,
    initial_gas: u64,
) -> Result<VpsResult> {
    let accepted_vps = a.accepted_vps.union(&b.accepted_vps).collect();
    let rejected_vps = a.rejected_vps.union(&b.rejected_vps).collect();
    let mut changed_keys = a.changed_keys;
    changed_keys.append(&mut b.changed_keys);
    let mut gas_used = a.gas_used;

    // Returning error from here will short-circuit the VP parallel execution.
    // It's important that we only short-circuit gas errors to get deterministic
    // gas costs

    gas_used.merge(&mut b.gas_used, initial_gas)?;

    Ok(VpsResult::new(
        accepted_vps,
        rejected_vps,
        changed_keys,
        gas_used,
        a.have_error || b.have_error,
    ))
}

#[allow(clippy::too_many_arguments)]
fn run_vp(
    mut result: VpsResult,
    tx_data: Vec<u8>,
    tx_code: Vec<u8>,
    storage: &PersistentStorage,
    write_log: &WriteLog,
    addresses: HashSet<Address>,
    vp_gas_meter: &mut VpGasMeter,
    (addr, keys, vp): (&Address, &[Key], &[u8]),
) -> Result<VpsResult> {
    let vp_runner = VpRunner::new();

    let mut accept = vp_runner.run(
        vp,
        tx_data,
        &tx_code,
        addr,
        storage,
        write_log,
        vp_gas_meter,
        keys.to_vec(),
        addresses,
    );
    result.changed_keys.extend_from_slice(&keys);

    // TODO for testing, undo
    accept = Ok(false);

    match accept {
        Ok(accepted) => {
            if !accepted {
                result.rejected_vps.insert(addr.clone());
            } else {
                result.accepted_vps.insert(addr.clone());
            }
        }
        Err(_) => {
            result.rejected_vps.insert(addr.clone());
            result.have_error = true;
        }
    }

    if vp_gas_meter.gas_overflow() {
        // Returning error from here will short-circuit the VP parallel
        // execution. It's important that we only short-circuit gas
        // errors to get deterministic gas costs
        Err(Error::VpExecutionError(result.rejected_vps))
    } else {
        Ok(result)
    }
}
