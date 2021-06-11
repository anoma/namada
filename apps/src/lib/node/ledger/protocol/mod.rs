//! The ledger's protocol

use std::collections::{HashMap, HashSet};
use std::convert::TryFrom;
use std::fmt;

use anoma_shared::ledger::gas::{self, BlockGasMeter, VpGasMeter, VpsGas};
use anoma_shared::ledger::storage::write_log::WriteLog;
use anoma_shared::types::{Address, Key};
use anoma_shared::vm;
use anoma_shared::vm::wasm::runner::{TxRunner, VpRunner};
use rayon::iter::{IntoParallelRefIterator, ParallelIterator};
use thiserror::Error;

use crate::node::ledger::storage::PersistentStorage;
use crate::proto::{self, Tx};

#[derive(Error, Debug)]
pub enum Error {
    #[error("Storage error: {0}")]
    StorageError(anoma_shared::ledger::storage::Error),
    #[error("Error decoding a transaction from bytes: {0}")]
    TxDecodingError(proto::Error),
    #[error("Transaction runner error: {0}")]
    TxRunnerError(vm::wasm::runner::Error),
    #[error("Gas error: {0}")]
    GasError(gas::Error),
    #[error("Error executing VP for addresses: {0:?}")]
    VpRunnerError(vm::wasm::runner::Error),
    #[error("The address {0} doesn't exist")]
    MissingAddress(Address),
}

pub type Result<T> = std::result::Result<T, Error>;

/// Transaction application result
#[derive(Clone, Debug)]
pub struct TxResult {
    pub gas_used: u64,
    pub changed_keys: Vec<Key>,
    pub vps_result: VpsResult,
}

impl TxResult {
    pub fn is_accepted(&self) -> bool {
        self.vps_result.rejected_vps.is_empty()
    }
}

/// Result of checking a transaction with validity predicates
#[derive(Clone, Debug)]
pub struct VpsResult {
    pub accepted_vps: HashSet<Address>,
    pub rejected_vps: HashSet<Address>,
    pub gas_used: VpsGas,
    pub errors: Vec<(Address, String)>,
}

impl Default for VpsResult {
    fn default() -> Self {
        Self {
            accepted_vps: HashSet::default(),
            rejected_vps: HashSet::default(),
            gas_used: VpsGas::default(),
            errors: Vec::default(),
        }
    }
}

/// Apply a given transaction
pub fn apply_tx(
    tx_bytes: &[u8],
    block_gas_meter: &mut BlockGasMeter,
    write_log: &mut WriteLog,
    storage: &PersistentStorage,
) -> Result<TxResult> {
    block_gas_meter
        .add_base_transaction_fee(tx_bytes.len())
        .map_err(Error::GasError)?;

    let tx = Tx::try_from(tx_bytes).map_err(Error::TxDecodingError)?;

    let verifiers = execute_tx(&tx, storage, block_gas_meter, write_log)?;

    let vps_result =
        check_vps(&tx, storage, block_gas_meter, write_log, &verifiers)?;

    let gas_used = block_gas_meter
        .finalize_transaction()
        .map_err(Error::GasError)?;
    let changed_keys = write_log.get_keys();

    Ok(TxResult {
        gas_used,
        changed_keys,
        vps_result,
    })
}

/// Execute a transaction code. Returns verifiers requested by the transaction.
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
    let tx_runner = TxRunner::new();

    tx_runner
        .run(storage, write_log, gas_meter, tx_code, tx_data)
        .map_err(Error::TxRunnerError)
}

/// Check the acceptance of a transaction by validity predicates
fn check_vps(
    tx: &Tx,
    storage: &PersistentStorage,
    gas_meter: &mut BlockGasMeter,
    write_log: &WriteLog,
    verifiers_from_tx: &HashSet<Address>,
) -> Result<VpsResult> {
    let verifiers = get_verifiers(write_log, verifiers_from_tx);

    let tx_data = tx.data.clone().unwrap_or_default();
    let tx_code = tx.code.clone();

    // collect the changed storage keys and VPs for the verifiers
    let verifiers: Vec<(Address, Vec<Key>, Vec<u8>)> = verifiers
        .iter()
        .map(|(addr, keys)| {
            let (vp, gas) = storage
                .validity_predicate(&addr)
                .map_err(Error::StorageError)?;
            gas_meter.add(gas).map_err(Error::GasError)?;
            let vp = vp.ok_or_else(|| Error::MissingAddress(addr.clone()))?;

            gas_meter
                .add_compiling_fee(vp.len())
                .map_err(Error::GasError)?;

            Ok((addr.clone(), keys.clone(), vp))
        })
        .collect::<std::result::Result<_, _>>()?;

    let initial_gas = gas_meter.get_current_transaction_gas();

    let vps_result = execute_vps(
        verifiers,
        tx_data,
        tx_code,
        storage,
        write_log,
        initial_gas,
    )?;
    tracing::debug!("Total VPs gas cost {:?}", vps_result.gas_used);

    gas_meter
        .add_vps_gas(&vps_result.gas_used)
        .map_err(Error::GasError)?;

    Ok(vps_result)
}

/// Get verifiers from storage changes written to a write log
fn get_verifiers(
    write_log: &WriteLog,
    verifiers_from_tx: &HashSet<Address>,
) -> HashMap<Address, Vec<Key>> {
    let mut verifiers =
        verifiers_from_tx
            .iter()
            .fold(HashMap::new(), |mut acc, addr| {
                acc.insert(addr.clone(), vec![]);
                acc
            });

    let (changed_keys, initialized_accounts) = write_log.get_partitioned_keys();
    // get changed keys grouped by the address
    for key in changed_keys {
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
    for key in initialized_accounts {
        for (_verifier, keys) in verifiers.iter_mut() {
            keys.push(key.clone());
        }
    }
    verifiers
}

/// Execute verifiers' validity predicates
fn execute_vps(
    verifiers: Vec<(Address, Vec<Key>, Vec<u8>)>,
    tx_data: Vec<u8>,
    tx_code: Vec<u8>,
    storage: &PersistentStorage,
    write_log: &WriteLog,
    initial_gas: u64,
) -> Result<VpsResult> {
    let addresses = verifiers
        .iter()
        .map(|(addr, _, _)| addr)
        .collect::<HashSet<_>>();

    verifiers
        .par_iter()
        .try_fold(VpsResult::default, |result, (addr, keys, vp)| {
            execute_vp(
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

/// Merge VP results from parallel runs
fn merge_vp_results(
    a: VpsResult,
    mut b: VpsResult,
    initial_gas: u64,
) -> Result<VpsResult> {
    let accepted_vps = a.accepted_vps.union(&b.accepted_vps).collect();
    let rejected_vps = a.rejected_vps.union(&b.rejected_vps).collect();
    let mut errors = a.errors;
    errors.append(&mut b.errors);
    let mut gas_used = a.gas_used;

    // Returning error from here will short-circuit the VP parallel execution.
    // It's important that we only short-circuit gas errors to get deterministic
    // gas costs

    gas_used
        .merge(&mut b.gas_used, initial_gas)
        .map_err(Error::GasError)?;

    Ok(VpsResult {
        accepted_vps,
        rejected_vps,
        gas_used,
        errors,
    })
}

/// Execute a validity predicates
#[allow(clippy::too_many_arguments)]
fn execute_vp(
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

    let accept = vp_runner
        .run(
            vp,
            tx_data,
            &tx_code,
            addr,
            storage,
            write_log,
            vp_gas_meter,
            keys,
            &addresses,
        )
        .map_err(Error::VpRunnerError);

    match accept {
        Ok(accepted) => {
            if !accepted {
                result.rejected_vps.insert(addr.clone());
            } else {
                result.accepted_vps.insert(addr.clone());
            }
        }
        Err(err) => {
            result.rejected_vps.insert(addr.clone());
            result.errors.push((addr.clone(), err.to_string()));
        }
    }

    // Returning error from here will short-circuit the VP parallel
    // execution. It's important that we only short-circuit gas
    // errors to get deterministic gas costs
    tracing::debug!("VP {} used gas {}", addr, vp_gas_meter.current_gas);
    result.gas_used.set(vp_gas_meter).map_err(Error::GasError)?;
    match &vp_gas_meter.error {
        Some(err) => Err(Error::GasError(err.clone())),
        None => Ok(result),
    }
}

impl fmt::Display for TxResult {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "Transaction is {}. Gas used: {};{} VPs result: {}",
            if self.is_accepted() {
                "valid"
            } else {
                "invalid"
            },
            self.gas_used,
            iterable_to_string("Changed keys", self.changed_keys.iter()),
            self.vps_result,
        )
    }
}

impl fmt::Display for VpsResult {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "{}{}{}",
            iterable_to_string("Accepted", self.accepted_vps.iter()),
            iterable_to_string("Rejected", self.rejected_vps.iter()),
            iterable_to_string(
                "Errors",
                self.errors
                    .iter()
                    .map(|(addr, err)| format!("{} in {}", err, addr))
            ),
        )
    }
}

fn iterable_to_string<T: fmt::Display>(
    label: &str,
    iter: impl Iterator<Item = T>,
) -> String {
    let mut iter = iter.peekable();
    if iter.peek().is_none() {
        "".into()
    } else {
        format!(
            " {}: {};",
            label,
            iter.map(|x| x.to_string())
                .collect::<Vec<String>>()
                .join(", ")
        )
    }
}
