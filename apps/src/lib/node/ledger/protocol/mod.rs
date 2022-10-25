//! The ledger's protocol
mod transactions;

use std::collections::BTreeSet;
use std::panic;

use namada::ledger::eth_bridge::bridge_pool_vp::BridgePoolVp;
use namada::ledger::eth_bridge::vp::EthBridge;
use namada::ledger::gas::{self, BlockGasMeter, VpGasMeter};
use namada::ledger::governance::GovernanceVp;
use namada::ledger::ibc::vp::{Ibc, IbcToken};
use namada::ledger::native_vp::{self, NativeVp};
use namada::ledger::parameters::{self, ParametersVp};
use namada::ledger::pos::{self, PosVP};
use namada::ledger::storage::traits::StorageHasher;
use namada::ledger::storage::write_log::WriteLog;
use namada::ledger::storage::{DBIter, Storage, DB};
use namada::ledger::treasury::TreasuryVp;
use namada::proto::{self, Tx};
use namada::types::address::{Address, InternalAddress};
use namada::types::storage;
use namada::types::transaction::protocol::{ProtocolTx, ProtocolTxType};
use namada::types::transaction::{DecryptedTx, TxResult, TxType, VpsResult};
#[cfg(not(feature = "abcipp"))]
use namada::types::vote_extensions::ethereum_events;
use namada::vm::wasm::{TxCache, VpCache};
use namada::vm::{self, wasm, WasmCacheAccess};
use rayon::iter::{IntoParallelRefIterator, ParallelIterator};
use thiserror::Error;

use crate::node::ledger::shell::Shell;

#[derive(Error, Debug)]
pub enum Error {
    #[error("Storage error: {0}")]
    StorageError(namada::ledger::storage::Error),
    #[error("Error decoding a transaction from bytes: {0}")]
    TxDecodingError(proto::Error),
    #[error("Transaction runner error: {0}")]
    TxRunnerError(vm::wasm::run::Error),
    #[error(transparent)]
    ProtocolTxError(#[from] eyre::Error),
    #[error("Txs must either be encrypted or a decryption of an encrypted tx")]
    TxTypeError,
    #[error("Gas error: {0}")]
    GasError(gas::Error),
    #[error("Error executing VP for addresses: {0:?}")]
    VpRunnerError(vm::wasm::run::Error),
    #[error("The address {0} doesn't exist")]
    MissingAddress(Address),
    #[error("IBC native VP: {0}")]
    IbcNativeVpError(namada::ledger::ibc::vp::Error),
    #[error("PoS native VP: {0}")]
    PosNativeVpError(pos::vp::Error),
    #[error("PoS native VP panicked")]
    PosNativeVpRuntime,
    #[error("Parameters native VP: {0}")]
    ParametersNativeVpError(parameters::Error),
    #[error("IBC Token native VP: {0}")]
    IbcTokenNativeVpError(namada::ledger::ibc::vp::IbcTokenError),
    #[error("Governance native VP error: {0}")]
    GovernanceNativeVpError(namada::ledger::governance::vp::Error),
    #[error("Treasury native VP error: {0}")]
    TreasuryNativeVpError(namada::ledger::treasury::Error),
    #[error("Ethereum bridge native VP error: {0}")]
    EthBridgeNativeVpError(namada::ledger::eth_bridge::vp::Error),
    #[error("Ethereum bridge pool native VP error: {0}")]
    BridgePoolNativeVpError(namada::ledger::eth_bridge::bridge_pool_vp::Error),
    #[error("Access to an internal address {0} is forbidden")]
    AccessForbidden(InternalAddress),
}

pub(crate) struct ShellParams<'a, D, H, CA>
where
    D: 'static + DB + for<'iter> DBIter<'iter> + Sync,
    H: 'static + StorageHasher + Sync,
    CA: 'static + WasmCacheAccess + Sync,
{
    pub block_gas_meter: &'a mut BlockGasMeter,
    pub write_log: &'a mut WriteLog,
    pub storage: &'a Storage<D, H>,
    pub vp_wasm_cache: &'a mut VpCache<CA>,
    pub tx_wasm_cache: &'a mut TxCache<CA>,
}

impl<'a, D, H> From<&'a mut Shell<D, H>>
    for ShellParams<'a, D, H, namada::vm::WasmCacheRwAccess>
where
    D: 'static + DB + for<'iter> DBIter<'iter> + Sync,
    H: 'static + StorageHasher + Sync,
{
    fn from(shell: &'a mut Shell<D, H>) -> Self {
        Self {
            block_gas_meter: &mut shell.gas_meter,
            write_log: &mut shell.write_log,
            storage: &shell.storage,
            vp_wasm_cache: &mut shell.vp_wasm_cache,
            tx_wasm_cache: &mut shell.tx_wasm_cache,
        }
    }
}

pub type Result<T> = std::result::Result<T, Error>;

/// Dispatch a given transaction to be applied based on its type. Some storage
/// updates may be derived and applied natively rather than via the wasm
/// environment, in which case validity predicates will be bypassed.
///
/// If the given tx is a successfully decrypted payload apply the necessary
/// vps. Otherwise, we include the tx on chain with the gas charge added
/// but no further validations.
pub(crate) fn dispatch_tx<'a, D, H, CA>(
    tx_type: TxType,
    tx_length: usize,
    block_gas_meter: &'a mut BlockGasMeter,
    write_log: &'a mut WriteLog,
    storage: &'a mut Storage<D, H>,
    vp_wasm_cache: &'a mut VpCache<CA>,
    tx_wasm_cache: &'a mut TxCache<CA>,
) -> Result<TxResult>
where
    D: 'static + DB + for<'iter> DBIter<'iter> + Sync,
    H: 'static + StorageHasher + Sync,
    CA: 'static + WasmCacheAccess + Sync,
{
    match tx_type {
        TxType::Raw(_) => Err(Error::TxTypeError),
        TxType::Decrypted(DecryptedTx::Decrypted(tx)) => apply_wasm_tx(
            tx,
            tx_length,
            ShellParams {
                block_gas_meter,
                write_log,
                storage,
                vp_wasm_cache,
                tx_wasm_cache,
            },
        ),
        TxType::Protocol(ProtocolTx { tx, .. }) => {
            apply_protocol_tx(tx, storage)
        }
        _ => {
            // other transaction types we treat as a noop
            Ok(TxResult::default())
        }
    }
}

/// Apply a transaction going via the wasm environment. Gas will be metered and
/// validity predicates will be triggered in the normal way.
pub(crate) fn apply_wasm_tx<'a, D, H, CA>(
    tx: Tx,
    tx_length: usize,
    ShellParams {
        block_gas_meter,
        write_log,
        storage,
        vp_wasm_cache,
        tx_wasm_cache,
    }: ShellParams<'a, D, H, CA>,
) -> Result<TxResult>
where
    D: 'static + DB + for<'iter> DBIter<'iter> + Sync,
    H: 'static + StorageHasher + Sync,
    CA: 'static + WasmCacheAccess + Sync,
{
    // Base gas cost for applying the tx
    block_gas_meter
        .add_base_transaction_fee(tx_length)
        .map_err(Error::GasError)?;
    let verifiers = execute_tx(
        &tx,
        storage,
        block_gas_meter,
        write_log,
        vp_wasm_cache,
        tx_wasm_cache,
    )?;

    let vps_result = check_vps(
        &tx,
        storage,
        block_gas_meter,
        write_log,
        &verifiers,
        vp_wasm_cache,
    )?;

    let gas_used = block_gas_meter
        .finalize_transaction()
        .map_err(Error::GasError)?;
    let initialized_accounts = write_log.get_initialized_accounts();
    let changed_keys = write_log.get_keys();
    let ibc_event = write_log.take_ibc_event();

    Ok(TxResult {
        gas_used,
        changed_keys,
        vps_result,
        initialized_accounts,
        ibc_event,
    })
}

/// Apply a derived transaction to storage based on some protocol transaction.
/// The logic here must be completely deterministic and will be executed by all
/// full nodes every time a protocol transaction is included in a block. Storage
/// is updated natively rather than via the wasm environment, so gas does not
/// need to be metered and validity predicates are bypassed. A [`TxResult`]
/// containing changed keys and the like should be returned in the normal way.
#[cfg(not(feature = "abcipp"))]
pub(crate) fn apply_protocol_tx<D, H>(
    tx: ProtocolTxType,
    storage: &mut Storage<D, H>,
) -> Result<TxResult>
where
    D: 'static + DB + for<'iter> DBIter<'iter> + Sync,
    H: 'static + StorageHasher + Sync,
{
    match tx {
        ProtocolTxType::EthereumEvents(ext) => {
            let ethereum_events::VextDigest { events, .. } = ext;
            self::transactions::ethereum_events::apply_derived_tx(
                storage, events,
            )
            .map_err(Error::ProtocolTxError)
        }
        ProtocolTxType::ValidatorSetUpdate(ext) => {
            // NOTE(feature = "abcipp"): we will not need to apply any
            // storage changes when we rollback to ABCI++; we could emit
            // some kind of event, notifying a relayer process of a newly
            // available validator set update, though
            self::transactions::validator_set_update::aggregate_votes(
                storage, ext,
            )
            .map_err(Error::ProtocolTxError)
        }
        _ => {
            tracing::error!(
                "Attempt made to apply an unsupported protocol transaction! - \
                 {:#?}",
                tx
            );
            Err(Error::TxTypeError)
        }
    }
}

#[cfg(feature = "abcipp")]
pub(crate) fn apply_protocol_tx<D, H>(
    tx: ProtocolTxType,
    _storage: &mut Storage<D, H>,
) -> Result<TxResult>
where
    D: 'static + DB + for<'iter> DBIter<'iter> + Sync,
    H: 'static + StorageHasher + Sync,
{
    match tx {
        ProtocolTxType::EthereumEvents(_)
        | ProtocolTxType::ValidatorSetUpdate(_) => {
            // TODO(namada#198): implement this
            tracing::warn!(
                "Attempt made to apply an unimplemented protocol transaction, \
                 no actions will be taken"
            );
            Ok(TxResult::default())
        }
        _ => {
            tracing::error!(
                "Attempt made to apply an unsupported protocol transaction! - \
                 {:#?}",
                tx
            );
            Err(Error::TxTypeError)
        }
    }
}

/// Execute a transaction code. Returns verifiers requested by the transaction.
fn execute_tx<D, H, CA>(
    tx: &Tx,
    storage: &Storage<D, H>,
    gas_meter: &mut BlockGasMeter,
    write_log: &mut WriteLog,
    vp_wasm_cache: &mut VpCache<CA>,
    tx_wasm_cache: &mut TxCache<CA>,
) -> Result<BTreeSet<Address>>
where
    D: 'static + DB + for<'iter> DBIter<'iter> + Sync,
    H: 'static + StorageHasher + Sync,
    CA: 'static + WasmCacheAccess + Sync,
{
    gas_meter
        .add_compiling_fee(tx.code.len())
        .map_err(Error::GasError)?;
    let empty = vec![];
    let tx_data = tx.data.as_ref().unwrap_or(&empty);
    wasm::run::tx(
        storage,
        write_log,
        gas_meter,
        &tx.code,
        tx_data,
        vp_wasm_cache,
        tx_wasm_cache,
    )
    .map_err(Error::TxRunnerError)
}

/// Check the acceptance of a transaction by validity predicates
fn check_vps<D, H, CA>(
    tx: &Tx,
    storage: &Storage<D, H>,
    gas_meter: &mut BlockGasMeter,
    write_log: &WriteLog,
    verifiers_from_tx: &BTreeSet<Address>,
    vp_wasm_cache: &mut VpCache<CA>,
) -> Result<VpsResult>
where
    D: 'static + DB + for<'iter> DBIter<'iter> + Sync,
    H: 'static + StorageHasher + Sync,
    CA: 'static + WasmCacheAccess + Sync,
{
    let (verifiers, keys_changed) =
        write_log.verifiers_and_changed_keys(verifiers_from_tx);

    let initial_gas = gas_meter.get_current_transaction_gas();

    let vps_result = execute_vps(
        verifiers,
        keys_changed,
        tx,
        storage,
        write_log,
        initial_gas,
        vp_wasm_cache,
    )?;
    tracing::debug!("Total VPs gas cost {:?}", vps_result.gas_used);

    gas_meter
        .add_vps_gas(&vps_result.gas_used)
        .map_err(Error::GasError)?;

    Ok(vps_result)
}

/// Execute verifiers' validity predicates
fn execute_vps<D, H, CA>(
    verifiers: BTreeSet<Address>,
    keys_changed: BTreeSet<storage::Key>,
    tx: &Tx,
    storage: &Storage<D, H>,
    write_log: &WriteLog,
    initial_gas: u64,
    vp_wasm_cache: &mut VpCache<CA>,
) -> Result<VpsResult>
where
    D: 'static + DB + for<'iter> DBIter<'iter> + Sync,
    H: 'static + StorageHasher + Sync,
    CA: 'static + WasmCacheAccess + Sync,
{
    verifiers
        .par_iter()
        // TODO temporary pending on <https://github.com/anoma/anoma/issues/193>
        .filter(|addr| !matches!(addr, Address::Implicit(_)))
        .try_fold(VpsResult::default, |mut result, addr| {
            let mut gas_meter = VpGasMeter::new(initial_gas);
            let accept = match &addr {
                Address::Established(_) => {
                    let (vp, gas) = storage
                        .validity_predicate(addr)
                        .map_err(Error::StorageError)?;
                    gas_meter.add(gas).map_err(Error::GasError)?;
                    let vp =
                        vp.ok_or_else(|| Error::MissingAddress(addr.clone()))?;

                    gas_meter
                        .add_compiling_fee(vp.len())
                        .map_err(Error::GasError)?;

                    wasm::run::vp(
                        vp,
                        tx,
                        addr,
                        storage,
                        write_log,
                        &mut gas_meter,
                        &keys_changed,
                        &verifiers,
                        vp_wasm_cache.clone(),
                    )
                    .map_err(Error::VpRunnerError)
                }
                Address::Internal(internal_addr) => {
                    let ctx = native_vp::Ctx::new(
                        storage,
                        write_log,
                        tx,
                        gas_meter,
                        vp_wasm_cache.clone(),
                    );
                    let tx_data = match tx.data.as_ref() {
                        Some(data) => &data[..],
                        None => &[],
                    };

                    let accepted: Result<bool> = match internal_addr {
                        InternalAddress::PoS => {
                            let pos = PosVP { ctx };
                            let verifiers_addr_ref = &verifiers;
                            let pos_ref = &pos;
                            // TODO this is temporarily ran in a new thread to
                            // avoid crashing the ledger (required `UnwindSafe`
                            // and `RefUnwindSafe` in
                            // shared/src/ledger/pos/vp.rs)
                            let keys_changed_ref = &keys_changed;
                            let result = match panic::catch_unwind(move || {
                                pos_ref
                                    .validate_tx(
                                        tx_data,
                                        keys_changed_ref,
                                        verifiers_addr_ref,
                                    )
                                    .map_err(Error::PosNativeVpError)
                            }) {
                                Ok(result) => result,
                                Err(err) => {
                                    tracing::error!(
                                        "PoS native VP failed with {:#?}",
                                        err
                                    );
                                    Err(Error::PosNativeVpRuntime)
                                }
                            };
                            // Take the gas meter back out of the context
                            gas_meter = pos.ctx.gas_meter.into_inner();
                            result
                        }
                        InternalAddress::Ibc => {
                            let ibc = Ibc { ctx };
                            let result = ibc
                                .validate_tx(tx_data, &keys_changed, &verifiers)
                                .map_err(Error::IbcNativeVpError);
                            // Take the gas meter back out of the context
                            gas_meter = ibc.ctx.gas_meter.into_inner();
                            result
                        }
                        InternalAddress::Parameters => {
                            let parameters = ParametersVp { ctx };
                            let result = parameters
                                .validate_tx(tx_data, &keys_changed, &verifiers)
                                .map_err(Error::ParametersNativeVpError);
                            // Take the gas meter back out of the context
                            gas_meter = parameters.ctx.gas_meter.into_inner();
                            result
                        }
                        InternalAddress::PosSlashPool => {
                            // Take the gas meter back out of the context
                            gas_meter = ctx.gas_meter.into_inner();
                            Err(Error::AccessForbidden(
                                (*internal_addr).clone(),
                            ))
                        }
                        InternalAddress::Governance => {
                            let governance = GovernanceVp { ctx };
                            let result = governance
                                .validate_tx(tx_data, &keys_changed, &verifiers)
                                .map_err(Error::GovernanceNativeVpError);
                            gas_meter = governance.ctx.gas_meter.into_inner();
                            result
                        }
                        InternalAddress::Treasury => {
                            let treasury = TreasuryVp { ctx };
                            let result = treasury
                                .validate_tx(tx_data, &keys_changed, &verifiers)
                                .map_err(Error::TreasuryNativeVpError);
                            gas_meter = treasury.ctx.gas_meter.into_inner();
                            result
                        }
                        InternalAddress::IbcEscrow(_)
                        | InternalAddress::IbcBurn
                        | InternalAddress::IbcMint => {
                            // validate the transfer
                            let ibc_token = IbcToken { ctx };
                            let result = ibc_token
                                .validate_tx(tx_data, &keys_changed, &verifiers)
                                .map_err(Error::IbcTokenNativeVpError);
                            gas_meter = ibc_token.ctx.gas_meter.into_inner();
                            result
                        }
                        InternalAddress::EthBridge => {
                            let bridge = EthBridge { ctx };
                            let result = bridge
                                .validate_tx(tx_data, &keys_changed, &verifiers)
                                .map_err(Error::EthBridgeNativeVpError);
                            gas_meter = bridge.ctx.gas_meter.into_inner();
                            result
                        }
                        InternalAddress::EthBridgePool => {
                            let bridge_pool = BridgePoolVp { ctx };
                            let result = bridge_pool
                                .validate_tx(tx_data, &keys_changed, &verifiers)
                                .map_err(Error::BridgePoolNativeVpError);
                            gas_meter = bridge_pool.ctx.gas_meter.into_inner();
                            result
                        }
                    };

                    accepted
                }
                // TODO temporary pending on <https://github.com/anoma/anoma/issues/193>
                Address::Implicit(_) => unreachable!(),
            };

            // Returning error from here will short-circuit the VP parallel
            // execution. It's important that we only short-circuit gas
            // errors to get deterministic gas costs
            result.gas_used.set(&gas_meter).map_err(Error::GasError)?;
            match accept {
                Ok(accepted) => {
                    if !accepted {
                        result.rejected_vps.insert(addr.clone());
                    } else {
                        result.accepted_vps.insert(addr.clone());
                    }
                    Ok(result)
                }
                Err(err) => match err {
                    Error::GasError(_) => Err(err),
                    _ => {
                        result.rejected_vps.insert(addr.clone());
                        result.errors.push((addr.clone(), err.to_string()));
                        Ok(result)
                    }
                },
            }
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
    let mut accepted_vps = a.accepted_vps;
    let mut rejected_vps = a.rejected_vps;
    accepted_vps.extend(b.accepted_vps);
    rejected_vps.extend(b.rejected_vps);
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
