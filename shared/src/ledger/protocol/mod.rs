//! The ledger's protocol

use std::collections::BTreeSet;
use std::panic;

use rayon::iter::{IntoParallelRefIterator, ParallelIterator};
use thiserror::Error;

use crate::ledger::gas::{self, BlockGasMeter, VpGasMeter};
use crate::ledger::ibc::vp::{Ibc, IbcToken};
use crate::ledger::native_vp::ethereum_bridge::bridge_pool_vp::BridgePoolVp;
use crate::ledger::native_vp::ethereum_bridge::vp::EthBridge;
use crate::ledger::native_vp::governance::GovernanceVp;
use crate::ledger::native_vp::parameters::{self, ParametersVp};
use crate::ledger::native_vp::slash_fund::SlashFundVp;
use crate::ledger::native_vp::{self, NativeVp};
use crate::ledger::pos::{self, PosVP};
use crate::ledger::storage::write_log::WriteLog;
use crate::ledger::storage::{DBIter, Storage, StorageHasher, DB};
use crate::proto::{self, Tx};
use crate::types::address::{Address, InternalAddress};
use crate::types::storage;
use crate::types::storage::TxIndex;
use crate::types::transaction::protocol::{ProtocolTx, ProtocolTxType};
use crate::types::transaction::{DecryptedTx, TxResult, TxType, VpsResult};
use crate::vm::wasm::{TxCache, VpCache};
use crate::vm::{self, wasm, WasmCacheAccess};

#[allow(missing_docs)]
#[derive(Error, Debug)]
pub enum Error {
    #[error("Storage error: {0}")]
    StorageError(crate::ledger::storage::Error),
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
    IbcNativeVpError(crate::ledger::ibc::vp::Error),
    #[error("PoS native VP: {0}")]
    PosNativeVpError(pos::vp::Error),
    #[error("PoS native VP panicked")]
    PosNativeVpRuntime,
    #[error("Parameters native VP: {0}")]
    ParametersNativeVpError(parameters::Error),
    #[error("IBC Token native VP: {0}")]
    IbcTokenNativeVpError(crate::ledger::ibc::vp::IbcTokenError),
    #[error("Governance native VP error: {0}")]
    GovernanceNativeVpError(crate::ledger::native_vp::governance::Error),
    #[error("SlashFund native VP error: {0}")]
    SlashFundNativeVpError(crate::ledger::native_vp::slash_fund::Error),
    #[error("Ethereum bridge native VP error: {0}")]
    EthBridgeNativeVpError(native_vp::ethereum_bridge::vp::Error),
    #[error("Ethereum bridge pool native VP error: {0}")]
    BridgePoolNativeVpError(native_vp::ethereum_bridge::bridge_pool_vp::Error),
    #[error("Access to an internal address {0} is forbidden")]
    AccessForbidden(InternalAddress),
}

#[allow(missing_docs)]
pub struct ShellParams<'a, D, H, CA>
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

/// Result of applying a transaction
pub type Result<T> = std::result::Result<T, Error>;

/// Dispatch a given transaction to be applied based on its type. Some storage
/// updates may be derived and applied natively rather than via the wasm
/// environment, in which case validity predicates will be bypassed.
///
/// If the given tx is a successfully decrypted payload apply the necessary
/// vps. Otherwise, we include the tx on chain with the gas charge added
/// but no further validations.
#[allow(clippy::too_many_arguments)]
pub fn dispatch_tx<'a, D, H, CA>(
    tx_type: TxType,
    tx_length: usize,
    tx_index: TxIndex,
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
            &tx_index,
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
    tx_index: &TxIndex,
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
        tx_index,
        storage,
        block_gas_meter,
        write_log,
        vp_wasm_cache,
        tx_wasm_cache,
    )?;

    let vps_result = check_vps(
        &tx,
        tx_index,
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
pub(crate) fn apply_protocol_tx<D, H>(
    tx: ProtocolTxType,
    storage: &mut Storage<D, H>,
) -> Result<TxResult>
where
    D: 'static + DB + for<'iter> DBIter<'iter> + Sync,
    H: 'static + StorageHasher + Sync,
{
    use namada_ethereum_bridge::protocol::transactions;

    use crate::types::vote_extensions::{
        ethereum_events, validator_set_update,
    };

    match tx {
        ProtocolTxType::EthEventsVext(ext) => {
            let ethereum_events::VextDigest { events, .. } =
                ethereum_events::VextDigest::singleton(ext);
            transactions::ethereum_events::apply_derived_tx(storage, events)
                .map_err(Error::ProtocolTxError)
        }
        ProtocolTxType::ValSetUpdateVext(ext) => {
            // NOTE(feature = "abcipp"): we will not need to apply any
            // storage changes when we rollback to ABCI++; this is because
            // the decided vote extension digest should have >2/3 of the
            // voting power already, which is the whole reason why we
            // have to apply state updates with `abciplus` - we need
            // to aggregate votes consisting of >2/3 of the voting power
            // on a validator set update.
            //
            // we could, however, emit some kind of event, notifying a
            // relayer process of a newly available validator set update;
            // for this, we need to receive a mutable reference to the
            // event log, in `apply_protocol_tx()`
            transactions::validator_set_update::aggregate_votes(
                storage,
                validator_set_update::VextDigest::singleton(ext),
            )
            .map_err(Error::ProtocolTxError)
        }
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
    tx_index: &TxIndex,
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
        tx_index,
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
    tx_index: &TxIndex,
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
        tx_index,
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
#[allow(clippy::too_many_arguments)]
fn execute_vps<D, H, CA>(
    verifiers: BTreeSet<Address>,
    keys_changed: BTreeSet<storage::Key>,
    tx: &Tx,
    tx_index: &TxIndex,
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
        .try_fold(VpsResult::default, |mut result, addr| {
            let mut gas_meter = VpGasMeter::new(initial_gas);
            let accept = match &addr {
                Address::Implicit(_) | Address::Established(_) => {
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
                        tx_index,
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
                        addr,
                        storage,
                        write_log,
                        tx,
                        tx_index,
                        gas_meter,
                        &keys_changed,
                        &verifiers,
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
                        InternalAddress::SlashFund => {
                            let slash_fund = SlashFundVp { ctx };
                            let result = slash_fund
                                .validate_tx(tx_data, &keys_changed, &verifiers)
                                .map_err(Error::SlashFundNativeVpError);
                            gas_meter = slash_fund.ctx.gas_meter.into_inner();
                            result
                        }
                        InternalAddress::IbcToken(_)
                        | InternalAddress::IbcEscrow
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

#[cfg(test)]
mod tests {
    use std::collections::HashSet;

    use borsh::BorshDeserialize;
    use eyre::Result;
    use namada_core::types::ethereum_events::testing::DAI_ERC20_ETH_ADDRESS;
    use namada_core::types::ethereum_events::{
        EthereumEvent, TransferToNamada,
    };
    use namada_core::types::storage::BlockHeight;
    use namada_core::types::token::Amount;
    use namada_core::types::vote_extensions::ethereum_events::EthereumEventsVext;
    use namada_core::types::{address, key};
    use namada_ethereum_bridge::protocol::transactions::ethereum_events;
    use namada_ethereum_bridge::protocol::transactions::votes::Votes;
    use namada_ethereum_bridge::storage::vote_tallies;

    use super::*;

    #[test]
    /// Tests that if the same [`ProtocolTxType::EthEventsVext`] is applied
    /// twice within the same block, it doesn't result in voting power being
    /// double counted.
    fn test_apply_protocol_tx_duplicate_eth_events_vext() -> Result<()> {
        let validator_a = address::testing::established_address_2();
        let validator_b = address::testing::established_address_3();
        let mut storage =
            ethereum_events::testing::setup_storage(HashSet::from_iter(vec![
                validator_a.clone(),
                validator_b,
            ]));
        let event = EthereumEvent::TransfersToNamada {
            nonce: 1.into(),
            transfers: vec![TransferToNamada {
                amount: Amount::from(100),
                asset: DAI_ERC20_ETH_ADDRESS,
                receiver: address::testing::established_address_4(),
            }],
        };
        let vext = EthereumEventsVext {
            block_height: BlockHeight(100),
            validator_addr: address::testing::established_address_2(),
            ethereum_events: vec![event.clone()],
        };
        let signing_key = key::testing::keypair_1();
        let signed = vext.sign(&signing_key);
        let tx = ProtocolTxType::EthEventsVext(signed);

        apply_protocol_tx(tx.clone(), &mut storage)?;
        apply_protocol_tx(tx, &mut storage)?;

        let eth_msg_keys = vote_tallies::Keys::from(&event);
        let (seen_by_bytes, _) = storage.read(&eth_msg_keys.seen_by())?;
        let seen_by_bytes = seen_by_bytes.unwrap();
        assert_eq!(
            Votes::try_from_slice(&seen_by_bytes)?,
            Votes::from([(validator_a, BlockHeight(100))])
        );

        // the vote should have only be applied once
        let (voting_power_bytes, _) =
            storage.read(&eth_msg_keys.voting_power())?;
        let voting_power_bytes = voting_power_bytes.unwrap();
        assert_eq!(<(u64, u64)>::try_from_slice(&voting_power_bytes)?, (1, 2));

        Ok(())
    }
}
