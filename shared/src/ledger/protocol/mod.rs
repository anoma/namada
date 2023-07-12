//! The ledger's protocol

use std::collections::BTreeSet;
use std::panic;

use eyre::{eyre, WrapErr};
use rayon::iter::{IntoParallelRefIterator, ParallelIterator};
use thiserror::Error;

use crate::ledger::gas::{self, BlockGasMeter, VpGasMeter};
use crate::ledger::ibc::vp::Ibc;
use crate::ledger::native_vp::ethereum_bridge::bridge_pool_vp::BridgePoolVp;
use crate::ledger::native_vp::ethereum_bridge::nut::NonUsableTokens;
use crate::ledger::native_vp::ethereum_bridge::vp::EthBridge;
use crate::ledger::native_vp::governance::GovernanceVp;
use crate::ledger::native_vp::multitoken::MultitokenVp;
use crate::ledger::native_vp::parameters::{self, ParametersVp};
use crate::ledger::native_vp::replay_protection::ReplayProtectionVp;
use crate::ledger::native_vp::slash_fund::SlashFundVp;
use crate::ledger::native_vp::{self, NativeVp};
use crate::ledger::pos::{self, PosVP};
use crate::ledger::storage::write_log::WriteLog;
use crate::ledger::storage::{DBIter, Storage, StorageHasher, WlStorage, DB};
use crate::proto::{self, Tx};
use crate::types::address::{Address, InternalAddress};
use crate::types::storage;
use crate::types::storage::TxIndex;
use crate::types::transaction::protocol::{EthereumTxData, ProtocolTxType};
use crate::types::transaction::{DecryptedTx, TxResult, TxType, VpsResult};
use crate::vm::wasm::{TxCache, VpCache};
use crate::vm::{self, wasm, WasmCacheAccess};

#[allow(missing_docs)]
#[derive(Error, Debug)]
pub enum Error {
    #[error("Missing wasm code error")]
    MissingCode,
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
    MultitokenNativeVpError(crate::ledger::native_vp::multitoken::Error),
    #[error("Governance native VP error: {0}")]
    GovernanceNativeVpError(crate::ledger::native_vp::governance::Error),
    #[error("SlashFund native VP error: {0}")]
    SlashFundNativeVpError(crate::ledger::native_vp::slash_fund::Error),
    #[error("Ethereum bridge native VP error: {0}")]
    EthBridgeNativeVpError(native_vp::ethereum_bridge::vp::Error),
    #[error("Ethereum bridge pool native VP error: {0}")]
    BridgePoolNativeVpError(native_vp::ethereum_bridge::bridge_pool_vp::Error),
    #[error("Replay protection native VP error: {0}")]
    ReplayProtectionNativeVpError(
        crate::ledger::native_vp::replay_protection::Error,
    ),
    #[error("Non usable tokens native VP error: {0}")]
    NutNativeVpError(native_vp::ethereum_bridge::nut::Error),
    #[error("Access to an internal address {0} is forbidden")]
    AccessForbidden(InternalAddress),
}

/// Shell parameters for running wasm transactions.
#[allow(missing_docs)]
pub enum ShellParams<'a, D, H, CA>
where
    D: 'static + DB + for<'iter> DBIter<'iter> + Sync,
    H: 'static + StorageHasher + Sync,
    CA: 'static + WasmCacheAccess + Sync,
{
    /// Parameters passed to dry ran txs.
    DryRun {
        storage: &'a Storage<D, H>,
        vp_wasm_cache: &'a mut VpCache<CA>,
        tx_wasm_cache: &'a mut TxCache<CA>,
    },
    /// Parameters passed to mutating tx executions.
    Mutating {
        block_gas_meter: &'a mut BlockGasMeter,
        wl_storage: &'a mut WlStorage<D, H>,
        vp_wasm_cache: &'a mut VpCache<CA>,
        tx_wasm_cache: &'a mut TxCache<CA>,
    },
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
    tx: Tx,
    tx_length: usize,
    tx_index: TxIndex,
    block_gas_meter: &'a mut BlockGasMeter,
    wl_storage: &'a mut WlStorage<D, H>,
    vp_wasm_cache: &'a mut VpCache<CA>,
    tx_wasm_cache: &'a mut TxCache<CA>,
) -> Result<TxResult>
where
    D: 'static + DB + for<'iter> DBIter<'iter> + Sync,
    H: 'static + StorageHasher + Sync,
    CA: 'static + WasmCacheAccess + Sync,
{
    match tx.header().tx_type {
        TxType::Raw => Err(Error::TxTypeError),
        TxType::Decrypted(DecryptedTx::Decrypted {
            #[cfg(not(feature = "mainnet"))]
            has_valid_pow,
        }) => apply_wasm_tx(
            tx,
            tx_length,
            &tx_index,
            ShellParams::Mutating {
                block_gas_meter,
                wl_storage,
                vp_wasm_cache,
                tx_wasm_cache,
            },
            #[cfg(not(feature = "mainnet"))]
            has_valid_pow,
        ),
        TxType::Protocol(protocol_tx) => {
            apply_protocol_tx(protocol_tx.tx, tx.data(), wl_storage)
        }
        TxType::Wrapper(_) | TxType::Decrypted(DecryptedTx::Undecryptable) => {
            // do not apply db updates, but charge gas anyway.
            // 1) we can only apply state updates on encrypted txs
            // at the next block height
            // 2) undecryptable txs should not perform any state
            // updates either. errors are emitted at a layer above,
            // in `Shell::finalize_block()`.
            let gas_used = block_gas_meter
                .finalize_transaction()
                .map_err(Error::GasError)?;
            Ok(TxResult {
                gas_used,
                ..Default::default()
            })
        }
    }
}

/// Apply a transaction going via the wasm environment. Gas will be metered and
/// validity predicates will be triggered in the normal way.
pub(crate) fn apply_wasm_tx<'a, D, H, CA>(
    tx: Tx,
    tx_length: usize,
    tx_index: &TxIndex,
    shell_params: ShellParams<'a, D, H, CA>,
    #[cfg(not(feature = "mainnet"))] has_valid_pow: bool,
) -> Result<TxResult>
where
    D: 'static + DB + for<'iter> DBIter<'iter> + Sync,
    H: 'static + StorageHasher + Sync,
    CA: 'static + WasmCacheAccess + Sync,
{
    let mut default_gas_meter = Default::default();
    let mut default_write_log = Default::default();

    let (block_gas_meter, storage, write_log, vp_wasm_cache, tx_wasm_cache) =
        match shell_params {
            ShellParams::Mutating {
                block_gas_meter,
                wl_storage,
                vp_wasm_cache,
                tx_wasm_cache,
            } => (
                block_gas_meter,
                &wl_storage.storage,
                &mut wl_storage.write_log,
                vp_wasm_cache,
                tx_wasm_cache,
            ),
            ShellParams::DryRun {
                storage,
                vp_wasm_cache,
                tx_wasm_cache,
            } => (
                &mut default_gas_meter,
                storage,
                &mut default_write_log,
                vp_wasm_cache,
                tx_wasm_cache,
            ),
        };

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

    let vps_result = check_vps(CheckVps {
        tx: &tx,
        tx_index,
        storage,
        gas_meter: block_gas_meter,
        write_log,
        verifiers_from_tx: &verifiers,
        vp_wasm_cache,
        #[cfg(not(feature = "mainnet"))]
        has_valid_pow,
    })?;

    let gas_used = block_gas_meter
        .finalize_transaction()
        .map_err(Error::GasError)?;
    let initialized_accounts = write_log.get_initialized_accounts();
    let changed_keys = write_log.get_keys();
    let ibc_events = write_log.take_ibc_events();

    Ok(TxResult {
        gas_used,
        changed_keys,
        vps_result,
        initialized_accounts,
        ibc_events,
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
    data: Option<Vec<u8>>,
    storage: &mut WlStorage<D, H>,
) -> Result<TxResult>
where
    D: 'static + DB + for<'iter> DBIter<'iter> + Sync,
    H: 'static + StorageHasher + Sync,
{
    use namada_ethereum_bridge::protocol::transactions;

    use crate::types::vote_extensions::{
        ethereum_events, validator_set_update,
    };

    let Some(data) = data else {
        return Err(Error::ProtocolTxError(
            eyre!("Protocol tx data must be present")),
        );
    };
    let ethereum_tx_data = EthereumTxData::deserialize(&tx, &data)
        .wrap_err_with(|| {
            format!(
                "Attempt made to apply an unsupported protocol transaction! - \
                 {tx:?}",
            )
        })
        .map_err(Error::ProtocolTxError)?;

    match ethereum_tx_data {
        EthereumTxData::EthEventsVext(ext) => {
            let ethereum_events::VextDigest { events, .. } =
                ethereum_events::VextDigest::singleton(ext);
            transactions::ethereum_events::apply_derived_tx(storage, events)
                .map_err(Error::ProtocolTxError)
        }
        EthereumTxData::BridgePoolVext(ext) => {
            transactions::bridge_pool_roots::apply_derived_tx(
                storage,
                ext.into(),
            )
            .map_err(Error::ProtocolTxError)
        }
        EthereumTxData::ValSetUpdateVext(ext) => {
            // NOTE(feature = "abcipp"): with ABCI++, we can write the
            // complete proof to storage in one go. the decided vote extension
            // digest must already have >2/3 of the voting power behind it.
            // with ABCI+, multiple vote extension protocol txs may be needed
            // to reach a complete proof.
            let signing_epoch = ext.data.signing_epoch;
            transactions::validator_set_update::aggregate_votes(
                storage,
                validator_set_update::VextDigest::singleton(ext),
                signing_epoch,
            )
            .map_err(Error::ProtocolTxError)
        }
        EthereumTxData::EthereumEvents(_)
        | EthereumTxData::BridgePool(_)
        | EthereumTxData::ValidatorSetUpdate(_) => {
            // TODO(namada#198): implement this
            tracing::warn!(
                "Attempt made to apply an unimplemented protocol transaction, \
                 no actions will be taken"
            );
            Ok(TxResult::default())
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
    wasm::run::tx(
        storage,
        write_log,
        gas_meter,
        tx_index,
        tx,
        vp_wasm_cache,
        tx_wasm_cache,
    )
    .map_err(Error::TxRunnerError)
}

/// Arguments to [`check_vps`].
struct CheckVps<'a, D, H, CA>
where
    D: 'static + DB + for<'iter> DBIter<'iter> + Sync,
    H: 'static + StorageHasher + Sync,
    CA: 'static + WasmCacheAccess + Sync,
{
    tx: &'a Tx,
    tx_index: &'a TxIndex,
    storage: &'a Storage<D, H>,
    gas_meter: &'a mut BlockGasMeter,
    write_log: &'a WriteLog,
    verifiers_from_tx: &'a BTreeSet<Address>,
    vp_wasm_cache: &'a mut VpCache<CA>,
    #[cfg(not(feature = "mainnet"))]
    has_valid_pow: bool,
}

/// Check the acceptance of a transaction by validity predicates
fn check_vps<D, H, CA>(
    CheckVps {
        tx,
        tx_index,
        storage,
        gas_meter,
        write_log,
        verifiers_from_tx,
        vp_wasm_cache,
        #[cfg(not(feature = "mainnet"))]
        has_valid_pow,
    }: CheckVps<'_, D, H, CA>,
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
        has_valid_pow,
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
    #[cfg(not(feature = "mainnet"))]
    // This is true when the wrapper of this tx contained a valid
    // `testnet_pow::Solution`
    has_valid_pow: bool,
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
                    let (vp_hash, gas) = storage
                        .validity_predicate(addr)
                        .map_err(Error::StorageError)?;
                    gas_meter.add(gas).map_err(Error::GasError)?;
                    let Some(vp_code_hash) = vp_hash else {
                        return Err(Error::MissingAddress(addr.clone()));
                    };

                    wasm::run::vp(
                        &vp_code_hash,
                        tx,
                        tx_index,
                        addr,
                        storage,
                        write_log,
                        &mut gas_meter,
                        &keys_changed,
                        &verifiers,
                        vp_wasm_cache.clone(),
                        #[cfg(not(feature = "mainnet"))]
                        has_valid_pow,
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
                                        tx,
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
                                .validate_tx(tx, &keys_changed, &verifiers)
                                .map_err(Error::IbcNativeVpError);
                            // Take the gas meter back out of the context
                            gas_meter = ibc.ctx.gas_meter.into_inner();
                            result
                        }
                        InternalAddress::Parameters => {
                            let parameters = ParametersVp { ctx };
                            let result = parameters
                                .validate_tx(tx, &keys_changed, &verifiers)
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
                                .validate_tx(tx, &keys_changed, &verifiers)
                                .map_err(Error::GovernanceNativeVpError);
                            gas_meter = governance.ctx.gas_meter.into_inner();
                            result
                        }
                        InternalAddress::SlashFund => {
                            let slash_fund = SlashFundVp { ctx };
                            let result = slash_fund
                                .validate_tx(tx, &keys_changed, &verifiers)
                                .map_err(Error::SlashFundNativeVpError);
                            gas_meter = slash_fund.ctx.gas_meter.into_inner();
                            result
                        }
                        InternalAddress::Multitoken => {
                            let multitoken = MultitokenVp { ctx };
                            let result = multitoken
                                .validate_tx(tx, &keys_changed, &verifiers)
                                .map_err(Error::MultitokenNativeVpError);
                            gas_meter = multitoken.ctx.gas_meter.into_inner();
                            result
                        }
                        InternalAddress::EthBridge => {
                            let bridge = EthBridge { ctx };
                            let result = bridge
                                .validate_tx(tx, &keys_changed, &verifiers)
                                .map_err(Error::EthBridgeNativeVpError);
                            gas_meter = bridge.ctx.gas_meter.into_inner();
                            result
                        }
                        InternalAddress::EthBridgePool => {
                            let bridge_pool = BridgePoolVp { ctx };
                            let result = bridge_pool
                                .validate_tx(tx, &keys_changed, &verifiers)
                                .map_err(Error::BridgePoolNativeVpError);
                            gas_meter = bridge_pool.ctx.gas_meter.into_inner();
                            result
                        }
                        InternalAddress::ReplayProtection => {
                            let replay_protection_vp =
                                ReplayProtectionVp { ctx };
                            let result = replay_protection_vp
                                .validate_tx(tx, &keys_changed, &verifiers)
                                .map_err(Error::ReplayProtectionNativeVpError);
                            gas_meter =
                                replay_protection_vp.ctx.gas_meter.into_inner();
                            result
                        }
                        InternalAddress::Nut(_) => {
                            let non_usable_tokens = NonUsableTokens { ctx };
                            let result = non_usable_tokens
                                .validate_tx(tx, &keys_changed, &verifiers)
                                .map_err(Error::NutNativeVpError);
                            gas_meter =
                                non_usable_tokens.ctx.gas_meter.into_inner();
                            result
                        }
                        InternalAddress::IbcToken(_)
                        | InternalAddress::Erc20(_) => {
                            // The address should be a part of a multitoken key
                            gas_meter = ctx.gas_meter.into_inner();
                            Ok(verifiers.contains(&Address::Internal(
                                InternalAddress::Multitoken,
                            )))
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
    use std::collections::HashMap;

    use borsh::BorshDeserialize;
    use eyre::Result;
    use namada_core::ledger::storage_api::StorageRead;
    use namada_core::proto::{SignableEthMessage, Signed};
    use namada_core::types::ethereum_events::testing::DAI_ERC20_ETH_ADDRESS;
    use namada_core::types::ethereum_events::{
        EthereumEvent, TransferToNamada,
    };
    use namada_core::types::keccak::keccak_hash;
    use namada_core::types::storage::BlockHeight;
    use namada_core::types::token::Amount;
    use namada_core::types::vote_extensions::bridge_pool_roots::BridgePoolRootVext;
    use namada_core::types::vote_extensions::ethereum_events::EthereumEventsVext;
    use namada_core::types::voting_power::FractionalVotingPower;
    use namada_core::types::{address, key};
    use namada_ethereum_bridge::protocol::transactions::votes::{
        EpochedVotingPower, Votes,
    };
    use namada_ethereum_bridge::storage::eth_bridge_queries::EthBridgeQueries;
    use namada_ethereum_bridge::storage::proof::EthereumProof;
    use namada_ethereum_bridge::storage::vote_tallies;
    use namada_ethereum_bridge::{bridge_pool_vp, test_utils};

    use super::*;

    fn apply_eth_tx<D, H>(
        tx: EthereumTxData,
        wl_storage: &mut WlStorage<D, H>,
    ) -> Result<TxResult>
    where
        D: 'static + DB + for<'iter> DBIter<'iter> + Sync,
        H: 'static + StorageHasher + Sync,
    {
        let (data, tx) = tx.serialize();
        let tx_result = apply_protocol_tx(tx, Some(data), wl_storage)?;
        Ok(tx_result)
    }

    #[test]
    /// Tests that if the same [`ProtocolTxType::EthEventsVext`] is applied
    /// twice within the same block, it doesn't result in voting power being
    /// double counted.
    fn test_apply_protocol_tx_duplicate_eth_events_vext() -> Result<()> {
        let validator_a = address::testing::established_address_2();
        let validator_b = address::testing::established_address_3();
        let (mut wl_storage, _) = test_utils::setup_storage_with_validators(
            HashMap::from_iter(vec![
                (validator_a.clone(), Amount::native_whole(100)),
                (validator_b, Amount::native_whole(100)),
            ]),
        );
        let event = EthereumEvent::TransfersToNamada {
            nonce: 0.into(),
            transfers: vec![TransferToNamada {
                amount: Amount::from(100),
                asset: DAI_ERC20_ETH_ADDRESS,
                receiver: address::testing::established_address_4(),
            }],
            valid_transfers_map: vec![true],
        };
        let vext = EthereumEventsVext {
            block_height: BlockHeight(100),
            validator_addr: address::testing::established_address_2(),
            ethereum_events: vec![event.clone()],
        };
        let signing_key = key::testing::keypair_1();
        let signed = vext.sign(&signing_key);
        let tx = EthereumTxData::EthEventsVext(signed);

        apply_eth_tx(tx.clone(), &mut wl_storage)?;
        apply_eth_tx(tx, &mut wl_storage)?;

        let eth_msg_keys = vote_tallies::Keys::from(&event);
        let seen_by_bytes = wl_storage.read_bytes(&eth_msg_keys.seen_by())?;
        let seen_by_bytes = seen_by_bytes.unwrap();
        assert_eq!(
            Votes::try_from_slice(&seen_by_bytes)?,
            Votes::from([(validator_a, BlockHeight(100))])
        );

        // the vote should have only be applied once
        let voting_power: EpochedVotingPower =
            wl_storage.read(&eth_msg_keys.voting_power())?.unwrap();
        let expected =
            EpochedVotingPower::from([(0.into(), FractionalVotingPower::HALF)]);
        assert_eq!(voting_power, expected);

        Ok(())
    }

    #[test]
    /// Tests that if the same [`ProtocolTxType::BridgePoolVext`] is applied
    /// twice within the same block, it doesn't result in voting power being
    /// double counted.
    fn test_apply_protocol_tx_duplicate_bp_roots_vext() -> Result<()> {
        let validator_a = address::testing::established_address_2();
        let validator_b = address::testing::established_address_3();
        let (mut wl_storage, keys) = test_utils::setup_storage_with_validators(
            HashMap::from_iter(vec![
                (validator_a.clone(), Amount::native_whole(100)),
                (validator_b, Amount::native_whole(100)),
            ]),
        );
        bridge_pool_vp::init_storage(&mut wl_storage);

        let root = wl_storage.ethbridge_queries().get_bridge_pool_root();
        let nonce = wl_storage.ethbridge_queries().get_bridge_pool_nonce();
        test_utils::commit_bridge_pool_root_at_height(
            &mut wl_storage.storage,
            &root,
            100.into(),
        );
        let to_sign = keccak_hash([root.0, nonce.to_bytes()].concat());
        let signing_key = key::testing::keypair_1();
        let hot_key =
            &keys[&address::testing::established_address_2()].eth_bridge;
        let sig = Signed::<_, SignableEthMessage>::new(hot_key, to_sign).sig;
        let vext = BridgePoolRootVext {
            block_height: BlockHeight(100),
            validator_addr: address::testing::established_address_2(),
            sig,
        }
        .sign(&signing_key);
        let tx = EthereumTxData::BridgePoolVext(vext);
        apply_eth_tx(tx.clone(), &mut wl_storage)?;
        apply_eth_tx(tx, &mut wl_storage)?;

        let bp_root_keys = vote_tallies::Keys::from(
            vote_tallies::BridgePoolRoot(EthereumProof::new((root, nonce))),
        );
        let root_seen_by_bytes =
            wl_storage.read_bytes(&bp_root_keys.seen_by())?;
        assert_eq!(
            Votes::try_from_slice(root_seen_by_bytes.as_ref().unwrap())?,
            Votes::from([(validator_a, BlockHeight(100))])
        );
        // the vote should have only be applied once
        let voting_power: EpochedVotingPower =
            wl_storage.read(&bp_root_keys.voting_power())?.unwrap();
        let expected =
            EpochedVotingPower::from([(0.into(), FractionalVotingPower::HALF)]);
        assert_eq!(voting_power, expected);

        Ok(())
    }
}
