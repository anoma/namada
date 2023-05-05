//! The ledger's protocol
use std::collections::{BTreeMap, BTreeSet};
use std::panic;

use namada_core::ledger::gas::TxGasMeter;
use namada_core::ledger::storage::TempWlStorage;
use namada_core::ledger::storage_api::{StorageRead, StorageWrite};
use namada_core::types::hash::Hash;
use namada_core::types::transaction::WrapperTx;
use rayon::iter::{IntoParallelRefIterator, ParallelIterator};
use thiserror::Error;

use crate::ledger::eth_bridge::vp::EthBridge;
use crate::ledger::gas::{self, TxVpGasMetering, VpGasMeter};
use crate::ledger::ibc::vp::{Ibc, IbcToken};
use crate::ledger::native_vp::governance::GovernanceVp;
use crate::ledger::native_vp::parameters::{self, ParametersVp};
use crate::ledger::native_vp::replay_protection::ReplayProtectionVp;
use crate::ledger::native_vp::slash_fund::SlashFundVp;
use crate::ledger::native_vp::{self, NativeVp};
use crate::ledger::pos::{self, PosVP};
use crate::ledger::replay_protection;
use crate::ledger::storage::write_log::WriteLog;
use crate::ledger::storage::{DBIter, Storage, StorageHasher, DB};
use crate::ledger::storage_api;
use crate::proto::{self, Tx};
use crate::types::address::{Address, InternalAddress};
use crate::types::hash;
use crate::types::storage;
use crate::types::storage::TxIndex;
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
    #[error("Txs must either be encrypted or a decryption of an encrypted tx")]
    TxTypeError,
    #[error("Gas error: {0}")]
    #[error("{0}")]
    FeeUnshieldingError(crate::types::transaction::WrapperTxErr),
    GasError(#[from] gas::Error),
    #[error("Error while processing transaction's fees: {0}")]
    FeeError(String),
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
    EthBridgeNativeVpError(crate::ledger::eth_bridge::vp::Error),
    #[error("Replay protection native VP error: {0}")]
    ReplayProtectionNativeVpError(
        crate::ledger::native_vp::replay_protection::Error,
    ),
    #[error("Access to an internal address {0} is forbidden")]
    AccessForbidden(InternalAddress),
}

/// Result of applying a transaction
pub type Result<T> = std::result::Result<T, Error>;

/// Apply a given transaction
///
/// The only Tx Types that should be input here are `Decrypted` and `Wrapper`
///
/// If the given tx is a successfully decrypted payload apply the necessary
/// vps. Otherwise, we include the tx on chain with the gas charge added
/// but no further validations.
#[allow(clippy::too_many_arguments)]
pub fn apply_tx<D, H, CA>(
    tx: TxType,
    tx_bytes: &[u8],
    tx_index: TxIndex,
    tx_gas_meter: &mut TxGasMeter,
    gas_table: &BTreeMap<String, u64>,
    write_log: &mut WriteLog,
    storage: &Storage<D, H>,
    vp_wasm_cache: &mut VpCache<CA>,
    tx_wasm_cache: &mut TxCache<CA>,
    block_proposer: Option<&Address>,
    #[cfg(not(feature = "mainnet"))] has_valid_pow: bool,
) -> Result<TxResult>
where
    D: 'static + DB + for<'iter> DBIter<'iter> + Sync,
    H: 'static + StorageHasher + Sync,
    CA: 'static + WasmCacheAccess + Sync,
{
    match tx {
        TxType::Raw(_) => Err(Error::TxTypeError),
        TxType::Decrypted(DecryptedTx::Decrypted {
            tx,
            #[cfg(not(feature = "mainnet"))]
            has_valid_pow,
        }) => {
            let verifiers = execute_tx(
                &tx,
                &tx_index,
                storage,
                tx_gas_meter,
                gas_table,
                write_log,
                vp_wasm_cache,
                tx_wasm_cache,
            )?;

            let vps_result = check_vps(
                &tx,
                &tx_index,
                storage,
                tx_gas_meter,
                gas_table,
                write_log,
                &verifiers,
                vp_wasm_cache,
                #[cfg(not(feature = "mainnet"))]
                has_valid_pow,
            )?;

            let gas_used = tx_gas_meter.get_current_transaction_gas();
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
        TxType::Wrapper(ref wrapper) => {
            let mut changed_keys = BTreeSet::default();

            apply_wrapper_tx(
                write_log,
                storage,
                &mut changed_keys,
                wrapper,
                tx_bytes,
                tx_gas_meter,
                gas_table,
                block_proposer,
                vp_wasm_cache,
                tx_wasm_cache,
                #[cfg(not(feature = "mainnet"))]
                has_valid_pow,
            )?;
            Ok(TxResult {
                gas_used: tx_gas_meter.get_current_transaction_gas(),
                changed_keys,
                vps_result: VpsResult::default(),
                initialized_accounts: vec![],
                ibc_event: None,
            })
        }
        _ => Ok(TxResult::default()),
    }
}

/// Performs the required operation on a wrapper transaction:
///  - replay protection
///  - fee payment
///  - gas accounting
fn apply_wrapper_tx<D, H, CA>(
    write_log: &mut WriteLog,
    storage: &Storage<D, H>,
    changed_keys: &mut BTreeSet<storage::Key>,
    wrapper: &WrapperTx,
    tx_bytes: &[u8],
    gas_meter: &mut TxGasMeter,
    gas_table: &BTreeMap<String, u64>,
    block_proposer: Option<&Address>,
    vp_wasm_cache: &mut VpCache<CA>,
    tx_wasm_cache: &mut TxCache<CA>,
    #[cfg(not(feature = "mainnet"))] has_valid_pow: bool,
) -> Result<()>
where
    D: 'static + DB + for<'iter> DBIter<'iter> + Sync,
    H: 'static + StorageHasher + Sync,
    CA: 'static + WasmCacheAccess + Sync,
{
    // Writes both txs hash to block write log (changes must be persisted even in case of failure)
    let tx: Tx = tx_bytes.try_into().unwrap();
    let wrapper_tx_hash_key =
        replay_protection::get_tx_hash_key(&hash::Hash(tx.unsigned_hash()));

    write_log
        .write(&wrapper_tx_hash_key, vec![])
        .expect("Error while writing tx hash to storage");

    let inner_tx_hash_key =
        replay_protection::get_tx_hash_key(&wrapper.tx_hash);

    write_log
        .write(&inner_tx_hash_key, vec![])
        .expect("Error while writing tx hash to storage");

    // Persist hashes to storage even in case of failure
    changed_keys.append(&mut write_log.get_keys());
    write_log.commit_tx();

    // Charge fee before performing any fallible operations
    charge_fee(
        wrapper,
        &gas_table,
        #[cfg(not(feature = "mainnet"))]
        has_valid_pow,
        block_proposer,
        write_log,
        storage,
        changed_keys,
        vp_wasm_cache,
        tx_wasm_cache,
    )?;

    // Account for gas
    gas_meter.add_tx_size_gas(tx_bytes)?;

    Ok(())
}

/// Charge fee for the provided wrapper transaction. In ABCI returns an error if the balance of the block proposer overflows. In ABCI++ returns error if:
/// - The unshielding fails
/// - Fee amount overflows
/// - Not enough funds are available to pay the entire amount of the fee
/// - The accumulated fee amount to be credited to the block proposer overflows
pub fn charge_fee<D, H, CA>(
    wrapper: &WrapperTx,
    gas_table: &BTreeMap<String, u64>,
    #[cfg(not(feature = "mainnet"))] has_valid_pow: bool,
    block_proposer: Option<&Address>,
    write_log: &mut WriteLog,
    storage: &Storage<D, H>,
    changed_keys: &mut BTreeSet<storage::Key>,
    vp_wasm_cache: &mut VpCache<CA>,
    tx_wasm_cache: &mut TxCache<CA>,
) -> Result<()>
where
    D: 'static + DB + for<'iter> DBIter<'iter> + Sync,
    H: 'static + StorageHasher + Sync,
    CA: 'static + WasmCacheAccess + Sync,
{
    // Unshield funds if requested
    if wrapper.unshield.is_some() {
        // The unshielding tx does not charge gas, instantiate a
        // custom gas meter for this step
        let mut gas_meter = TxGasMeter::new(
            self.wl_storage
                .read(&parameters::storage::get_fee_unshielding_gas_limit_key())
                .expect("Error reading the storage")
                .expect("Missing fee unshielding gas limit in storage"),
        );

        let transparent_balance = storage_api::token::read_balance(
            &self.wl_storage,
            &wrapper.fee.token,
            &wrapper.fee_payer(),
        )?;

        // If it fails, do not return early
        // from this function but try to take the funds from the unshielded
        // balance
        match wrapper.generate_fee_unshielding(
            transparent_balance,
            // By this time we've already validated the chain id and
            // expiration, we don't need the correct values anymore
            self.chain_id.clone(),
            None,
            self.load_transfer_code_from_storage(),
        ) {
            Ok(Some(fee_unshielding_tx)) => {
                // NOTE: A clean write log must be provided to this call for a correct vp validation
                match apply_tx(
                    TxType::Decrypted(DecryptedTx::Decrypted {
                        tx: fee_unshielding_tx,
                        has_valid_pow: false,
                    }),
                    TxIndex::default(),
                    &mut gas_meter,
                    gas_table,
                    &mut self.wl_storage.write_log,
                    &self.wl_storage.storage,
                    &mut self.vp_wasm_cache,
                    &mut self.tx_wasm_cache,
                ) {
                    Ok(result) => {
                        if result.is_accepted() {
                            self.wl_storage.write_log.commit_tx();
                        } else {
                            self.wl_storage.write_log.drop_tx();
                            tracing::error!(
                                "The unshielding tx is invalid, some VPs \
                                     rejected it: {:#?}",
                                result.vps_result.rejected_vps
                            );
                        }
                    }
                    Err(e) => {
                        self.wl_storage.write_log.drop_tx();
                        tracing::error!(
                            "The unshielding tx is invalid, wasm run \
                                 failed: {}",
                            e
                        );
                    }
                }
            }
            Ok(None) => {
                tracing::error!("Missing expected fee unshielding tx")
            }
            Err(e) => tracing::error!("{}", e),
        }
    }

    // Charge fee
    let mut wl_storage = TempWlStorage::new(storage);
    wl_storage.write_log = std::mem::take(write_log);

    transfer_fee(&mut wl_storage, block_proposer, has_valid_pow, &wrapper)
        .map_err(Error::FeeError)?;

    // Rejoin the updated write log
    *write_log = wl_storage.write_log;
    changed_keys.append(&mut write_log.get_keys());

    Ok(())
}

/// Perform the actual transfer of fess from the fee payer to the block proposer. If the block proposer is not provided, fees will be be burned and the total supply reduced accordingly
pub fn transfer_fee<S>(
    wl_storage: &mut S,
    block_proposer: Option<&Address>,
    #[cfg(not(feature = "mainnet"))] has_valid_pow: bool,
    wrapper: &WrapperTx,
) -> std::result::Result<(), String>
where
    S: StorageRead + StorageWrite,
{
    let balance = storage_api::token::read_balance(
        wl_storage,
        &wrapper.fee.token,
        &wrapper.fee_payer(),
    )
    .unwrap();

    match wrapper.fee_amount() {
        Ok(fees) => {
            if balance.checked_sub(fees).is_some() {
                dispatch_fee_action(wl_storage, wrapper, block_proposer, fees)
                    .map_err(|e| e.to_string())
            } else {
                // Balance was insufficient for fee payment
                #[cfg(not(feature = "mainnet"))]
                let reject = !has_valid_pow;
                #[cfg(feature = "mainnet")]
                let reject = true;

                if reject {
                    #[cfg(not(feature = "abcipp"))]
                    {
                        // Move all the available funds in the transparent balance of the fee payer
                        dispatch_fee_action(
                            wl_storage,
                            wrapper,
                            block_proposer,
                            balance,
                        )
                        .map_err(|e| e.to_string())?;

                        return Err("Transparent balance of wrapper's signer was insufficient to pay fee".to_string());
                    }
                    #[cfg(feature = "abcipp")]
                    return Err("Insufficient transparent balance to pay fees"
                        .to_string());
                } else {
                    tracing::debug!("Balance was insufficient for fee payment but a valid PoW was provided");
                    Ok(())
                }
            }
        }
        Err(e) => {
            // Fee overflow
            #[cfg(not(feature = "abcipp"))]
            {
                // Move all the available funds in the transparent balance of the fee payer
                dispatch_fee_action(
                    wl_storage,
                    wrapper,
                    block_proposer,
                    balance,
                )
                .map_err(|e| e.to_string())?;

                return Err(e.to_string());
            }

            #[cfg(feature = "abcipp")]
            return Err(e.to_string());
        }
    }
}

/// Decides whether to transfer the fees to the block proposer or burn them. Operations are done on the block write log.
fn dispatch_fee_action<S>(
    wl_storage: &mut S,
    wrapper: &WrapperTx,
    block_proposer: Option<&Address>,
    amount: storage_api::token::Amount,
) -> storage_api::Result<()>
where
    S: StorageRead + StorageWrite,
{
    match block_proposer {
        Some(block_proposer) => storage_api::token::transfer(
            wl_storage,
            &wrapper.fee.token,
            &wrapper.fee_payer(),
            block_proposer,
            amount,
        ),
        None => storage_api::token::burn_tokens(
            wl_storage,
            &wrapper.fee.token,
            &wrapper.fee_payer(),
            amount,
        ),
    }
}

/// Execute a transaction code. Returns verifiers requested by the transaction.
#[allow(clippy::too_many_arguments)]
fn execute_tx<D, H, CA>(
    tx: &Tx,
    tx_index: &TxIndex,
    storage: &Storage<D, H>,
    tx_gas_meter: &mut TxGasMeter,
    gas_table: &BTreeMap<String, u64>,
    write_log: &mut WriteLog,
    vp_wasm_cache: &mut VpCache<CA>,
    tx_wasm_cache: &mut TxCache<CA>,
) -> Result<BTreeSet<Address>>
where
    D: 'static + DB + for<'iter> DBIter<'iter> + Sync,
    H: 'static + StorageHasher + Sync,
    CA: 'static + WasmCacheAccess + Sync,
{
    let empty = vec![];
    let tx_data = tx.data.as_ref().unwrap_or(&empty);
    wasm::run::tx(
        storage,
        write_log,
        tx_gas_meter,
        gas_table,
        tx_index,
        &tx.code_or_hash,
        tx_data,
        vp_wasm_cache,
        tx_wasm_cache,
    )
    .map_err(|e| {
        if let wasm::run::Error::GasError(gas_error) = e {
            Error::GasError(gas_error)
        } else {
            Error::TxRunnerError(e)
        }
    })
}

/// Check the acceptance of a transaction by validity predicates
#[allow(clippy::too_many_arguments)]
fn check_vps<D, H, CA>(
    tx: &Tx,
    tx_index: &TxIndex,
    storage: &Storage<D, H>,
    tx_gas_meter: &mut TxGasMeter,
    gas_table: &BTreeMap<String, u64>,
    write_log: &WriteLog,
    verifiers_from_tx: &BTreeSet<Address>,
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
    let (verifiers, keys_changed) =
        write_log.verifiers_and_changed_keys(verifiers_from_tx);

    let vps_result = execute_vps(
        verifiers,
        keys_changed,
        tx,
        tx_index,
        storage,
        write_log,
        tx_gas_meter.tx_gas_limit,
        tx_gas_meter.get_current_transaction_gas(),
        gas_table,
        vp_wasm_cache,
        #[cfg(not(feature = "mainnet"))]
        has_valid_pow,
    )?;
    tracing::debug!("Total VPs gas cost {:?}", vps_result.gas_used);

    tx_gas_meter.add_vps_gas(&vps_result.gas_used)?;

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
    tx_gas_limit: u64,
    initial_gas: u64,
    gas_table: &BTreeMap<String, u64>,
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
            let mut gas_meter = VpGasMeter::new(tx_gas_limit, initial_gas);
            let accept = match &addr {
                Address::Implicit(_) | Address::Established(_) => {
                    let (vp_hash, gas) = storage
                        .validity_predicate(addr)
                        .map_err(Error::StorageError)?;
                    gas_meter.add(gas).map_err(Error::GasError)?;
                    let vp_code_hash = match vp_hash {
                        Some(v) => Hash::try_from(&v[..])
                            .map_err(|_| Error::MissingAddress(addr.clone()))?,
                        None => {
                            return Err(Error::MissingAddress(addr.clone()));
                        }
                    };

                    // NOTE: because of the whitelisted gas and the gas metering
                    // for the exposed vm env functions,
                    //    the first signature verification (if any) is accounted
                    // twice
                    wasm::run::vp(
                        &vp_code_hash,
                        tx,
                        tx_index,
                        addr,
                        storage,
                        write_log,
                        &mut gas_meter,
                        gas_table,
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
                        InternalAddress::ReplayProtection => {
                            let replay_protection_vp =
                                ReplayProtectionVp { ctx };
                            let result = replay_protection_vp
                                .validate_tx(tx_data, &keys_changed, &verifiers)
                                .map_err(Error::ReplayProtectionNativeVpError);
                            gas_meter =
                                replay_protection_vp.ctx.gas_meter.into_inner();
                            result
                        }
                    };

                    accepted
                }
            };

            // Returning error from here will short-circuit the VP parallel
            // execution.
            result.gas_used.set(gas_meter).map_err(Error::GasError)?;
            if accept? {
                result.accepted_vps.insert(addr.clone());
            } else {
                result.rejected_vps.insert(addr.clone());
            }
            Ok(result)
        })
        .try_reduce(VpsResult::default, |a, b| {
            merge_vp_results(a, b, tx_gas_limit, initial_gas)
        })
}

/// Merge VP results from parallel runs
fn merge_vp_results(
    a: VpsResult,
    mut b: VpsResult,
    tx_gas_limit: u64,
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

    gas_used.merge(&mut b.gas_used, tx_gas_limit, initial_gas)?;

    Ok(VpsResult {
        accepted_vps,
        rejected_vps,
        gas_used,
        errors,
    })
}
