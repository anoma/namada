//! The ledger's protocol
use std::collections::{BTreeMap, BTreeSet};
use std::panic;

use borsh::BorshSerialize;
use masp_primitives::transaction::Transaction;
use namada_core::ledger::gas::TxGasMeter;
use namada_core::types::storage::Key;
use namada_core::proto::Section;
use namada_core::ledger::storage::TempWlStorage;
use namada_core::ledger::storage_api::{StorageRead, StorageWrite};
use namada_core::types::hash::Hash;
use namada_core::types::token::Amount;
use namada_core::types::transaction::WrapperTx;
use rayon::iter::{IntoParallelRefIterator, ParallelIterator, Empty};
use thiserror::Error;

use crate::ledger::eth_bridge::vp::EthBridge;
use crate::ledger::gas::{self, GasMetering, VpGasMeter};
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
    #[error("Missing wasm code error")]
    MissingCode,
    #[error("Storage error: {0}")]
    StorageError(crate::ledger::storage::Error),
    #[error("Error decoding a transaction from bytes: {0}")]
    TxDecodingError(proto::Error),
    #[error("Transaction runner error: {0}")]
    TxRunnerError(vm::wasm::run::Error),
    #[error("Txs must either be encrypted or a decryption of an encrypted tx")]
    TxTypeError,
    #[error("Fee ushielding error: {0}")]
    FeeUnshieldingError(crate::types::transaction::WrapperTxErr),
    #[error("{0}")]
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
    tx: Tx,
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
    match tx.header().tx_type {
        TxType::Raw => Err(Error::TxTypeError),
        TxType::Decrypted(DecryptedTx::Decrypted {
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
            let masp_transaction = wrapper.unshield_section_hash.map(|ref hash| tx.get_section(hash).map(|section| if let Section::MaspTx(transaction) = section { Some(transaction.to_owned()) } else { None }).flatten()).flatten();

            let changed_keys = apply_wrapper_tx(
                write_log,
                storage,
                wrapper,
                masp_transaction,
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
                ibc_events: BTreeSet::default(),
            })
        }
        _ => Ok(TxResult::default()),
    }
}

    /// Load the wasm hash for a transfer from storage.
    ///
    /// # Panics
    /// If the transaction hash is not found in storage
    pub fn get_transfer_hash_from_storage<S>(storage: &S) -> Hash
where S: StorageRead{
        let transfer_code_name_key =
            Key::wasm_code_name("tx_transfer.wasm".to_string());
            storage
            .read(&transfer_code_name_key)
            .expect("Could not read the storage")
            .expect("Expected tx transfer hash in storage")

    }

/// Performs the required operation on a wrapper transaction:
///  - replay protection
///  - fee payment
///  - gas accounting
fn apply_wrapper_tx<D, H, CA>(
    write_log: &mut WriteLog,
    storage: &Storage<D, H>,
    wrapper: &WrapperTx,
    masp_transaction: Option<Transaction>,
    tx_bytes: &[u8],
    gas_meter: &mut TxGasMeter,
    gas_table: &BTreeMap<String, u64>,
    block_proposer: Option<&Address>,
    vp_wasm_cache: &mut VpCache<CA>,
    tx_wasm_cache: &mut TxCache<CA>,
    #[cfg(not(feature = "mainnet"))] has_valid_pow: bool,
) -> Result<BTreeSet<Key>>
where
    D: 'static + DB + for<'iter> DBIter<'iter> + Sync,
    H: 'static + StorageHasher + Sync,
    CA: 'static + WasmCacheAccess + Sync,
{
    let mut changed_keys = BTreeSet::default();
    let tx: Tx = tx_bytes.try_into().unwrap();

    for hash in [&hash::Hash(tx.header_hash().0), &tx.clone().update_header(TxType::Raw).header_hash()] {
        let key = replay_protection::get_tx_hash_key(hash);
    // Writes both txs hash to block write log (changes must be persisted even in case of failure)
        //FIXME: need a unit test to check this
        write_log.protocol_write(&key, vec![]).expect("Error while writing tx hash to storage");
        changed_keys.insert(key);
    }

    // Charge fee before performing any fallible operations
    changed_keys.extend(charge_fee(
        wrapper,
        masp_transaction,
        tx_bytes,
        &gas_table,
        #[cfg(not(feature = "mainnet"))]
        has_valid_pow,
        block_proposer,
        write_log,
        storage,
        vp_wasm_cache,
        tx_wasm_cache,
    )?);

    // Account for gas
    gas_meter.add_tx_size_gas(tx_bytes)?;

    Ok(changed_keys)
}

/// Charge fee for the provided wrapper transaction. In ABCI returns an error if the balance of the block proposer overflows. In ABCI plus returns error if:
/// - The unshielding fails
/// - Fee amount overflows
/// - Not enough funds are available to pay the entire amount of the fee
/// - The accumulated fee amount to be credited to the block proposer overflows
///
/// Returns the set of changed keys.
pub fn charge_fee<D, H, CA>(
    wrapper: &WrapperTx,
    masp_transaction: Option<Transaction>,
    tx_bytes: &[u8],
    gas_table: &BTreeMap<String, u64>,
    #[cfg(not(feature = "mainnet"))] has_valid_pow: bool,
    block_proposer: Option<&Address>,

    write_log: &mut WriteLog,
    storage: &Storage<D, H>,
    vp_wasm_cache: &mut VpCache<CA>,
    tx_wasm_cache: &mut TxCache<CA>,
) -> Result<BTreeSet<Key>>
where
    D: 'static + DB + for<'iter> DBIter<'iter> + Sync,
    H: 'static + StorageHasher + Sync,
    CA: 'static + WasmCacheAccess + Sync,
{
    // Reconstruct a WlStorage with the current WriteLog to account for prior modifications
    let mut temp_wl_storage = TempWlStorage::new(storage);
    temp_wl_storage.write_log = write_log.clone();  //FIXME: can avoid this clone? Only if I pass WlStorage to apply_tx instead of the write log and storage split. But if I do that I might screw upa ll of the calls to write! Actually not, I'm already taking care of them here, I would just need to double check the calls in apply_tx
    
    // Unshield funds if requested
        let unexpected_unshielding_tx =    if let Some(transaction ) = masp_transaction {
        // The unshielding tx does not charge gas, instantiate a
        // custom gas meter for this step
        let mut gas_meter =
            TxGasMeter::new(
                temp_wl_storage 
                    .read(
                        &namada_core::ledger::parameters::storage::get_fee_unshielding_gas_limit_key(
                        ),
                    )
                    .expect("Error reading the storage")
                    .expect("Missing fee unshielding gas limit in storage"),
            );

        let transparent_balance = storage_api::token::read_balance(
            &temp_wl_storage,
            &wrapper.fee.token,
            &wrapper.fee_payer(),
        ).map_err(|e| Error::FeeError(e.to_string()))?;
            let unshield_amount = wrapper
                .get_tx_fee().map_err(|e| Error::FeeUnshieldingError(e))?
                .checked_sub(transparent_balance)
                .and_then(|v| if v.is_zero() { None } else { Some(v) });

        // If it fails, do not return early
        // from this function but try to take the funds from the unshielded
        // balance
        if let Some(unshield_amount) = unshield_amount {
        match wrapper.generate_fee_unshielding(
            unshield_amount,
            get_transfer_hash_from_storage(&temp_wl_storage),
                transaction
        ) {
            Ok(fee_unshielding_tx) => {
                // NOTE: A clean tx write log must be provided to this call for a correct vp validation. Block write log, instead, should contain any prior changes (if any)
                    temp_wl_storage.write_log.precommit_tx();
                match apply_tx(
                        fee_unshielding_tx,
                    tx_bytes,
                    TxIndex::default(),
                    &mut gas_meter,
                    gas_table,
                    &mut temp_wl_storage.write_log,
                    &temp_wl_storage.storage,
                    vp_wasm_cache,
                    tx_wasm_cache,
                    None,
    #[cfg(not(feature = "mainnet"))] false,
                    
                ) {
                    Ok(result) => {
                            //NOTE: do not commit yet cause this could be exploited to get free unshieldings
                            if !result.is_accepted() {
                            temp_wl_storage.write_log.drop_tx();
                            tracing::error!(
                                "The unshielding tx is invalid, some VPs \
                                     rejected it: {:#?}",
                                result.vps_result.rejected_vps
                            );
                        }
                    }
                    Err(e) => {
                        temp_wl_storage.write_log.drop_tx();
                        tracing::error!(
                            "The unshielding tx is invalid, wasm run \
                                 failed: {}",
                            e
                        );
                    }
                }
            }
            Err(e) => tracing::error!("{}", e), 
        }
            false
        } else {

        true}
    } else {
        false
    };

           // Charge or check fees
    match block_proposer {
        Some(proposer) => transfer_fee(&mut temp_wl_storage, proposer, #[cfg(not(feature = "mainnet"))]has_valid_pow, &wrapper)?,
        None => check_fees(&temp_wl_storage, #[cfg(not(feature = "mainnet"))]has_valid_pow, &wrapper)?
        }

    let changed_keys = temp_wl_storage.write_log.get_keys_with_precommit();

    // Commit tx write log even in case of subsequent errors
    temp_wl_storage.write_log.commit_tx();
    *write_log = temp_wl_storage.write_log;

    if unexpected_unshielding_tx{
        Err(Error::FeeUnshieldingError(namada_core::types::transaction::WrapperTxErr::InvalidUnshield("Found unnecessary unshielding tx attached".to_string())))
    } else {
        Ok(changed_keys)
    }


}

/// Perform the actual transfer of fess from the fee payer to the block proposer.
pub fn transfer_fee<D, H>( 
    temp_wl_storage: &mut TempWlStorage<D, H>,
    block_proposer: &Address, 
    #[cfg(not(feature = "mainnet"))] has_valid_pow: bool,
    wrapper: &WrapperTx,
) -> Result<()> 
where
    D: 'static + DB + for<'iter> DBIter<'iter> + Sync,
    H: 'static + StorageHasher + Sync,
{
    let balance = storage_api::token::read_balance(
        temp_wl_storage,
        &wrapper.fee.token,
        &wrapper.fee_payer(),
    )
    .unwrap();

    match wrapper.get_tx_fee() {
        Ok(fees) => {
            if balance.checked_sub(fees).is_some() {
        token_transfer(
            temp_wl_storage,
            &wrapper.fee.token,
            &wrapper.fee_payer(),
            block_proposer,
            fees,
        ).map_err(|e| Error::FeeError(e.to_string()))
            } else {
                // Balance was insufficient for fee payment
                #[cfg(not(feature = "mainnet"))]
                let reject = !has_valid_pow;
                #[cfg(feature = "mainnet")]
                let reject = true;

                if reject {
                #[cfg(not(any(feature = "abciplus", feature = "abcipp")))]
                    {
                        // Move all the available funds in the transparent balance of the fee payer
        token_transfer(
            temp_wl_storage,
            &wrapper.fee.token,
            &wrapper.fee_payer(),
            block_proposer,
            balance,
        ).map_err(|e| Error::FeeError(e.to_string()))?;


                        return Err(Error::FeeError("Transparent balance of wrapper's signer was insufficient to pay fee. All the available transparent funds have been moved to the block proposer".to_string()));
                    }
                #[cfg(any(feature = "abciplus", feature = "abcipp"))]
                    return Err(Error::FeeError("Insufficient transparent balance to pay fees"
                        .to_string()));
                } else {
                    tracing::debug!("Balance was insufficient for fee payment but a valid PoW was provided");
                    Ok(())
                }
            }
        }
        Err(e) => {
            // Fee overflow
                #[cfg(not(any(feature = "abciplus", feature = "abcipp")))]
            {
                // Move all the available funds in the transparent balance of the fee payer
token_transfer(
            temp_wl_storage,
            &wrapper.fee.token,
            &wrapper.fee_payer(),
            block_proposer,
            balance,
        ).map_err(|e| Error::FeeError(e.to_string()))?;


                return Err(Error::FeeError(
                    format!("{}. All the available transparent funds have been moved to the block proposer", e
                )));
            }

                #[cfg(any(feature = "abciplus", feature = "abcipp"))]
            return Err(Error::FeeError(e.to_string()));
        }
}
}

/// Transfer `token` from `src` to `dest`. Returns an `Err` if `src` has
/// insufficient balance or if the transfer the `dest` would overflow (This can
/// only happen if the total supply does't fit in `token::Amount`). Contrary to `storage_api::token::transfer` this function updates the tx write log and not the block write log.
fn token_transfer<D, H>(
    temp_wl_storage: &mut TempWlStorage<D, H>,
    token: &Address,
    src: &Address,
    dest: &Address,
    amount: Amount
    
) -> Result<()> 
where
    D: 'static + DB + for<'iter> DBIter<'iter> + Sync,
    H: 'static + StorageHasher + Sync,
    {
    
    if amount.is_zero() {
        return Ok(());
    }
    let src_key = namada_core::types::token::balance_key(token, src);
    let src_balance = namada_core::ledger::storage_api::token::read_balance(temp_wl_storage, token, src).expect("Token balance read in protocol must not fail");
    match src_balance.checked_sub(amount) {
        Some(new_src_balance) => {
            let dest_key = namada_core::types::token::balance_key(token, dest);
            let dest_balance = namada_core::ledger::storage_api::token::read_balance(temp_wl_storage, token, dest).expect("Token balance read in protocol must not fail");
            match dest_balance.checked_add(amount) {
                Some(new_dest_balance) => {
                    temp_wl_storage.write_log.write(&src_key, new_src_balance.try_to_vec().unwrap()).map_err(|e| Error::FeeError(e.to_string()))?;
                    match temp_wl_storage.write_log.write(&dest_key, new_dest_balance.try_to_vec().unwrap()) {
                        Ok(_) => Ok(()),
                        Err(e) => Err(Error::FeeError(e.to_string()))
                    }
                }
                None => Err(Error::FeeError(
                    "The transfer would overflow destination balance".to_string(),
                )),
            }
        }
        None => {
            Err(Error::FeeError("Insufficient source balance".to_string()))
        }
    }
}

/// Check if the fee payer has enough transparent balance to pay fees
pub fn check_fees<D, H>( 
    temp_wl_storage: &TempWlStorage<D, H>,
    #[cfg(not(feature = "mainnet"))] has_valid_pow: bool, 
    wrapper: &WrapperTx,
) -> Result<()> 
where
    D: 'static + DB + for<'iter> DBIter<'iter> + Sync,
    H: 'static + StorageHasher + Sync,
{
    
    let balance = storage_api::token::read_balance(
        temp_wl_storage,
        &wrapper.fee.token,
        &wrapper.fee_payer(),
    )
    .unwrap();

    let fees = wrapper.get_tx_fee().map_err(|e| Error::FeeError(e.to_string()))?;

    if balance.checked_sub(fees).is_some() {
        Ok(())
    } else {
        
                // Balance was insufficient for fee payment
                #[cfg(not(feature = "mainnet"))]
                let reject = !has_valid_pow;
                #[cfg(feature = "mainnet")]
                let reject = true;

        if reject {
            Err(Error::FeeError("Insufficient transparent balance to pay fees".to_string()))
        } else {
            
                    tracing::debug!("Balance was insufficient for fee payment but a valid PoW was provided");
                    Ok(())
        }

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
    wasm::run::tx(
        storage,
        write_log,
        tx_gas_meter,
        gas_table,
        tx_index,
        tx,
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
                    gas_meter.consume(gas).map_err(Error::GasError)?;
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
                        InternalAddress::IbcToken(_)
                        | InternalAddress::IbcEscrow
                        | InternalAddress::IbcBurn
                        | InternalAddress::IbcMint => {
                            // validate the transfer
                            let ibc_token = IbcToken { ctx };
                            let result = ibc_token
                                .validate_tx(tx, &keys_changed, &verifiers)
                                .map_err(Error::IbcTokenNativeVpError);
                            gas_meter = ibc_token.ctx.gas_meter.into_inner();
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

    gas_used.merge(&mut b.gas_used, tx_gas_limit, initial_gas)?;

    Ok(VpsResult {
        accepted_vps,
        rejected_vps,
        gas_used,
        errors,
    })
}
