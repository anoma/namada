//! The ledger's protocol
use std::collections::BTreeSet;

use borsh_ext::BorshSerializeExt;
use eyre::{eyre, WrapErr};
use masp_primitives::transaction::Transaction;
use namada_core::types::hash::Hash;
use namada_core::types::storage::Key;
use namada_gas::TxGasMeter;
use namada_sdk::tx::TX_TRANSFER_WASM;
use namada_state::wl_storage::WriteLogAndStorage;
use namada_state::StorageRead;
use namada_tx::data::protocol::ProtocolTxType;
use namada_tx::data::{
    DecryptedTx, GasLimit, TxResult, TxType, VpsResult, WrapperTx,
};
use namada_tx::{Section, Tx};
use namada_vote_ext::EthereumTxData;
use rayon::iter::{IntoParallelRefIterator, ParallelIterator};
use thiserror::Error;

use crate::ledger::gas::{GasMetering, VpGasMeter};
use crate::ledger::governance::GovernanceVp;
use crate::ledger::native_vp::ethereum_bridge::bridge_pool_vp::BridgePoolVp;
use crate::ledger::native_vp::ethereum_bridge::nut::NonUsableTokens;
use crate::ledger::native_vp::ethereum_bridge::vp::EthBridge;
use crate::ledger::native_vp::ibc::Ibc;
use crate::ledger::native_vp::masp::MaspVp;
use crate::ledger::native_vp::multitoken::MultitokenVp;
use crate::ledger::native_vp::parameters::{self, ParametersVp};
use crate::ledger::native_vp::{self, NativeVp};
use crate::ledger::pgf::PgfVp;
use crate::ledger::pos::{self, PosVP};
use crate::state::write_log::WriteLog;
use crate::state::{DBIter, State, StorageHasher, WlStorage, DB};
use crate::token::Amount;
use crate::types::address::{Address, InternalAddress};
use crate::types::storage;
use crate::types::storage::TxIndex;
use crate::vm::wasm::{TxCache, VpCache};
use crate::vm::{self, wasm, WasmCacheAccess};

#[allow(missing_docs)]
#[derive(Error, Debug)]
pub enum Error {
    #[error("Missing tx section: {0}")]
    MissingSection(String),
    #[error("Storage error: {0}")]
    StorageError(namada_state::Error),
    #[error("Transaction runner error: {0}")]
    TxRunnerError(vm::wasm::run::Error),
    #[error("{0:?}")]
    ProtocolTxError(#[from] eyre::Error),
    #[error("Txs must either be encrypted or a decryption of an encrypted tx")]
    TxTypeError,
    #[error("Fee ushielding error: {0}")]
    FeeUnshieldingError(namada_tx::data::WrapperTxErr),
    #[error("Gas error: {0}")]
    GasError(String),
    #[error("Error while processing transaction's fees: {0}")]
    FeeError(String),
    #[error("Invalid transaction signature")]
    InvalidTxSignature,
    #[error(
        "The decrypted transaction {0} has already been applied in this block"
    )]
    ReplayAttempt(Hash),
    #[error("Error executing VP for addresses: {0:?}")]
    VpRunnerError(vm::wasm::run::Error),
    #[error("The address {0} doesn't exist")]
    MissingAddress(Address),
    #[error("IBC native VP: {0}")]
    IbcNativeVpError(crate::ledger::native_vp::ibc::Error),
    #[error("PoS native VP: {0}")]
    PosNativeVpError(pos::vp::Error),
    #[error("PoS native VP panicked")]
    PosNativeVpRuntime,
    #[error("Parameters native VP: {0}")]
    ParametersNativeVpError(parameters::Error),
    #[error("IBC Token native VP: {0}")]
    MultitokenNativeVpError(crate::ledger::native_vp::multitoken::Error),
    #[error("Governance native VP error: {0}")]
    GovernanceNativeVpError(crate::ledger::governance::Error),
    #[error("Pgf native VP error: {0}")]
    PgfNativeVpError(crate::ledger::pgf::Error),
    #[error("Ethereum bridge native VP error: {0:?}")]
    EthBridgeNativeVpError(native_vp::ethereum_bridge::vp::Error),
    #[error("Ethereum bridge pool native VP error: {0:?}")]
    BridgePoolNativeVpError(native_vp::ethereum_bridge::bridge_pool_vp::Error),
    #[error("Non usable tokens native VP error: {0:?}")]
    NutNativeVpError(native_vp::ethereum_bridge::nut::Error),
    #[error("MASP native VP error: {0}")]
    MaspNativeVpError(native_vp::masp::Error),
    #[error("Access to an internal address {0:?} is forbidden")]
    AccessForbidden(InternalAddress),
}

/// Shell parameters for running wasm transactions.
#[allow(missing_docs)]
pub struct ShellParams<'a, CA, WLS>
where
    CA: 'static + WasmCacheAccess + Sync,
    WLS: WriteLogAndStorage + StorageRead,
{
    tx_gas_meter: &'a mut TxGasMeter,
    wl_storage: &'a mut WLS,
    vp_wasm_cache: &'a mut VpCache<CA>,
    tx_wasm_cache: &'a mut TxCache<CA>,
}

impl<'a, CA, WLS> ShellParams<'a, CA, WLS>
where
    CA: 'static + WasmCacheAccess + Sync,
    WLS: WriteLogAndStorage + StorageRead,
{
    /// Create a new instance of `ShellParams`
    pub fn new(
        tx_gas_meter: &'a mut TxGasMeter,
        wl_storage: &'a mut WLS,
        vp_wasm_cache: &'a mut VpCache<CA>,
        tx_wasm_cache: &'a mut TxCache<CA>,
    ) -> Self {
        Self {
            tx_gas_meter,
            wl_storage,
            vp_wasm_cache,
            tx_wasm_cache,
        }
    }
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
    tx_bytes: &'a [u8],
    tx_index: TxIndex,
    tx_gas_meter: &'a mut TxGasMeter,
    wl_storage: &'a mut WlStorage<D, H>,
    vp_wasm_cache: &'a mut VpCache<CA>,
    tx_wasm_cache: &'a mut TxCache<CA>,
    block_proposer: Option<&'a Address>,
) -> Result<TxResult>
where
    D: 'static + DB + for<'iter> DBIter<'iter> + Sync,
    H: 'static + StorageHasher + Sync,
    CA: 'static + WasmCacheAccess + Sync,
{
    match tx.header().tx_type {
        TxType::Raw => Err(Error::TxTypeError),
        TxType::Decrypted(DecryptedTx::Decrypted) => apply_wasm_tx(
            tx,
            &tx_index,
            ShellParams {
                tx_gas_meter,
                wl_storage,
                vp_wasm_cache,
                tx_wasm_cache,
            },
        ),
        TxType::Protocol(protocol_tx) => {
            apply_protocol_tx(protocol_tx.tx, tx.data(), wl_storage)
        }
        TxType::Wrapper(ref wrapper) => {
            let fee_unshielding_transaction =
                get_fee_unshielding_transaction(&tx, wrapper);
            let changed_keys = apply_wrapper_tx(
                tx,
                wrapper,
                fee_unshielding_transaction,
                tx_bytes,
                ShellParams {
                    tx_gas_meter,
                    wl_storage,
                    vp_wasm_cache,
                    tx_wasm_cache,
                },
                block_proposer,
            )?;
            Ok(TxResult {
                gas_used: tx_gas_meter.get_tx_consumed_gas(),
                changed_keys,
                vps_result: VpsResult::default(),
                initialized_accounts: vec![],
                ibc_events: BTreeSet::default(),
                eth_bridge_events: BTreeSet::default(),
            })
        }
        TxType::Decrypted(DecryptedTx::Undecryptable) => {
            Ok(TxResult::default())
        }
    }
}

/// Load the wasm hash for a transfer from storage.
///
/// # Panics
/// If the transaction hash is not found in storage
pub fn get_transfer_hash_from_storage<S>(storage: &S) -> Hash
where
    S: StorageRead,
{
    let transfer_code_name_key =
        Key::wasm_code_name(TX_TRANSFER_WASM.to_string());
    storage
        .read(&transfer_code_name_key)
        .expect("Could not read the storage")
        .expect("Expected tx transfer hash in storage")
}

/// Performs the required operation on a wrapper transaction:
///  - replay protection
///  - fee payment
///  - gas accounting
///
/// Returns the set of changed storage keys.
pub(crate) fn apply_wrapper_tx<'a, D, H, CA, WLS>(
    tx: Tx,
    wrapper: &WrapperTx,
    fee_unshield_transaction: Option<Transaction>,
    tx_bytes: &[u8],
    mut shell_params: ShellParams<'a, CA, WLS>,
    block_proposer: Option<&Address>,
) -> Result<BTreeSet<Key>>
where
    CA: 'static + WasmCacheAccess + Sync,
    D: 'static + DB + for<'iter> DBIter<'iter> + Sync,
    H: 'static + StorageHasher + Sync,
    WLS: WriteLogAndStorage<D = D, H = H> + StorageRead,
{
    let mut changed_keys = BTreeSet::default();

    // Write wrapper tx hash to storage
    shell_params
        .wl_storage
        .write_tx_hash(tx.header_hash())
        .expect("Error while writing tx hash to storage");

    // Charge fee before performing any fallible operations
    charge_fee(
        wrapper,
        fee_unshield_transaction,
        &mut shell_params,
        block_proposer,
        &mut changed_keys,
    )?;

    // Account for gas
    shell_params
        .tx_gas_meter
        .add_wrapper_gas(tx_bytes)
        .map_err(|err| Error::GasError(err.to_string()))?;

    Ok(changed_keys)
}

/// Retrieve the Masp `Transaction` for fee unshielding from the provided
/// transaction, if present
pub fn get_fee_unshielding_transaction(
    tx: &Tx,
    wrapper: &WrapperTx,
) -> Option<Transaction> {
    wrapper
        .unshield_section_hash
        .and_then(|ref hash| tx.get_section(hash))
        .and_then(|section| {
            if let Section::MaspTx(transaction) = section.as_ref() {
                Some(transaction.to_owned())
            } else {
                None
            }
        })
}

/// Charge fee for the provided wrapper transaction. In ABCI returns an error if
/// the balance of the block proposer overflows. In ABCI plus returns error if:
/// - The unshielding fails
/// - Fee amount overflows
/// - Not enough funds are available to pay the entire amount of the fee
/// - The accumulated fee amount to be credited to the block proposer overflows
fn charge_fee<'a, D, H, CA, WLS>(
    wrapper: &WrapperTx,
    masp_transaction: Option<Transaction>,
    shell_params: &mut ShellParams<'a, CA, WLS>,
    block_proposer: Option<&Address>,
    changed_keys: &mut BTreeSet<Key>,
) -> Result<()>
where
    CA: 'static + WasmCacheAccess + Sync,
    D: 'static + DB + for<'iter> DBIter<'iter> + Sync,
    H: 'static + StorageHasher + Sync,
    WLS: WriteLogAndStorage<D = D, H = H> + StorageRead,
{
    let ShellParams {
        tx_gas_meter: _,
        wl_storage,
        vp_wasm_cache,
        tx_wasm_cache,
    } = shell_params;

    // Unshield funds if requested
    if let Some(transaction) = masp_transaction {
        // The unshielding tx does not charge gas, instantiate a
        // custom gas meter for this step
        let mut tx_gas_meter =
            TxGasMeter::new(GasLimit::from(
                wl_storage
                    .read::<u64>(
                        &namada_parameters::storage::get_fee_unshielding_gas_limit_key(
                        ),
                    )
                    .expect("Error reading the storage")
                    .expect("Missing fee unshielding gas limit in storage")),
            );

        // If it fails, do not return early
        // from this function but try to take the funds from the unshielded
        // balance
        match wrapper.generate_fee_unshielding(
            get_transfer_hash_from_storage(*wl_storage),
            Some(TX_TRANSFER_WASM.to_string()),
            transaction,
        ) {
            Ok(fee_unshielding_tx) => {
                // NOTE: A clean tx write log must be provided to this call
                // for a correct vp validation. Block write log, instead,
                // should contain any prior changes (if any)
                wl_storage.write_log_mut().precommit_tx();
                match apply_wasm_tx(
                    fee_unshielding_tx,
                    &TxIndex::default(),
                    ShellParams {
                        tx_gas_meter: &mut tx_gas_meter,
                        wl_storage: *wl_storage,
                        vp_wasm_cache,
                        tx_wasm_cache,
                    },
                ) {
                    Ok(result) => {
                        // NOTE: do not commit yet cause this could be
                        // exploited to get free unshieldings
                        if !result.is_accepted() {
                            wl_storage.write_log_mut().drop_tx_keep_precommit();
                            tracing::error!(
                                "The unshielding tx is invalid, some VPs \
                                 rejected it: {:#?}",
                                result.vps_result.rejected_vps
                            );
                        }
                    }
                    Err(e) => {
                        wl_storage.write_log_mut().drop_tx_keep_precommit();
                        tracing::error!(
                            "The unshielding tx is invalid, wasm run failed: \
                             {}",
                            e
                        );
                    }
                }
            }
            Err(e) => tracing::error!("{}", e),
        }
    }

    // Charge or check fees
    match block_proposer {
        Some(proposer) => transfer_fee(*wl_storage, proposer, wrapper)?,
        None => check_fees(*wl_storage, wrapper)?,
    }

    changed_keys.extend(wl_storage.write_log_mut().get_keys_with_precommit());

    // Commit tx write log even in case of subsequent errors
    wl_storage.write_log_mut().commit_tx();

    Ok(())
}

/// Perform the actual transfer of fess from the fee payer to the block
/// proposer.
pub fn transfer_fee<WLS>(
    wl_storage: &mut WLS,
    block_proposer: &Address,
    wrapper: &WrapperTx,
) -> Result<()>
where
    WLS: WriteLogAndStorage + StorageRead,
{
    let balance = crate::token::read_balance(
        wl_storage,
        &wrapper.fee.token,
        &wrapper.fee_payer(),
    )
    .unwrap();

    match wrapper.get_tx_fee() {
        Ok(fees) => {
            let fees = crate::token::denom_to_amount(
                fees,
                &wrapper.fee.token,
                wl_storage,
            )
            .map_err(|e| Error::FeeError(e.to_string()))?;
            if balance.checked_sub(fees).is_some() {
                token_transfer(
                    wl_storage,
                    &wrapper.fee.token,
                    &wrapper.fee_payer(),
                    block_proposer,
                    fees,
                )
                .map_err(|e| Error::FeeError(e.to_string()))
            } else {
                // Balance was insufficient for fee payment, move all the
                // available funds in the transparent balance of
                // the fee payer. This shouldn't happen as it should be
                // prevented from mempool.
                tracing::error!(
                    "Transfer of tx fee cannot be applied to due to \
                     insufficient funds. Falling back to transferring the \
                     available balance which is less than the fee. This \
                     shouldn't happen."
                );
                token_transfer(
                    wl_storage,
                    &wrapper.fee.token,
                    &wrapper.fee_payer(),
                    block_proposer,
                    balance,
                )
                .map_err(|e| Error::FeeError(e.to_string()))?;

                Err(Error::FeeError(
                    "Transparent balance of wrapper's signer was insufficient \
                     to pay fee. All the available transparent funds have \
                     been moved to the block proposer"
                        .to_string(),
                ))
            }
        }
        Err(e) => {
            // Fee overflow. This shouldn't happen as it should be prevented
            // from mempool.
            tracing::error!(
                "Transfer of tx fee cannot be applied to due to fee overflow. \
                 This shouldn't happen."
            );

            Err(Error::FeeError(format!("{}", e)))
        }
    }
}

/// Transfer `token` from `src` to `dest`. Returns an `Err` if `src` has
/// insufficient balance or if the transfer the `dest` would overflow (This can
/// only happen if the total supply doesn't fit in `token::Amount`). Contrary to
/// `crate::token::transfer` this function updates the tx write log and
/// not the block write log.
fn token_transfer<WLS>(
    wl_storage: &mut WLS,
    token: &Address,
    src: &Address,
    dest: &Address,
    amount: Amount,
) -> Result<()>
where
    WLS: WriteLogAndStorage + StorageRead,
{
    let src_key = crate::token::storage_key::balance_key(token, src);
    let src_balance = crate::token::read_balance(wl_storage, token, src)
        .expect("Token balance read in protocol must not fail");
    match src_balance.checked_sub(amount) {
        Some(new_src_balance) => {
            if src == dest {
                return Ok(());
            }
            let dest_key = crate::token::storage_key::balance_key(token, dest);
            let dest_balance =
                crate::token::read_balance(wl_storage, token, dest)
                    .expect("Token balance read in protocol must not fail");
            match dest_balance.checked_add(amount) {
                Some(new_dest_balance) => {
                    wl_storage
                        .write_log_mut()
                        .write(&src_key, new_src_balance.serialize_to_vec())
                        .map_err(|e| Error::FeeError(e.to_string()))?;
                    match wl_storage
                        .write_log_mut()
                        .write(&dest_key, new_dest_balance.serialize_to_vec())
                    {
                        Ok(_) => Ok(()),
                        Err(e) => Err(Error::FeeError(e.to_string())),
                    }
                }
                None => Err(Error::FeeError(
                    "The transfer would overflow destination balance"
                        .to_string(),
                )),
            }
        }
        None => Err(Error::FeeError("Insufficient source balance".to_string())),
    }
}

/// Check if the fee payer has enough transparent balance to pay fees
pub fn check_fees<WLS>(wl_storage: &WLS, wrapper: &WrapperTx) -> Result<()>
where
    WLS: WriteLogAndStorage + StorageRead,
{
    let balance = crate::token::read_balance(
        wl_storage,
        &wrapper.fee.token,
        &wrapper.fee_payer(),
    )
    .unwrap();

    let fees = wrapper
        .get_tx_fee()
        .map_err(|e| Error::FeeError(e.to_string()))?;

    let fees =
        crate::token::denom_to_amount(fees, &wrapper.fee.token, wl_storage)
            .map_err(|e| Error::FeeError(e.to_string()))?;
    if balance.checked_sub(fees).is_some() {
        Ok(())
    } else {
        Err(Error::FeeError(
            "Insufficient transparent balance to pay fees".to_string(),
        ))
    }
}

/// Apply a transaction going via the wasm environment. Gas will be metered and
/// validity predicates will be triggered in the normal way.
pub fn apply_wasm_tx<'a, D, H, CA, WLS>(
    tx: Tx,
    tx_index: &TxIndex,
    shell_params: ShellParams<'a, CA, WLS>,
) -> Result<TxResult>
where
    CA: 'static + WasmCacheAccess + Sync,
    D: 'static + DB + for<'iter> DBIter<'iter> + Sync,
    H: 'static + StorageHasher + Sync,
    WLS: WriteLogAndStorage<D = D, H = H> + StorageRead,
{
    let ShellParams {
        tx_gas_meter,
        wl_storage,
        vp_wasm_cache,
        tx_wasm_cache,
    } = shell_params;

    let (tx_gas_meter, storage, write_log, vp_wasm_cache, tx_wasm_cache) = {
        let (write_log, storage) = wl_storage.split_borrow();
        (
            tx_gas_meter,
            storage,
            write_log,
            vp_wasm_cache,
            tx_wasm_cache,
        )
    };

    let tx_hash = tx.raw_header_hash();
    if let Some(true) = write_log.has_replay_protection_entry(&tx_hash) {
        // If the same transaction has already been applied in this block, skip
        // execution and return
        return Err(Error::ReplayAttempt(tx_hash));
    }

    let verifiers = execute_tx(
        &tx,
        tx_index,
        storage,
        tx_gas_meter,
        write_log,
        vp_wasm_cache,
        tx_wasm_cache,
    )?;

    let vps_result = check_vps(CheckVps {
        tx: &tx,
        tx_index,
        storage,
        tx_gas_meter,
        write_log,
        verifiers_from_tx: &verifiers,
        vp_wasm_cache,
    })?;

    let gas_used = tx_gas_meter.get_tx_consumed_gas();
    let initialized_accounts = write_log.get_initialized_accounts();
    let changed_keys = write_log.get_keys();
    let ibc_events = write_log.take_ibc_events();

    Ok(TxResult {
        gas_used,
        changed_keys,
        vps_result,
        initialized_accounts,
        ibc_events,
        eth_bridge_events: BTreeSet::default(),
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
    use namada_vote_ext::{ethereum_events, validator_set_update};

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
        EthereumTxData::EthEventsVext(
            namada_vote_ext::ethereum_events::SignedVext(ext),
        ) => {
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
#[allow(clippy::too_many_arguments)]
fn execute_tx<D, H, CA>(
    tx: &Tx,
    tx_index: &TxIndex,
    storage: &State<D, H>,
    tx_gas_meter: &mut TxGasMeter,
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
        tx_index,
        tx,
        vp_wasm_cache,
        tx_wasm_cache,
    )
    .map_err(|err| match err {
        wasm::run::Error::GasError(msg) => Error::GasError(msg),
        wasm::run::Error::MissingSection(msg) => Error::MissingSection(msg),
        _ => Error::TxRunnerError(err),
    })
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
    storage: &'a State<D, H>,
    tx_gas_meter: &'a mut TxGasMeter,
    write_log: &'a WriteLog,
    verifiers_from_tx: &'a BTreeSet<Address>,
    vp_wasm_cache: &'a mut VpCache<CA>,
}

/// Check the acceptance of a transaction by validity predicates
fn check_vps<D, H, CA>(
    CheckVps {
        tx,
        tx_index,
        storage,
        tx_gas_meter,
        write_log,
        verifiers_from_tx,
        vp_wasm_cache,
    }: CheckVps<'_, D, H, CA>,
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
        tx_gas_meter,
        vp_wasm_cache,
    )?;
    tracing::debug!("Total VPs gas cost {:?}", vps_result.gas_used);

    tx_gas_meter
        .add_vps_gas(&vps_result.gas_used)
        .map_err(|err| Error::GasError(err.to_string()))?;

    Ok(vps_result)
}

/// Execute verifiers' validity predicates
#[allow(clippy::too_many_arguments)]
fn execute_vps<D, H, CA>(
    verifiers: BTreeSet<Address>,
    keys_changed: BTreeSet<storage::Key>,
    tx: &Tx,
    tx_index: &TxIndex,
    storage: &State<D, H>,
    write_log: &WriteLog,
    tx_gas_meter: &TxGasMeter,
    vp_wasm_cache: &mut VpCache<CA>,
) -> Result<VpsResult>
where
    D: 'static + DB + for<'iter> DBIter<'iter> + Sync,
    H: 'static + StorageHasher + Sync,
    CA: 'static + WasmCacheAccess + Sync,
{
    let vps_result = verifiers
        .par_iter()
        .try_fold(VpsResult::default, |mut result, addr| {
            let mut gas_meter = VpGasMeter::new_from_tx_meter(tx_gas_meter);
            let accept = match &addr {
                Address::Implicit(_) | Address::Established(_) => {
                    let (vp_hash, gas) = storage
                        .validity_predicate(addr)
                        .map_err(Error::StorageError)?;
                    gas_meter
                        .consume(gas)
                        .map_err(|err| Error::GasError(err.to_string()))?;
                    let Some(vp_code_hash) = vp_hash else {
                        return Err(Error::MissingAddress(addr.clone()));
                    };

                    // NOTE: because of the whitelisted gas and the gas
                    // metering for the exposed vm
                    // env functions,    the first
                    // signature verification (if any) is accounted
                    // twice
                    wasm::run::vp(
                        vp_code_hash,
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
                    .map_err(|err| match err {
                        wasm::run::Error::GasError(msg) => Error::GasError(msg),
                        wasm::run::Error::InvalidTxSignature => {
                            Error::InvalidTxSignature
                        }
                        _ => Error::VpRunnerError(err),
                    })
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

                    let (accepted, sentinel): (Result<bool>, _) =
                        match internal_addr {
                            InternalAddress::PoS => {
                                let pos = PosVP { ctx };
                                let verifiers_addr_ref = &verifiers;
                                let pos_ref = &pos;
                                // TODO this is temporarily ran in a new thread
                                // to
                                // avoid crashing the ledger (required
                                // `UnwindSafe`
                                // and `RefUnwindSafe` in
                                // shared/src/ledger/pos/vp.rs)
                                let keys_changed_ref = &keys_changed;
                                let result = pos_ref
                                    .validate_tx(
                                        tx,
                                        keys_changed_ref,
                                        verifiers_addr_ref,
                                    )
                                    .map_err(Error::PosNativeVpError);
                                // Take the gas meter and sentinel
                                // back
                                // out of the context
                                gas_meter = pos.ctx.gas_meter.into_inner();
                                (result, pos.ctx.sentinel.into_inner())
                            }
                            InternalAddress::Ibc => {
                                let ibc = Ibc { ctx };
                                let result = ibc
                                    .validate_tx(tx, &keys_changed, &verifiers)
                                    .map_err(Error::IbcNativeVpError);
                                // Take the gas meter and the sentinel
                                // back
                                // out of the context
                                gas_meter = ibc.ctx.gas_meter.into_inner();
                                (result, ibc.ctx.sentinel.into_inner())
                            }
                            InternalAddress::Parameters => {
                                let parameters = ParametersVp { ctx };
                                let result = parameters
                                    .validate_tx(tx, &keys_changed, &verifiers)
                                    .map_err(Error::ParametersNativeVpError);
                                // Take the gas meter and the sentinel
                                // back
                                // out of the context
                                gas_meter =
                                    parameters.ctx.gas_meter.into_inner();
                                (result, parameters.ctx.sentinel.into_inner())
                            }
                            InternalAddress::PosSlashPool => {
                                // Take the gas meter and the sentinel
                                // back
                                // out of the context
                                gas_meter = ctx.gas_meter.into_inner();
                                (
                                    Err(Error::AccessForbidden(
                                        (*internal_addr).clone(),
                                    )),
                                    ctx.sentinel.into_inner(),
                                )
                            }
                            InternalAddress::Governance => {
                                let governance = GovernanceVp { ctx };
                                let result = governance
                                    .validate_tx(tx, &keys_changed, &verifiers)
                                    .map_err(Error::GovernanceNativeVpError);
                                // Take the gas meter and the sentinel
                                // back
                                // out of the context
                                gas_meter =
                                    governance.ctx.gas_meter.into_inner();
                                (result, governance.ctx.sentinel.into_inner())
                            }
                            InternalAddress::Multitoken => {
                                let multitoken = MultitokenVp { ctx };
                                let result = multitoken
                                    .validate_tx(tx, &keys_changed, &verifiers)
                                    .map_err(Error::MultitokenNativeVpError);
                                // Take the gas meter and the sentinel
                                // back
                                // out of the context
                                gas_meter =
                                    multitoken.ctx.gas_meter.into_inner();
                                (result, multitoken.ctx.sentinel.into_inner())
                            }
                            InternalAddress::EthBridge => {
                                let bridge = EthBridge { ctx };
                                let result = bridge
                                    .validate_tx(tx, &keys_changed, &verifiers)
                                    .map_err(Error::EthBridgeNativeVpError);
                                // Take the gas meter and the sentinel
                                // back
                                // out of the context
                                gas_meter = bridge.ctx.gas_meter.into_inner();
                                (result, bridge.ctx.sentinel.into_inner())
                            }
                            InternalAddress::EthBridgePool => {
                                let bridge_pool = BridgePoolVp { ctx };
                                let result = bridge_pool
                                    .validate_tx(tx, &keys_changed, &verifiers)
                                    .map_err(Error::BridgePoolNativeVpError);
                                // Take the gas meter and the sentinel
                                // back
                                // out of the context
                                gas_meter =
                                    bridge_pool.ctx.gas_meter.into_inner();
                                (result, bridge_pool.ctx.sentinel.into_inner())
                            }
                            InternalAddress::Pgf => {
                                let pgf_vp = PgfVp { ctx };
                                let result = pgf_vp
                                    .validate_tx(tx, &keys_changed, &verifiers)
                                    .map_err(Error::PgfNativeVpError);
                                // Take the gas meter and the sentinel
                                // back
                                // out of the context
                                gas_meter = pgf_vp.ctx.gas_meter.into_inner();
                                (result, pgf_vp.ctx.sentinel.into_inner())
                            }
                            InternalAddress::Nut(_) => {
                                let non_usable_tokens = NonUsableTokens { ctx };
                                let result = non_usable_tokens
                                    .validate_tx(tx, &keys_changed, &verifiers)
                                    .map_err(Error::NutNativeVpError);
                                // Take the gas meter and the sentinel
                                // back
                                // out of the context
                                gas_meter = non_usable_tokens
                                    .ctx
                                    .gas_meter
                                    .into_inner();
                                (
                                    result,
                                    non_usable_tokens.ctx.sentinel.into_inner(),
                                )
                            }
                            InternalAddress::IbcToken(_)
                            | InternalAddress::Erc20(_) => {
                                // The address should be a part of a multitoken
                                // key
                                // Take the gas meter and the sentinel
                                // back
                                // out of the context
                                gas_meter = ctx.gas_meter.into_inner();
                                (
                                    Ok(verifiers.contains(&Address::Internal(
                                        InternalAddress::Multitoken,
                                    ))),
                                    ctx.sentinel.into_inner(),
                                )
                            }
                            InternalAddress::Masp => {
                                let masp = MaspVp { ctx };
                                let result = masp
                                    .validate_tx(tx, &keys_changed, &verifiers)
                                    .map_err(Error::MaspNativeVpError);
                                // Take the gas meter and the sentinel back out
                                // of the context
                                gas_meter = masp.ctx.gas_meter.into_inner();
                                (result, masp.ctx.sentinel.into_inner())
                            }
                        };

                    accepted.map_err(|err| {
                        // No need to check invalid sig because internal vps
                        // don't check the signature
                        if sentinel.is_out_of_gas() {
                            Error::GasError(err.to_string())
                        } else {
                            err
                        }
                    })
                }
            };

            match accept {
                Ok(accepted) => {
                    if accepted {
                        result.accepted_vps.insert(addr.clone());
                    } else {
                        result.rejected_vps.insert(addr.clone());
                    }
                }
                Err(err) => match err {
                    // Execution of VPs can (and must) be short-circuited
                    // only in case of a gas overflow to prevent the
                    // transaction from consuming resources that have not
                    // been acquired in the corresponding wrapper tx. For
                    // all the other errors we keep evaluating the vps. This
                    // allows to display a consistent VpsResult across all
                    // nodes and find any invalid signatures
                    Error::GasError(_) => {
                        return Err(err);
                    }
                    Error::InvalidTxSignature => {
                        result.invalid_sig = true;
                        result.rejected_vps.insert(addr.clone());
                        // Don't push the error since this is just a flag error
                    }
                    _ => {
                        result.rejected_vps.insert(addr.clone());
                        result.errors.push((addr.clone(), err.to_string()));
                    }
                },
            }

            result
                .gas_used
                .set(gas_meter)
                .map_err(|err| Error::GasError(err.to_string()))?;

            Ok(result)
        })
        .try_reduce(VpsResult::default, |a, b| {
            merge_vp_results(a, b, tx_gas_meter)
        })?;

    Ok(vps_result)
}

/// Merge VP results from parallel runs
fn merge_vp_results(
    a: VpsResult,
    mut b: VpsResult,
    tx_gas_meter: &TxGasMeter,
) -> Result<VpsResult> {
    let mut accepted_vps = a.accepted_vps;
    let mut rejected_vps = a.rejected_vps;
    accepted_vps.extend(b.accepted_vps);
    rejected_vps.extend(b.rejected_vps);
    let mut errors = a.errors;
    errors.append(&mut b.errors);
    let invalid_sig = a.invalid_sig || b.invalid_sig;
    let mut gas_used = a.gas_used;

    gas_used
        .merge(b.gas_used, tx_gas_meter)
        .map_err(|err| Error::GasError(err.to_string()))?;

    Ok(VpsResult {
        accepted_vps,
        rejected_vps,
        gas_used,
        errors,
        invalid_sig,
    })
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use borsh::BorshDeserialize;
    use eyre::Result;
    use namada_core::types::ethereum_events::testing::DAI_ERC20_ETH_ADDRESS;
    use namada_core::types::ethereum_events::{
        EthereumEvent, TransferToNamada,
    };
    use namada_core::types::keccak::keccak_hash;
    use namada_core::types::storage::BlockHeight;
    use namada_core::types::voting_power::FractionalVotingPower;
    use namada_core::types::{address, key};
    use namada_ethereum_bridge::protocol::transactions::votes::{
        EpochedVotingPower, Votes,
    };
    use namada_ethereum_bridge::storage::eth_bridge_queries::EthBridgeQueries;
    use namada_ethereum_bridge::storage::proof::EthereumProof;
    use namada_ethereum_bridge::storage::{vote_tallies, vp};
    use namada_ethereum_bridge::test_utils;
    use namada_state::StorageRead;
    use namada_token::Amount;
    use namada_tx::{SignableEthMessage, Signed};
    use namada_vote_ext::bridge_pool_roots::BridgePoolRootVext;
    use namada_vote_ext::ethereum_events::EthereumEventsVext;

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
        let validator_a_stake = Amount::native_whole(100);
        let validator_b_stake = Amount::native_whole(100);
        let total_stake = validator_a_stake + validator_b_stake;
        let (mut wl_storage, _) = test_utils::setup_storage_with_validators(
            HashMap::from_iter(vec![
                (validator_a.clone(), validator_a_stake),
                (validator_b, validator_b_stake),
            ]),
        );
        let event = EthereumEvent::TransfersToNamada {
            nonce: 0.into(),
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
        let tx = EthereumTxData::EthEventsVext(
            namada_vote_ext::ethereum_events::SignedVext(signed),
        );

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
        let expected = EpochedVotingPower::from([(
            0.into(),
            FractionalVotingPower::HALF * total_stake,
        )]);
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
        let validator_a_stake = Amount::native_whole(100);
        let validator_b_stake = Amount::native_whole(100);
        let total_stake = validator_a_stake + validator_b_stake;
        let (mut wl_storage, keys) = test_utils::setup_storage_with_validators(
            HashMap::from_iter(vec![
                (validator_a.clone(), validator_a_stake),
                (validator_b, validator_b_stake),
            ]),
        );
        vp::bridge_pool::init_storage(&mut wl_storage);

        let root = wl_storage.ethbridge_queries().get_bridge_pool_root();
        let nonce = wl_storage.ethbridge_queries().get_bridge_pool_nonce();
        test_utils::commit_bridge_pool_root_at_height(
            &mut wl_storage,
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

        let bp_root_keys = vote_tallies::Keys::from((
            &vote_tallies::BridgePoolRoot(EthereumProof::new((root, nonce))),
            100.into(),
        ));
        let root_seen_by_bytes =
            wl_storage.read_bytes(&bp_root_keys.seen_by())?;
        assert_eq!(
            Votes::try_from_slice(root_seen_by_bytes.as_ref().unwrap())?,
            Votes::from([(validator_a, BlockHeight(100))])
        );
        // the vote should have only be applied once
        let voting_power: EpochedVotingPower =
            wl_storage.read(&bp_root_keys.voting_power())?.unwrap();
        let expected = EpochedVotingPower::from([(
            0.into(),
            FractionalVotingPower::HALF * total_stake,
        )]);
        assert_eq!(voting_power, expected);

        Ok(())
    }
}
