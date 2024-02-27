//! The ledger's protocol
use std::cell::RefCell;
use std::collections::BTreeSet;
use std::fmt::Debug;

use borsh_ext::BorshSerializeExt;
use eyre::{eyre, WrapErr};
use masp_primitives::transaction::Transaction;
use namada_core::hash::Hash;
use namada_core::storage::Key;
use namada_core::validity_predicate::VpSentinel;
use namada_gas::TxGasMeter;
use namada_sdk::tx::TX_TRANSFER_WASM;
use namada_state::StorageWrite;
use namada_tx::data::protocol::ProtocolTxType;
use namada_tx::data::{
    DecryptedTx, GasLimit, TxResult, TxType, VpsResult, WrapperTx,
};
use namada_tx::{Section, Tx};
use namada_vote_ext::EthereumTxData;
use rayon::iter::{IntoParallelRefIterator, ParallelIterator};
use thiserror::Error;

use crate::address::{Address, InternalAddress};
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
use crate::state::{DBIter, State, StorageHasher, StorageRead, WlState, DB};
use crate::storage;
use crate::storage::TxIndex;
use crate::token::Amount;
use crate::vm::wasm::{TxCache, VpCache};
use crate::vm::{self, wasm, WasmCacheAccess};

#[allow(missing_docs)]
#[derive(Error, Debug)]
pub enum Error {
    #[error("Missing tx section: {0}")]
    MissingSection(String),
    #[error("State error: {0}")]
    StateError(namada_state::Error),
    #[error("Storage error: {0}")]
    StorageError(namada_state::StorageError),
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
    #[error("Tx is not allowed in allowlist parameter.")]
    DisallowedTx,
}

/// Shell parameters for running wasm transactions.
#[allow(missing_docs)]
#[derive(Debug)]
pub struct ShellParams<'a, S, D, H, CA>
where
    S: State<D = D, H = H> + Sync,
    D: 'static + DB + for<'iter> DBIter<'iter> + Sync,
    H: 'static + StorageHasher + Sync,
    CA: 'static + WasmCacheAccess + Sync,
{
    pub tx_gas_meter: &'a RefCell<TxGasMeter>,
    pub state: &'a mut S,
    pub vp_wasm_cache: &'a mut VpCache<CA>,
    pub tx_wasm_cache: &'a mut TxCache<CA>,
}

impl<'a, S, D, H, CA> ShellParams<'a, S, D, H, CA>
where
    S: State<D = D, H = H> + Sync,
    D: 'static + DB + for<'iter> DBIter<'iter> + Sync,
    H: 'static + StorageHasher + Sync,
    CA: 'static + WasmCacheAccess + Sync,
{
    /// Create a new instance of `ShellParams`
    pub fn new(
        tx_gas_meter: &'a RefCell<TxGasMeter>,
        state: &'a mut S,
        vp_wasm_cache: &'a mut VpCache<CA>,
        tx_wasm_cache: &'a mut TxCache<CA>,
    ) -> Self {
        Self {
            tx_gas_meter,
            state,
            vp_wasm_cache,
            tx_wasm_cache,
        }
    }
}

/// Result of applying a transaction
pub type Result<T> = std::result::Result<T, Error>;

/// Arguments needed to execute a Wrapper transaction
pub struct WrapperArgs<'a> {
    /// The block proposer for the current block
    pub block_proposer: &'a Address,
    /// Flag if the wrapper transaction committed the fee unshielding operation
    pub is_committed_fee_unshield: bool,
}

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
    tx_gas_meter: &'a RefCell<TxGasMeter>,
    state: &'a mut WlState<D, H>,
    vp_wasm_cache: &'a mut VpCache<CA>,
    tx_wasm_cache: &'a mut TxCache<CA>,
    wrapper_args: Option<&mut WrapperArgs>,
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
                state,
                vp_wasm_cache,
                tx_wasm_cache,
            },
        ),
        TxType::Protocol(protocol_tx) => {
            apply_protocol_tx(protocol_tx.tx, tx.data(), state)
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
                    state,
                    vp_wasm_cache,
                    tx_wasm_cache,
                },
                wrapper_args,
            )?;
            Ok(TxResult {
                gas_used: tx_gas_meter.borrow().get_tx_consumed_gas(),
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
pub(crate) fn apply_wrapper_tx<S, D, H, CA>(
    tx: Tx,
    wrapper: &WrapperTx,
    fee_unshield_transaction: Option<Transaction>,
    tx_bytes: &[u8],
    mut shell_params: ShellParams<'_, S, D, H, CA>,
    wrapper_args: Option<&mut WrapperArgs>,
) -> Result<BTreeSet<Key>>
where
    S: State<D = D, H = H> + Sync,
    D: 'static + DB + for<'iter> DBIter<'iter> + Sync,
    H: 'static + StorageHasher + Sync,
    CA: 'static + WasmCacheAccess + Sync,
{
    let mut changed_keys = BTreeSet::default();

    // Write wrapper tx hash to storage
    shell_params
        .state
        .write_log_mut()
        .write_tx_hash(tx.header_hash())
        .expect("Error while writing tx hash to storage");

    // Charge fee before performing any fallible operations
    charge_fee(
        wrapper,
        fee_unshield_transaction,
        &mut shell_params,
        &mut changed_keys,
        wrapper_args,
    )?;

    // Account for gas
    shell_params
        .tx_gas_meter
        .borrow_mut()
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
fn charge_fee<'a, S, D, H, CA>(
    wrapper: &WrapperTx,
    masp_transaction: Option<Transaction>,
    shell_params: &mut ShellParams<'a, S, D, H, CA>,
    changed_keys: &mut BTreeSet<Key>,
    wrapper_args: Option<&mut WrapperArgs>,
) -> Result<()>
where
    S: State<D = D, H = H> + Sync,
    D: 'static + DB + for<'iter> DBIter<'iter> + Sync,
    H: 'static + StorageHasher + Sync,
    CA: 'static + WasmCacheAccess + Sync,
{
    let ShellParams {
        tx_gas_meter: _,
        state,
        vp_wasm_cache,
        tx_wasm_cache,
    } = shell_params;

    // Unshield funds if requested
    let requires_fee_unshield = if let Some(transaction) = masp_transaction {
        // The unshielding tx does not charge gas, instantiate a
        // custom gas meter for this step
        let  tx_gas_meter =
            RefCell::new(TxGasMeter::new(GasLimit::from(
                state
                    .read::<u64>(
                        &namada_parameters::storage::get_fee_unshielding_gas_limit_key(
                        ),
                    )
                    .expect("Error reading the storage")
                    .expect("Missing fee unshielding gas limit in storage")),
            ));

        // If it fails, do not return early
        // from this function but try to take the funds from the unshielded
        // balance
        match wrapper.generate_fee_unshielding(
            get_transfer_hash_from_storage(*state),
            Some(TX_TRANSFER_WASM.to_string()),
            transaction,
        ) {
            Ok(fee_unshielding_tx) => {
                // NOTE: A clean tx write log must be provided to this call
                // for a correct vp validation. Block write log, instead,
                // should contain any prior changes (if any)
                state.write_log_mut().precommit_tx();
                match apply_wasm_tx(
                    fee_unshielding_tx,
                    &TxIndex::default(),
                    ShellParams {
                        tx_gas_meter: &tx_gas_meter,
                        state: *state,
                        vp_wasm_cache,
                        tx_wasm_cache,
                    },
                ) {
                    Ok(result) => {
                        // NOTE: do not commit yet cause this could be
                        // exploited to get free unshieldings
                        if !result.is_accepted() {
                            state.write_log_mut().drop_tx_keep_precommit();
                            tracing::error!(
                                "The unshielding tx is invalid, some VPs \
                                 rejected it: {:#?}",
                                result.vps_result.rejected_vps
                            );
                        }
                    }
                    Err(e) => {
                        state.write_log_mut().drop_tx_keep_precommit();
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

        true
    } else {
        false
    };

    // Charge or check fees
    match wrapper_args {
        Some(WrapperArgs {
            block_proposer,
            is_committed_fee_unshield: _,
        }) => transfer_fee(*state, block_proposer, wrapper)?,
        None => check_fees(*state, wrapper)?,
    }

    changed_keys.extend(state.write_log_mut().get_keys_with_precommit());

    // Commit tx write log even in case of subsequent errors
    state.write_log_mut().commit_tx();
    // Update the flag only after the fee payment has been committed
    if let Some(args) = wrapper_args {
        args.is_committed_fee_unshield = requires_fee_unshield;
    }

    Ok(())
}

/// Perform the actual transfer of fess from the fee payer to the block
/// proposer.
pub fn transfer_fee<S>(
    state: &mut S,
    block_proposer: &Address,
    wrapper: &WrapperTx,
) -> Result<()>
where
    S: State + StorageRead + StorageWrite,
{
    let balance = crate::token::read_balance(
        state,
        &wrapper.fee.token,
        &wrapper.fee_payer(),
    )
    .unwrap();

    match wrapper.get_tx_fee() {
        Ok(fees) => {
            let fees =
                crate::token::denom_to_amount(fees, &wrapper.fee.token, state)
                    .map_err(|e| Error::FeeError(e.to_string()))?;
            if balance.checked_sub(fees).is_some() {
                token_transfer(
                    state,
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
                    state,
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
    state: &mut WLS,
    token: &Address,
    src: &Address,
    dest: &Address,
    amount: Amount,
) -> Result<()>
where
    WLS: State + StorageRead,
{
    let src_key = crate::token::storage_key::balance_key(token, src);
    let src_balance = crate::token::read_balance(state, token, src)
        .expect("Token balance read in protocol must not fail");
    match src_balance.checked_sub(amount) {
        Some(new_src_balance) => {
            if src == dest {
                return Ok(());
            }
            let dest_key = crate::token::storage_key::balance_key(token, dest);
            let dest_balance = crate::token::read_balance(state, token, dest)
                .expect("Token balance read in protocol must not fail");
            match dest_balance.checked_add(amount) {
                Some(new_dest_balance) => {
                    state
                        .write_log_mut()
                        .write(&src_key, new_src_balance.serialize_to_vec())
                        .map_err(|e| Error::FeeError(e.to_string()))?;
                    match state
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
pub fn check_fees<S>(state: &S, wrapper: &WrapperTx) -> Result<()>
where
    S: State + StorageRead,
{
    let balance = crate::token::read_balance(
        state,
        &wrapper.fee.token,
        &wrapper.fee_payer(),
    )
    .unwrap();

    let fees = wrapper
        .get_tx_fee()
        .map_err(|e| Error::FeeError(e.to_string()))?;

    let fees = crate::token::denom_to_amount(fees, &wrapper.fee.token, state)
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
pub fn apply_wasm_tx<'a, S, D, H, CA>(
    tx: Tx,
    tx_index: &TxIndex,
    shell_params: ShellParams<'a, S, D, H, CA>,
) -> Result<TxResult>
where
    S: State<D = D, H = H> + Sync,
    D: 'static + DB + for<'iter> DBIter<'iter> + Sync,
    H: 'static + StorageHasher + Sync,
    CA: 'static + WasmCacheAccess + Sync,
{
    let ShellParams {
        tx_gas_meter,
        state,
        vp_wasm_cache,
        tx_wasm_cache,
    } = shell_params;

    let tx_hash = tx.raw_header_hash();
    if let Some(true) = state.write_log().has_replay_protection_entry(&tx_hash)
    {
        // If the same transaction has already been applied in this block, skip
        // execution and return
        return Err(Error::ReplayAttempt(tx_hash));
    }

    let verifiers = execute_tx(
        &tx,
        tx_index,
        state,
        tx_gas_meter,
        vp_wasm_cache,
        tx_wasm_cache,
    )?;

    let vps_result = check_vps(CheckVps {
        tx: &tx,
        tx_index,
        state,
        tx_gas_meter: &mut tx_gas_meter.borrow_mut(),
        verifiers_from_tx: &verifiers,
        vp_wasm_cache,
    })?;

    let gas_used = tx_gas_meter.borrow().get_tx_consumed_gas();
    let initialized_accounts = state.write_log().get_initialized_accounts();
    let changed_keys = state.write_log().get_keys();
    let ibc_events = state.write_log_mut().take_ibc_events();

    Ok(TxResult {
        gas_used,
        changed_keys,
        vps_result,
        initialized_accounts,
        ibc_events,
        eth_bridge_events: BTreeSet::default(),
    })
}

/// Returns [`Error::DisallowedTx`] when the given tx is inner (decrypted) tx
/// and its code `Hash` is not included in the `tx_allowlist` parameter.
pub fn check_tx_allowed<D, H>(tx: &Tx, state: &WlState<D, H>) -> Result<()>
where
    D: 'static + DB + for<'iter> DBIter<'iter> + Sync,
    H: 'static + StorageHasher + Sync,
{
    if let TxType::Decrypted(DecryptedTx::Decrypted) = tx.header().tx_type {
        if let Some(code_sec) = tx
            .get_section(tx.code_sechash())
            .and_then(|x| Section::code_sec(&x))
        {
            if crate::parameters::is_tx_allowed(state, &code_sec.code.hash())
                .map_err(Error::StorageError)?
            {
                return Ok(());
            }
        }
        return Err(Error::DisallowedTx);
    }
    Ok(())
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
    state: &mut WlState<D, H>,
) -> Result<TxResult>
where
    D: 'static + DB + for<'iter> DBIter<'iter> + Sync,
    H: 'static + StorageHasher + Sync,
{
    use namada_ethereum_bridge::protocol::transactions;
    use namada_vote_ext::{ethereum_events, validator_set_update};

    let Some(data) = data else {
        return Err(Error::ProtocolTxError(eyre!(
            "Protocol tx data must be present"
        )));
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
            transactions::ethereum_events::apply_derived_tx(state, events)
                .map_err(Error::ProtocolTxError)
        }
        EthereumTxData::BridgePoolVext(ext) => {
            transactions::bridge_pool_roots::apply_derived_tx(state, ext.into())
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
                state,
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
fn execute_tx<S, D, H, CA>(
    tx: &Tx,
    tx_index: &TxIndex,
    state: &mut S,
    tx_gas_meter: &RefCell<TxGasMeter>,
    vp_wasm_cache: &mut VpCache<CA>,
    tx_wasm_cache: &mut TxCache<CA>,
) -> Result<BTreeSet<Address>>
where
    S: State<D = D, H = H>,
    D: 'static + DB + for<'iter> DBIter<'iter> + Sync,
    H: 'static + StorageHasher + Sync,
    CA: 'static + WasmCacheAccess + Sync,
{
    wasm::run::tx(
        state,
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
struct CheckVps<'a, S, CA>
where
    S: State,
    CA: 'static + WasmCacheAccess + Sync,
{
    tx: &'a Tx,
    tx_index: &'a TxIndex,
    state: &'a S,
    tx_gas_meter: &'a mut TxGasMeter,
    verifiers_from_tx: &'a BTreeSet<Address>,
    vp_wasm_cache: &'a mut VpCache<CA>,
}

/// Check the acceptance of a transaction by validity predicates
fn check_vps<S, CA>(
    CheckVps {
        tx,
        tx_index,
        state,
        tx_gas_meter,
        verifiers_from_tx,
        vp_wasm_cache,
    }: CheckVps<'_, S, CA>,
) -> Result<VpsResult>
where
    S: State + Sync,
    CA: 'static + WasmCacheAccess + Sync,
{
    let (verifiers, keys_changed) = state
        .write_log()
        .verifiers_and_changed_keys(verifiers_from_tx);

    let vps_result = execute_vps(
        verifiers,
        keys_changed,
        tx,
        tx_index,
        state,
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
fn execute_vps<S, CA>(
    verifiers: BTreeSet<Address>,
    keys_changed: BTreeSet<storage::Key>,
    tx: &Tx,
    tx_index: &TxIndex,
    state: &S,
    tx_gas_meter: &TxGasMeter,
    vp_wasm_cache: &mut VpCache<CA>,
) -> Result<VpsResult>
where
    S: State + Sync,
    CA: 'static + WasmCacheAccess + Sync,
{
    let vps_result = verifiers
        .par_iter()
        .try_fold(VpsResult::default, |mut result, addr| {
            let gas_meter =
                RefCell::new(VpGasMeter::new_from_tx_meter(tx_gas_meter));
            let accept = match &addr {
                Address::Implicit(_) | Address::Established(_) => {
                    let (vp_hash, gas) = state
                        .validity_predicate(addr)
                        .map_err(Error::StateError)?;
                    gas_meter
                        .borrow_mut()
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
                        state,
                        &gas_meter,
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
                    let sentinel = RefCell::new(VpSentinel::default());
                    let ctx = native_vp::Ctx::new(
                        addr,
                        state,
                        tx,
                        tx_index,
                        &gas_meter,
                        &sentinel,
                        &keys_changed,
                        &verifiers,
                        vp_wasm_cache.clone(),
                    );

                    let accepted: Result<bool> = match internal_addr {
                        InternalAddress::PoS => {
                            let pos = PosVP { ctx };
                            pos.validate_tx(tx, &keys_changed, &verifiers)
                                .map_err(Error::PosNativeVpError)
                        }
                        InternalAddress::Ibc => {
                            let ibc = Ibc { ctx };
                            ibc.validate_tx(tx, &keys_changed, &verifiers)
                                .map_err(Error::IbcNativeVpError)
                        }
                        InternalAddress::Parameters => {
                            let parameters = ParametersVp { ctx };
                            parameters
                                .validate_tx(tx, &keys_changed, &verifiers)
                                .map_err(Error::ParametersNativeVpError)
                        }
                        InternalAddress::PosSlashPool => Err(
                            Error::AccessForbidden((*internal_addr).clone()),
                        ),
                        InternalAddress::Governance => {
                            let governance = GovernanceVp { ctx };
                            governance
                                .validate_tx(tx, &keys_changed, &verifiers)
                                .map_err(Error::GovernanceNativeVpError)
                        }
                        InternalAddress::Multitoken => {
                            let multitoken = MultitokenVp { ctx };
                            multitoken
                                .validate_tx(tx, &keys_changed, &verifiers)
                                .map_err(Error::MultitokenNativeVpError)
                        }
                        InternalAddress::EthBridge => {
                            let bridge = EthBridge { ctx };
                            bridge
                                .validate_tx(tx, &keys_changed, &verifiers)
                                .map_err(Error::EthBridgeNativeVpError)
                        }
                        InternalAddress::EthBridgePool => {
                            let bridge_pool = BridgePoolVp { ctx };
                            bridge_pool
                                .validate_tx(tx, &keys_changed, &verifiers)
                                .map_err(Error::BridgePoolNativeVpError)
                        }
                        InternalAddress::Pgf => {
                            let pgf_vp = PgfVp { ctx };
                            pgf_vp
                                .validate_tx(tx, &keys_changed, &verifiers)
                                .map_err(Error::PgfNativeVpError)
                        }
                        InternalAddress::Nut(_) => {
                            let non_usable_tokens = NonUsableTokens { ctx };
                            non_usable_tokens
                                .validate_tx(tx, &keys_changed, &verifiers)
                                .map_err(Error::NutNativeVpError)
                        }
                        InternalAddress::IbcToken(_)
                        | InternalAddress::Erc20(_) => {
                            // The address should be a part of a multitoken
                            // key
                            Ok(verifiers.contains(&Address::Internal(
                                InternalAddress::Multitoken,
                            )))
                        }
                        InternalAddress::Masp => {
                            let masp = MaspVp { ctx };
                            masp.validate_tx(tx, &keys_changed, &verifiers)
                                .map_err(Error::MaspNativeVpError)
                        }
                    };

                    accepted.map_err(|err| {
                        // No need to check invalid sig because internal vps
                        // don't check the signature
                        if sentinel.borrow().is_out_of_gas() {
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
                .set(gas_meter.into_inner())
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
    use namada_core::chain::ChainId;
    use namada_core::ethereum_events::testing::DAI_ERC20_ETH_ADDRESS;
    use namada_core::ethereum_events::{EthereumEvent, TransferToNamada};
    use namada_core::keccak::keccak_hash;
    use namada_core::storage::BlockHeight;
    use namada_core::voting_power::FractionalVotingPower;
    use namada_core::{address, key};
    use namada_ethereum_bridge::protocol::transactions::votes::{
        EpochedVotingPower, Votes,
    };
    use namada_ethereum_bridge::storage::eth_bridge_queries::EthBridgeQueries;
    use namada_ethereum_bridge::storage::proof::EthereumProof;
    use namada_ethereum_bridge::storage::{vote_tallies, vp};
    use namada_ethereum_bridge::test_utils;
    use namada_tx::{SignableEthMessage, Signed};
    use namada_vote_ext::bridge_pool_roots::BridgePoolRootVext;
    use namada_vote_ext::ethereum_events::EthereumEventsVext;

    use super::*;

    fn apply_eth_tx<D, H>(
        tx: EthereumTxData,
        state: &mut WlState<D, H>,
    ) -> Result<TxResult>
    where
        D: 'static + DB + for<'iter> DBIter<'iter> + Sync,
        H: 'static + StorageHasher + Sync,
    {
        let (data, tx) = tx.serialize();
        let tx_result = apply_protocol_tx(tx, Some(data), state)?;
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
        let (mut state, _) = test_utils::setup_storage_with_validators(
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

        apply_eth_tx(tx.clone(), &mut state)?;
        apply_eth_tx(tx, &mut state)?;

        let eth_msg_keys = vote_tallies::Keys::from(&event);
        let seen_by_bytes = state.read_bytes(&eth_msg_keys.seen_by())?;
        let seen_by_bytes = seen_by_bytes.unwrap();
        assert_eq!(
            Votes::try_from_slice(&seen_by_bytes)?,
            Votes::from([(validator_a, BlockHeight(100))])
        );

        // the vote should have only be applied once
        let voting_power: EpochedVotingPower =
            state.read(&eth_msg_keys.voting_power())?.unwrap();
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
        let (mut state, keys) = test_utils::setup_storage_with_validators(
            HashMap::from_iter(vec![
                (validator_a.clone(), validator_a_stake),
                (validator_b, validator_b_stake),
            ]),
        );
        vp::bridge_pool::init_storage(&mut state);

        let root = state.ethbridge_queries().get_bridge_pool_root();
        let nonce = state.ethbridge_queries().get_bridge_pool_nonce();
        test_utils::commit_bridge_pool_root_at_height(
            &mut state,
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
        apply_eth_tx(tx.clone(), &mut state)?;
        apply_eth_tx(tx, &mut state)?;

        let bp_root_keys = vote_tallies::Keys::from((
            &vote_tallies::BridgePoolRoot(EthereumProof::new((root, nonce))),
            100.into(),
        ));
        let root_seen_by_bytes = state.read_bytes(&bp_root_keys.seen_by())?;
        assert_eq!(
            Votes::try_from_slice(root_seen_by_bytes.as_ref().unwrap())?,
            Votes::from([(validator_a, BlockHeight(100))])
        );
        // the vote should have only be applied once
        let voting_power: EpochedVotingPower =
            state.read(&bp_root_keys.voting_power())?.unwrap();
        let expected = EpochedVotingPower::from([(
            0.into(),
            FractionalVotingPower::HALF * total_stake,
        )]);
        assert_eq!(voting_power, expected);

        Ok(())
    }

    #[test]
    fn test_apply_wasm_tx_allowlist() {
        let (mut state, _validators) = test_utils::setup_default_storage();

        let mut tx = Tx::new(ChainId::default(), None);
        tx.update_header(TxType::Decrypted(DecryptedTx::Decrypted));
        // pseudo-random code hash
        let code = vec![1_u8, 2, 3];
        let tx_hash = Hash::sha256(&code);
        tx.set_code(namada_tx::Code::new(code, None));

        // Check that using a disallowed tx leads to an error
        {
            let allowlist = vec![format!("{}-bad", tx_hash)];
            crate::parameters::update_tx_allowlist_parameter(
                &mut state, allowlist,
            )
            .unwrap();
            state.commit_tx();

            let result = check_tx_allowed(&tx, &state);
            assert_matches!(result.unwrap_err(), Error::DisallowedTx);
        }

        // Check that using an allowed tx doesn't lead to `Error::DisallowedTx`
        {
            let allowlist = vec![tx_hash.to_string()];
            crate::parameters::update_tx_allowlist_parameter(
                &mut state, allowlist,
            )
            .unwrap();
            state.commit_tx();

            let result = check_tx_allowed(&tx, &state);
            if let Err(result) = result {
                assert!(!matches!(result, Error::DisallowedTx));
            }
        }
    }
}
