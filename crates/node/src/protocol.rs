//! The ledger's protocol
use std::cell::RefCell;
use std::collections::BTreeSet;
use std::fmt::Debug;

use either::Either;
use eyre::{eyre, WrapErr};
use namada_core::booleans::BoolResultUnitExt;
use namada_core::hash::Hash;
use namada_core::ibc::{IbcTxDataHash, IbcTxDataRefs};
use namada_core::masp::{MaspTxRefs, TxId};
use namada_events::extend::{
    ComposeEvent, Height as HeightAttr, TxHash as TxHashAttr, UserAccount,
};
use namada_events::EventLevel;
use namada_gas::TxGasMeter;
use namada_parameters::get_gas_scale;
use namada_state::TxWrites;
use namada_token::event::{TokenEvent, TokenOperation};
use namada_token::utils::is_masp_transfer;
use namada_tx::action::{is_ibc_shielding_transfer, Read};
use namada_tx::data::protocol::{ProtocolTx, ProtocolTxType};
use namada_tx::data::{
    BatchedTxResult, ExtendedTxResult, TxResult, VpStatusFlags, VpsResult,
    WrapperTx,
};
use namada_tx::{BatchedTxRef, Tx, TxCommitments};
use namada_vote_ext::EthereumTxData;
use rayon::iter::{IntoParallelRefIterator, ParallelIterator};
use smooth_operator::checked;
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
    #[error("No inner transactions were found")]
    MissingInnerTxs,
    #[error("Missing tx section: {0}")]
    MissingSection(String),
    #[error("State error: {0}")]
    StateError(namada_state::Error),
    #[error("Storage error: {0}")]
    StorageError(namada_state::StorageError),
    #[error("Wrapper tx runner error: {0}")]
    WrapperRunnerError(String),
    #[error("Transaction runner error: {0}")]
    TxRunnerError(vm::wasm::run::Error),
    #[error("{0:?}")]
    ProtocolTxError(#[from] eyre::Error),
    #[error("The atomic batch failed at inner transaction {0}")]
    FailingAtomicBatch(Hash),
    #[error("Gas error: {0}")]
    GasError(String),
    #[error("Error while processing transaction's fees: {0}")]
    FeeError(String),
    #[error("Invalid transaction section signature: {0}")]
    InvalidSectionSignature(String),
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
    #[error("Multitoken native VP: {0}")]
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

impl Error {
    /// Determine if the error originates from an invalid transaction
    /// section signature. This is required for replay protection.
    const fn invalid_section_signature_flag(&self) -> VpStatusFlags {
        if matches!(self, Self::InvalidSectionSignature(_)) {
            VpStatusFlags::INVALID_SIGNATURE
        } else {
            VpStatusFlags::empty()
        }
    }
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

/// The result of a call to [`dispatch_tx`]
pub struct DispatchError {
    /// The result of the function call
    pub error: Error,
    /// The extended tx result produced. It could be produced even in case of
    /// an error
    pub tx_result: Option<ExtendedTxResult<Error>>,
}

impl From<Error> for DispatchError {
    fn from(error: Error) -> Self {
        Self {
            error,
            tx_result: None,
        }
    }
}

/// Arguments for transactions' execution
pub enum DispatchArgs<'a, CA: 'static + WasmCacheAccess + Sync> {
    /// Protocol tx data
    Protocol(&'a ProtocolTx),
    /// Raw tx data
    Raw {
        /// The tx index
        tx_index: TxIndex,
        /// Hash of the header of the wrapper tx containing
        /// this raw tx
        wrapper_hash: Option<&'a Hash>,
        /// The result of the corresponding wrapper tx (missing if governance
        /// transaction)
        wrapper_tx_result: Option<ExtendedTxResult<Error>>,
        /// Vp cache
        vp_wasm_cache: &'a mut VpCache<CA>,
        /// Tx cache
        tx_wasm_cache: &'a mut TxCache<CA>,
    },
    /// Wrapper tx data
    Wrapper {
        /// The wrapper header
        wrapper: &'a WrapperTx,
        /// The transaction bytes for gas accounting
        tx_bytes: &'a [u8],
        /// The tx index
        tx_index: TxIndex,
        /// The block proposer
        block_proposer: &'a Address,
        /// Vp cache
        vp_wasm_cache: &'a mut VpCache<CA>,
        /// Tx cache
        tx_wasm_cache: &'a mut TxCache<CA>,
    },
}

/// Dispatch a given transaction to be applied based on its type. Some storage
/// updates may be derived and applied natively rather than via the wasm
/// environment, in which case validity predicates will be bypassed.
pub fn dispatch_tx<'a, D, H, CA>(
    tx: &Tx,
    dispatch_args: DispatchArgs<'a, CA>,
    tx_gas_meter: &'a RefCell<TxGasMeter>,
    state: &'a mut WlState<D, H>,
) -> std::result::Result<ExtendedTxResult<Error>, DispatchError>
where
    D: 'static + DB + for<'iter> DBIter<'iter> + Sync,
    H: 'static + StorageHasher + Sync,
    CA: 'static + WasmCacheAccess + Sync,
{
    match dispatch_args {
        DispatchArgs::Raw {
            tx_index,
            wrapper_hash,
            wrapper_tx_result,
            vp_wasm_cache,
            tx_wasm_cache,
        } => {
            if let Some(tx_result) = wrapper_tx_result {
                // Replay protection check on the batch
                let tx_hash = tx.raw_header_hash();
                if state.write_log().has_replay_protection_entry(&tx_hash) {
                    // If the same batch has already been committed in
                    // this block, skip execution and return
                    return Err(DispatchError {
                        error: Error::ReplayAttempt(tx_hash),
                        tx_result: None,
                    });
                }

                dispatch_inner_txs(
                    tx,
                    wrapper_hash,
                    tx_result,
                    tx_index,
                    tx_gas_meter,
                    state,
                    vp_wasm_cache,
                    tx_wasm_cache,
                )
            } else {
                // Governance proposal. We don't allow tx batches in this case,
                // just take the first one
                let cmt =
                    tx.first_commitments().ok_or(Error::MissingInnerTxs)?;
                let batched_tx_result = apply_wasm_tx(
                    &tx.batch_ref_tx(cmt),
                    &tx_index,
                    ShellParams {
                        tx_gas_meter,
                        state,
                        vp_wasm_cache,
                        tx_wasm_cache,
                    },
                )?;

                Ok({
                    let mut batch_results = TxResult::new();
                    batch_results.insert_inner_tx_result(
                        wrapper_hash,
                        either::Right(cmt),
                        Ok(batched_tx_result),
                    );
                    batch_results
                }
                .to_extended_result(None))
            }
        }
        DispatchArgs::Protocol(protocol_tx) => {
            // No bundles of protocol transactions, only take the first one
            let cmt = tx.first_commitments().ok_or(Error::MissingInnerTxs)?;
            let batched_tx_result =
                apply_protocol_tx(protocol_tx.tx, tx.data(cmt), state)?;

            Ok({
                let mut batch_results = TxResult::new();
                batch_results.insert_inner_tx_result(
                    None,
                    either::Right(cmt),
                    Ok(batched_tx_result),
                );
                batch_results
            }
            .to_extended_result(None))
        }
        DispatchArgs::Wrapper {
            wrapper,
            tx_bytes,
            tx_index,
            block_proposer,
            vp_wasm_cache,
            tx_wasm_cache,
        } => {
            let mut shell_params = ShellParams::new(
                tx_gas_meter,
                state,
                vp_wasm_cache,
                tx_wasm_cache,
            );

            apply_wrapper_tx(
                tx,
                wrapper,
                tx_bytes,
                &tx_index,
                tx_gas_meter,
                &mut shell_params,
                Some(block_proposer),
            )
            .map_err(|e| Error::WrapperRunnerError(e.to_string()).into())
        }
    }
}

pub(crate) fn get_batch_txs_to_execute<'a>(
    tx: &'a Tx,
    masp_tx_refs: &MaspTxRefs,
    ibc_tx_data_refs: &IbcTxDataRefs,
) -> impl Iterator<Item = &'a TxCommitments> {
    let mut batch_iter = tx.commitments().iter();
    if !masp_tx_refs.0.is_empty() || !ibc_tx_data_refs.0.is_empty() {
        // If fees were paid via masp skip the first transaction of the batch
        // which has already been executed
        batch_iter.next();
    }

    batch_iter
}

#[allow(clippy::too_many_arguments)]
fn dispatch_inner_txs<'a, D, H, CA>(
    tx: &Tx,
    wrapper_hash: Option<&'a Hash>,
    mut extended_tx_result: ExtendedTxResult<Error>,
    tx_index: TxIndex,
    tx_gas_meter: &'a RefCell<TxGasMeter>,
    state: &'a mut WlState<D, H>,
    vp_wasm_cache: &'a mut VpCache<CA>,
    tx_wasm_cache: &'a mut TxCache<CA>,
) -> std::result::Result<ExtendedTxResult<Error>, DispatchError>
where
    D: 'static + DB + for<'iter> DBIter<'iter> + Sync,
    H: 'static + StorageHasher + Sync,
    CA: 'static + WasmCacheAccess + Sync,
{
    for cmt in get_batch_txs_to_execute(
        tx,
        &extended_tx_result.masp_tx_refs,
        &extended_tx_result.ibc_tx_data_refs,
    ) {
        match apply_wasm_tx(
            &tx.batch_ref_tx(cmt),
            &tx_index,
            ShellParams {
                tx_gas_meter,
                state,
                vp_wasm_cache,
                tx_wasm_cache,
            },
        ) {
            Err(Error::GasError(ref msg)) => {
                // Gas error aborts the execution of the entire batch
                extended_tx_result.tx_result.insert_inner_tx_result(
                    wrapper_hash,
                    either::Right(cmt),
                    Err(Error::GasError(msg.to_owned())),
                );
                state.write_log_mut().drop_tx();
                return Err(DispatchError {
                    error: Error::GasError(msg.to_owned()),
                    tx_result: Some(extended_tx_result),
                });
            }
            res => {
                let is_accepted =
                    matches!(&res, Ok(result) if result.is_accepted());

                extended_tx_result.tx_result.insert_inner_tx_result(
                    wrapper_hash,
                    either::Right(cmt),
                    res,
                );
                if is_accepted {
                    // If the transaction was a masp one append the
                    // transaction refs for the events
                    let actions =
                        state.read_actions().map_err(Error::StateError)?;
                    if let Some(masp_section_ref) =
                        namada_tx::action::get_masp_section_ref(&actions)
                    {
                        extended_tx_result
                            .masp_tx_refs
                            .0
                            .push(masp_section_ref);
                    }
                    if is_ibc_shielding_transfer(&*state)
                        .map_err(Error::StateError)?
                    {
                        extended_tx_result
                            .ibc_tx_data_refs
                            .0
                            .push(*cmt.data_sechash())
                    }
                    state.write_log_mut().commit_tx_to_batch();
                } else {
                    state.write_log_mut().drop_tx();

                    if tx.header.atomic {
                        // Stop the execution of an atomic batch at the
                        // first failed transaction
                        return Err(DispatchError {
                            error: Error::FailingAtomicBatch(cmt.get_hash()),
                            tx_result: Some(extended_tx_result),
                        });
                    }
                }
            }
        };
    }

    Ok(extended_tx_result)
}

/// Transaction result for masp transfer
pub struct MaspTxResult {
    tx_result: BatchedTxResult,
    masp_section_ref: Either<TxId, IbcTxDataHash>,
}

/// Performs the required operation on a wrapper transaction:
///  - replay protection
///  - fee payment
///  - gas accounting
pub(crate) fn apply_wrapper_tx<S, D, H, CA>(
    tx: &Tx,
    wrapper: &WrapperTx,
    tx_bytes: &[u8],
    tx_index: &TxIndex,
    tx_gas_meter: &RefCell<TxGasMeter>,
    shell_params: &mut ShellParams<'_, S, D, H, CA>,
    block_proposer: Option<&Address>,
) -> Result<ExtendedTxResult<Error>>
where
    S: State<D = D, H = H> + Read<Err = namada_state::Error> + TxWrites + Sync,
    D: 'static + DB + for<'iter> DBIter<'iter> + Sync,
    H: 'static + StorageHasher + Sync,
    CA: 'static + WasmCacheAccess + Sync,
{
    // Write wrapper tx hash to storage
    shell_params
        .state
        .write_log_mut()
        .write_tx_hash(tx.header_hash())
        .expect("Error while writing tx hash to storage");

    // Charge or check fees, propagate any errors to prevent committing invalid
    // data
    let payment_result = match block_proposer {
        Some(block_proposer) => {
            transfer_fee(shell_params, block_proposer, tx, wrapper, tx_index)?
        }
        None => check_fees(shell_params, tx, wrapper)?,
    };

    // Commit tx to the block write log even in case of subsequent errors (if
    // the fee payment failed instead, than the previous two functions must
    // have propagated an error)
    shell_params.state.write_log_mut().commit_batch();

    let (batch_results, masp_section_refs) = payment_result.map_or_else(
        || (TxResult::default(), None),
        |masp_tx_result| {
            let mut batch = TxResult::default();
            batch.insert_inner_tx_result(
                // Ok to unwrap cause if we have a batched result it means
                // we've executed the first tx in the batch
                tx.wrapper_hash().as_ref(),
                either::Right(tx.first_commitments().unwrap()),
                Ok(masp_tx_result.tx_result),
            );
            let masp_section_refs =
                Some(masp_tx_result.masp_section_ref.map_either(
                    |masp_tx_ref| MaspTxRefs(vec![masp_tx_ref]),
                    |ibc_tx_data| IbcTxDataRefs(vec![ibc_tx_data]),
                ));
            (batch, masp_section_refs)
        },
    );

    // Account for gas
    tx_gas_meter
        .borrow_mut()
        .add_wrapper_gas(tx_bytes)
        .map_err(|err| Error::GasError(err.to_string()))?;

    Ok(batch_results.to_extended_result(masp_section_refs))
}

/// Perform the actual transfer of fees from the fee payer to the block
/// proposer. No modifications to the write log are committed or dropped in this
/// function: this logic is up to the caller.
pub fn transfer_fee<S, D, H, CA>(
    shell_params: &mut ShellParams<'_, S, D, H, CA>,
    block_proposer: &Address,
    tx: &Tx,
    wrapper: &WrapperTx,
    tx_index: &TxIndex,
) -> Result<Option<MaspTxResult>>
where
    S: State<D = D, H = H>
        + StorageRead
        + TxWrites
        + Read<Err = namada_state::Error>
        + Sync,
    D: 'static + DB + for<'iter> DBIter<'iter> + Sync,
    H: 'static + StorageHasher + Sync,
    CA: 'static + WasmCacheAccess + Sync,
{
    match wrapper.get_tx_fee() {
        Ok(fees) => {
            let fees = crate::token::denom_to_amount(
                fees,
                &wrapper.fee.token,
                shell_params.state,
            )
            .map_err(Error::StorageError)?;

            let balance = crate::token::read_balance(
                shell_params.state,
                &wrapper.fee.token,
                &wrapper.fee_payer(),
            )
            .map_err(Error::StorageError)?;

            let (post_bal, valid_batched_tx_result) = if let Some(post_bal) =
                balance.checked_sub(fees)
            {
                fee_token_transfer(
                    shell_params.state,
                    &wrapper.fee.token,
                    &wrapper.fee_payer(),
                    block_proposer,
                    fees,
                )?;

                (post_bal, None)
            } else {
                // See if the first inner transaction of the batch pays the fees
                // with a masp unshield
                if let Ok(Some(valid_batched_tx_result)) =
                    try_masp_fee_payment(shell_params, tx, tx_index)
                {
                    let balance = crate::token::read_balance(
                        shell_params.state,
                        &wrapper.fee.token,
                        &wrapper.fee_payer(),
                    )
                    .expect("Could not read balance key from storage");

                    let post_bal = match balance.checked_sub(fees) {
                        Some(post_bal) => {
                            // This cannot fail given the checked_sub check here
                            // above
                            fee_token_transfer(
                                shell_params.state,
                                &wrapper.fee.token,
                                &wrapper.fee_payer(),
                                block_proposer,
                                fees,
                            )?;

                            post_bal
                        }
                        None => {
                            // This shouldn't happen as it should be prevented
                            // from process_proposal.
                            tracing::error!(
                                "Transfer of tx fee cannot be applied to due \
                                 to insufficient funds. This shouldn't happen."
                            );
                            return Err(Error::FeeError(
                                "Insufficient funds for fee payment"
                                    .to_string(),
                            ));
                        }
                    };

                    // Batched tx result must be returned (and considered) only
                    // if fee payment was successful
                    (post_bal, Some(valid_batched_tx_result))
                } else {
                    // This shouldn't happen as it should be prevented by
                    // process_proposal.
                    tracing::error!(
                        "Transfer of tx fee cannot be applied to due to \
                         insufficient funds. This shouldn't happen."
                    );
                    return Err(Error::FeeError(
                        "Insufficient funds for fee payment".to_string(),
                    ));
                }
            };

            let target_post_balance = Some(
                namada_token::read_balance(
                    shell_params.state,
                    &wrapper.fee.token,
                    block_proposer,
                )
                .map_err(Error::StorageError)?
                .into(),
            );

            const FEE_PAYMENT_DESCRIPTOR: std::borrow::Cow<'static, str> =
                std::borrow::Cow::Borrowed("wrapper-fee-payment");
            let current_block_height = shell_params
                .state
                .in_mem()
                .get_last_block_height()
                .next_height();
            shell_params.state.write_log_mut().emit_event(
                TokenEvent {
                    descriptor: FEE_PAYMENT_DESCRIPTOR,
                    level: EventLevel::Tx,
                    operation: TokenOperation::transfer(
                        UserAccount::Internal(wrapper.fee_payer()),
                        UserAccount::Internal(block_proposer.clone()),
                        wrapper.fee.token.clone(),
                        fees.into(),
                        post_bal.into(),
                        target_post_balance,
                    ),
                }
                .with(HeightAttr(current_block_height))
                .with(TxHashAttr(tx.header_hash())),
            );

            Ok(valid_batched_tx_result)
        }
        Err(e) => {
            // Fee overflow. This shouldn't happen as it should be prevented
            // by process_proposal.
            tracing::error!(
                "Transfer of tx fee cannot be applied to due to fee overflow. \
                 This shouldn't happen."
            );
            Err(Error::FeeError(format!("{}", e)))
        }
    }
}

fn try_masp_fee_payment<S, D, H, CA>(
    ShellParams {
        tx_gas_meter,
        state,
        vp_wasm_cache,
        tx_wasm_cache,
    }: &mut ShellParams<'_, S, D, H, CA>,
    tx: &Tx,
    tx_index: &TxIndex,
) -> Result<Option<MaspTxResult>>
where
    S: State<D = D, H = H>
        + StorageRead
        + Read<Err = namada_state::Error>
        + Sync,
    D: 'static + DB + for<'iter> DBIter<'iter> + Sync,
    H: 'static + StorageHasher + Sync,
    CA: 'static + WasmCacheAccess + Sync,
{
    // The fee payment is subject to a gas limit imposed by a protocol
    // parameter. Here we instantiate a custom gas meter for this step and
    // initialize it with the already consumed gas. The gas limit should
    // actually be the lowest between the protocol parameter and the actual gas
    // limit of the transaction
    let max_gas_limit = state
        .read::<u64>(
            &namada_parameters::storage::get_masp_fee_payment_gas_limit_key(),
        )
        .expect("Error reading the storage")
        .expect("Missing masp fee payment gas limit in storage")
        .min(tx_gas_meter.borrow().tx_gas_limit.into());
    let gas_scale = get_gas_scale(&**state).map_err(Error::StorageError)?;

    let mut gas_meter = TxGasMeter::new(
        namada_gas::Gas::from_whole_units(max_gas_limit.into(), gas_scale)
            .ok_or_else(|| {
                Error::GasError("Overflow in gas expansion".to_string())
            })?,
    );
    gas_meter
        .copy_consumed_gas_from(&tx_gas_meter.borrow())
        .map_err(|e| Error::GasError(e.to_string()))?;
    let ref_unshield_gas_meter = RefCell::new(gas_meter);

    let valid_batched_tx_result = {
        let first_tx = tx
            .batch_ref_first_tx()
            .ok_or_else(|| Error::MissingInnerTxs)?;
        match apply_wasm_tx(
            &first_tx,
            tx_index,
            ShellParams {
                tx_gas_meter: &ref_unshield_gas_meter,
                state: *state,
                vp_wasm_cache,
                tx_wasm_cache,
            },
        ) {
            Ok(result) => {
                // NOTE: do not commit yet cause this could be exploited to get
                // free masp operations. We can commit only after the entire fee
                // payment has been deemed valid. Also, do not commit to batch
                // cause we might need to discard the effects of this valid
                // unshield (e.g. if it unshield an amount which is not enough
                // to pay the fees)
                if !result.is_accepted() {
                    state.write_log_mut().drop_tx();
                    tracing::error!(
                        "The fee unshielding tx is invalid, some VPs rejected \
                         it: {:#?}",
                        result.vps_result.rejected_vps
                    );
                }

                let actions =
                    state.read_actions().map_err(Error::StateError)?;

                // Ensure that the transaction is actually a masp one, otherwise
                // reject
                if is_masp_transfer(&result.changed_keys)
                    && result.is_accepted()
                {
                    if let Some(masp_tx_id) =
                        namada_tx::action::get_masp_section_ref(&actions)
                    {
                        Some(MaspTxResult {
                            tx_result: result,
                            masp_section_ref: Either::Left(masp_tx_id),
                        })
                    } else {
                        is_ibc_shielding_transfer(*state)
                            .map_err(Error::StateError)?
                            .then_some(MaspTxResult {
                                tx_result: result,
                                masp_section_ref: Either::Right(
                                    *first_tx.cmt.data_sechash(),
                                ),
                            })
                    }
                } else {
                    None
                }
            }
            Err(e) => {
                state.write_log_mut().drop_tx();
                tracing::error!(
                    "The fee unshielding tx is invalid, wasm run failed: {}",
                    e
                );
                if let Error::GasError(_) = e {
                    // Propagate only if it is a gas error
                    return Err(e);
                }

                None
            }
        }
    };

    tx_gas_meter
        .borrow_mut()
        .copy_consumed_gas_from(&ref_unshield_gas_meter.borrow())
        .map_err(|e| Error::GasError(e.to_string()))?;

    Ok(valid_batched_tx_result)
}

// Manage the token transfer for the fee payment. If an error is detected the
// write log is dropped to prevent committing an inconsistent state. Propagates
// the result to the caller
fn fee_token_transfer<WLS>(
    state: &mut WLS,
    token: &Address,
    src: &Address,
    dest: &Address,
    amount: Amount,
) -> Result<()>
where
    WLS: State + StorageRead + TxWrites,
{
    crate::token::transfer(
        &mut state.with_tx_writes(),
        token,
        src,
        dest,
        amount,
    )
    .map_err(|err| {
        state.write_log_mut().drop_tx();

        Error::StorageError(err)
    })
}

/// Check if the fee payer has enough transparent balance to pay fees
pub fn check_fees<S, D, H, CA>(
    shell_params: &mut ShellParams<'_, S, D, H, CA>,
    tx: &Tx,
    wrapper: &WrapperTx,
) -> Result<Option<MaspTxResult>>
where
    S: State<D = D, H = H>
        + StorageRead
        + Read<Err = namada_state::Error>
        + Sync,
    D: 'static + DB + for<'iter> DBIter<'iter> + Sync,
    H: 'static + StorageHasher + Sync,
    CA: 'static + WasmCacheAccess + Sync,
{
    match wrapper.get_tx_fee() {
        Ok(fees) => {
            let fees = crate::token::denom_to_amount(
                fees,
                &wrapper.fee.token,
                shell_params.state,
            )
            .map_err(Error::StorageError)?;

            let balance = crate::token::read_balance(
                shell_params.state,
                &wrapper.fee.token,
                &wrapper.fee_payer(),
            )
            .map_err(Error::StorageError)?;

            checked!(balance - fees).map_or_else(
                |_| {
                    // See if the first inner transaction of the batch pays
                    // the fees with a masp unshield
                    if let Ok(valid_batched_tx_result @ Some(_)) =
                        try_masp_fee_payment(
                            shell_params,
                            tx,
                            &TxIndex::default(),
                        )
                    {
                        let balance = crate::token::read_balance(
                            shell_params.state,
                            &wrapper.fee.token,
                            &wrapper.fee_payer(),
                        )
                        .map_err(Error::StorageError)?;

                        checked!(balance - fees).map_or_else(
                            |_| {
                                Err(Error::FeeError(
                                    "Masp fee payment unshielded an \
                                     insufficient amount"
                                        .to_string(),
                                ))
                            },
                            |_| Ok(valid_batched_tx_result),
                        )
                    } else {
                        Err(Error::FeeError(
                            "Failed masp fee payment".to_string(),
                        ))
                    }
                },
                |_| Ok(None),
            )
        }
        Err(e) => Err(Error::FeeError(e.to_string())),
    }
}

/// Apply a transaction going via the wasm environment. Gas will be metered and
/// validity predicates will be triggered in the normal way.
pub fn apply_wasm_tx<'a, S, D, H, CA>(
    batched_tx: &BatchedTxRef<'_>,
    tx_index: &TxIndex,
    shell_params: ShellParams<'a, S, D, H, CA>,
) -> Result<BatchedTxResult>
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

    let verifiers = execute_tx(
        batched_tx,
        tx_index,
        state,
        tx_gas_meter,
        vp_wasm_cache,
        tx_wasm_cache,
    )?;

    let vps_result = check_vps(CheckVps {
        batched_tx,
        tx_index,
        state,
        tx_gas_meter: &mut tx_gas_meter.borrow_mut(),
        verifiers_from_tx: &verifiers,
        vp_wasm_cache,
    })?;

    let initialized_accounts = state.write_log().get_initialized_accounts();
    let changed_keys = state.write_log().get_keys();
    let events = state.write_log_mut().take_events();

    Ok(BatchedTxResult {
        changed_keys,
        vps_result,
        initialized_accounts,
        events,
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
    state: &mut WlState<D, H>,
) -> Result<BatchedTxResult>
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
            Ok(BatchedTxResult::default())
        }
    }
}

/// Execute a transaction code. Returns verifiers requested by the transaction.
#[allow(clippy::too_many_arguments)]
fn execute_tx<S, D, H, CA>(
    batched_tx: &BatchedTxRef<'_>,
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
        batched_tx.tx,
        batched_tx.cmt,
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
    batched_tx: &'a BatchedTxRef<'a>,
    tx_index: &'a TxIndex,
    state: &'a S,
    tx_gas_meter: &'a mut TxGasMeter,
    verifiers_from_tx: &'a BTreeSet<Address>,
    vp_wasm_cache: &'a mut VpCache<CA>,
}

/// Check the acceptance of a transaction by validity predicates
fn check_vps<S, CA>(
    CheckVps {
        batched_tx: tx,
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
    batched_tx: &BatchedTxRef<'_>,
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
            let tx_accepted = match &addr {
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

                    wasm::run::vp(
                        vp_code_hash,
                        batched_tx,
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
                        wasm::run::Error::InvalidSectionSignature(msg) => {
                            Error::InvalidSectionSignature(msg)
                        }
                        _ => Error::VpRunnerError(err),
                    })
                }
                Address::Internal(internal_addr) => {
                    let ctx = native_vp::Ctx::new(
                        addr,
                        state,
                        batched_tx.tx,
                        batched_tx.cmt,
                        tx_index,
                        &gas_meter,
                        &keys_changed,
                        &verifiers,
                        vp_wasm_cache.clone(),
                    );

                    match internal_addr {
                        InternalAddress::PoS => {
                            let pos = PosVP { ctx };
                            pos.validate_tx(
                                batched_tx,
                                &keys_changed,
                                &verifiers,
                            )
                            .map_err(Error::PosNativeVpError)
                        }
                        InternalAddress::Ibc => {
                            let ibc = Ibc { ctx };
                            ibc.validate_tx(
                                batched_tx,
                                &keys_changed,
                                &verifiers,
                            )
                            .map_err(Error::IbcNativeVpError)
                        }
                        InternalAddress::Parameters => {
                            let parameters = ParametersVp { ctx };
                            parameters
                                .validate_tx(
                                    batched_tx,
                                    &keys_changed,
                                    &verifiers,
                                )
                                .map_err(Error::ParametersNativeVpError)
                        }
                        InternalAddress::PosSlashPool => Err(
                            Error::AccessForbidden((*internal_addr).clone()),
                        ),
                        InternalAddress::Governance => {
                            let governance = GovernanceVp { ctx };
                            governance
                                .validate_tx(
                                    batched_tx,
                                    &keys_changed,
                                    &verifiers,
                                )
                                .map_err(Error::GovernanceNativeVpError)
                        }
                        InternalAddress::Multitoken => {
                            let multitoken = MultitokenVp { ctx };
                            multitoken
                                .validate_tx(
                                    batched_tx,
                                    &keys_changed,
                                    &verifiers,
                                )
                                .map_err(Error::MultitokenNativeVpError)
                        }
                        InternalAddress::EthBridge => {
                            let bridge = EthBridge { ctx };
                            bridge
                                .validate_tx(
                                    batched_tx,
                                    &keys_changed,
                                    &verifiers,
                                )
                                .map_err(Error::EthBridgeNativeVpError)
                        }
                        InternalAddress::EthBridgePool => {
                            let bridge_pool = BridgePoolVp { ctx };
                            bridge_pool
                                .validate_tx(
                                    batched_tx,
                                    &keys_changed,
                                    &verifiers,
                                )
                                .map_err(Error::BridgePoolNativeVpError)
                        }
                        InternalAddress::Pgf => {
                            let pgf_vp = PgfVp { ctx };
                            pgf_vp
                                .validate_tx(
                                    batched_tx,
                                    &keys_changed,
                                    &verifiers,
                                )
                                .map_err(Error::PgfNativeVpError)
                        }
                        InternalAddress::Nut(_) => {
                            let non_usable_tokens = NonUsableTokens { ctx };
                            non_usable_tokens
                                .validate_tx(
                                    batched_tx,
                                    &keys_changed,
                                    &verifiers,
                                )
                                .map_err(Error::NutNativeVpError)
                        }
                        internal_addr @ (InternalAddress::IbcToken(_)
                        | InternalAddress::Erc20(_)) => {
                            // The address should be a part of a multitoken
                            // key
                            verifiers
                                .contains(&Address::Internal(
                                    InternalAddress::Multitoken,
                                ))
                                .ok_or_else(|| {
                                    Error::AccessForbidden(
                                        internal_addr.clone(),
                                    )
                                })
                        }
                        InternalAddress::Masp => {
                            let masp = MaspVp { ctx };
                            masp.validate_tx(
                                batched_tx,
                                &keys_changed,
                                &verifiers,
                            )
                            .map_err(Error::MaspNativeVpError)
                        }
                        InternalAddress::TempStorage => Err(
                            // Temp storage changes must never be committed
                            Error::AccessForbidden((*internal_addr).clone()),
                        ),
                        InternalAddress::ReplayProtection => Err(
                            // Replay protection entries should never be
                            // written to
                            // via transactions
                            Error::AccessForbidden((*internal_addr).clone()),
                        ),
                    }
                }
            };

            tx_accepted.map_or_else(
                |err| {
                    result
                        .status_flags
                        .insert(err.invalid_section_signature_flag());
                    result.rejected_vps.insert(addr.clone());
                    result.errors.push((addr.clone(), err.to_string()));
                },
                |()| {
                    result.accepted_vps.insert(addr.clone());
                },
            );

            // Execution of VPs can (and must) be short-circuited
            // only in case of a gas overflow to prevent the
            // transaction from consuming resources that have not
            // been acquired in the corresponding wrapper tx. For
            // all the other errors we keep evaluating the vps. This
            // allows to display a consistent VpsResult across all
            // nodes and find any invalid signatures
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
    let status_flags = a.status_flags | b.status_flags;
    let mut gas_used = a.gas_used;

    gas_used
        .merge(b.gas_used, tx_gas_meter)
        .map_err(|err| Error::GasError(err.to_string()))?;

    Ok(VpsResult {
        accepted_vps,
        rejected_vps,
        gas_used,
        errors,
        status_flags,
    })
}

#[cfg(test)]
mod tests {
    use eyre::Result;
    use namada_core::collections::HashMap;
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
    ) -> Result<BatchedTxResult>
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
        let seen_by: Votes = state.read(&eth_msg_keys.seen_by())?.unwrap();
        assert_eq!(seen_by, Votes::from([(validator_a, BlockHeight(100))]));

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
        let root_seen_by: Votes = state.read(&bp_root_keys.seen_by())?.unwrap();
        assert_eq!(
            root_seen_by,
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
    fn test_native_vp_out_of_gas() {
        let (mut state, _validators) = test_utils::setup_default_storage();

        // some random token address
        let token_address = Address::Established([0xff; 20].into());

        let src_address = Address::Established([0xab; 20].into());
        let dst_address = Address::Established([0xba; 20].into());

        // supply an address with 1000 of said token
        namada_token::credit_tokens(
            &mut state,
            &token_address,
            &src_address,
            1000.into(),
        )
        .unwrap();

        // commit storage changes. this will act as the
        // initial state of the chain
        state.commit_tx_batch();
        state.commit_block().unwrap();

        // "execute" a dummy tx, by manually performing its state changes
        let (dummy_tx, changed_keys, verifiers) = {
            let mut tx = Tx::from_type(namada_tx::data::TxType::Raw);
            tx.set_code(namada_tx::Code::new(vec![], None));
            tx.set_data(namada_tx::Data::new(vec![]));

            // transfer half of the supply of src to dst
            namada_token::transfer(
                &mut state,
                &token_address,
                &src_address,
                &dst_address,
                500.into(),
            )
            .unwrap();

            let changed_keys = {
                let mut set = BTreeSet::new();
                set.insert(namada_token::storage_key::balance_key(
                    &token_address,
                    &src_address,
                ));
                set.insert(namada_token::storage_key::balance_key(
                    &token_address,
                    &dst_address,
                ));
                set
            };

            let verifiers = {
                let mut set = BTreeSet::new();
                set.insert(Address::Internal(InternalAddress::Multitoken));
                set
            };

            (tx, changed_keys, verifiers)
        };

        // temp vp cache
        let (mut vp_cache, _) =
            wasm::compilation_cache::common::testing::cache();

        // gas meter with no gas left
        let gas_meter = TxGasMeter::new(0);

        let batched_tx = dummy_tx.batch_ref_first_tx().unwrap();
        let result = execute_vps(
            verifiers,
            changed_keys,
            &batched_tx,
            &TxIndex::default(),
            &state,
            &gas_meter,
            &mut vp_cache,
        );
        assert!(matches!(result.unwrap_err(), Error::GasError(_)));
    }
}
