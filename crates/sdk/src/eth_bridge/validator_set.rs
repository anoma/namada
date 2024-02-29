//! Validator set updates SDK functionality.

use std::cmp::Ordering;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::task::Poll;

use data_encoding::HEXLOWER;
use ethbridge_bridge_contract::Bridge;
use ethers::providers::Middleware;
use futures::future::{self, FutureExt};
use namada_core::eth_abi::EncodeCell;
use namada_core::ethereum_events::EthAddress;
use namada_core::hints;
use namada_core::storage::Epoch;
use namada_ethereum_bridge::storage::proof::EthereumProof;
use namada_vote_ext::validator_set_update::{
    ValidatorSetArgs, VotingPowersMap,
};

use super::{block_on_eth_sync, eth_sync_or, eth_sync_or_exit, BlockOnEthSync};
use crate::control_flow::install_shutdown_signal;
use crate::control_flow::time::{self, Duration, Instant};
use crate::error::{Error as SdkError, EthereumBridgeError, QueryError};
use crate::eth_bridge::ethers::abi::{AbiDecode, AbiType, Tokenizable};
use crate::eth_bridge::ethers::types::TransactionReceipt;
use crate::eth_bridge::structs::Signature;
use crate::internal_macros::{echo_error, trace_error};
use crate::io::Io;
use crate::queries::{Client, RPC};
use crate::{args, display_line, edisplay_line};

/// Relayer related errors.
#[derive(Debug, Default)]
enum Error {
    /// An error, with no further context.
    ///
    /// This is usually because context was already
    /// provided in the form of `tracing!()` calls.
    #[default]
    NoContext,
    /// An error message with a reason and an associated
    /// `tracing` log level.
    WithReason {
        /// The reason of the error.
        reason: SdkError,
        /// The log level where to display the error message.
        level: tracing::Level,
        /// If critical, exit the relayer.
        critical: bool,
    },
}

impl Error {
    /// Create a new error message.
    ///
    /// The error is recoverable.
    fn recoverable<M>(msg: M) -> Self
    where
        M: Into<SdkError>,
    {
        Error::WithReason {
            level: tracing::Level::DEBUG,
            reason: msg.into(),
            critical: false,
        }
    }

    /// Create a new error message.
    ///
    /// The error is not recoverable.
    fn critical<M>(msg: M) -> Self
    where
        M: Into<SdkError>,
    {
        Error::WithReason {
            level: tracing::Level::ERROR,
            reason: msg.into(),
            critical: true,
        }
    }

    /// Display the error message, and return a new [`Result`],
    /// with the error already handled appropriately.
    fn handle(self) -> Result<(), SdkError> {
        let (critical, reason) = match self {
            Error::WithReason {
                reason,
                critical,
                level: tracing::Level::ERROR,
                ..
            } => {
                tracing::error!(
                    %reason,
                    "An error occurred during the relay"
                );
                (critical, reason)
            }
            Error::WithReason {
                reason,
                critical,
                level: tracing::Level::DEBUG,
            } => {
                tracing::debug!(
                    %reason,
                    "An error occurred during the relay"
                );
                (critical, reason)
            }
            // all log levels we care about are DEBUG and ERROR
            _ => {
                hints::cold();
                return Ok(());
            }
        };
        if hints::unlikely(critical) {
            Err(reason)
        } else {
            Ok(())
        }
    }
}

/// Get the status of a relay result.
trait GetStatus {
    /// Return whether a relay result is successful or not.
    fn is_successful(&self) -> bool;
}

impl GetStatus for TransactionReceipt {
    fn is_successful(&self) -> bool {
        self.status.map(|s| s.as_u64() == 1).unwrap_or(false)
    }
}

impl GetStatus for Option<TransactionReceipt> {
    fn is_successful(&self) -> bool {
        self.as_ref()
            .map(|receipt| receipt.is_successful())
            .unwrap_or(false)
    }
}

impl GetStatus for RelayResult {
    fn is_successful(&self) -> bool {
        use RelayResult::*;
        match self {
            BridgeCallError(_) | NonceError { .. } | NoReceipt => false,
            Receipt { receipt } => receipt.is_successful(),
        }
    }
}

/// Check the nonce of a relay.
enum CheckNonce {}

/// Do not check the nonce of a relay.
enum DoNotCheckNonce {}

/// Determine if the nonce in the Bridge smart contract prompts
/// a relay operation or not.
trait ShouldRelay {
    /// The result of a relay operation.
    type RelayResult: GetStatus + From<Option<TransactionReceipt>>;

    /// The type of the future to be returned.
    type Future<'gov>: Future<Output = Result<(), Self::RelayResult>> + 'gov;

    /// Returns [`Ok`] if the relay should happen.
    fn should_relay<E>(_: Epoch, _: &Bridge<E>) -> Self::Future<'_>
    where
        E: Middleware,
        E::Error: std::fmt::Display;

    /// Try to recover from an error that has happened.
    fn try_recover<E: Into<SdkError>>(err: E) -> Error;
}

impl ShouldRelay for DoNotCheckNonce {
    type Future<'gov> = std::future::Ready<Result<(), Self::RelayResult>>;
    type RelayResult = Option<TransactionReceipt>;

    #[inline]
    fn should_relay<E>(_: Epoch, _: &Bridge<E>) -> Self::Future<'_>
    where
        E: Middleware,
        E::Error: std::fmt::Display,
    {
        std::future::ready(Ok(()))
    }

    #[inline]
    fn try_recover<E: Into<SdkError>>(err: E) -> Error {
        Error::recoverable(err)
    }
}

impl ShouldRelay for CheckNonce {
    type Future<'gov> =
        Pin<Box<dyn Future<Output = Result<(), Self::RelayResult>> + 'gov>>;
    type RelayResult = RelayResult;

    fn should_relay<E>(epoch: Epoch, bridge: &Bridge<E>) -> Self::Future<'_>
    where
        E: Middleware,
        E::Error: std::fmt::Display,
    {
        Box::pin(async move {
            let bridge_epoch_prep_call = bridge.validator_set_nonce();
            let bridge_epoch_fut =
                bridge_epoch_prep_call.call().map(|result| {
                    result
                        .map_err(|err| {
                            RelayResult::BridgeCallError(err.to_string())
                        })
                        .map(|e| Epoch(e.as_u64()))
                });

            let gov_current_epoch = bridge_epoch_fut.await?;
            if epoch == gov_current_epoch + 1u64 {
                Ok(())
            } else {
                Err(RelayResult::NonceError {
                    argument: epoch,
                    contract: gov_current_epoch,
                })
            }
        })
    }

    #[inline]
    fn try_recover<E: Into<SdkError>>(err: E) -> Error {
        Error::critical(err)
    }
}

/// Relay result for [`CheckNonce`].
enum RelayResult {
    /// The call to Bridge failed.
    BridgeCallError(String),
    /// Some nonce related error occurred.
    ///
    /// The following comparison must hold: `contract + 1 = argument`.
    NonceError {
        /// The value of the [`Epoch`] argument passed via CLI.
        argument: Epoch,
        /// The value of the [`Epoch`] in the bridge contract.
        contract: Epoch,
    },
    /// No receipt was returned from the relay operation.
    NoReceipt,
    /// The relay operation returned a transfer receipt.
    Receipt {
        /// The receipt of the transaction.
        receipt: TransactionReceipt,
    },
}

impl From<Option<TransactionReceipt>> for RelayResult {
    #[inline]
    fn from(maybe_receipt: Option<TransactionReceipt>) -> Self {
        if let Some(receipt) = maybe_receipt {
            Self::Receipt { receipt }
        } else {
            Self::NoReceipt
        }
    }
}

/// Query an ABI encoding of the validator set to be installed
/// at the given epoch, and its associated proof.
pub async fn query_validator_set_update_proof(
    client: &(impl Client + Sync),
    io: &impl Io,
    args: args::ValidatorSetProof,
) -> Result<EncodeCell<EthereumProof<(Epoch, VotingPowersMap)>>, SdkError> {
    let epoch = if let Some(epoch) = args.epoch {
        epoch
    } else {
        RPC.shell().epoch(client).await.unwrap().next()
    };

    let encoded_proof = RPC
        .shell()
        .eth_bridge()
        .read_valset_upd_proof(client, &epoch)
        .await
        .map_err(|err| {
            SdkError::Query(QueryError::General(echo_error!(
                io,
                "Failed to fetch validator set update proof: {err}"
            )))
        })?;

    display_line!(io, "0x{}", HEXLOWER.encode(encoded_proof.as_ref()));
    Ok(encoded_proof)
}

/// Query an ABI encoding of the Bridge validator set at a given epoch.
pub async fn query_bridge_validator_set(
    client: &(impl Client + Sync),
    io: &impl Io,
    args: args::BridgeValidatorSet,
) -> Result<ValidatorSetArgs, SdkError> {
    let epoch = if let Some(epoch) = args.epoch {
        epoch
    } else {
        RPC.shell().epoch(client).await.unwrap()
    };

    let args = RPC
        .shell()
        .eth_bridge()
        .read_bridge_valset(client, &epoch)
        .await
        .map_err(|err| {
            SdkError::Query(QueryError::General(echo_error!(
                io,
                "Failed to fetch Bridge validator set: {err}"
            )))
        })?;

    display_validator_set(io, args.clone());
    Ok(args)
}

/// Query an ABI encoding of the Governance validator set at a given epoch.
pub async fn query_governnace_validator_set(
    client: &(impl Client + Sync),
    io: &impl Io,
    args: args::GovernanceValidatorSet,
) -> Result<ValidatorSetArgs, SdkError> {
    let epoch = if let Some(epoch) = args.epoch {
        epoch
    } else {
        RPC.shell().epoch(client).await.unwrap()
    };

    let args = RPC
        .shell()
        .eth_bridge()
        .read_governance_valset(client, &epoch)
        .await
        .map_err(|err| {
            SdkError::Query(QueryError::General(echo_error!(
                io,
                "Failed to fetch Governance validator set: {err}"
            )))
        })?;

    display_validator_set(io, args.clone());
    Ok(args)
}

/// Display the given [`ValidatorSetArgs`].
fn display_validator_set<IO: Io>(io: &IO, args: ValidatorSetArgs) {
    use serde::Serialize;

    #[derive(Serialize)]
    struct Validator {
        addr: EthAddress,
        voting_power: u128,
    }

    #[derive(Serialize)]
    struct ValidatorSet {
        set: Vec<Validator>,
    }

    let ValidatorSetArgs {
        validators,
        voting_powers,
        ..
    } = args;
    let validator_set = ValidatorSet {
        set: validators
            .into_iter()
            .zip(voting_powers.into_iter().map(u128::from))
            .map(|(addr, voting_power)| Validator { addr, voting_power })
            .collect(),
    };

    display_line!(
        io,
        "{}",
        serde_json::to_string_pretty(&validator_set).unwrap()
    );
}

/// Relay a validator set update, signed off for a given epoch.
pub async fn relay_validator_set_update<'a, E>(
    eth_client: Arc<E>,
    client: &(impl Client + Sync),
    io: &impl Io,
    args: args::ValidatorSetUpdateRelay,
) -> Result<(), SdkError>
where
    E: Middleware,
    E::Error: std::fmt::Debug + std::fmt::Display,
{
    let mut signal_receiver = args.safe_mode.then(install_shutdown_signal);

    if args.sync {
        block_on_eth_sync(
            &*eth_client,
            io,
            BlockOnEthSync {
                deadline: Instant::now() + Duration::from_secs(60),
                delta_sleep: Duration::from_secs(1),
            },
        )
        .await?;
    } else {
        eth_sync_or_exit(&*eth_client, io).await?;
    }

    if args.daemon {
        relay_validator_set_update_daemon(
            args,
            eth_client,
            client,
            io,
            &mut signal_receiver,
        )
        .await
    } else {
        relay_validator_set_update_once::<CheckNonce, _, _, _>(
            &args,
            eth_client,
            client,
            |relay_result| match relay_result {
                RelayResult::BridgeCallError(reason) => {
                    edisplay_line!(
                        io,
                        "Calling Bridge failed due to: {reason}"
                    );
                }
                RelayResult::NonceError { argument, contract } => {
                    let whence = match argument.cmp(&contract) {
                        Ordering::Less => "behind",
                        Ordering::Equal => "identical to",
                        Ordering::Greater => "too far ahead of",
                    };
                    edisplay_line!(
                        io,
                        "Argument nonce <{argument}> is {whence} contract \
                         nonce <{contract}>"
                    );
                }
                RelayResult::NoReceipt => {
                    edisplay_line!(
                        io,
                        "No transfer receipt received from the Ethereum node"
                    );
                }
                RelayResult::Receipt { receipt } => {
                    if receipt.is_successful() {
                        display_line!(
                            io,
                            "Ethereum transfer succeeded: {:?}",
                            receipt
                        );
                    } else {
                        display_line!(
                            io,
                            "Ethereum transfer failed: {:?}",
                            receipt
                        );
                    }
                }
            },
        )
        .await
    }
    .or_else(|err| err.handle())
}

async fn relay_validator_set_update_daemon<'a, E, F>(
    mut args: args::ValidatorSetUpdateRelay,
    eth_client: Arc<E>,
    client: &(impl Client + Sync),
    io: &impl Io,
    shutdown_receiver: &mut Option<F>,
) -> Result<(), Error>
where
    E: Middleware,
    E::Error: std::fmt::Debug + std::fmt::Display,
    F: Future<Output = ()> + Unpin,
{
    const DEFAULT_RETRY_DURATION: Duration = Duration::from_secs(1);
    const DEFAULT_SUCCESS_DURATION: Duration = Duration::from_secs(10);

    let retry_duration = args.retry_dur.unwrap_or(DEFAULT_RETRY_DURATION);
    let success_duration = args.success_dur.unwrap_or(DEFAULT_SUCCESS_DURATION);

    let mut last_call_succeeded = true;

    tracing::info!("The validator set update relayer daemon has started");

    loop {
        let should_exit = if let Some(fut) = shutdown_receiver.as_mut() {
            let fut = future::poll_fn(|cx| match fut.poll_unpin(cx) {
                Poll::Pending => Poll::Ready(false),
                Poll::Ready(_) => Poll::Ready(true),
            });
            futures::pin_mut!(fut);
            fut.as_mut().await
        } else {
            false
        };

        if should_exit {
            return Ok(());
        }

        let sleep_for = if last_call_succeeded {
            success_duration
        } else {
            retry_duration
        };

        tracing::debug!(?sleep_for, "Sleeping");
        time::sleep(sleep_for).await;

        let is_synchronizing =
            eth_sync_or(&*eth_client, io, || ()).await.is_err();
        if is_synchronizing {
            tracing::debug!("The Ethereum node is synchronizing");
            last_call_succeeded = false;
            continue;
        }

        // we could be racing against governance updates,
        // so it is best to always fetch the latest Bridge
        // contract address
        let bridge =
            get_bridge_contract(client, Arc::clone(&eth_client)).await?;
        let bridge_epoch_prep_call = bridge.validator_set_nonce();
        let bridge_epoch_fut = bridge_epoch_prep_call.call().map(|result| {
            result
                .map_err(|err| {
                    Error::critical(QueryError::General(trace_error!(
                        error,
                        "Failed to fetch latest validator set nonce: {err}"
                    )))
                })
                .map(|e| e.as_u64() as i128)
        });

        let shell = RPC.shell();
        let nam_current_epoch_fut = shell.epoch(client).map(|result| {
            result
                .map_err(|err| {
                    Error::critical(QueryError::General(trace_error!(
                        error,
                        "Failed to fetch the latest epoch in Namada: {err}"
                    )))
                })
                .map(|Epoch(e)| e as i128)
        });

        let (nam_current_epoch, gov_current_epoch) =
            futures::try_join!(nam_current_epoch_fut, bridge_epoch_fut)?;

        tracing::debug!(
            ?nam_current_epoch,
            ?gov_current_epoch,
            "Fetched the latest epochs"
        );

        let new_epoch = match nam_current_epoch - gov_current_epoch {
            // NB: a namada epoch should always be one behind the nonce
            // in the bridge contract, for the latter to be considered
            // up to date
            -1 => {
                tracing::debug!(
                    "Nothing to do, since the validator set in the Bridge \
                     contract is up to date",
                );
                last_call_succeeded = false;
                continue;
            }
            0.. => {
                let e = gov_current_epoch + 1;
                // consider only the lower 64-bits
                Epoch((e & (u64::MAX as i128)) as u64)
            }
            // NB: if the nonce difference is lower than 0, somehow the state
            // of namada managed to fall behind the state of the smart contract
            _ => {
                tracing::error!("The Bridge contract is ahead of Namada!");
                last_call_succeeded = false;
                continue;
            }
        };

        // update epoch in the contract
        args.epoch = Some(new_epoch);

        let result =
            relay_validator_set_update_once::<DoNotCheckNonce, _, _, _>(
                &args,
                Arc::clone(&eth_client),
                client,
                |transf_result| {
                    let Some(receipt) = transf_result else {
                        tracing::warn!(
                            "No transfer receipt received from the Ethereum \
                             node"
                        );
                        last_call_succeeded = false;
                        return;
                    };
                    last_call_succeeded = receipt.is_successful();
                    if last_call_succeeded {
                        tracing::info!(?receipt, "Ethereum transfer succeeded");
                        tracing::info!(?new_epoch, "Updated the validator set");
                    } else {
                        tracing::error!(?receipt, "Ethereum transfer failed");
                    }
                },
            )
            .await;

        if let Err(err) = result {
            // only print errors, do not exit
            _ = err.handle();
            last_call_succeeded = false;
        }
    }
}

async fn get_bridge_contract<C, E>(
    nam_client: &C,
    eth_client: Arc<E>,
) -> Result<Bridge<E>, Error>
where
    C: Client + Sync,
    E: Middleware,
{
    let bridge_contract = RPC
        .shell()
        .eth_bridge()
        .read_bridge_contract(nam_client)
        .await
        .map_err(|err| {
            Error::critical(EthereumBridgeError::RetrieveContract(
                err.to_string(),
            ))
        })?;
    Ok(Bridge::new(bridge_contract.address, eth_client))
}

async fn relay_validator_set_update_once<R, F, C, E>(
    args: &args::ValidatorSetUpdateRelay,
    eth_client: Arc<E>,
    nam_client: &C,
    mut action: F,
) -> Result<(), Error>
where
    C: Client + Sync,
    E: Middleware,
    E::Error: std::fmt::Debug + std::fmt::Display,
    R: ShouldRelay,
    F: FnMut(R::RelayResult),
{
    let epoch_to_relay = if let Some(epoch) = args.epoch {
        epoch
    } else {
        RPC.shell()
            .epoch(nam_client)
            .await
            .map_err(|e| Error::critical(QueryError::General(e.to_string())))?
            .next()
    };

    if hints::unlikely(epoch_to_relay == Epoch(0)) {
        return Err(Error::critical(SdkError::Other(
            "There is no validator set update proof for epoch 0".into(),
        )));
    }

    let shell = RPC.shell().eth_bridge();
    let encoded_proof_fut = shell
        .read_valset_upd_proof(nam_client, &epoch_to_relay)
        .map(|result| {
            result.map_err(|err| {
                let msg = format!(
                    "Failed to fetch validator set update proof: {err}"
                );
                SdkError::Query(QueryError::General(msg))
            })
        });

    let bridge_current_epoch = epoch_to_relay - 1;
    let shell = RPC.shell().eth_bridge();
    let validator_set_args_fut = shell
        .read_bridge_valset(nam_client, &bridge_current_epoch)
        .map(|result| {
            result.map_err(|err| {
                let msg =
                    format!("Failed to fetch Bridge validator set: {err}");
                SdkError::Query(QueryError::General(msg))
            })
        });

    let shell = RPC.shell().eth_bridge();
    let bridge_address_fut =
        shell.read_bridge_contract(nam_client).map(|result| {
            result.map_err(|err| {
                SdkError::EthereumBridge(EthereumBridgeError::RetrieveContract(
                    err.to_string(),
                ))
            })
        });

    let (encoded_proof, validator_set_args, bridge_contract) =
        futures::try_join!(
            encoded_proof_fut,
            validator_set_args_fut,
            bridge_address_fut
        )
        .map_err(|err| R::try_recover(err))?;

    let (bridge_hash, gov_hash, signatures): (
        [u8; 32],
        [u8; 32],
        Vec<Signature>,
    ) = abi_decode_struct(encoded_proof);

    let bridge = Bridge::new(bridge_contract.address, eth_client);

    if let Err(result) = R::should_relay(epoch_to_relay, &bridge).await {
        action(result);
        return Err(Error::NoContext);
    }

    let mut relay_op = bridge.update_validator_set(
        validator_set_args.into(),
        bridge_hash,
        gov_hash,
        signatures,
    );
    if let Some(gas) = args.gas {
        relay_op.tx.set_gas(gas);
    }
    if let Some(gas_price) = args.gas_price {
        relay_op.tx.set_gas_price(gas_price);
    }
    if let Some(eth_addr) = args.eth_addr {
        relay_op.tx.set_from(eth_addr.into());
    }

    let pending_tx = relay_op.send().await.map_err(|e| {
        Error::critical(EthereumBridgeError::ContractCall(e.to_string()))
    })?;
    let transf_result = pending_tx
        .confirmations(args.confirmations as usize)
        .await
        .map_err(|e| {
            Error::critical(EthereumBridgeError::Rpc(e.to_string()))
        })?;

    let transf_result: R::RelayResult = transf_result.into();
    let status = if transf_result.is_successful() {
        Ok(())
    } else {
        Err(Error::NoContext)
    };

    action(transf_result);
    status
}

// NOTE: there's a bug (or feature?!) in ethers, where
// `EthAbiCodec` derived `AbiDecode` implementations
// have a decode method that expects a tuple, but
// passes invalid param types to `abi::decode()`
fn abi_decode_struct<T, D>(data: T) -> D
where
    T: AsRef<[u8]>,
    D: Tokenizable + AbiDecode + AbiType,
{
    let decoded: (D,) = AbiDecode::decode(data).unwrap();
    decoded.0
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Test [`GetStatus`] on various values.
    #[test]
    fn test_relay_op_statuses() {
        // failure cases
        assert!(!Option::<TransactionReceipt>::None.is_successful());
        assert!(
            !Some(TransactionReceipt {
                status: Some(0.into()),
                ..Default::default()
            })
            .is_successful()
        );
        assert!(!RelayResult::BridgeCallError("".into()).is_successful());
        assert!(
            !RelayResult::NonceError {
                contract: 0.into(),
                argument: 0.into(),
            }
            .is_successful()
        );
        assert!(!RelayResult::NoReceipt.is_successful());
        assert!(
            !TransactionReceipt {
                status: Some(0.into()),
                ..Default::default()
            }
            .is_successful()
        );

        // success cases
        assert!(
            Some(TransactionReceipt {
                status: Some(1.into()),
                ..Default::default()
            })
            .is_successful()
        );
        assert!(
            TransactionReceipt {
                status: Some(1.into()),
                ..Default::default()
            }
            .is_successful()
        );
    }
}
