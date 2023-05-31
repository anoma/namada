use std::borrow::Cow;
use std::cmp::Ordering;
use std::sync::Arc;

use borsh::BorshSerialize;
use data_encoding::HEXLOWER;
use ethbridge_governance_contract::Governance;
use futures::future::{self, FutureExt};
use namada_core::hints;
use namada_core::types::storage::Epoch;
use namada_core::types::vote_extensions::validator_set_update;

use super::{block_on_eth_sync, eth_sync_or, eth_sync_or_exit};
use crate::client::eth_bridge::BlockOnEthSync;
use crate::eth_bridge::ethers::abi::{AbiDecode, AbiType, Tokenizable};
use crate::eth_bridge::ethers::core::types::TransactionReceipt;
use crate::eth_bridge::ethers::providers::{Http, Provider};
use crate::eth_bridge::structs::{Signature, ValidatorSetArgs};
use crate::ledger::queries::{Client, RPC};
use crate::proto::Tx;
use crate::types::control_flow::time::{self, Duration, Instant};
use crate::types::control_flow::{
    self, install_shutdown_signal, Halt, TryHalt,
};
use crate::types::key::RefTo;
use crate::types::transaction::protocol::{ProtocolTx, ProtocolTxType};
use crate::types::transaction::TxType;

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
        reason: Cow<'static, str>,
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
        M: Into<Cow<'static, str>>,
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
        M: Into<Cow<'static, str>>,
    {
        Error::WithReason {
            level: tracing::Level::ERROR,
            reason: msg.into(),
            critical: true,
        }
    }

    /// Display the error message, and return the [`Halt`] status.
    fn handle(&self) -> Halt<()> {
        let critical = match self {
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
                critical
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
                critical
            }
            // all log levels we care about are DEBUG and ERROR
            _ => {
                hints::cold();
                return control_flow::proceed(());
            }
        };
        if hints::unlikely(critical) {
            control_flow::halt()
        } else {
            control_flow::proceed(())
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
            GovernanceCallError(_) | NonceError { .. } | NoReceipt => false,
            Receipt { receipt } => receipt.is_successful(),
        }
    }
}

/// Check the nonce of a relay.
enum CheckNonce {}

/// Do not check the nonce of a relay.
enum DoNotCheckNonce {}

/// Determine if the nonce in the Governance smart contract prompts
/// a relay operation or not.
trait ShouldRelay {
    /// The result of a relay operation.
    type RelayResult: GetStatus + From<Option<TransactionReceipt>>;

    /// Returns [`Ok`] if the relay should happen.
    fn should_relay(
        _: Epoch,
        _: &Governance<Provider<Http>>,
    ) -> Result<(), Self::RelayResult>;
}

impl ShouldRelay for DoNotCheckNonce {
    type RelayResult = Option<TransactionReceipt>;

    #[inline]
    fn should_relay(
        _: Epoch,
        _: &Governance<Provider<Http>>,
    ) -> Result<(), Self::RelayResult> {
        Ok(())
    }
}

impl ShouldRelay for CheckNonce {
    type RelayResult = RelayResult;

    fn should_relay(
        epoch: Epoch,
        governance: &Governance<Provider<Http>>,
    ) -> Result<(), Self::RelayResult> {
        let task = async move {
            let governance_epoch_prep_call = governance.validator_set_nonce();
            let governance_epoch_fut =
                governance_epoch_prep_call.call().map(|result| {
                    result
                        .map_err(|err| {
                            RelayResult::GovernanceCallError(err.to_string())
                        })
                        .map(|e| Epoch(e.as_u64()))
                });

            let gov_current_epoch = governance_epoch_fut.await?;
            if epoch == gov_current_epoch + 1u64 {
                Ok(())
            } else {
                Err(RelayResult::NonceError {
                    argument: epoch,
                    contract: gov_current_epoch,
                })
            }
        };
        // TODO: we should not rely on tokio for this. it won't
        // work on a web browser, for the most part.
        //
        // see: https://github.com/tokio-rs/tokio/pull/4967
        tokio::task::block_in_place(move || {
            tokio::runtime::Handle::current().block_on(task)
        })
    }
}

/// Relay result for [`CheckNonce`].
enum RelayResult {
    /// The call to Governance failed.
    GovernanceCallError(String),
    /// Some nonce related error occurred.
    ///
    /// The following comparison must hold: `contract + 1 = argument`.
    NonceError {
        /// The value of the [`Epoch`] argument passed via CLI.
        argument: Epoch,
        /// The value of the [`Epoch`] in the Governance contract.
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
pub async fn query_validator_set_update_proof(args: args::ValidatorSetProof) {
    let client = HttpClient::new(args.query.ledger_address).unwrap();

    let epoch = if let Some(epoch) = args.epoch {
        epoch
    } else {
        RPC.shell().epoch(&client).await.unwrap().next()
    };

    let encoded_proof = RPC
        .shell()
        .eth_bridge()
        .read_valset_upd_proof(&client, &epoch)
        .await
        .unwrap();

    println!("0x{}", HEXLOWER.encode(encoded_proof.as_ref()));
}

/// Query an ABI encoding of the validator set at a given epoch.
pub async fn query_validator_set_args(args: args::ConsensusValidatorSet) {
    let client = HttpClient::new(args.query.ledger_address).unwrap();

    let epoch = if let Some(epoch) = args.epoch {
        epoch
    } else {
        RPC.shell().epoch(&client).await.unwrap()
    };

    let encoded_validator_set_args = RPC
        .shell()
        .eth_bridge()
        .read_consensus_valset(&client, &epoch)
        .await
        .unwrap();

    println!("0x{}", HEXLOWER.encode(encoded_validator_set_args.as_ref()));
}

/// Relay a validator set update, signed off for a given epoch.
pub async fn relay_validator_set_update<C>(
    nam_client: &C,
    args: args::ValidatorSetUpdateRelay,
) -> Halt<()>
where
    C: Client + Sync,
{
    let mut signal_receiver = args.safe_mode.then(install_shutdown_signal);

    if args.sync {
        block_on_eth_sync(BlockOnEthSync {
            url: &args.eth_rpc_endpoint,
            deadline: Instant::now() + Duration::from_secs(60),
            rpc_timeout: std::time::Duration::from_secs(3),
            delta_sleep: Duration::from_secs(1),
        })
        .await?;
    } else {
        eth_sync_or_exit(&args.eth_rpc_endpoint).await?;
    }

    if args.daemon {
        relay_validator_set_update_daemon(
            args,
            nam_client,
            Pin::new(&mut signal_receiver),
        )
        .await?;
    } else {
        relay_validator_set_update_once::<CheckNonce, _>(
            &args,
            &nam_client,
            |relay_result| match relay_result {
                RelayResult::GovernanceCallError(reason) => {
                    tracing::error!(reason, "Calling Governance failed");
                }
                RelayResult::NonceError { argument, contract } => {
                    let whence = match argument.cmp(&contract) {
                        Ordering::Less => "behind",
                        Ordering::Equal => "identical to",
                        Ordering::Greater => "too far ahead of",
                    };
                    tracing::error!(
                        ?argument,
                        ?contract,
                        "Argument nonce is {whence} contract nonce"
                    );
                }
                RelayResult::NoReceipt => {
                    tracing::warn!(
                        "No transfer receipt received from the Ethereum node"
                    );
                }
                RelayResult::Receipt { receipt } => {
                    if receipt.is_successful() {
                        tracing::info!(?receipt, "Ethereum transfer succeded");
                    } else {
                        tracing::error!(?receipt, "Ethereum transfer failed");
                    }
                }
            },
        )
        .await
        .try_halt_or_recover(|error| error.handle())
    }
}

async fn relay_validator_set_update_daemon<C>(
    mut args: args::ValidatorSetUpdateRelay,
    nam_client: &C,
    shutdown_receiver: &mut Option<F>,
) -> Halt<()>
where
    C: Client + Sync,
    F: Future<Output = ()>,
{
    let eth_client =
        Arc::new(Provider::<Http>::try_from(&args.eth_rpc_endpoint).unwrap());

    const DEFAULT_RETRY_DURATION: Duration = Duration::from_secs(1);
    const DEFAULT_SUCCESS_DURATION: Duration = Duration::from_secs(10);

    let retry_duration = args.retry_dur.unwrap_or(DEFAULT_RETRY_DURATION);
    let success_duration = args.success_dur.unwrap_or(DEFAULT_SUCCESS_DURATION);

    let mut last_call_succeeded = true;

    tracing::info!("The validator set update relayer daemon has started");

    loop {
        let should_exit = if let Some(fut) = shutdown_receiver.as_mut() {
            let fut = future::maybe_done(fut);
            futures::pin_mut!(fut);
            fut.as_mut().await;
            fut.as_mut().take_output().is_some()
        } else {
            false
        };

        if should_exit {
            return control_flow::halt();
        }

        let sleep_for = if last_call_succeeded {
            success_duration
        } else {
            retry_duration
        };

        tracing::debug!(?sleep_for, "Sleeping");
        time::sleep(sleep_for).await;

        let is_synchronizing =
            eth_sync_or(&args.eth_rpc_endpoint, || ()).await.is_break();
        if is_synchronizing {
            tracing::debug!("The Ethereum node is synchronizing");
            last_call_succeeded = false;
            continue;
        }

        // we could be racing against governance updates,
        // so it is best to always fetch the latest governance
        // contract address
        let governance =
            get_governance_contract(&nam_client, Arc::clone(&eth_client))
                .await
                .try_halt(|err| {
                    // only care about displaying errors,
                    // exit on all circumstances
                    _ = err.handle();
                })?;
        let governance_epoch_prep_call = governance.validator_set_nonce();
        let governance_epoch_fut =
            governance_epoch_prep_call.call().map(|result| {
                result
                    .map_err(|err| {
                        tracing::error!(
                            "Failed to fetch latest validator set nonce: {err}"
                        );
                    })
                    .map(|e| Epoch(e.as_u64()))
            });

        let shell = RPC.shell();
        let nam_current_epoch_fut = shell.epoch(&nam_client).map(|result| {
            result.map_err(|err| {
                tracing::error!(
                    "Failed to fetch the latest epoch in Namada: {err}"
                );
            })
        });

        let (nam_current_epoch, gov_current_epoch) =
            futures::try_join!(nam_current_epoch_fut, governance_epoch_fut)
                .try_halt(|()| ())?;

        tracing::debug!(
            ?nam_current_epoch,
            ?gov_current_epoch,
            "Fetched the latest epochs"
        );

        match nam_current_epoch.cmp(&gov_current_epoch) {
            Ordering::Equal => {
                tracing::debug!(
                    "Nothing to do, since the validator set in the Governance \
                     contract is up to date",
                );
                last_call_succeeded = false;
                continue;
            }
            Ordering::Less => {
                tracing::error!("The Governance contract is ahead of Namada!");
                last_call_succeeded = false;
                continue;
            }
            Ordering::Greater => {}
        }

        // update epoch in the contract
        let new_epoch = gov_current_epoch + 1u64;
        args.epoch = Some(new_epoch);

        let result = relay_validator_set_update_once::<DoNotCheckNonce, _>(
            &args,
            &nam_client,
            |transf_result| {
                let Some(receipt) = transf_result else {
                    tracing::warn!("No transfer receipt received from the Ethereum node");
                    last_call_succeeded = false;
                    return;
                };
                last_call_succeeded = receipt.is_successful();
                if last_call_succeeded {
                    tracing::info!(?receipt, "Ethereum transfer succeded");
                    tracing::info!(?new_epoch, "Updated the validator set");
                } else {
                    tracing::error!(?receipt, "Ethereum transfer failed");
                }
            },
        ).await;

        if let Err(err) = result {
            // only print errors, do not exit
            _ = err.handle();
            last_call_succeeded = false;
        }
    }
}

async fn get_governance_contract(
    nam_client: &HttpClient,
    eth_client: Arc<Provider<Http>>,
) -> Result<Governance<Provider<Http>>, Error> {
    let governance_contract = RPC
        .shell()
        .eth_bridge()
        .read_governance_contract(nam_client)
        .await
        .map_err(|err| Error::critical(e.to_string()))?;
    Ok(Governance::new(governance_contract.address, eth_client))
}

async fn relay_validator_set_update_once<R, F>(
    args: &args::ValidatorSetUpdateRelay,
    nam_client: &HttpClient,
    mut action: F,
) -> Result<(), Error>
where
    R: ShouldRelay,
    F: FnMut(R::RelayResult),
{
    let epoch_to_relay = if let Some(epoch) = args.epoch {
        epoch
    } else {
        RPC.shell()
            .epoch(nam_client)
            .await
            .map_err(|e| Error::critical(e.to_string()))?
            .next()
    };
    let shell = RPC.shell().eth_bridge();
    let encoded_proof_fut =
        shell.read_valset_upd_proof(nam_client, &epoch_to_relay);

    let bridge_current_epoch = Epoch(epoch_to_relay.0.saturating_sub(2));
    let shell = RPC.shell().eth_bridge();
    let encoded_validator_set_args_fut =
        shell.read_consensus_valset(nam_client, &bridge_current_epoch);

    let shell = RPC.shell().eth_bridge();
    let governance_address_fut = shell.read_governance_contract(nam_client);

    let (encoded_proof, encoded_validator_set_args, governance_contract) =
        futures::try_join!(
            encoded_proof_fut,
            encoded_validator_set_args_fut,
            governance_address_fut
        )
        .map_err(|err| Error::recoverable(err.to_string()))?;

    let (bridge_hash, gov_hash, signatures): (
        [u8; 32],
        [u8; 32],
        Vec<Signature>,
    ) = abi_decode_struct(encoded_proof);
    let consensus_set: ValidatorSetArgs =
        abi_decode_struct(encoded_validator_set_args);

    let eth_client = Arc::new(
        Provider::<Http>::try_from(&args.eth_rpc_endpoint).map_err(|err| {
            Error::critical(format!(
                "Invalid rpc endpoint: {:?}: {err}",
                args.eth_rpc_endpoint
            ))
        })?,
    );
    let governance = Governance::new(governance_contract.address, eth_client);

    if let Err(result) = R::should_relay(epoch_to_relay, &governance) {
        action(result);
        return Err(Error::NoContext);
    }

    let mut relay_op = governance.update_validators_set(
        consensus_set,
        bridge_hash,
        gov_hash,
        signatures,
        epoch_to_relay.0.into(),
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

    let pending_tx = relay_op
        .send()
        .await
        .map_err(|e| Error::critical(e.to_string()))?;
    let transf_result = pending_tx
        .confirmations(args.confirmations as usize)
        .await
        .map_err(|err| Error::critical(err.to_string()))?;

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
        assert!(!RelayResult::GovernanceCallError("".into()).is_successful());
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
