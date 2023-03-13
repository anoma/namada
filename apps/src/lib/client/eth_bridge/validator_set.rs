use std::sync::Arc;

use data_encoding::HEXLOWER;
use ethbridge_governance_contract::Governance;
use futures::future::FutureExt;
use namada::core::types::storage::Epoch;
use namada::eth_bridge::ethers::abi::{AbiDecode, AbiType, Tokenizable};
use namada::eth_bridge::ethers::core::types::TransactionReceipt;
use namada::eth_bridge::ethers::providers::{Http, Provider};
use namada::eth_bridge::structs::{Signature, ValidatorSetArgs};
use namada::ledger::queries::RPC;
use tokio::time::{Duration, Instant};

use super::{block_on_eth_sync, eth_sync_or, eth_sync_or_exit};
use crate::cli::{args, safe_exit};
use crate::client::eth_bridge::BlockOnEthSync;
use crate::facade::tendermint_rpc::HttpClient;

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
pub async fn query_validator_set_args(args: args::ActiveValidatorSet) {
    let client = HttpClient::new(args.query.ledger_address).unwrap();

    let epoch = if let Some(epoch) = args.epoch {
        epoch
    } else {
        RPC.shell().epoch(&client).await.unwrap()
    };

    let encoded_validator_set_args = RPC
        .shell()
        .eth_bridge()
        .read_active_valset(&client, &epoch)
        .await
        .unwrap();

    println!("0x{}", HEXLOWER.encode(encoded_validator_set_args.as_ref()));
}

/// Relay a validator set update, signed off for a given epoch.
pub async fn relay_validator_set_update(args: args::ValidatorSetUpdateRelay) {
    if args.sync {
        block_on_eth_sync(BlockOnEthSync {
            url: &args.eth_rpc_endpoint,
            deadline: Instant::now() + Duration::from_secs(60),
            rpc_timeout: std::time::Duration::from_secs(3),
            delta_sleep: Duration::from_secs(1),
        })
        .await;
    } else {
        eth_sync_or_exit(&args.eth_rpc_endpoint).await;
    }

    let nam_client =
        HttpClient::new(args.query.ledger_address.clone()).unwrap();

    if args.daemon {
        relay_validator_set_update_daemon(args, nam_client).await;
    } else {
        relay_validator_set_update_once(&args, &nam_client, |transf_result| {
            println!("{transf_result:?}");
        })
        .await;
    }
}

async fn relay_validator_set_update_daemon(
    args: args::ValidatorSetUpdateRelay,
    nam_client: HttpClient,
) {
    let eth_client =
        Arc::new(Provider::<Http>::try_from(&args.eth_rpc_endpoint).unwrap());

    const RETRY_DURATION: Duration = Duration::from_secs(10);

    loop {
        tracing::info!(sleeping_for = ?RETRY_DURATION, "Sleeping");
        tokio::time::sleep(RETRY_DURATION).await;

        let is_synchronizing =
            eth_sync_or(&args.eth_rpc_endpoint, || ()).await.is_err();
        if is_synchronizing {
            tracing::info!("The Ethereum node is still synchronizing");
            continue;
        }

        // we could be racing against governance updates,
        // so it is best to always fetch the latest governance
        // contract address
        let governance =
            get_governance_contract(&nam_client, Arc::clone(&eth_client)).await;
        let governance_epoch_prep_call = governance.validator_set_nonce();
        let governance_epoch_fut =
            governance_epoch_prep_call.call().map(|result| {
                result
                    .map_err(|err| {
                        tracing::error!(
                            "Failed to fetch latest validator set nonce: {err}"
                        );
                        safe_exit(1);
                    })
                    .map(|e| Epoch(e.try_into().expect("Epoch overflow")))
            });

        let shell = RPC.shell();
        let nam_current_epoch_fut = shell.epoch(&nam_client).map(|result| {
            result.map_err(|err| {
                tracing::error!(
                    "Failed to fetch the latest epoch in Namada: {err}"
                );
                safe_exit(1);
            })
        });

        let (nam_current_epoch, gov_current_epoch) =
            futures::try_join!(nam_current_epoch_fut, governance_epoch_fut)
                .unwrap();

        tracing::info!(
            ?nam_current_epoch,
            ?gov_current_epoch,
            "Fetched the latest epochs"
        );

        if nam_current_epoch == gov_current_epoch {
            tracing::info!(
                "Nothing to do, since the validator set in the Governance \
                 contract is up to date",
            );
            continue;
        }

        // TODO
    }
}

async fn get_governance_contract(
    nam_client: &HttpClient,
    eth_client: Arc<Provider<Http>>,
) -> Governance<Provider<Http>> {
    let governance_contract = RPC
        .shell()
        .eth_bridge()
        .read_governance_contract(nam_client)
        .await
        .unwrap();
    Governance::new(governance_contract.address, eth_client)
}

async fn relay_validator_set_update_once<F>(
    args: &args::ValidatorSetUpdateRelay,
    nam_client: &HttpClient,
    mut action: F,
) where
    F: FnMut(Option<TransactionReceipt>),
{
    let epoch_to_relay = if let Some(epoch) = args.epoch {
        epoch
    } else {
        RPC.shell().epoch(nam_client).await.unwrap().next()
    };
    let shell = RPC.shell().eth_bridge();
    let encoded_proof_fut =
        shell.read_valset_upd_proof(nam_client, &epoch_to_relay);

    let bridge_current_epoch = Epoch(epoch_to_relay.0.saturating_sub(2));
    let shell = RPC.shell().eth_bridge();
    let encoded_validator_set_args_fut =
        shell.read_active_valset(nam_client, &bridge_current_epoch);

    let shell = RPC.shell().eth_bridge();
    let governance_address_fut = shell.read_governance_contract(nam_client);

    let (encoded_proof, encoded_validator_set_args, governance_contract) =
        futures::try_join!(
            encoded_proof_fut,
            encoded_validator_set_args_fut,
            governance_address_fut
        )
        .unwrap();

    let (bridge_hash, gov_hash, signatures): (
        [u8; 32],
        [u8; 32],
        Vec<Signature>,
    ) = abi_decode_struct(encoded_proof);
    let active_set: ValidatorSetArgs =
        abi_decode_struct(encoded_validator_set_args);

    let eth_client =
        Arc::new(Provider::<Http>::try_from(&args.eth_rpc_endpoint).unwrap());
    let governance = Governance::new(governance_contract.address, eth_client);

    let mut relay_op = governance.update_validators_set(
        active_set,
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

    let pending_tx = relay_op.send().await.unwrap();
    let transf_result = pending_tx
        .confirmations(args.confirmations as usize)
        .await
        .unwrap();

    action(transf_result);
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
