use std::sync::Arc;

use data_encoding::HEXLOWER;
use ethabi::Address;
use ethbridge_governance_contract::Governance;
use ethbridge_structs::{Signature, ValidatorSetArgs};
use namada::core::types::storage::Epoch;
use namada::eth_bridge::ethers::abi::AbiDecode;
use namada::eth_bridge::ethers::providers::{Http, Provider};
use namada::ledger::queries::RPC;

use crate::cli::args;
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
    let nam_client = HttpClient::new(args.query.ledger_address).unwrap();

    let epoch_to_relay = if let Some(epoch) = args.epoch {
        epoch
    } else {
        RPC.shell().epoch(&nam_client).await.unwrap().next()
    };
    let encoded_proof = RPC
        .shell()
        .eth_bridge()
        .read_valset_upd_proof(&nam_client, &epoch_to_relay)
        .await
        .unwrap();

    let bridge_current_epoch = Epoch(epoch_to_relay.0.saturating_sub(2));
    let encoded_validator_set_args = RPC
        .shell()
        .eth_bridge()
        .read_active_valset(&nam_client, &bridge_current_epoch)
        .await
        .unwrap();

    let (bridge_hash, gov_hash, signatures): (
        [u8; 32],
        [u8; 32],
        Vec<Signature>,
    ) = AbiDecode::decode(encoded_proof).unwrap();
    let active_set: ValidatorSetArgs =
        AbiDecode::decode(encoded_validator_set_args).unwrap();

    let eth_client = Arc::new(
        // TODO: add eth rpc address to args
        Provider::<Http>::try_from("http://localhost:8545").unwrap(),
    );
    // TODO: query address of governance contract from RPC method
    let governance_address = "0xDc64a140Aa3E981100a9becA4E685f962f0cF6C9"
        .parse::<Address>()
        .unwrap();
    let governance = Governance::new(governance_address, eth_client);
}
