use data_encoding::HEXLOWER;
use namada::ledger::queries::RPC;

use crate::cli::args;
use crate::client::rpc::query_epoch_silent;
use crate::facade::tendermint_rpc::HttpClient;

/// Query an ABI encoding of the validator set to be installed
/// at the given epoch, and its associated proof.
pub async fn query_validator_set_update_proof() {
    todo!()
}

/// Query an ABI encoding of the validator set at a given epoch.
pub async fn query_validator_set_args(args: args::ActiveValidatorSet) {
    let epoch = if let Some(epoch) = args.epoch {
        epoch
    } else {
        query_epoch_silent(args.query.clone()).await
    };

    let client = HttpClient::new(args.query.ledger_address).unwrap();
    let encoded_validator_set_args = RPC
        .shell()
        .eth_bridge()
        .read_active_valset(&client, &epoch)
        .await
        .unwrap();

    println!("0x{}", HEXLOWER.encode(encoded_validator_set_args.as_ref()));
}
