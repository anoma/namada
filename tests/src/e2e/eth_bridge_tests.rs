use namada::ledger::eth_bridge;

use crate::e2e::helpers::get_actor_rpc;
use crate::e2e::setup;
use crate::e2e::setup::constants::{
    wasm_abs_path, ALBERT, TX_WRITE_STORAGE_KEY_WASM,
};
use crate::e2e::setup::{Bin, Who};
use crate::{run, run_as};

/// # Examples
///
/// ```
/// let storage_key = storage_key("queue");
/// assert_eq!(storage_key, "#atest1v9hx7w36g42ysgzzwf5kgem9ypqkgerjv4ehxgpqyqszqgpqyqszqgpqyqszqgpqyqszqgpq8f99ew/queue");
/// ```
fn storage_key(path: &str) -> String {
    format!("#{}/{}", eth_bridge::vp::ADDRESS, path)
}

/// Test that a regular transaction cannot modify arbitrary keys of the Ethereum
/// bridge VP.
#[test]
fn test_unauthorized_tx_cannot_write_storage() {
    const LEDGER_STARTUP_TIMEOUT_SECONDS: u64 = 30;
    const CLIENT_COMMAND_TIMEOUT_SECONDS: u64 = 30;
    const SOLE_VALIDATOR: Who = Who::Validator(0);

    let test = setup::single_node_net().unwrap();

    let mut ledger = run_as!(
        test,
        SOLE_VALIDATOR,
        Bin::Node,
        &["ledger"],
        Some(LEDGER_STARTUP_TIMEOUT_SECONDS)
    )
    .unwrap();
    ledger.exp_string("Namada ledger node started").unwrap();
    ledger.exp_string("Tendermint node started").unwrap();
    ledger.exp_string("Committed block hash").unwrap();
    let _bg_ledger = ledger.background();

    let tx_data_path = test.test_dir.path().join("arbitrary_storage_key.txt");
    std::fs::write(&tx_data_path, &storage_key("arbitrary")[..]).unwrap();

    let tx_code_path = wasm_abs_path(TX_WRITE_STORAGE_KEY_WASM);

    let tx_data_path = tx_data_path.to_string_lossy().to_string();
    let tx_code_path = tx_code_path.to_string_lossy().to_string();
    let ledger_addr = get_actor_rpc(&test, &SOLE_VALIDATOR);
    let tx_args = vec![
        "tx",
        "--signer",
        ALBERT,
        "--code-path",
        &tx_code_path,
        "--data-path",
        &tx_data_path,
        "--ledger-address",
        &ledger_addr,
    ];

    let mut client_tx = run!(
        test,
        Bin::Client,
        tx_args,
        Some(CLIENT_COMMAND_TIMEOUT_SECONDS)
    )
    .unwrap();

    client_tx.exp_string("Transaction accepted").unwrap();
    client_tx.exp_string("Transaction applied").unwrap();
    client_tx.exp_string("Transaction is invalid").unwrap();
    client_tx
        .exp_string(&format!("Rejected: {}", eth_bridge::vp::ADDRESS))
        .unwrap();
    client_tx.assert_success();
}
