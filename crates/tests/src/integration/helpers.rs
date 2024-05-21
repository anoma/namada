use std::path::PathBuf;
use std::str::FromStr;

use eyre::eyre;
use namada_apps_lib::node::ledger::shell::testing::client::run;
use namada_apps_lib::node::ledger::shell::testing::node::MockNode;
use namada_apps_lib::node::ledger::shell::testing::utils::{
    Bin, CapturedOutput,
};
use namada_core::address::Address;

/// Query the wallet to get an address from a given alias.
pub fn find_address(
    node: &MockNode,
    alias: impl AsRef<str>,
) -> eyre::Result<Address> {
    let captured = CapturedOutput::of(|| {
        run(
            node,
            Bin::Wallet,
            vec!["find", "--addr", "--alias", alias.as_ref()],
        )
    });
    assert!(captured.result.is_ok());
    assert!(captured.contains("Found transparent address:"));
    let matched = captured.matches("\".*\": .*").unwrap();
    let address_str = strip_trailing_newline(matched)
        .trim()
        .rsplit_once(' ')
        .unwrap()
        .1;
    let address = Address::from_str(address_str).map_err(|e| {
        eyre!(format!(
            "Address: {} parsed from {}, Error: {}",
            address_str, matched, e,
        ))
    })?;
    println!("Found {}", address);
    Ok(address)
}

fn strip_trailing_newline(input: &str) -> &str {
    input
        .strip_suffix("\r\n")
        .or_else(|| input.strip_suffix('\n'))
        .unwrap_or(input)
}

pub fn prepare_steward_commission_update_data(
    test_dir: &std::path::Path,
    data: impl serde::Serialize,
) -> PathBuf {
    let valid_commission_json_path = test_dir.join("commission.json");
    write_json_file(valid_commission_json_path.as_path(), &data);
    valid_commission_json_path
}

fn write_json_file<T>(proposal_path: &std::path::Path, proposal_content: T)
where
    T: serde::Serialize,
{
    let intent_writer = std::fs::OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(true)
        .open(proposal_path)
        .unwrap();

    serde_json::to_writer(intent_writer, &proposal_content).unwrap();
}
