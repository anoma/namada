//! Namada client CLI.

use color_eyre::eyre::{eyre, Report, Result};
use namada::ledger::eth_bridge::bridge_pool;
use namada::ledger::rpc::wait_until_node_is_synched;
use namada::ledger::{signing, tx as sdk_tx};
use namada::types::control_flow::ProceedOrElse;
use namada_apps::cli;
use namada_apps::cli::api::CliApi;
use namada_apps::cli::args::CliToSdk;
use namada_apps::cli::cmds::*;
use namada_apps::client::{rpc, tx, utils};
use namada_apps::facade::tendermint_rpc::HttpClient;

pub async fn main() -> Result<()> {
    CliApi::<()>::handle_client_command::<HttpClient>(cli::namada_client_cli()?)
}
