use std::ops::ControlFlow;

use clap::Command as App;
use eyre::Report;
use namada::types::control_flow::Halt;
use namada::types::io::{DefaultIo, Io};
use tendermint_config::net::Address as TendermintAddress;

use super::node::MockNode;
use crate::cli::api::{CliApi, CliClient};
use crate::cli::args::Global;
use crate::cli::{args, cmds, Cmd, Context, NamadaClient, NamadaRelayer};
use crate::node::ledger::shell::testing::utils::Bin;

pub fn run(
    node: &MockNode,
    who: Bin,
    mut args: Vec<&str>,
) -> Result<(), Report> {
    let global = {
        let locked = node.shell.lock().unwrap();
        Global {
            chain_id: Some(locked.chain_id.clone()),
            base_dir: locked.base_dir.clone(),
            wasm_dir: Some(locked.wasm_dir.clone()),
        }
    };
    let ctx = Context::new::<DefaultIo>(global.clone())?;

    let rt = tokio::runtime::Runtime::new().unwrap();
    match who {
        Bin::Node => {
            unreachable!("Node commands aren't supported by integration tests")
        }
        Bin::Client => {
            args.insert(0, "client");
            let app = App::new("test");
            let app = cmds::NamadaClient::add_sub(args::Global::def(app));
            let matches = app.get_matches_from(args.clone());
            let cmd = match cmds::NamadaClient::parse(&matches)
                .expect("Could not parse client command")
            {
                cmds::NamadaClient::WithContext(sub_cmd) => {
                    NamadaClient::WithContext(Box::new((sub_cmd, ctx)))
                }
                cmds::NamadaClient::WithoutContext(sub_cmd) => {
                    NamadaClient::WithoutContext(sub_cmd, global)
                }
            };
            rt.block_on(CliApi::<DefaultIo>::handle_client_command(
                Some(node),
                cmd,
            ))
        }
        Bin::Wallet => {
            args.insert(0, "wallet");
            let app = App::new("test");
            let app = cmds::NamadaWallet::add_sub(args::Global::def(app));
            let matches = app.get_matches_from(args.clone());

            let cmd = cmds::NamadaWallet::parse(&matches)
                .expect("Could not parse wallet command");
            CliApi::<DefaultIo>::handle_wallet_command(cmd, ctx)
        }
        Bin::Relayer => {
            args.insert(0, "relayer");
            let app = App::new("test");
            let app = cmds::NamadaRelayer::add_sub(args::Global::def(app));
            let matches = app.get_matches_from(args.clone());
            let cmd = match cmds::NamadaRelayer::parse(&matches)
                .expect("Could not parse relayer command")
            {
                cmds::NamadaRelayer::EthBridgePool(
                    cmds::EthBridgePool::WithContext(sub_cmd),
                ) => NamadaRelayer::EthBridgePoolWithCtx(Box::new((
                    sub_cmd, ctx,
                ))),
                cmds::NamadaRelayer::EthBridgePool(
                    cmds::EthBridgePool::WithoutContext(sub_cmd),
                ) => NamadaRelayer::EthBridgePoolWithoutCtx(sub_cmd),
                cmds::NamadaRelayer::ValidatorSet(sub_cmd) => {
                    NamadaRelayer::ValidatorSet(sub_cmd)
                }
            };
            rt.block_on(CliApi::<DefaultIo>::handle_relayer_command(
                Some(node),
                cmd,
            ))
        }
    }
}

#[async_trait::async_trait(?Send)]
impl<'a> CliClient for &'a MockNode {
    fn from_tendermint_address(_: &mut TendermintAddress) -> Self {
        unreachable!("MockNode should always be instantiated at test start.")
    }

    async fn wait_until_node_is_synced<IO: Io>(&self) -> Halt<()> {
        ControlFlow::Continue(())
    }
}
