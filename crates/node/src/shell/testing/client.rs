use clap::Command as App;
use eyre::Report;
use namada_apps_lib::cli::api::{CliApi, CliClient};
use namada_apps_lib::cli::args::Global;
use namada_apps_lib::cli::{
    args, cmds, Cmd, Context, NamadaClient, NamadaRelayer,
};
use namada_sdk::error::Error as SdkError;
use namada_sdk::io::Io;

use super::node::MockNode;
use crate::shell::testing::utils::{Bin, TestingIo};

pub fn run(
    node: &MockNode,
    who: Bin,
    mut args: Vec<&str>,
) -> Result<(), Report> {
    let global = {
        let locked = node.shell.lock().unwrap();
        Global {
            is_pre_genesis: false,
            chain_id: Some(locked.chain_id.clone()),
            base_dir: locked.base_dir.clone(),
            wasm_dir: Some(locked.wasm_dir.clone()),
        }
    };
    let ctx = Context::new::<TestingIo>(global.clone())?;

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
            rt.block_on(CliApi::handle_client_command(
                Some(node),
                cmd,
                TestingIo,
            ))
        }
        Bin::Wallet => {
            args.insert(0, "wallet");
            let app = App::new("test");
            let app = cmds::NamadaWallet::add_sub(args::Global::def(app));
            let matches = app.get_matches_from(args.clone());

            let cmd = cmds::NamadaWallet::parse(&matches)
                .expect("Could not parse wallet command");
            rt.block_on(CliApi::handle_wallet_command(cmd, ctx, &TestingIo))
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
            rt.block_on(CliApi::handle_relayer_command(
                Some(node),
                cmd,
                TestingIo,
            ))
        }
    }
}

#[async_trait::async_trait(?Send)]
impl<'a> CliClient for &'a MockNode {
    fn from_tendermint_address(_: &crate::facade::tendermint_rpc::Url) -> Self {
        unreachable!("MockNode should always be instantiated at test start.")
    }

    async fn wait_until_node_is_synced(
        &self,
        _io: &impl Io,
    ) -> Result<(), SdkError> {
        Ok(())
    }
}
