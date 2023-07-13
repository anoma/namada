use std::fs::File;
use std::path::PathBuf;
use std::sync::Arc;

use clap::Command as App;
use eyre::Report;
use namada::ledger::signing;
use namada::ledger::tx::ProcessTxResponse;
use namada_apps::cli;
use namada_apps::cli::args::{CliToSdk, Global};
use namada_apps::cli::cmds::{Namada, NamadaClient, NamadaClientWithContext};
use namada_apps::cli::utils::Cmd;
use namada_apps::cli::{args, cmds, Context};
use namada_apps::client::tx::submit_reveal_aux;
use namada_apps::client::{rpc, tx};
use namada_apps::wallet::cli_utils::{
    address_add, address_key_add, address_key_find, address_list,
    address_or_alias_find, key_and_address_gen, key_and_address_restore,
    key_export, key_find, key_list, payment_address_gen,
    payment_addresses_list, spending_key_gen, spending_keys_list,
};

use crate::e2e::setup::Bin;
use crate::integration::node::MockNode;

pub fn run(
    node: &MockNode,
    who: Bin,
    mut args: Vec<&str>,
) -> Result<(), Report> {
    let cmd = match who {
        Bin::Node => {
            args.insert(0, "namadan");
            let app = App::new("test");
            let app = cmds::NamadaNode::add_sub(args::Global::def(app));
            let matches = app.get_matches_from(args.clone());
            cmds::Namada::Node(
                cmds::NamadaNode::parse(&matches)
                    .expect("Could not parse node command"),
            )
        }
        Bin::Client => {
            args.insert(0, "client");
            let app = App::new("test");
            let app = cmds::NamadaClient::add_sub(args::Global::def(app));
            let matches = app.get_matches_from(args.clone());
            cmds::Namada::Client(
                cmds::NamadaClient::parse(&matches)
                    .expect("Could not parse client command"),
            )
        }
        Bin::Wallet => {
            args.insert(0, "wallet");
            let app = App::new("test");
            let app = cmds::NamadaWallet::add_sub(args::Global::def(app));
            let matches = app.get_matches_from(args.clone());
            cmds::Namada::Wallet(
                cmds::NamadaWallet::parse(&matches)
                    .expect("Could not parse wallet command"),
            )
        }
    };
    let rt = tokio::runtime::Runtime::new().unwrap();

    rt.block_on(node.handle_command(cmd))
}

impl MockNode {
    async fn handle_command(
        &self,
        cmd: cli::cmds::Namada,
    ) -> Result<(), Report> {
        let global = {
            let locked = self.shell.lock().unwrap();
            Global {
                chain_id: Some(locked.chain_id.clone()),
                base_dir: locked.base_dir.clone(),
                wasm_dir: Some(locked.wasm_dir.clone()),
            }
        };
        let mut ctx = Context::new(global)?;
        match cmd {
            cli::cmds::Namada::Node(cmd) => {
                unreachable!(
                    "Command not supported by integration test: {:?}",
                    cmd
                );
            }
            cli::cmds::Namada::Ledger(cmd) => {
                unreachable!(
                    "Command not supported by integration test: {:?}",
                    cmd
                );
            }
            cli::cmds::Namada::Client(cmd) => match cmd {
                NamadaClient::WithContext(cmd) => match cmd {
                    NamadaClientWithContext::TxCustom(args) => {
                        let args = args.0.to_sdk(&mut ctx);
                        let dry_run = args.tx.dry_run;
                        tx::submit_custom::<MockNode>(self, &mut ctx, args)
                            .await?;
                        if !dry_run {
                            namada_apps::wallet::save(&ctx.wallet)
                                .unwrap_or_else(|err| eprintln!("{}", err));
                        } else {
                            println!(
                                "Transaction dry run. No addresses have been \
                                 saved."
                            )
                        }
                    }
                    NamadaClientWithContext::TxTransfer(args) => {
                        let args = args.0.to_sdk(&mut ctx);
                        submit_transfer(self, &mut ctx, args).await?;
                    }
                    NamadaClientWithContext::TxIbcTransfer(args) => {
                        let args = args.0.to_sdk(&mut ctx);
                        tx::submit_ibc_transfer::<MockNode>(self, ctx, args)
                            .await?;
                    }
                    NamadaClientWithContext::QueryResult(args) => {
                        let args = args.0.to_sdk(&mut ctx);
                        rpc::query_result::<MockNode>(self, args).await;
                    }
                    NamadaClientWithContext::TxUpdateVp(args) => {
                        let args = args.0.to_sdk(&mut ctx);
                        tx::submit_update_vp::<MockNode>(self, &mut ctx, args)
                            .await?;
                    }
                    NamadaClientWithContext::TxInitAccount(args) => {
                        let args = args.0.to_sdk(&mut ctx);
                        let dry_run = args.tx.dry_run;
                        tx::submit_init_account::<MockNode>(
                            self, &mut ctx, args,
                        )
                        .await?;
                        if !dry_run {
                            namada_apps::wallet::save(&ctx.wallet)
                                .unwrap_or_else(|err| eprintln!("{}", err));
                        } else {
                            println!(
                                "Transaction dry run. No addresses have been \
                                 saved."
                            )
                        }
                    }
                    NamadaClientWithContext::TxInitValidator(args) => {
                        let args = args.0.to_sdk(&mut ctx);
                        tx::submit_init_validator::<MockNode>(self, ctx, args)
                            .await?;
                    }
                    NamadaClientWithContext::TxInitProposal(args) => {
                        let args = args.0.to_sdk(&mut ctx);
                        tx::submit_init_proposal::<MockNode>(self, ctx, args)
                            .await?;
                    }
                    NamadaClientWithContext::TxVoteProposal(args) => {
                        let args = args.0.to_sdk(&mut ctx);
                        tx::submit_vote_proposal::<MockNode>(self, ctx, args)
                            .await?;
                    }
                    NamadaClientWithContext::TxRevealPk(args) => {
                        let args = args.0.to_sdk(&mut ctx);
                        tx::submit_reveal_pk::<MockNode>(self, &mut ctx, args)
                            .await?;
                    }
                    NamadaClientWithContext::Bond(args) => {
                        let args = args.0.to_sdk(&mut ctx);
                        tx::submit_bond::<MockNode>(self, &mut ctx, args)
                            .await?;
                    }
                    NamadaClientWithContext::Unbond(args) => {
                        let args = args.0.to_sdk(&mut ctx);
                        tx::submit_unbond::<MockNode>(self, &mut ctx, args)
                            .await?;
                    }
                    NamadaClientWithContext::Withdraw(args) => {
                        let args = args.0.to_sdk(&mut ctx);
                        tx::submit_withdraw::<MockNode>(self, ctx, args)
                            .await?;
                    }
                    NamadaClientWithContext::QueryEpoch(_) => {
                        rpc::query_and_print_epoch::<MockNode>(self).await;
                    }
                    NamadaClientWithContext::QueryTransfers(args) => {
                        let args = args.0.to_sdk(&mut ctx);
                        rpc::query_transfers::<MockNode, _>(
                            self,
                            &mut ctx.wallet,
                            &mut ctx.shielded,
                            args,
                        )
                        .await;
                    }
                    NamadaClientWithContext::QueryConversions(args) => {
                        let args = args.0.to_sdk(&mut ctx);
                        rpc::query_conversions::<MockNode>(
                            self,
                            &mut ctx.wallet,
                            args,
                        )
                        .await;
                    }
                    NamadaClientWithContext::QueryBlock(_) => {
                        rpc::query_block::<MockNode>(self).await;
                    }
                    NamadaClientWithContext::QueryBalance(args) => {
                        let args = args.0.to_sdk(&mut ctx);
                        rpc::query_balance::<MockNode, _>(
                            self,
                            &mut ctx.wallet,
                            &mut ctx.shielded,
                            args,
                        )
                        .await;
                    }
                    NamadaClientWithContext::QueryBonds(args) => {
                        let args = args.0.to_sdk(&mut ctx);
                        rpc::query_bonds::<MockNode>(
                            self,
                            &mut ctx.wallet,
                            args,
                        )
                        .await
                        .expect("expected successful query of bonds");
                    }
                    NamadaClientWithContext::QueryBondedStake(args) => {
                        let args = args.0.to_sdk(&mut ctx);
                        rpc::query_bonded_stake::<MockNode>(self, args).await;
                    }
                    NamadaClientWithContext::QueryCommissionRate(args) => {
                        let args = args.0.to_sdk(&mut ctx);
                        rpc::query_and_print_commission_rate::<MockNode>(
                            self,
                            &mut ctx.wallet,
                            args,
                        )
                        .await;
                    }
                    NamadaClientWithContext::QuerySlashes(args) => {
                        let args = args.0.to_sdk(&mut ctx);
                        rpc::query_slashes::<MockNode>(
                            self,
                            &mut ctx.wallet,
                            args,
                        )
                        .await;
                    }
                    NamadaClientWithContext::QueryDelegations(args) => {
                        let args = args.0.to_sdk(&mut ctx);
                        rpc::query_delegations::<MockNode>(
                            self,
                            &mut ctx.wallet,
                            args,
                        )
                        .await;
                    }
                    NamadaClientWithContext::QueryFindValidator(args) => {
                        let args = args.0.to_sdk(&mut ctx);
                        rpc::query_find_validator::<MockNode>(self, args).await;
                    }
                    NamadaClientWithContext::QueryRawBytes(args) => {
                        let args = args.0.to_sdk(&mut ctx);
                        rpc::query_raw_bytes::<MockNode>(self, args).await;
                    }
                    NamadaClientWithContext::QueryProposal(args) => {
                        let args = args.0.to_sdk(&mut ctx);
                        rpc::query_proposal::<MockNode>(self, args).await;
                    }
                    NamadaClientWithContext::QueryProposalResult(args) => {
                        let args = args.0.to_sdk(&mut ctx);
                        rpc::query_proposal_result::<MockNode>(self, args)
                            .await;
                    }
                    NamadaClientWithContext::QueryProtocolParameters(args) => {
                        let args = args.0.to_sdk(&mut ctx);
                        rpc::query_protocol_parameters::<MockNode>(self, args)
                            .await;
                    }
                    NamadaClientWithContext::TxCommissionRateChange(args) => {
                        let args = args.0.to_sdk(&mut ctx);
                        tx::submit_validator_commission_change::<MockNode>(
                            self, ctx, args,
                        )
                        .await?;
                    }
                },
                NamadaClient::WithoutContext(cmd) => unreachable!(
                    "Command not supported by integration test: {:?}",
                    cmd
                ),
            },
            cli::cmds::Namada::Wallet(cmd) => match cmd {
                cmds::NamadaWallet::Key(sub) => match sub {
                    cmds::WalletKey::Restore(cmds::KeyRestore(args)) => {
                        key_and_address_restore(ctx, args)
                    }
                    cmds::WalletKey::Gen(cmds::KeyGen(args)) => {
                        key_and_address_gen(ctx, args)
                    }
                    cmds::WalletKey::Find(cmds::KeyFind(args)) => {
                        key_find(ctx, args)
                    }
                    cmds::WalletKey::List(cmds::KeyList(args)) => {
                        key_list(ctx, args)
                    }
                    cmds::WalletKey::Export(cmds::Export(args)) => {
                        key_export(ctx, args)
                    }
                },
                cmds::NamadaWallet::Address(sub) => match sub {
                    cmds::WalletAddress::Gen(cmds::AddressGen(args)) => {
                        key_and_address_gen(ctx, args)
                    }
                    cmds::WalletAddress::Restore(cmds::AddressRestore(
                        args,
                    )) => key_and_address_restore(ctx, args),
                    cmds::WalletAddress::Find(cmds::AddressOrAliasFind(
                        args,
                    )) => address_or_alias_find(ctx, args),
                    cmds::WalletAddress::List(cmds::AddressList) => {
                        address_list(ctx)
                    }
                    cmds::WalletAddress::Add(cmds::AddressAdd(args)) => {
                        address_add(ctx, args)
                    }
                },
                cmds::NamadaWallet::Masp(sub) => match sub {
                    cmds::WalletMasp::GenSpendKey(cmds::MaspGenSpendKey(
                        args,
                    )) => spending_key_gen(ctx, args),
                    cmds::WalletMasp::GenPayAddr(cmds::MaspGenPayAddr(
                        args,
                    )) => {
                        let args = args.to_sdk(&mut ctx);
                        payment_address_gen(ctx, args)
                    }
                    cmds::WalletMasp::AddAddrKey(cmds::MaspAddAddrKey(
                        args,
                    )) => address_key_add(ctx, args),
                    cmds::WalletMasp::ListPayAddrs(cmds::MaspListPayAddrs) => {
                        payment_addresses_list(ctx)
                    }
                    cmds::WalletMasp::ListKeys(cmds::MaspListKeys(args)) => {
                        spending_keys_list(ctx, args)
                    }
                    cmds::WalletMasp::FindAddrKey(cmds::MaspFindAddrKey(
                        args,
                    )) => address_key_find(ctx, args),
                },
            },
            Namada::TxCustom(args) => {
                let args = args.0.to_sdk(&mut ctx);
                let dry_run = args.tx.dry_run;
                tx::submit_custom::<MockNode>(self, &mut ctx, args).await?;
                if !dry_run {
                    namada_apps::wallet::save(&ctx.wallet)
                        .unwrap_or_else(|err| eprintln!("{}", err));
                } else {
                    println!(
                        "Transaction dry run. No addresses have been saved."
                    )
                }
            }
            Namada::TxTransfer(args) => {
                let args = args.0.to_sdk(&mut ctx);
                submit_transfer(self, &mut ctx, args).await?;
            }
            Namada::TxIbcTransfer(args) => {
                let args = args.0.to_sdk(&mut ctx);
                tx::submit_ibc_transfer::<MockNode>(self, ctx, args).await?;
            }
            Namada::TxUpdateVp(args) => {
                let args = args.0.to_sdk(&mut ctx);
                tx::submit_update_vp::<MockNode>(self, &mut ctx, args).await?;
            }
            Namada::TxInitProposal(args) => {
                let args = args.0.to_sdk(&mut ctx);
                tx::submit_init_proposal::<MockNode>(self, ctx, args).await?;
            }
            Namada::TxVoteProposal(args) => {
                let args = args.0.to_sdk(&mut ctx);
                tx::submit_vote_proposal::<MockNode>(self, ctx, args).await?;
            }
            Namada::TxRevealPk(args) => {
                let args = args.0.to_sdk(&mut ctx);
                tx::submit_reveal_pk::<MockNode>(self, &mut ctx, args).await?;
            }
        }
        Ok(())
    }
}

struct TempFile(PathBuf);
impl TempFile {
    fn new(path: PathBuf) -> (Self, File) {
        let f = File::create(&path).unwrap();
        (Self(path), f)
    }
}

impl Drop for TempFile {
    fn drop(&mut self) {
        _ = std::fs::remove_file(&self.0);
    }
}

/// Test helper that captures stdout of
/// a process.
pub struct CapturedOutput<T = ()> {
    pub output: String,
    pub result: T,
    input: String,
}

impl CapturedOutput {
    pub fn with_input(input: String) -> Self {
        Self {
            output: "".to_string(),
            result: (),
            input,
        }
    }
}

impl<T> CapturedOutput<T> {
    pub(crate) fn of<F>(func: F) -> Self
    where
        F: FnOnce() -> T,
    {
        std::io::set_output_capture(Some(Default::default()));
        let mut capture = Self {
            output: Default::default(),
            result: func(),
            input: Default::default(),
        };
        let captured = std::io::set_output_capture(None);
        let captured = captured.unwrap();
        let captured = Arc::try_unwrap(captured).unwrap();
        let captured = captured.into_inner().unwrap();
        capture.output = String::from_utf8(captured).unwrap();
        capture
    }

    pub fn run<U, F>(&self, func: F) -> CapturedOutput<U>
    where
        F: FnOnce() -> U,
    {
        use std::io::Write;
        let _temp = {
            let (temp, mut f) = TempFile::new(PathBuf::from("stdin.mock"));
            write!(&mut f, "{}", self.input).unwrap();
            temp
        };
        CapturedOutput::of(func)
    }

    /// Check if the captured output contains the regex.
    pub fn matches(&self, needle: regex::Regex) -> bool {
        needle.captures(&self.output).is_some()
    }

    /// Check if the captured output contains the string.
    pub fn contains(&self, needle: &str) -> bool {
        let needle = regex::Regex::new(needle).unwrap();
        self.matches(needle)
    }
}

async fn submit_transfer(
    client: &MockNode,
    ctx: &mut Context,
    args: args::TxTransfer,
) -> Result<(), namada::ledger::tx::Error> {
    let arg = args.clone();
    let (mut tx, addr, pk, tx_epoch, _isf) =
        namada::ledger::tx::build_transfer(
            client,
            &mut ctx.wallet,
            &mut ctx.shielded,
            arg,
        )
        .await?;
    submit_reveal_aux(client, ctx, &args.tx, addr, pk.clone(), &mut tx).await?;
    signing::sign_tx(&mut ctx.wallet, &mut tx, &args.tx, &pk).await?;
    let result =
        namada::ledger::tx::process_tx(client, &mut ctx.wallet, &args.tx, tx)
            .await?;
    // Query the epoch in which the transaction was probably submitted
    let submission_epoch = rpc::query_and_print_epoch(client).await;

    match result {
        ProcessTxResponse::Applied(resp) if
        // If a transaction is shielded
        tx_epoch.is_some() &&
            // And it is rejected by a VP
            resp.code == 1.to_string() &&
            // And the its submission epoch doesn't match construction epoch
            tx_epoch.unwrap() != submission_epoch =>
        {
            // Then we probably straddled an epoch boundary
            println!(
                "MASP transaction rejected and this may be due to the \
                epoch changing. Attempting to resubmit transaction.",
            );

        }
        _ => {}
    }
    Ok(())
}
