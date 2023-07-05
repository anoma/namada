use borsh::{BorshDeserialize, BorshSerialize};
use clap::App;
use eyre::Report;
use namada_apps::cli;
use namada_apps::cli::args::CliToSdk;
use namada_apps::cli::cmds::{Namada, NamadaClient, NamadaClientWithContext};
use namada_apps::cli::utils::Cmd;
use namada_apps::cli::{args, cmds, Context};
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
    let app = match who {
        Bin::Node => {
            args.insert(0, "namadan");
            let app = App::new("test");
            let app = cmds::NamadaNode::add_sub(args::Global::def(app));
            cmds::NamadaNode::add_sub(app)
        }
        Bin::Client => {
            args.insert(0, "namadac");
            let app = App::new("test");
            let app = cmds::NamadaClient::add_sub(args::Global::def(app));
            cmds::NamadaClient::add_sub(app)
        }
        Bin::Wallet => {
            args.insert(0, "namadaw");
            let app = App::new("test");
            let app = cmds::NamadaWallet::add_sub(args::Global::def(app));
            cmds::NamadaWallet::add_sub(app)
        }
    };
    let matches = app.get_matches_from(args);
    let cmd = cmds::Namada::parse(&matches).expect("Could not parse command");
    let global_args = args::Global::parse(&matches);
    let rt = tokio::runtime::Runtime::new().unwrap();

    rt.block_on(node.handle_command(cmd, global_args))
}

impl MockNode {
    async fn handle_command(
        &self,
        cmd: cli::cmds::Namada,
        global: args::Global,
    ) -> Result<(), Report> {
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
                        namada::ledger::tx::submit_transfer::<MockNode, _, _>(
                            self,
                            &mut ctx.wallet,
                            &mut ctx.shielded,
                            args,
                        )
                        .await?;
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
                            .await;
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
                                                 )) => address_or_alias_find(ctx, args),
                    cmds::WalletAddress::List(cmds::AddressList) => {
                        address_list(ctx)
                    }
                    cmds::WalletAddress::Add(cmds::AddressAdd(args)) => {
                        address_add(ctx, args)
                    }
                },
                        args,
                    )) => key_and_address_restore(ctx, args),
                    cmds::WalletAddress::Find(cmds::AddressOrAliasFind(
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
                namada::ledger::tx::submit_transfer::<MockNode, _, _>(
                    self,
                    &mut ctx.wallet,
                    &mut ctx.shielded,
                    args,
                )
                .await?;
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

#[derive(Default, Clone, BorshSerialize, BorshDeserialize)]
struct MockShieldedUtils;

// #[async_trait(?Send)]
// impl masp::ShieldedUtils for MockShieldedUtils {
//
//
// fn local_tx_prover(&self) -> LocalTxProver {
// if let Ok(params_dir) = std::env::var(masp::ENV_VAR_MASP_PARAMS_DIR) {
// let params_dir = std::path::PathBuf::from(params_dir);
// let spend_path = params_dir.join(masp::SPEND_NAME);
// let convert_path = params_dir.join(masp::CONVERT_NAME);
// let output_path = params_dir.join(masp::OUTPUT_NAME);
// LocalTxProver::new(&spend_path, &output_path, &convert_path)
// } else {
// LocalTxProver::with_default_location()
// .expect("unable to load MASP Parameters")
// }
// }
//
// Try to load the last saved shielded context from the given context
// directory. If this fails, then leave the current context unchanged.
// async fn load(self) -> std::io::Result<masp::ShieldedContext<Self>> {
// Try to load shielded context from file
// let mut ctx_file = std::fs::File::open(self.context_dir.join(FILE_NAME))?;
// let mut bytes = Vec::new();
// ctx_file.read_to_end(&mut bytes)?;
// let mut new_ctx = masp::ShieldedContext::deserialize(&mut &bytes[..])?;
// Associate the originating context directory with the
// shielded context under construction
// new_ctx.utils = self;
// Ok(new_ctx)
// }
//
// Save this shielded context into its associated context directory
// async fn save(
// &self,
// ctx: &masp::ShieldedContext<Self>,
// ) -> std::io::Result<()> {
// TODO: use mktemp crate?
// let tmp_path = self.context_dir.join(TMP_FILE_NAME);
// {
// First serialize the shielded context into a temporary file.
// Inability to create this file implies a simultaneuous write is in
// progress. In this case, immediately fail. This is unproblematic
// because the data intended to be stored can always be re-fetched
// from the blockchain.
// let mut ctx_file = OpenOptions::new()
// .write(true)
// .create_new(true)
// .open(tmp_path.clone())?;
// let mut bytes = Vec::new();
// ctx.serialize(&mut bytes)
// .expect("cannot serialize shielded context");
// ctx_file.write_all(&bytes[..])?;
// }
// Atomically update the old shielded context file with new data.
// Atomicity is required to prevent other client instances from reading
// corrupt data.
// std::fs::rename(tmp_path.clone(), self.context_dir.join(FILE_NAME))?;
// Finally, remove our temporary file to allow future saving of shielded
// contexts.
// std::fs::remove_file(tmp_path)?;
// Ok(())
// }
// }
