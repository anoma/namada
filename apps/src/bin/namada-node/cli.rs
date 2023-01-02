//! Namada node CLI.

use eyre::{Context, Result};
use namada_apps::cli::{self, cmds};
use namada_apps::node::ledger;

pub fn main() -> Result<()> {
    let (cmd, mut ctx) = cli::namada_node_cli()?;
    if let Some(mode) = ctx.global_args.mode.clone() {
        ctx.config.ledger.tendermint.tendermint_mode = mode;
    }
    match cmd {
        cmds::NamadaNode::Ledger(sub) => match sub {
            cmds::Ledger::Run(cmds::LedgerRun(args)) => {
                let wasm_dir = ctx.wasm_dir();
                ledger::run(ctx.config.ledger, args, wasm_dir);
            }
            cmds::Ledger::Reset(_) => {
                ledger::reset(ctx.config.ledger)
                    .wrap_err("Failed to reset Namada node")?;
            }
        },
        cmds::NamadaNode::Config(sub) => match sub {
            cmds::Config::Gen(cmds::ConfigGen) => {
                // If the config doesn't exit, it gets generated in the context.
                // In here, we just need to overwrite the default chain ID, in
                // case it's been already set to a different value
                if let Some(chain_id) = ctx.global_args.chain_id.as_ref() {
                    ctx.global_config.default_chain_id = chain_id.clone();
                    ctx.global_config
                        .write(&ctx.global_args.base_dir)
                        .unwrap_or_else(|err| {
                            eprintln!("Error writing global config: {}", err);
                            cli::safe_exit(1)
                        });
                }
                tracing::debug!(
                    "Generated config and set default chain ID to {}",
                    &ctx.global_config.default_chain_id
                );
            }
        },
    }
    Ok(())
}
