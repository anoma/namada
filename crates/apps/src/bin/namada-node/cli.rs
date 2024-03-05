//! Namada node CLI.

use eyre::{Context, Result};
use namada::core::time::{DateTimeUtc, Utc};
use namada_apps::cli::{self, cmds};
use namada_apps::config::ValidatorLocalConfig;
use namada_apps::node::ledger;

pub fn main() -> Result<()> {
    let (cmd, mut ctx) = cli::namada_node_cli()?;
    match cmd {
        cmds::NamadaNode::Ledger(sub) => match sub {
            cmds::Ledger::Run(cmds::LedgerRun(args)) => {
                let chain_ctx = ctx.take_chain_or_exit();
                let wasm_dir = chain_ctx.wasm_dir();
                sleep_until(args.start_time);
                ledger::run(chain_ctx.config.ledger, wasm_dir);
            }
            cmds::Ledger::RunUntil(cmds::LedgerRunUntil(args)) => {
                let mut chain_ctx = ctx.take_chain_or_exit();
                let wasm_dir = chain_ctx.wasm_dir();
                sleep_until(args.time);
                chain_ctx.config.ledger.shell.action_at_height =
                    Some(args.action_at_height);
                ledger::run(chain_ctx.config.ledger, wasm_dir);
            }
            cmds::Ledger::Reset(_) => {
                let chain_ctx = ctx.take_chain_or_exit();
                ledger::reset(chain_ctx.config.ledger)
                    .wrap_err("Failed to reset Namada node")?;
            }
            cmds::Ledger::DumpDb(cmds::LedgerDumpDb(args)) => {
                let chain_ctx = ctx.take_chain_or_exit();
                ledger::dump_db(chain_ctx.config.ledger, args);
            }
            cmds::Ledger::RollBack(_) => {
                let chain_ctx = ctx.take_chain_or_exit();
                ledger::rollback(chain_ctx.config.ledger)
                    .wrap_err("Failed to rollback the Namada node")?;
            }
        },
        cmds::NamadaNode::Config(sub) => match sub {
            cmds::Config::Gen(cmds::ConfigGen) => {
                // If the config doesn't exit, it gets generated in the context.
                // In here, we just need to overwrite the default chain ID, in
                // case it's been already set to a different value
                if let Some(chain_id) = ctx.global_args.chain_id.as_ref() {
                    ctx.global_config.default_chain_id = Some(chain_id.clone());
                    ctx.global_config
                        .write(&ctx.global_args.base_dir)
                        .unwrap_or_else(|err| {
                            eprintln!("Error writing global config: {err}");
                            cli::safe_exit(1)
                        });
                    tracing::debug!(
                        "Generated config and set default chain ID to \
                         {chain_id}"
                    );
                }
            }
            cmds::Config::UpdateLocalConfig(cmds::LocalConfig(args)) => {
                // Validate the new config
                let updated_config = std::fs::read(args.config_path).unwrap();
                let _validator_local_config: ValidatorLocalConfig =
                    toml::from_slice(&updated_config).unwrap();

                // Update the validator configuration file with the new one
                let config_path = ctx
                    .global_args
                    .base_dir
                    .join(format!(
                        "{}",
                        ctx.chain.unwrap().config.ledger.chain_id
                    ))
                    .join("validator_local_config.toml");
                std::fs::write(config_path, updated_config).unwrap();
            }
        },
    }
    Ok(())
}

/// Sleep until the given start time if necessary.
fn sleep_until(time: Option<DateTimeUtc>) {
    // Sleep until start time if needed
    if let Some(time) = time {
        if let Ok(sleep_time) =
            time.0.signed_duration_since(Utc::now()).to_std()
        {
            if !sleep_time.is_zero() {
                tracing::info!(
                    "Waiting ledger start time: {:?}, time left: {:?}",
                    time,
                    sleep_time
                );
                std::thread::sleep(sleep_time)
            }
        }
    }
}
