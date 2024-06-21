//! Namada node CLI.

use eyre::{Context, Result};
use namada_apps_lib::cli::cmds::TestGenesis;
use namada_apps_lib::cli::{self, cmds};
use namada_apps_lib::config::{
    Action, ActionAtHeight, NodeLocalConfig, ValidatorLocalConfig,
};
#[cfg(not(feature = "migrations"))]
use namada_apps_lib::display_line;
use namada_apps_lib::migrations::ScheduledMigration;
use namada_apps_lib::time::{DateTimeUtc, Utc};
use namada_node as node;

pub fn main() -> Result<()> {
    let (cmd, mut ctx) = cli::namada_node_cli()?;
    match cmd {
        cmds::NamadaNode::Ledger(sub) => match sub {
            cmds::Ledger::Run(cmds::LedgerRun(args)) => {
                let chain_ctx = ctx.take_chain_or_exit();
                let wasm_dir = chain_ctx.wasm_dir();
                sleep_until(args.start_time);
                let scheduled_migration = args.migration_path.map(|p| {
                    let hash = args.migration_hash.expect(
                        "Expected a hash to be provided along with the \
                         migrations file.",
                    );
                    let height = args.migration_height.expect(
                        "Expected a block height for the scheduled migration.",
                    );
                    ScheduledMigration::from_path(p, hash, height).unwrap()
                });
                node::run(
                    chain_ctx.config.ledger,
                    wasm_dir,
                    scheduled_migration,
                );
            }
            cmds::Ledger::RunUntil(cmds::LedgerRunUntil(args)) => {
                let mut chain_ctx = ctx.take_chain_or_exit();
                let wasm_dir = chain_ctx.wasm_dir();
                sleep_until(args.time);
                chain_ctx.config.ledger.shell.action_at_height =
                    Some(args.action_at_height);
                node::run(chain_ctx.config.ledger, wasm_dir, None);
            }
            cmds::Ledger::Reset(_) => {
                let chain_ctx = ctx.take_chain_or_exit();
                node::reset(chain_ctx.config.ledger)
                    .wrap_err("Failed to reset Namada node")?;
            }
            cmds::Ledger::DumpDb(cmds::LedgerDumpDb(args)) => {
                let chain_ctx = ctx.take_chain_or_exit();
                node::dump_db(chain_ctx.config.ledger, args);
            }
            cmds::Ledger::RollBack(_) => {
                let chain_ctx = ctx.take_chain_or_exit();
                node::rollback(chain_ctx.config.ledger)
                    .wrap_err("Failed to rollback the Namada node")?;
            }
            cmds::Ledger::UpdateDB(cmds::LedgerUpdateDB(args)) => {
                #[cfg(not(feature = "migrations"))]
                {
                    panic!(
                        "This command is only available if built with the \
                         \"migrations\" feature."
                    )
                }
                let mut chain_ctx = ctx.take_chain_or_exit();
                #[cfg(feature = "migrations")]
                node::update_db_keys(
                    chain_ctx.config.ledger.clone(),
                    args.updates,
                    args.dry_run,
                );
                if !args.dry_run {
                    let wasm_dir = chain_ctx.wasm_dir();
                    chain_ctx.config.ledger.shell.action_at_height =
                        Some(ActionAtHeight {
                            height: args.last_height.checked_add(2).unwrap(),
                            action: Action::Halt,
                        });
                    std::env::set_var(
                        "NAMADA_INITIAL_HEIGHT",
                        args.last_height.to_string(),
                    );
                    // don't stop on panics
                    let handle = std::thread::spawn(|| {
                        node::run(chain_ctx.config.ledger, wasm_dir, None)
                    });
                    _ = handle.join();
                    std::env::remove_var("NAMADA_INITIAL_HEIGHT");
                }
            }
            cmds::Ledger::QueryDB(cmds::LedgerQueryDB(args)) => {
                #[cfg(not(feature = "migrations"))]
                {
                    panic!(
                        "This command is only available if built with the \
                         \"migrations\" feature."
                    )
                }
                let chain_ctx = ctx.take_chain_or_exit();
                #[cfg(feature = "migrations")]
                node::query_db(
                    chain_ctx.config.ledger,
                    &args.key,
                    &args.hash,
                    &args.cf,
                );
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
            cmds::Config::UpdateValidatorLocalConfig(
                cmds::ValidatorLocalConfig(args),
            ) => {
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
            cmds::Config::UpdateLocalConfig(cmds::LocalConfig(args)) => {
                // Validate the new config
                let updated_config = std::fs::read(args.config_path).unwrap();
                let _local_config: NodeLocalConfig =
                    toml::from_slice(&updated_config).unwrap();

                // Update the configuration file with the new one
                let config_path = ctx
                    .global_args
                    .base_dir
                    .join(format!(
                        "{}",
                        ctx.chain.unwrap().config.ledger.chain_id
                    ))
                    .join("local_config.toml");
                std::fs::write(config_path, updated_config).unwrap();
            }
        },
        cmds::NamadaNode::Utils(sub) => match sub {
            cmds::NodeUtils::TestGenesis(TestGenesis(args)) => {
                node::utils::test_genesis(args)
            }
        },
    }
    Ok(())
}

/// Sleep until the given start time if necessary.
fn sleep_until(time: Option<DateTimeUtc>) {
    // Sleep until start time if needed
    if let Some(time) = time {
        #[allow(clippy::disallowed_methods)]
        let now = Utc::now();
        if let Ok(sleep_time) = time.0.signed_duration_since(now).to_std() {
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
