//! The docstrings on types and their fields with `derive(Clap)` are displayed
//! in the CLI `--help`.
use anoma::cli::ArgMatchesExt;
use anoma::config::Config;
use anoma::node::{gossip, ledger};
use anoma::{cli, config};
use eyre::{Context, Result};

pub fn main() -> Result<()> {
    let mut app = cli::anoma_node_cli();

    let matches = &app.get_matches_mut();

    let global_args = matches.global();
    let base_dir = &global_args.base_dir;

    match matches.subcommand() {
        Some((cli::RUN_GOSSIP_CMD, args)) => {
            let config = get_cfg(base_dir);
            let mut gossip_cfg = config.intent_gossiper.unwrap_or_default();
            cli::update_gossip_config(args, &mut gossip_cfg)
                .expect("failed to update config with cli option");
            gossip::run(gossip_cfg).wrap_err("Failed to run gossip service")
        }
        Some((cli::RUN_LEDGER_CMD, _)) => {
            let config = get_cfg(base_dir);
            let ledger_cfg = config.ledger.unwrap_or_default();
            ledger::run(ledger_cfg).wrap_err("Failed to run Anoma node")
        }
        Some((cli::RESET_LEDGER_CMD, _)) => {
            let config = get_cfg(base_dir);
            let ledger_cfg = config.ledger.unwrap_or_default();
            ledger::reset(ledger_cfg).wrap_err("Failed to reset Anoma node")
        }
        Some((cli::GENERATE_CONFIG_CMD, _args)) => {
            let gen_config = config::Config::generate(base_dir, false)
                .wrap_err("failed to generate default config")?;
            tracing::debug!("generated config {:?}", gen_config);
            Ok(())
        }
        _ => app.print_help().wrap_err("Can't display help."),
    }
}

// for dev purpose this is useful so if the config change it automatically
// generate the default one
#[cfg(feature = "dev")]
fn get_cfg(base_dir: &str) -> Config {
    match Config::read(base_dir) {
        Ok(config) => config,
        Err(err) => {
            tracing::error!(
                "Tried to read config in {} but failed with: {}",
                base_dir,
                err
            );
            // generate(home,true) replace current config if it exists
            match config::Config::generate(base_dir, true) {
                Ok(config) => {
                    tracing::warn!("Generated default config in {}", base_dir,);
                    config
                }
                Err(err) => {
                    tracing::error!(
                        "Tried to generate config in {} but failed with: \
                         {}.Using default config (with new generated key)",
                        base_dir,
                        err
                    );
                    config::Config::default()
                }
            }
        }
    }
}

#[cfg(not(feature = "dev"))]
fn get_cfg(home: String) -> Config {
    Config::read(&home).expect("Failed to read config file.")
}
