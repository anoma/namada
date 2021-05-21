//! The docstrings on types and their fields with `derive(Clap)` are displayed
//! in the CLI `--help`.
use anoma::config::Config;
use anoma::node::{gossip, shell};
use anoma::{cli, config};
use eyre::{Context, Result};

pub fn main() -> Result<()> {
    let mut app = cli::anoma_node_cli();

    let matches = &app.get_matches_mut();

    // here unwrap is safe to use req as the argument even it's not mandatory
    // because it has a default
    let home = cli::parse_string_req(&matches, cli::BASE_ARG);

    match matches.subcommand() {
        Some((cli::RUN_GOSSIP_COMMAND, args)) => {
            let config = get_cfg(home);
            let mut gossip_cfg = config.intent_broadcaster.unwrap_or_default();
            cli::update_gossip_config(args, &mut gossip_cfg)
                .expect("failed to update config with cli option");
            gossip::run(gossip_cfg).wrap_err("Failed to run gossip service")
        }
        Some((cli::RUN_LEDGER_COMMAND, _)) => {
            let config = get_cfg(home);
            let ledger_cfg = config.ledger.unwrap_or_default();
            shell::run(ledger_cfg).wrap_err("Failed to run Anoma node")
        }
        Some((cli::RESET_LEDGER_COMMAND, _)) => {
            let config = get_cfg(home);
            let ledger_cfg = config.ledger.unwrap_or_default();
            shell::reset(ledger_cfg).wrap_err("Failed to reset Anoma node")
        }
        Some((cli::GENERATE_CONFIG_COMMAND, _args)) => {
            let gen_config = config::Config::generate(&home, false)
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
fn get_cfg(home: String) -> Config {
    match Config::read(&home) {
        Ok(config) => config,
        Err(err) => {
            tracing::error!(
                "Tried to read config in {} but failed with: {}",
                home,
                err
            );
            // generate(home,true) replace current config if it exists
            match config::Config::generate(&home, true) {
                Ok(config) => {
                    tracing::warn!("Generated default config in {}", home,);
                    config
                }
                Err(err) => {
                    tracing::error!(
                        "Tried to generate config in {} but failed with: {}. \
                         Using default config (with new generated key)",
                        home,
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
