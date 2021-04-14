//! The docstrings on types and their fields with `derive(Clap)` are displayed
//! in the CLI `--help`.
use anoma::cli;
use anoma::config::Config;
use eyre::{Context, Result};

use crate::{gossip, shell};

pub fn main() -> Result<()> {
    let mut app = cli::anoma_node_cli();

    let matches = &app.get_matches_mut();

    // here unwrap is safe as the argument has a default
    let home = matches.value_of("base").unwrap().to_string();
    let mut config = Config::read(home).expect("error config");

    match matches.subcommand() {
        Some((cli::RUN_GOSSIP_COMMAND, args)) => {
            let mut gossip_cfg = config.gossip.unwrap_or_default();
            cli::update_gossip_config(args, &mut gossip_cfg)
                .expect("failed to update config with cli option");
            gossip::run(gossip_cfg).wrap_err("Failed to run gossip service")
        }
        Some((cli::RUN_LEDGER_COMMAND, _)) => {
            let ledger_cfg = config.ledger.unwrap_or_default();
            shell::run(ledger_cfg).wrap_err("Failed to run Anoma node")
        }
        Some((cli::RESET_LEDGER_COMMAND, _)) => {
            let ledger_cfg = config.ledger.unwrap_or_default();
            shell::reset(ledger_cfg).wrap_err("Failed to reset Anoma node")
        }
        _ => app.print_help().wrap_err("Can't display help."),
    }
}
