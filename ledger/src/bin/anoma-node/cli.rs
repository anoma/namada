//! The docstrings on types and their fields with `derive(Clap)` are displayed
//! in the CLI `--help`.
use anoma::{cli::CliBuilder, config::Config};
use eyre::{Context, Result};

use crate::{gossip, shell};

pub fn main() -> Result<()> {
    let cli = CliBuilder::new();
    let mut app = cli.anoma_node_cli();

    let matches = app.clone().get_matches();

    match matches.subcommand() {
        Some((CliBuilder::RUN_GOSSIP_COMMAND, args)) => {
            let home = matches.value_of("base").unwrap();
            println!("{}", home);
            let mut config =
                Config::new(home.to_string()).expect("error config");

            config.p2p.set_peers(args, CliBuilder::PEERS_ARG);
            config.p2p.set_address(args, CliBuilder::ADDRESS_ARG);
            config.p2p.set_dkg_topic(args, CliBuilder::DKG_ARG);
            config
                .p2p
                .set_orderbook_topic(args, CliBuilder::ORDERBOOK_ARG);
            config.p2p.set_rpc(args, CliBuilder::RPC_ARG);
            config.p2p.set_matchmaker(args, CliBuilder::MATCHMAKER);
            config
                .p2p
                .set_ledger_address(args, CliBuilder::LEDGER_ADDRESS);

            println!("{}", config.p2p.matchmaker.clone());

            return gossip::run(config)
                .wrap_err("Failed to run gossip service");
        }
        Some((CliBuilder::RUN_LEDGER_COMMAND, _)) => {
            let home = matches.value_of("base").unwrap_or(".anoma").to_string();
            let config = Config::new(home).unwrap();
            return shell::run(config).wrap_err("Failed to run Anoma node");
        }
        Some((CliBuilder::RESET_ANOMA_COMMAND, _)) => {
            let home = matches.value_of("base").unwrap_or(".anoma").to_string();
            let config = Config::new(home).unwrap();
            return shell::reset(config).wrap_err("Failed to reset Anoma node");
        }
        _ => {}
    }

    app.print_help().wrap_err("Can't display help.")
}
