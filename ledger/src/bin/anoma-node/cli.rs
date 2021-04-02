//! The docstrings on types and their fields with `derive(Clap)` are displayed
//! in the CLI `--help`.
use anoma::{cli::CliBuilder, config::Config};
use clap::ArgMatches;
use eyre::{Context, Result};

use crate::{gossip, shell};

pub fn main() -> Result<()> {
    let matches = CliBuilder::new().anoma_node_cli();

    exec_inlined(matches)
}

fn exec_inlined(matches: ArgMatches) -> Result<()> {
    match matches.subcommand() {
        Some((CliBuilder::RUN_GOSSIP_COMMAND, args)) => {
            let home = matches.value_of("base").unwrap_or_default();
            let config = Config::new(home.to_string()).unwrap();
            let peers = args.values_of("peers").map(|peers| {
                peers.map(|peer| peer.to_string()).collect::<Vec<String>>()
            });
            let rpc = args.is_present("rpc");
            let address = args.value_of("address").map(|s| s.to_string());
            let orderbook = args.is_present("orderbook");
            let dkg = args.is_present("dkg");
            Ok(gossip::run(config, rpc, orderbook, dkg, address, peers))
        }
        Some((CliBuilder::RUN_LEDGER_COMMAND, _)) => {
            let home = matches.value_of("base").unwrap_or(".anoma").to_string();
            let config = Config::new(home).unwrap();
            shell::run(config).wrap_err("Failed to run Anoma node")
        }
        Some((CliBuilder::RESET_ANOMA_COMMAND, _)) => {
            let home = matches.value_of("base").unwrap_or(".anoma").to_string();
            let config = Config::new(home).unwrap();
            shell::reset(config).wrap_err("Failed to reset Anoma node")
        }
        _ => Ok(()),
    }
}
