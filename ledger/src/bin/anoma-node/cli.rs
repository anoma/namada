//! The docstrings on types and their fields with `derive(Clap)` are displayed
//! in the CLI `--help`.
use anoma::{cli::anoma_node_cli, config::Config};
use clap::ArgMatches;
use eyre::{Context, Result};

use crate::{gossip, shell};

pub fn main() -> Result<()> {
    let matches = anoma_node_cli();

    exec_inlined(matches)
}

fn exec_inlined(matches: ArgMatches) -> Result<()> {
    match matches.subcommand() {
        Some(("run-gossip", args)) => {
            let home = args.value_of("base").unwrap_or(".anoma").to_string();
            let config = Config::new(home).unwrap();
            // TODO: parse peers into Vec<String>
            // let peers = m.values_of("peers") ???
            let rpc = args.is_present("rpc");
            let address = args.value_of("address").map(|s| s.to_string());
            let orderbook = args.is_present("orderbook");
            let dkg = args.is_present("dkg");
            Ok(gossip::run(config, rpc, orderbook, dkg, address, None))
        }
        Some(("run-ledger", args)) => {
            let home = args.value_of("base").unwrap_or(".anoma").to_string();
            let config = Config::new(home).unwrap();
            shell::run(config).wrap_err("Failed to run Anoma node")
        }
        Some(("reset", args)) => {
            let home = args.value_of("base").unwrap_or(".anoma").to_string();
            let config = Config::new(home).unwrap();
            shell::reset(config).wrap_err("Failed to reset Anoma node")
        }
        _ => {
            // should say somethng if no arguments matches?
            Ok(())
        }
    }
}
