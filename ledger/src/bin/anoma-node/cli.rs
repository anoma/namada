//! The docstrings on types and their fields with `derive(Clap)` are displayed
//! in the CLI `--help`.
use anoma::{cli, config::Config};
use eyre::{Context, Result};

use crate::{gossip, shell};

pub fn main() -> Result<()> {
    let mut app = cli::anoma_node_cli();

    let matches = app.clone().get_matches();

    match matches.subcommand() {
        Some((cli::RUN_GOSSIP_COMMAND, args)) => {
            // here unwrap is safe as the argument has a default
            let home = matches.value_of("base").unwrap().to_string();
            let mut config = Config::new(home).expect("error config");

            let peers = cli::parse_vector(args, cli::PEERS_ARG);
            config.p2p.set_peers(peers);

            let address = cli::parse_address(args, cli::ADDRESS_ARG);
            config.p2p.set_address(address);

            let dkg = cli::parse_bool(args, cli::DKG_ARG);
            config.p2p.set_dkg_topic(dkg);

            let orderbook = cli::parse_bool(args, cli::ORDERBOOK_ARG);
            config.p2p.set_orderbook_topic(orderbook);

            let rpc = cli::parse_bool(args, cli::RPC_ARG);
            config.p2p.set_rpc(rpc);

            let matchmaker = cli::parse_string(args, cli::MATCHMAKER);
            config.p2p.set_matchmaker(matchmaker);

            let ledger_address = cli::parse_address(args, cli::LEDGER_ADDRESS);
            config.p2p.set_ledger_address(ledger_address);

            gossip::run(config).wrap_err("Failed to run gossip service")
        }
        Some((cli::RUN_LEDGER_COMMAND, _)) => {
            // here unwrap is safe as the argument has a default
            let home = matches.value_of("base").unwrap().to_string();
            let config = Config::new(home).unwrap();
            shell::run(config).wrap_err("Failed to run Anoma node")
        }
        Some((cli::RESET_ANOMA_COMMAND, _)) => {
            // here unwrap is safe as the argument has a default
            let home = matches.value_of("base").unwrap().to_string();
            let config = Config::new(home).unwrap();
            shell::reset(config).wrap_err("Failed to reset Anoma node")
        }
        _ => app.print_help().wrap_err("Can't display help."),
    }
}
