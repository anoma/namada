//! The docstrings on types and their fields with `derive(Clap)` are displayed
//! in the CLI `--help`.
use anoma::cli;
use anoma::config::Config;
use eyre::{Context, Result};

use crate::{gossip, shell};

pub fn main() -> Result<()> {
    let mut app = cli::anoma_node_cli();

    let matches = app.clone().get_matches();

    // here unwrap is safe as the argument has a default
    let home = matches.value_of("base").unwrap().to_string();
    let mut config = Config::new(home).expect("error config");

    match matches.subcommand() {
        Some((cli::RUN_GOSSIP_COMMAND, args)) => {
            // TODO: this could be refactored into a function that updates
            // config
            cli::parse_hashset(args, cli::PEERS_ARG)
                .map(|peers| config.gossip.peers = peers);

            let address = cli::parse_address(args, cli::ADDRESS_ARG);
            config.gossip.set_address(address);

            config
                .gossip
                .enable_dkg(cli::parse_bool(args, cli::DKG_ARG));

            if cli::parse_bool(args, cli::ORDERBOOK_ARG) {
                let matchmaker_pgm =
                    cli::parse_string(args, cli::MATCHMAKER_ARG);
                let tx_template = cli::parse_string(args, cli::TX_TEMPLATE_ARG);
                let ledger_address =
                    cli::parse_address(args, cli::LEDGER_ADDRESS_ARG);
                let matchmaker_cfg = if let (
                    Some(matchmaker_pgm),
                    Some(tx_template),
                    Some((ledger_host, ledger_port)),
                ) =
                    (matchmaker_pgm, tx_template, ledger_address)
                {
                    Some(anoma::config::Matchmaker::new(
                        matchmaker_pgm,
                        tx_template,
                        ledger_host,
                        ledger_port,
                    ))
                } else {
                    None
                };
                config.gossip.enable_orderbook(Some(
                    anoma::config::Orderbook::new(matchmaker_cfg),
                ));
            }
            config.gossip.rpc = cli::parse_bool(args, cli::RPC_ARG);

            gossip::run(config).wrap_err("Failed to run gossip service")
        }
        Some((cli::RUN_LEDGER_COMMAND, _)) => {
            shell::run(config).wrap_err("Failed to run Anoma node")
        }
        Some((cli::RESET_LEDGER_COMMAND, _)) => {
            shell::reset(config).wrap_err("Failed to reset Anoma node")
        }
        _ => app.print_help().wrap_err("Can't display help."),
    }
}
