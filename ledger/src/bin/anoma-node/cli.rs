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
            let mut config = Config::new(home.to_string()).unwrap();

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

            gossip::run(config).wrap_err("Failed to run gossip service")
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

// fn exec_inlined(config: Config, rpc: bool, ops: InlinedNodeOpts) -> Result<()> {
//     match ops {
//         InlinedNodeOpts::RunGossip(arg) => gossip::run(
//             config,
//             rpc,
//             arg.orderbook,
//             arg.dkg,
//             arg.address,
//             arg.peers,
//             arg.matchmaker,
//             arg.ledger_address,
//         )
//         .wrap_err("Failed to run gossip service"),
//         InlinedNodeOpts::RunAnoma => {
