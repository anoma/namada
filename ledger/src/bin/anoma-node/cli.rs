//! The docstrings on types and their fields with `derive(Clap)` are displayed
//! in the CLI `--help`.
use anoma::cli::{InlinedNodeOpts, NodeOpts};
use anoma::config::Config;
use clap::Clap;
use eyre::{Result, WrapErr};

use crate::{gossip, shell};

pub fn main() -> Result<()> {
    let NodeOpts { home, rpc, ops } = NodeOpts::parse();
    let config = Config::new(home).unwrap();
    exec_inlined(config, rpc, ops)
}

fn exec_inlined(config: Config, rpc: bool, ops: InlinedNodeOpts) -> Result<()> {
    match ops {
        InlinedNodeOpts::RunGossip(arg) => gossip::run(
            config,
            rpc,
            arg.orderbook,
            arg.dkg,
            arg.address,
            arg.peers,
            arg.matchmaker,
            arg.tx_template,
            arg.ledger_address,
        )
        .wrap_err("Failed to run gossip service"),
        InlinedNodeOpts::RunAnoma => {
            shell::run(config).wrap_err("Failed to run Anoma node")
        }
        InlinedNodeOpts::ResetAnoma => {
            shell::reset(config).wrap_err("Failed to reset Anoma node")
        }
    }
}
