//! The docstrings on types and their fields with `derive(Clap)` are displayed
//! in the CLI `--help`.
use anoma::{cli::{InlinedNodeOpts, NodeOpts}, config::AnomaConfig};
use clap::Clap;
use eyre::{Result, WrapErr};

use crate::{gossip, shell};

pub fn main() {
    let NodeOpts { home, rpc, ops } = NodeOpts::parse();
    let config = AnomaConfig::new(home).unwrap();
    exec_inlined(config, rpc, ops)
}

fn exec_inlined(config: AnomaConfig, rpc: bool, ops: InlinedNodeOpts) {
    match ops {
        InlinedNodeOpts::RunOrderbook(arg) => {
            gossip::run(config, rpc, arg.local_address, arg.peers, arg.topics)
        }
        InlinedNodeOpts::RunAnoma => {
            shell::run(config);
            Ok(())
        }
        InlinedNodeOpts::ResetAnoma => {
            shell::reset(config);
            Ok(())
        }
    }
}
