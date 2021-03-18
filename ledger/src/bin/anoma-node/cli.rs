//! The docstrings on types and their fields with `derive(Clap)` are displayed
//! in the CLI `--help`.
use anoma::{cli::{InlinedNodeOpts, NodeOpts}, config::AnomaConfig};
use clap::Clap;

use crate::{gossip, shell};

pub fn main() {
    let NodeOpts { home, rpc, ops } = NodeOpts::parse();
    let anoma_config = AnomaConfig::new(home).unwrap();
    exec_inlined(anoma_config, rpc, ops)
}

fn exec_inlined(a_config: AnomaConfig, rpc: bool, ops: InlinedNodeOpts) {
    match ops {
        InlinedNodeOpts::RunOrderbook(arg) => {
            gossip::run(a_config, rpc, arg.local_address, arg.peers, arg.topics)
        }
        InlinedNodeOpts::RunAnoma => {
            shell::run(a_config);
            Ok(())
        }
        InlinedNodeOpts::ResetAnoma => {
            shell::reset(a_config);
            Ok(())
        }
    }
    .unwrap();
}
