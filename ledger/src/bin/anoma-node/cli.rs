//! The docstrings on types and their fields with `derive(Clap)` are displayed
//! in the CLI `--help`.

use anoma::{
    cli::{InlinedNodeOpts, NodeOpts},
    config::Config,
};
use clap::Clap;

use crate::shell;

pub fn main(config: Config) {
    match NodeOpts::parse() {
        NodeOpts::Inlined(ops) => exec_inlined(config, ops),
    }
}

fn exec_inlined(config: Config, ops: InlinedNodeOpts) {
    match ops {
        InlinedNodeOpts::Run => shell::run(config),
        InlinedNodeOpts::Reset => shell::reset(config),
    }
}
