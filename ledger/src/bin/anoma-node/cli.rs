//! The docstrings on types and their fields with `derive(Clap)` are displayed
//! in the CLI `--help`.

use anoma::cli::{InlinedNodeOpts, NodeOpts};
use clap::Clap;

use crate::shell;

pub fn main() {
    match NodeOpts::parse() {
        NodeOpts::Inlined(ops) => exec_inlined(ops),
    }
}

fn exec_inlined(ops: InlinedNodeOpts) {
    match ops {
        InlinedNodeOpts::Run => shell::run(),
        InlinedNodeOpts::Reset => shell::reset(),
    }
}
