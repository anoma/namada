//! The docstrings on types and their fields with `derive(Clap)` are displayed
//! in the CLI `--help`.

use crate::shell;
use anoma::cli::NodeOpts;

use clap::Clap;

#[derive(Clap)]
#[clap(version = "1.0", author = "Heliax <TODO@heliax.dev>")]
enum Opts {
    #[clap(flatten)]
    Shared(NodeOpts),
}

pub fn main() {
    match Opts::parse() {
        Opts::Shared(ops) => exec_shared(ops),
    }
}

fn exec_shared(ops: NodeOpts) {
    match ops {
        NodeOpts::Run => shell::run(),
        NodeOpts::Reset => shell::reset(),
    }
}
