//! The docstrings on types and their fields with `derive(Clap)` are displayed
//! in the CLI `--help`.

use clap::Clap;

use crate::shell;

#[derive(Clap)]
#[clap(version = "1.0", author = "Heliax <TODO@heliax.dev>")]
enum Opts {
    /// Run the Anoma node daemon
    Run,
    /// Reset any store state
    Reset,
}

pub fn main() {
    match Opts::parse() {
        Opts::Run => shell::run(),
        Opts::Reset => shell::reset(),
    }
}
