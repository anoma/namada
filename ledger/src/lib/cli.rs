//! The CLI commands that are re-used between the executables `anoma`,
//! `anoma-client` and `anoma-node`

use clap::Clap;

// Anoma client
#[derive(Clap)]
pub enum ClientOpts {
    /// Transfer
    Transfer(Transfer),
}
/// A subcommand for controlling trasfers
#[derive(Clap)]
pub struct Transfer {
    /// An example command
    #[clap(short)]
    pub count: u64,
}


// Anoma node
#[derive(Clap)]
pub enum NodeOpts {
    /// Run the Anoma node daemon
    Run,
    /// Reset any store state
    Reset,
}
