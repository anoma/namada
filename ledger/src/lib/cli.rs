//! The CLI commands that are re-used between the executables `anoma`,
//! `anoma-node` and `anoma-client`.
//!
//! The `anoma` exectuable groups together the most commonly used commands
//! inlined from the node and the client. The other commands for the node or the
//! client can be dispatched via `anoma node ...` or `anoma client ...`,
//! respectively.

use clap::{Clap, FromArgMatches, IntoApp};

/// The Anoma CLI
#[derive(Clap)]
#[clap(version = "1.0", author = "Heliax <TODO@heliax.dev>")]
pub enum AnomaOpts {
    /// Anoma node commands
    Node(LazyOpt),
    /// Anoma client commands
    Client(LazyOpt),
    #[clap(flatten)]
    InlinedNode(NodeOpts),
    #[clap(flatten)]
    InlinedClient(ClientOpts),
}

/// The Anoma Client CLI
#[derive(Clap)]
#[clap(version = "1.0", author = "Heliax <TODO@heliax.dev>")]
pub enum ClientOpts {
    #[clap(flatten)]
    Inlined(InlinedClientOpts),
}

// `anomac` commands inlined in `anoma`
#[derive(Clap)]
pub enum InlinedClientOpts {
    /// Transfer
    Transfer(Transfer),
}

// `anomac` subcommand for controlling trasfers
#[derive(Clap)]
pub struct Transfer {
    /// An example command
    #[clap(short)]
    pub count: u64,
}

/// The Anoma Node CLI
#[derive(Clap)]
#[clap(version = "1.0", author = "Heliax <TODO@heliax.dev>")]
pub enum NodeOpts {
    #[clap(flatten)]
    Inlined(InlinedNodeOpts),
}

// `anomad` commands inlined in `anoma`
#[derive(Clap)]
pub enum InlinedNodeOpts {
    /// Run the Anoma node daemon
    Run,
    /// Reset any store state
    Reset,
}

/// The lazy opt is used for node and client sub-commands, it doesn't actually
/// parse any commands as the commands are dispatched to `anoma-node` and
/// `anoma-client`, respectively.
pub struct LazyOpt;
impl IntoApp for LazyOpt {
    fn into_app<'help>() -> clap::App<'help> {
        clap::App::default()
    }

    fn augment_clap(app: clap::App<'_>) -> clap::App<'_> {
        app
    }
}
impl FromArgMatches for LazyOpt {
    fn from_arg_matches(_matches: &clap::ArgMatches) -> Self {
        Self
    }
}
