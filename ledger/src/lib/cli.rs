//! The CLI commands that are re-used between the executables `anoma`,
//! `anoma-node` and `anoma-client`.
//!
//! The `anoma` executable groups together the most commonly used commands
//! inlined from the node and the client. The other commands for the node or the
//! client can be dispatched via `anoma node ...` or `anoma client ...`,
//! respectively.

use clap::Clap;

const AUTHOR: &str = "Heliax <TODO@heliax.dev>";

// Examples of how to use Clap v3: https://github.com/clap-rs/clap/tree/v3.0.0-beta.2/clap_derive
// Use `cargo expand --lib cli` to see the expanded macros

/// The Anoma CLI
#[derive(Clap)]
#[clap(version = "1.0", author = AUTHOR)]
pub enum AnomaOpts {
    InlinedNode(NodeOpts),
    #[clap(flatten)]
    InlinedClient(ClientOpts),
}

/// The Anoma Client CLI
#[derive(Clap)]
#[clap(version = "1.0", author = AUTHOR)]
pub enum ClientOpts {
    #[clap(flatten)]
    Inlined(InlinedClientOpts),
}

// `anomac` commands inlined in `anoma`
#[derive(Clap)]
pub enum InlinedClientOpts {
    /// Submit a transaction and wait for the result
    Tx(Tx),
    Gossip(Gossip),
}

// `anomac` subcommand for submitting transactions
#[derive(Clap)]
pub struct Tx {
    /// The path to the wasm code to be executed
    #[clap(long, short)]
    pub code_path: String,
    /// The data is an arbitrary hex string that will be passed to the code
    /// when it's executed
    #[clap(long, short)]
    pub data_hex: Option<String>,
}
// `anomac` subcommand for controlling intent
#[derive(Clap)]
pub struct Gossip {
    /// An example command
    #[clap(short, long)]
    pub orderbook: String,
    #[clap(short, long)]
    pub data: String,
}

/// The Anoma Node CLI
#[derive(Clap)]
#[clap(version = "1.0", author = AUTHOR)]
pub struct NodeOpts {
    #[clap(short, long, default_value = ".anoma")]
    pub home: String,
    #[clap(short, long)]
    pub rpc: bool,
    #[clap(flatten)]
    pub ops: InlinedNodeOpts,
}

// `anomad` commands inlined in `anoma`
#[derive(Clap)]
pub enum InlinedNodeOpts {
    /// Run the Anoma gossip node daemon
    RunOrderbook(Orderbook),
    /// Run the Anoma node daemon
    RunAnoma,
    /// Reset any store state
    ResetAnoma,
}

#[derive(Clap)]
pub struct Orderbook {
    #[clap(short, long)]
    pub local_address: Option<String>,
    #[clap(short, long)]
    pub peers: Option<Vec<String>>,
    #[clap(short, long)]
    pub topics: Option<Vec<String>>,
}
