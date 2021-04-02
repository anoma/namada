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
    /// Submit an intent to the orderbook
    Intent(IntentArg),
    /// Craft file to be send as intent data
    CraftIntent(CraftIntentArg),
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
pub struct IntentArg {
    /// the orderbook adress
    #[clap(short, long, default_value = "http://[::1]:39111")]
    pub orderbook: String,
    /// the data of the intent, that contains all value necessary for the
    /// matchmaker
    pub data_path: String,
}

// `anomac` subcommand for crafting intent
#[derive(Clap)]
pub struct CraftIntentArg {
    /// the orderbook adress
    #[clap(long)]
    pub addr: String,
    #[clap(long)]
    pub token_sell: String,
    #[clap(long)]
    pub amount_sell: u64,
    #[clap(long)]
    pub token_buy: String,
    #[clap(long)]
    pub amount_buy: u64,
    #[clap(long)]
    pub file: String,
}

/// The Anoma Node CLI
#[derive(Clap)]
#[clap(version = "1.0", author = AUTHOR)]
pub struct NodeOpts {
    #[clap(short, long, default_value = ".anoma")]
    pub home: String,
    /// start the rpc server
    #[clap(short, long)]
    pub rpc: bool,
    #[clap(flatten)]
    pub ops: InlinedNodeOpts,
}

// `anomad` commands inlined in `anoma`
#[derive(Clap)]
pub enum InlinedNodeOpts {
    /// Run the Anoma gossip node daemon
    RunGossip(GossipArg),
    /// Run the Anoma node daemon
    RunAnoma,
    /// Reset any store state
    ResetAnoma,
}

#[derive(Clap)]
pub struct GossipArg {
    /// Local address to listen
    #[clap(short, long)]
    pub address: Option<String>,
    #[clap(short, long)]
    /// peers to connect
    pub peers: Option<Vec<String>>,
    /// start orderbook network
    #[clap(short, long)]
    pub orderbook: bool,
    /// start dkg network
    #[clap(short, long)]
    pub dkg: bool,
    #[clap(short, long)]
    pub matchmaker: Option<String>,
    #[clap(short, long)]
    pub tx_template: Option<String>,
    #[clap(short, long)]
    pub ledger_address: Option<String>,
}
