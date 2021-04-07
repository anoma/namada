//! The CLI commands that are re-used between the executables `anoma`,
//! `anoma-node` and `anoma-client`.
//!
//! The `anoma` executable groups together the most commonly used commands
//! inlined from the node and the client. The other commands for the node or the
//! client can be dispatched via `anoma node ...` or `anoma client ...`,
//! respectively.

use clap::{Arg, ArgMatches};

const AUTHOR: &str = "Heliax <TODO@heliax.dev>";
const CLI_DESCRIPTION: &str = "Anoma cli interface.";
const CLI_VERSION: &str = "0.1.0";
const NODE_VERSION: &str = "0.1.0";
const CLIENT_VERSION: &str = "0.1.0";

pub const NODE_COMMAND: &str = "node";
pub const CLIENT_COMMAND: &str = "client";
pub const RUN_GOSSIP_COMMAND: &str = "run-gossip";
pub const RUN_LEDGER_COMMAND: &str = "run-ledger";
pub const RESET_ANOMA_COMMAND: &str = "reset-anoma";
pub const INTENT_COMMAND: &str = "intent";
pub const TX_COMMAND: &str = "tx";

// gossip args
pub const PEERS_ARG: &str = "peers";
pub const ADDRESS_ARG: &str = "address";
pub const DKG_ARG: &str = "dkg";
pub const ORDERBOOK_ARG: &str = "orderbook";
pub const RPC_ARG: &str = "rpc";
pub const MATCHMAKER: &str = "matchmaker";
pub const LEDGER_ADDRESS: &str = "ledger-address";

// client args
pub const DATA_INTENT_ARG: &str = "data";
pub const DATA_TX_ARG: &str = "data";
pub const PATH_TX_ARG: &str = "path";
pub const ORDERBOOK_INTENT_ARG: &str = "orderbook";

type App = clap::App<'static>;

pub fn anoma_inline_cli() -> App {
    return App::new(CLI_DESCRIPTION)
        .version(CLI_VERSION)
        .author(AUTHOR)
        .about(CLI_DESCRIPTION)
        .subcommand(build_run_gossip_subcommand())
        .subcommand(build_run_ledger_subcommand())
        .subcommand(build_reset_anoma_subcommand())
        .subcommand(build_client_tx_subcommand())
        .subcommand(build_client_intent_subcommand())
        .subcommand(
            App::new(NODE_COMMAND)
                .about("Node sub-commands")
                .subcommand(build_run_gossip_subcommand())
                .subcommand(build_run_ledger_subcommand())
                .subcommand(build_reset_anoma_subcommand()),
        )
        .subcommand(
            App::new(CLIENT_COMMAND)
                .about("Client sub-commands")
                .subcommand(build_client_tx_subcommand())
                .subcommand(build_client_intent_subcommand()),
        );
}

pub fn anoma_client_cli() -> App {
    return App::new(CLI_DESCRIPTION)
        .version(CLI_VERSION)
        .author(AUTHOR)
        .about("Anoma client interface.")
        .subcommand(build_client_tx_subcommand())
        .subcommand(build_client_intent_subcommand());
}

pub fn anoma_node_cli() -> App {
    return App::new(CLI_DESCRIPTION)
        .version(CLI_VERSION)
        .author(AUTHOR)
        .about("Anoma node cli.")
        .arg(
            Arg::new("base")
                .short('b')
                .long("base-dir")
                .takes_value(true)
                .required(false)
                .default_value(".anoma")
                .about("Set the base directiory."),
        )
        .subcommand(build_run_gossip_subcommand())
        .subcommand(build_run_ledger_subcommand())
        .subcommand(build_reset_anoma_subcommand());
}

fn build_client_tx_subcommand() -> App {
    App::new(TX_COMMAND)
        .version(CLIENT_VERSION)
        .about("Send an transaction.")
        .arg(
            Arg::new(DATA_TX_ARG)
            .long("data")
            .takes_value(true)
            .required(false)
            .about("The data is an arbitrary hex string that will be passed to the code when it's executed."),
        )
        .arg(
            Arg::new(PATH_TX_ARG)
            .long("path")
            .takes_value(true)
            .required(true)
            .about("The path to the wasm code to be executed."),
        )
}

fn build_client_intent_subcommand() -> App {
    App::new(INTENT_COMMAND)
        .version(CLIENT_VERSION)
        .about("Send an intent.")
        .arg(
            Arg::new(ORDERBOOK_INTENT_ARG)
            .long("orderbook")
            .takes_value(true)
            .required(true)
            .about("The orderbook address."),
        )
        .arg(
            Arg::new(DATA_INTENT_ARG)
            .long("data")
            .takes_value(true)
            .required(true)
            .about("The data of the intent, that contains all value necessary for the matchmaker."),
        )
}

fn build_run_gossip_subcommand() -> App {
    App::new(RUN_GOSSIP_COMMAND)
        .version(NODE_VERSION)
        .about("Run Anoma gossip service.")
        .arg(
            Arg::new(ADDRESS_ARG)
                .short('a')
                .long("address")
                .takes_value(true)
                .about("Gossip service address as host:port."),
        )
        .arg(
            Arg::new(PEERS_ARG)
                .short('p')
                .long("peers")
                .multiple(true)
                .takes_value(true)
                .about("List of peers to connect to."),
        )
        .arg(
            Arg::new(DKG_ARG)
                .long("dkg")
                .multiple(false)
                .takes_value(false)
                .about("Enable DKG gossip topic."),
        )
        .arg(
            Arg::new(ORDERBOOK_ARG)
                .long("orderbook")
                .multiple(false)
                .takes_value(false)
                .about("Enable Orderbook gossip topic."),
        )
        .arg(
            Arg::new(RPC_ARG)
                .long("rpc")
                .multiple(false)
                .takes_value(false)
                .about("Enable RPC service."),
        )
        .arg(
            Arg::new(MATCHMAKER)
                .long("matchmaker")
                .multiple(false)
                .takes_value(true)
                .about("The matchmaker."),
        )
        .arg(
            Arg::new(LEDGER_ADDRESS)
                .long("ledger-address")
                .multiple(false)
                .takes_value(true)
                .about("The address of the ledger as host:port."),
        )
}

fn build_run_ledger_subcommand() -> App {
    App::new(RUN_LEDGER_COMMAND)
        .version(NODE_VERSION)
        .about("Run Anoma node service.")
}

fn build_reset_anoma_subcommand() -> App {
    App::new(RESET_ANOMA_COMMAND)
        .version(NODE_VERSION)
        .about("Reset Anoma node state.")
}

pub fn parse_vector(args: &ArgMatches, field: &str) -> Vec<String> {
    return args
        .values_of(field)
        .map(|peers| {
            peers.map(|peer| peer.to_string()).collect::<Vec<String>>()
        })
        .unwrap_or(Vec::new());
}

pub fn parse_address(
    args: &ArgMatches,
    field: &str,
) -> Option<(String, String)> {
    let address = args.value_of(field).map(|s| s.to_string());
    match address {
        Some(address) => {
            let split_addresses: Vec<String> =
                address.split(":").map(|s| s.to_string()).collect();
            Some((split_addresses[0].clone(), split_addresses[1].clone()))
        }
        None => None,
    }
}

pub fn parse_bool(args: &ArgMatches, field: &str) -> bool {
    return args.is_present(field);
}

pub fn parse_string(args: &ArgMatches, field: &str) -> Option<String> {
    return args.value_of(field).map(|s| s.to_string());
}
