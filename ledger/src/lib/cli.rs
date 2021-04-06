//! The CLI commands that are re-used between the executables `anoma`,
//! `anoma-node` and `anoma-client`.
//!
//! The `anoma` executable groups together the most commonly used commands
//! inlined from the node and the client. The other commands for the node or the
//! client can be dispatched via `anoma node ...` or `anoma client ...`,
//! respectively.

use clap::{App, Arg, ArgMatches};

const AUTHOR: &str = "Heliax <TODO@heliax.dev>";
const CLI_DESCRIPTION: &str = "Anoma cli interface.";
const CLI_VERSION: &str = "0.1.0";
const NODE_VERSION: &str = "0.1.0";
const CLIENT_VERSION: &str = "0.1.0";

pub struct CliBuilder {}

impl CliBuilder {
    pub const NODE_COMMAND: &'static str = "node";
    pub const CLIENT_COMMAND: &'static str = "client";
    pub const RUN_GOSSIP_COMMAND: &'static str = "run-gossip";
    pub const RUN_LEDGER_COMMAND: &'static str = "run-ledger";
    pub const RESET_ANOMA_COMMAND: &'static str = "reset-anoma";
    pub const INTENT_COMMAND: &'static str = "intent";
    pub const TX_COMMAND: &'static str = "tx";

    // gossip args
    pub const PEERS_ARG: &'static str = "peers";
    pub const ADDRESS_ARG: &'static str = "address";
    pub const DKG_ARG: &'static str = "dkg";
    pub const ORDERBOOK_ARG: &'static str = "orderbook";
    pub const RPC_ARG: &'static str = "rpc";
    pub const MATCHMAKER: &'static str = "matchmaker";
    pub const LEDGER_ADDRESS: &'static str = "ledger-address";

    // client args
    pub const DATA_INTENT_ARG: &'static str = "data";
    pub const DATA_TX_ARG: &'static str = "data";
    pub const PATH_TX_ARG: &'static str = "path";
    pub const ORDERBOOK_INTENT_ARG: &'static str = "orderbook";

    pub fn new() -> Self {
        Self {}
    }

    pub fn anoma_inline_cli(&self) -> App {
        return App::new(CLI_DESCRIPTION)
            .version(CLI_VERSION)
            .author(AUTHOR)
            .about(CLI_DESCRIPTION)
            .subcommand(CliBuilder::build_run_gossip_subcommand(&self))
            .subcommand(CliBuilder::build_run_ledger_subcommand(&self))
            .subcommand(CliBuilder::build_reset_anoma_subcommand(&self))
            .subcommand(CliBuilder::build_client_tx_subcommand(&self))
            .subcommand(CliBuilder::build_client_intent_subcommand(&self))
            .subcommand(
                App::new(Self::NODE_COMMAND)
                    .about("Node inline subcommands")
                    .subcommand(CliBuilder::build_run_gossip_subcommand(&self))
                    .subcommand(CliBuilder::build_run_ledger_subcommand(&self))
                    .subcommand(CliBuilder::build_reset_anoma_subcommand(
                        &self,
                    )),
            )
            .subcommand(
                App::new(Self::CLIENT_COMMAND)
                    .about("Client inline subcommands")
                    .subcommand(CliBuilder::build_client_tx_subcommand(&self))
                    .subcommand(CliBuilder::build_client_intent_subcommand(
                        &self,
                    )),
            );
    }

    pub fn anoma_client_cli(&self) -> App {
        return App::new(CLI_DESCRIPTION)
            .version(CLI_VERSION)
            .author(AUTHOR)
            .about("Anoma client interface.")
            .subcommand(CliBuilder::build_client_tx_subcommand(&self))
            .subcommand(CliBuilder::build_client_intent_subcommand(&self));
    }

    pub fn anoma_node_cli(&self) -> App {
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
            .subcommand(CliBuilder::build_run_gossip_subcommand(&self))
            .subcommand(CliBuilder::build_run_ledger_subcommand(&self))
            .subcommand(CliBuilder::build_reset_anoma_subcommand(&self));
    }

    fn build_client_tx_subcommand(&self) -> App {
        App::new(Self::TX_COMMAND)
            .version(CLIENT_VERSION)
            .about("Send an transaction.")
            .arg(
                Arg::new(Self::DATA_TX_ARG)
                .long("data")
                .takes_value(true)
                .required(true)
                .about("The data of the intent, that contains all value necessary for the matchmaker."),
            )
            .arg(
                Arg::new(Self::PATH_TX_ARG)
                .long("path")
                .takes_value(true)
                .required(true)
                .about("The path to the wasm code to be executed."),
            )
    }

    fn build_client_intent_subcommand(&self) -> App {
        App::new(Self::INTENT_COMMAND)
            .version(CLIENT_VERSION)
            .about("Send an intent.")
            .arg(
                Arg::new(Self::ORDERBOOK_INTENT_ARG)
                .long("orderbook")
                .takes_value(true)
                .required(true)
                .about("The orderbook address."),
            )
            .arg(
                Arg::new(Self::DATA_INTENT_ARG)
                .long("data")
                .takes_value(true)
                .required(true)
                .about("The data is an arbitrary hex string that will be passed to the code when it's executed."),
            )
    }

    fn build_run_gossip_subcommand(&self) -> App {
        App::new(Self::RUN_GOSSIP_COMMAND)
            .version(NODE_VERSION)
            .about("Run Anoma gossip service.")
            .arg(
                Arg::new(Self::ADDRESS_ARG)
                    .short('a')
                    .long("address")
                    .takes_value(true)
                    .about("Gossip service address as host:port."),
            )
            .arg(
                Arg::new(Self::PEERS_ARG)
                    .short('p')
                    .long("peers")
                    .multiple(true)
                    .takes_value(true)
                    .about("List of peers to connect to."),
            )
            .arg(
                Arg::new(Self::DKG_ARG)
                    .long("dkg")
                    .multiple(false)
                    .takes_value(false)
                    .about("Enable DKG gossip topic."),
            )
            .arg(
                Arg::new(Self::ORDERBOOK_ARG)
                    .long("orderbook")
                    .multiple(false)
                    .takes_value(false)
                    .about("Enable Orderbook gossip topic."),
            )
            .arg(
                Arg::new(Self::RPC_ARG)
                    .long("rpc")
                    .multiple(false)
                    .takes_value(false)
                    .about("Enable RPC service."),
            )
            .arg(
                Arg::new(Self::MATCHMAKER)
                    .long("matchmaker")
                    .multiple(false)
                    .takes_value(true)
                    .about("The matchmaker."),
            )
            .arg(
                Arg::new(Self::LEDGER_ADDRESS)
                    .long("ledger-address")
                    .multiple(false)
                    .takes_value(true)
                    .about("The address of the ledger as host:port."),
            )
    }

    fn build_run_ledger_subcommand(&self) -> App {
        App::new(Self::RUN_LEDGER_COMMAND)
            .version(NODE_VERSION)
            .about("Run Anoma node service.")
    }

    fn build_reset_anoma_subcommand(&self) -> App {
        App::new(Self::RESET_ANOMA_COMMAND)
            .version(NODE_VERSION)
            .about("Reset Anoma node state.")
    }
}
