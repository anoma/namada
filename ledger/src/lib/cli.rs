//! The CLI commands that are re-used between the executables `anoma`,
//! `anoma-node` and `anoma-client`.
//!
//! The `anoma` executable groups together the most commonly used commands
//! inlined from the node and the client. The other commands for the node or the
//! client can be dispatched via `anoma node ...` or `anoma client ...`,
//! respectively.

use std::collections::HashMap;

use clap::{App, Arg, ArgMatches, Clap, Subcommand};
use maplit::hashmap;

const AUTHOR: &str = "Heliax <TODO@heliax.dev>";
const APP_DESCRIPTION: &str = "Anoma node daemon";
const VERSION: &str = "0.1.0";

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
    pub data: String,
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
}

pub struct CliBuilder<'a> {
    common: HashMap<&'a str, &'a str>,
    client: HashMap<&'a str, &'a str>,
    node: HashMap<&'a str, &'a str>,
    inline: HashMap<&'a str, &'a str>,
    args: HashMap<&'a str, HashMap<&'a str, &'a str>>,
}

impl CliBuilder<'_> {
    pub fn new() -> Self {
        Self {
            common: hashmap! {
                "author" => "Heliax <TODO@heliax.dev>.",
                "version" => "0.1.0",
                "description" => "Anoma node daemon."
            },
            client: hashmap! {
                "about" => "Anoma node client.",
                "intent_command" => "intent",
                "intent_command_about" => "Send an intent",
                "tx_command" => "tx",
                "tx_command_about" => "Send an transaction"
            },
            node: hashmap! {
                "about" => "Anoma node daemon.",
                "run_gossip_command" => "run-gossip",
                "run_gossip_command_about" => "Run Anoma gossip service.",
                "tx_command" => "tx",
                "tx_command_about" => "Send an transaction",
                "run_ledger_command" => "run-ledger",
                "run_ledger_command_about" => "Run Anoma gossip service.",
                "reset_command" => "reset-anoma",
                "reset_command_about" => "Reset Anoma node state."
            },
            inline: hashmap! {
                "node_command" => "node",
                "node_command_about" => "Run a node command.",
                "client_command" => "client",
                "node_command_about" => "Run a client command.",
            },
            args: hashmap! {
                "intent_data" =>  hashmap! {
                    "name" => "data",
                    "long" => "data",
                    "about" => "The data of the intent, that contains all value necessary for the matchmaker."
                },
                "intent_orderbook" =>  hashmap! {
                    "name" => "orderbook",
                    "long" => "orderbook",
                    "about" => "The orderbook address."
                },
                "tx_data" =>  hashmap! {
                    "name" => "data",
                    "long" => "data",
                    "about" => "The data is an arbitrary hex string that will be passed to the code when it's executed."
                },
                "tx_path" =>  hashmap! {
                    "name" => "path",
                    "long" => "path",
                    "about" => "The path to the wasm code to be executed."
                },
                "base" =>  hashmap! {
                    "name" => "base",
                    "short" => "b",
                    "long" => "base-dir",
                    "about" => "Set the base directiory."
                },
                "gossip_address" =>  hashmap! {
                    "name" => "address",
                    "short" => "a",
                    "long" => "address",
                    "about" => "Gossip service address."
                },
                "peers" =>  hashmap! {
                    "name" => "peers",
                    "short" => "p",
                    "long" => "peers",
                    "about" => "List of peers."
                },
                "dkg" =>  hashmap! {
                    "name" => "dkg",
                    "long" => "dkg",
                    "about" => "Enable DKG gossip topic."
                },
                "orderbook" =>  hashmap! {
                    "name" => "orderbook",
                    "long" => "orderbook",
                    "about" => "Enable ORDERBOOK gossip topic."
                },
                "rpc" =>  hashmap! {
                    "name" => "rpc",
                    "long" => "rpc",
                    "about" => "Enable RPC service."
                },
            },
        }
    }

    pub fn anoma_inline_cli(&self) -> ArgMatches {
        return App::new(CliBuilder::get_from_map(
            &self,
            "common",
            "description",
        ))
        .version(CliBuilder::get_from_map(&self, "common", "version"))
        .author(CliBuilder::get_from_map(&self, "common", "author"))
        .about(CliBuilder::get_from_map(&self, "client", "about"))
        .subcommand(CliBuilder::build_run_gossip_subcommand(&self))
        .subcommand(CliBuilder::build_run_ledger_subcommand(&self))
        .subcommand(CliBuilder::build_reset_anoma_subcommand(&self))
        .subcommand(CliBuilder::build_client_tx_subcommand(&self))
        .subcommand(CliBuilder::build_client_intent_subcommand(&self))
        .subcommand(
            App::new(CliBuilder::get_from_map(&self, "inline", "node_command"))
                .about(CliBuilder::get_from_map(
                    &self,
                    "inline",
                    "node_command_about",
                ))
                .subcommand(CliBuilder::build_run_gossip_subcommand(&self))
                .subcommand(CliBuilder::build_run_ledger_subcommand(&self))
                .subcommand(CliBuilder::build_reset_anoma_subcommand(&self)),
        )
        .subcommand(
            App::new(CliBuilder::get_from_map(
                &self,
                "inline",
                "client_command",
            ))
            .about(CliBuilder::get_from_map(
                &self,
                "inline",
                "client_command_about",
            ))
            .subcommand(CliBuilder::build_client_tx_subcommand(&self))
            .subcommand(CliBuilder::build_client_intent_subcommand(&self)),
        )
        .get_matches();
    }

    pub fn anoma_client_cli(&self) -> ArgMatches {
        return App::new(CliBuilder::get_from_map(
            &self,
            "common",
            "description",
        ))
        .version(CliBuilder::get_from_map(&self, "common", "version"))
        .author(CliBuilder::get_from_map(&self, "common", "author"))
        .about(CliBuilder::get_from_map(&self, "client", "about"))
        .subcommand(CliBuilder::build_client_tx_subcommand(&self))
        .subcommand(CliBuilder::build_client_intent_subcommand(&self))
        .get_matches();
    }

    pub fn anoma_node_cli(&self) -> ArgMatches {
        return App::new(CliBuilder::get_from_map(
            &self,
            "common",
            "description",
        ))
        .version(CliBuilder::get_from_map(&self, "common", "version"))
        .author(CliBuilder::get_from_map(&self, "common", "author"))
        .about(CliBuilder::get_from_map(&self, "node", "about"))
        .arg(
            Arg::new(CliBuilder::get_from_map_arg(&self, "base", "name"))
                .short(
                    CliBuilder::get_from_map_arg(&self, "base", "short")
                        .chars()
                        .next()
                        .unwrap(),
                )
                .long(CliBuilder::get_from_map_arg(&self, "base", "long"))
                .takes_value(true)
                .required(false)
                .about(CliBuilder::get_from_map_arg(&self, "base", "about")),
        )
        .subcommand(CliBuilder::build_run_gossip_subcommand(&self))
        .subcommand(CliBuilder::build_run_ledger_subcommand(&self))
        .subcommand(CliBuilder::build_reset_anoma_subcommand(&self))
        .get_matches();
    }

    fn build_client_tx_subcommand(&self) -> App {
        App::new(CliBuilder::get_from_map(&self, "client", "tx_command"))
            .about(CliBuilder::get_from_map(
                &self,
                "client",
                "tx_command_about",
            ))
            .arg(
                Arg::new(CliBuilder::get_from_map_arg(
                    &self, "tx_path", "name",
                ))
                .long(CliBuilder::get_from_map_arg(&self, "tx_path", "long"))
                .takes_value(true)
                .required(true)
                .about(CliBuilder::get_from_map_arg(&self, "tx_path", "about")),
            )
            .arg(
                Arg::new(CliBuilder::get_from_map_arg(
                    &self,
                    "intent_data",
                    "name",
                ))
                .long(CliBuilder::get_from_map_arg(
                    &self,
                    "intent_data",
                    "long",
                ))
                .takes_value(true)
                .required(true)
                .about(CliBuilder::get_from_map_arg(
                    &self,
                    "intent_data",
                    "about",
                )),
            )
    }

    fn build_client_intent_subcommand(&self) -> App {
        App::new(CliBuilder::get_from_map(&self, "client", "intent_command"))
            .about(CliBuilder::get_from_map(
                &self,
                "client",
                "intent_command_about",
            ))
            .arg(
                Arg::new(CliBuilder::get_from_map_arg(
                    &self,
                    "intent_orderbook",
                    "name",
                ))
                .long(CliBuilder::get_from_map_arg(
                    &self,
                    "intent_orderbook",
                    "long",
                ))
                .takes_value(true)
                .required(true)
                .about(CliBuilder::get_from_map_arg(
                    &self,
                    "intent_orderbook",
                    "about",
                )),
            )
            .arg(
                Arg::new(CliBuilder::get_from_map_arg(
                    &self, "tx_data", "name",
                ))
                .long(CliBuilder::get_from_map_arg(&self, "tx_data", "long"))
                .takes_value(true)
                .required(true)
                .about(CliBuilder::get_from_map_arg(&self, "tx_data", "about")),
            )
    }

    fn build_run_gossip_subcommand(&self) -> App {
        App::new(CliBuilder::get_from_map(
            &self,
            "node",
            "run_gossip_command",
        ))
        .about(CliBuilder::get_from_map(
            &self,
            "node",
            "run_gossip_command_about",
        ))
        .arg(
            Arg::new(CliBuilder::get_from_map_arg(
                &self,
                "gossip_address",
                "name",
            ))
            .short(
                CliBuilder::get_from_map_arg(&self, "gossip_address", "short")
                    .chars()
                    .next()
                    .unwrap(),
            )
            .long(CliBuilder::get_from_map_arg(
                &self,
                "gossip_address",
                "long",
            ))
            .takes_value(true)
            .about(CliBuilder::get_from_map_arg(
                &self,
                "gossip_address",
                "about",
            )),
        )
        .arg(
            Arg::new(CliBuilder::get_from_map_arg(&self, "peers", "name"))
                .short(
                    CliBuilder::get_from_map_arg(&self, "peers", "short")
                        .chars()
                        .next()
                        .unwrap(),
                )
                .long(CliBuilder::get_from_map_arg(&self, "peers", "long"))
                .multiple(true)
                .takes_value(true)
                .about(CliBuilder::get_from_map_arg(&self, "peers", "about")),
        )
        .arg(
            Arg::new(CliBuilder::get_from_map_arg(&self, "dkg", "name"))
                .long(CliBuilder::get_from_map_arg(&self, "dkg", "long"))
                .multiple(false)
                .takes_value(false)
                .about(CliBuilder::get_from_map_arg(&self, "dkg", "about")),
        )
        .arg(
            Arg::new(CliBuilder::get_from_map_arg(&self, "orderbook", "name"))
                .long(CliBuilder::get_from_map_arg(&self, "orderbook", "long"))
                .multiple(false)
                .takes_value(false)
                .about(CliBuilder::get_from_map_arg(
                    &self,
                    "orderbook",
                    "about",
                )),
        )
        .arg(
            Arg::new(CliBuilder::get_from_map_arg(&self, "rpc", "name"))
                .long(CliBuilder::get_from_map_arg(&self, "rpc", "long"))
                .multiple(false)
                .takes_value(false)
                .about(CliBuilder::get_from_map_arg(&self, "rpc", "about")),
        )
    }

    fn build_run_ledger_subcommand(&self) -> App {
        App::new(CliBuilder::get_from_map(
            &self,
            "node",
            "run_ledger_command",
        ))
        .about(CliBuilder::get_from_map(
            &self,
            "node",
            "run_ledger_command_about",
        ))
    }

    fn build_reset_anoma_subcommand(&self) -> App {
        App::new(CliBuilder::get_from_map(&self, "node", "reset_command"))
            .about(CliBuilder::get_from_map(
                &self,
                "node",
                "reset_command_about",
            ))
    }

    fn get_from_map(&self, key: &str, sub_key: &str) -> &str {
        println!("{}", key);
        println!("{}", sub_key);
        match key {
            "common" => self.common.get(sub_key).map(|res| *res).unwrap(),
            "client" => self.client.get(sub_key).map(|res| *res).unwrap(),
            "node" => self.node.get(sub_key).map(|res| *res).unwrap(),
            _ => panic!("Invalid key/subkey in cli: {}", key),
        }
    }

    fn get_from_map_arg(&self, key: &str, sub_key: &str) -> &str {
        println!("{}", key);
        println!("{}", sub_key);
        self.args
            .get(key)
            .unwrap()
            .get(sub_key)
            .map(|res| *res)
            .unwrap()
    }
}

pub fn anoma_client_cli() -> ArgMatches {
    return App::new(APP_DESCRIPTION)
        .version(VERSION)
        .author(AUTHOR)
        .about("Anoma client")
        .subcommand(
            App::new("tx")
                .about("Send a transaction")
                .arg(
                    Arg::new("path")
                        .long("path")
                        .takes_value(true)
                        .required(true)
                        .about("The path to the wasm code to be executed."),
                )
                .arg(
                    Arg::new("data")
                        .long("data")
                        .takes_value(true)
                        .required(true)
                        .about("The data is an arbitrary hex string that will be passed to the code when it's executed"),
                ),
        )
        .subcommand(
            App::new("run-ledger")
                .about("Run Anoma gossip service")
                .arg(
                    Arg::new("orderbook")
                        .long("orderbook")
                        .takes_value(true)
                        .required(true)
                        .about("The orderbook address."),
                )
                .arg(
                    Arg::new("data")
                        .long("data")
                        .takes_value(true)
                        .required(true)
                        .about("The data of the intent, that contains all value necessary for the matchmaker"),
                ),
        )
        .get_matches();
}

pub fn anoma_node_cli() -> ArgMatches {
    return App::new(APP_DESCRIPTION)
        .version(VERSION)
        .author(AUTHOR)
        .about("Anoma node daemon")
        .arg(
            Arg::new("test")
                .short('t')
                .long("test")
                .takes_value(true)
                .about("test"),
        )
        .subcommand(
            App::new("run-gossip")
                .about("Run Anoma gossip service")
                .arg(
                    Arg::new("address")
                        .short('a')
                        .long("address")
                        .takes_value(true)
                        .about("Gossip service address"),
                )
                .arg(
                    Arg::new("peers")
                        .short('p')
                        .long("peers")
                        .multiple(true)
                        .takes_value(true)
                        .about("List of peers"),
                )
                .arg(
                    Arg::new("dkg")
                        .long("dkg")
                        .multiple(false)
                        .takes_value(false)
                        .about("Enable DKG gossip topic."),
                )
                .arg(
                    Arg::new("orderbook")
                        .long("orderbook")
                        .multiple(false)
                        .takes_value(false)
                        .about("Enable Orderbook gossip topic."),
                )
                .arg(
                    Arg::new("rpc")
                        .long("rpc")
                        .multiple(false)
                        .takes_value(false)
                        .about("Enable RPC service."),
                ),
        )
        .subcommand(App::new("run-ledger").about("Run Anoma gossip service."))
        .subcommand(App::new("reset").about("Reset Anoma node state."))
        .get_matches();
}
