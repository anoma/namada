//! The CLI commands that are re-used between the executables `anoma`,
//! `anoma-node` and `anoma-client`.
//!
//! The `anoma` executable groups together the most commonly used commands
//! inlined from the node and the client. The other commands for the node or the
//! client can be dispatched via `anoma node ...` or `anoma client ...`,
//! respectively.

use std::collections::HashSet;
use std::fmt::Debug;
use std::str::FromStr;

use clap::{Arg, ArgMatches};
use libp2p::Multiaddr;

use super::config;

const AUTHOR: &str = "Heliax <TODO@heliax.dev>";
const APP_NAME: &str = "Anoma";
const CLI_VERSION: &str = "0.1.0";
const NODE_VERSION: &str = "0.1.0";
const CLIENT_VERSION: &str = "0.1.0";

pub const NODE_COMMAND: &str = "node";
pub const CLIENT_COMMAND: &str = "client";
pub const RUN_GOSSIP_COMMAND: &str = "run-gossip";
pub const RUN_LEDGER_COMMAND: &str = "run-ledger";
pub const RESET_LEDGER_COMMAND: &str = "reset-ledger";
pub const GENERATE_CONFIG_COMMAND: &str = "generate-config";
pub const INTENT_COMMAND: &str = "intent";
pub const CRAFT_INTENT_COMMAND: &str = "craft-intent";
pub const TX_COMMAND: &str = "tx";
pub const CRAFT_DATA_TX_COMMAND: &str = "craft-tx-data";

// gossip args
pub const BASE_ARG: &str = "base-dir";
pub const PEERS_ARG: &str = "peers";
pub const ADDRESS_ARG: &str = "address";
pub const TOPIC_ARG: &str = "topic";
pub const RPC_ARG: &str = "rpc";
pub const MATCHMAKER_ARG: &str = "matchmaker";
pub const TX_TEMPLATE_ARG: &str = "tx-template";
pub const PUBLIC_FILTER_ARG: &str = "public-filter";
pub const LEDGER_ADDRESS_ARG: &str = "ledger-address";
pub const MATCHMAKER_FILTER_ARG: &str = "matchmaker-filter";

// client args
pub const DATA_TX_ARG: &str = "data";
pub const PATH_TX_ARG: &str = "path";
pub const DATA_INTENT_ARG: &str = "data";
pub const NODE_INTENT_ARG: &str = "node";
pub const DRY_RUN_TX_ARG: &str = "dry-run";
pub const TOKEN_SELL_ARG: &str = "token-sell";
pub const TOKEN_BUY_ARG: &str = "token-buy";
pub const AMOUNT_SELL_ARG: &str = "amount-sell";
pub const AMOUNT_BUY_ARG: &str = "amount-buy";
pub const FILE_ARG: &str = "file";
pub const SOURCE_ARG: &str = "source";
pub const TARGET_ARG: &str = "target";
pub const TOKEN_ARG: &str = "token";
pub const AMOUNT_ARG: &str = "amount";

type App = clap::App<'static>;

pub fn anoma_inline_cli() -> App {
    App::new(APP_NAME)
        .version(CLI_VERSION)
        .author(AUTHOR)
        .about("Anoma command line interface.")
        // Inlined commands from the node and the client.
        // NOTE: If these are changed, please also update the
        // `handle_command` function in `src/bin/anoma/cli.rs`.
        .subcommand(run_gossip_subcommand())
        .subcommand(run_ledger_subcommand())
        .subcommand(reset_ledger_subcommand())
        .subcommand(client_tx_subcommand())
        .subcommand(client_intent_subcommand())
        // Node sub-commands
        .subcommand(add_node_commands(
            App::new(NODE_COMMAND).about("Node sub-commands"),
        ))
        // Client sub-commands
        .subcommand(add_client_commands(
            App::new(CLIENT_COMMAND).about("Client sub-commands"),
        ))
}

pub fn anoma_client_cli() -> App {
    add_client_commands(
        App::new(APP_NAME)
            .version(CLIENT_VERSION)
            .author(AUTHOR)
            .about("Anoma client command line interface."),
    )
}

fn add_client_commands(app: App) -> App {
    app.subcommand(client_tx_subcommand())
        .subcommand(client_intent_subcommand())
        .subcommand(client_craft_intent_subcommand())
        .subcommand(client_craft_tx_data_subcommand())
}

pub fn anoma_node_cli() -> App {
    add_node_commands(
        App::new(APP_NAME)
            .version(NODE_VERSION)
            .author(AUTHOR)
            .about("Anoma node command line interface.")
            .arg(
                Arg::new(BASE_ARG)
                    .short('b')
                    .long(BASE_ARG)
                    .takes_value(true)
                    .required(false)
                    .default_value(".anoma")
                    .about("Set the base directiory."),
            ),
    )
}

fn add_node_commands(app: App) -> App {
    app.subcommand(run_gossip_subcommand())
        .subcommand(run_ledger_subcommand())
        .subcommand(reset_ledger_subcommand())
        .subcommand(generate_config())
}

fn client_tx_subcommand() -> App {
    App::new(TX_COMMAND)
        .about("Send an transaction.")
        .arg(
            Arg::new(DATA_TX_ARG)
                .long(DATA_TX_ARG)
                .takes_value(true)
                .required(false)
                .about(
                    "The data is an arbitrary hex string that will be passed \
                     to the code when it's executed.",
                ),
        )
        .arg(
            Arg::new(PATH_TX_ARG)
                .long(PATH_TX_ARG)
                .takes_value(true)
                .required(true)
                .about("The path to the wasm code to be executed."),
        )
        .arg(
            Arg::new(DRY_RUN_TX_ARG)
                .long(DRY_RUN_TX_ARG)
                .takes_value(false)
                .required(false)
                .about("Dry run the transaction."),
        )
}

fn client_intent_subcommand() -> App {
    App::new(INTENT_COMMAND)
        .about("Send an intent.")
        .arg(
            Arg::new(NODE_INTENT_ARG)
                .long(NODE_INTENT_ARG)
                .takes_value(true)
                .required(true)
                .about("The gossip node address."),
        )
        .arg(
            Arg::new(DATA_INTENT_ARG)
                .long(DATA_INTENT_ARG)
                .takes_value(true)
                .required(true)
                .about(
                    "The data of the intent, that contains all value \
                     necessary for the matchmaker.",
                ),
        )
}

fn client_craft_intent_subcommand() -> App {
    App::new(CRAFT_INTENT_COMMAND)
        .about("Craft an intent.")
        .arg(
            Arg::new(ADDRESS_ARG)
                .long(ADDRESS_ARG)
                .takes_value(true)
                .required(true)
                .about("The account address."),
        )
        .arg(
            Arg::new(TOKEN_SELL_ARG)
                .long(TOKEN_SELL_ARG)
                .takes_value(true)
                .required(true)
                .about("The selling token."),
        )
        .arg(
            Arg::new(AMOUNT_SELL_ARG)
                .long(AMOUNT_SELL_ARG)
                .takes_value(true)
                .required(true)
                .about("The amount selling."),
        )
        .arg(
            Arg::new(TOKEN_BUY_ARG)
                .long(TOKEN_BUY_ARG)
                .takes_value(true)
                .required(true)
                .about("The buying token."),
        )
        .arg(
            Arg::new(AMOUNT_BUY_ARG)
                .long(AMOUNT_BUY_ARG)
                .takes_value(true)
                .required(true)
                .about("The amount buying."),
        )
        .arg(
            Arg::new("file")
                .long(FILE_ARG)
                .takes_value(true)
                .required(false)
                .default_value("intent_data")
                .about("the output file"),
        )
}

fn client_craft_tx_data_subcommand() -> App {
    App::new(CRAFT_DATA_TX_COMMAND)
        .about("Craft a transaction data.")
        .arg(
            Arg::new("source")
                .long(SOURCE_ARG)
                .takes_value(true)
                .required(true)
                .about("The source account address."),
        )
        .arg(
            Arg::new("target")
                .long(TARGET_ARG)
                .takes_value(true)
                .required(true)
                .about("The target account address."),
        )
        .arg(
            Arg::new("token")
                .long(TOKEN_ARG)
                .takes_value(true)
                .required(true)
                .about("The transfer token."),
        )
        .arg(
            Arg::new("amount")
                .long(AMOUNT_ARG)
                .takes_value(true)
                .required(true)
                .about("The amount transfering."),
        )
        .arg(
            Arg::new("file")
                .long(FILE_ARG)
                .takes_value(true)
                .required(false)
                .default_value("intent_data")
                .about("the output file"),
        )
}

fn run_gossip_subcommand() -> App {
    App::new(RUN_GOSSIP_COMMAND)
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
            Arg::new(TOPIC_ARG)
                .long(TOPIC_ARG)
                .multiple(true)
                .takes_value(true)
                .about("Enable a new gossip topic."),
        )
        .arg(
            Arg::new(RPC_ARG)
                .long(RPC_ARG)
                .multiple(false)
                .takes_value(false)
                .about("Enable RPC service."),
        )
        .arg(
            Arg::new(MATCHMAKER_ARG)
                .long(MATCHMAKER_ARG)
                .multiple(false)
                .takes_value(true)
                .about("The matchmaker."),
        )
        .arg(
            Arg::new(TX_TEMPLATE_ARG)
                .long(TX_TEMPLATE_ARG)
                .multiple(false)
                .takes_value(true)
                .about("The tx template to use with the matchmaker"),
        )
        .arg(
            Arg::new(PUBLIC_FILTER_ARG)
                .long(PUBLIC_FILTER_ARG)
                .multiple(false)
                .takes_value(true)
                .about("The public filter to use for the gossip intent"),
        )
        .arg(
            Arg::new(LEDGER_ADDRESS_ARG)
                .long(LEDGER_ADDRESS_ARG)
                .multiple(false)
                .takes_value(true)
                .about(
                    "The address of the ledger as host:port that the \
                     matchmaker must send transactions to.",
                ),
        )
        .arg(
            Arg::new(MATCHMAKER_FILTER_ARG)
                .long(MATCHMAKER_FILTER_ARG)
                .multiple(false)
                .takes_value(true)
                .about("The private filter for the matchmaker"),
        )
}

fn run_ledger_subcommand() -> App {
    App::new(RUN_LEDGER_COMMAND).about("Run Anoma node service.")
}

fn reset_ledger_subcommand() -> App {
    App::new(RESET_LEDGER_COMMAND).about("Reset Anoma node state.")
}

fn generate_config() -> App {
    App::new(GENERATE_CONFIG_COMMAND).about("Generate default node config.")
}

pub fn parse_hashset_opt(
    args: &ArgMatches,
    field: &str,
) -> Option<HashSet<String>> {
    args.values_of(field).map(|peers| {
        peers
            .map(|peer| peer.to_string())
            .collect::<HashSet<String>>()
    })
}

pub fn parse_opt<F>(args: &ArgMatches, field: &str) -> Option<F>
where
    F: FromStr,
    F::Err: Debug,
{
    args.value_of(field)
        .map(|address| address.parse().expect("failed to parse the argument"))
}

pub fn parse_req<F>(args: &ArgMatches, field: &str) -> F
where
    F: FromStr,
    F::Err: Debug,
{
    parse_opt(args, field).expect("field is mandatory")
}

pub fn parse_string_opt(args: &ArgMatches, field: &str) -> Option<String> {
    args.value_of(field).map(|s| s.to_string())
}

pub fn parse_string_req(args: &ArgMatches, field: &str) -> String {
    parse_string_opt(args, field).expect("field is mandatory")
}

pub fn update_gossip_config(
    args: &ArgMatches,
    config: &mut config::Gossip,
) -> Result<(), Box<dyn std::error::Error>> {
    if let Some(peers) = parse_hashset_opt(args, PEERS_ARG) {
        config.peers = peers
            .iter()
            .map(|p| Multiaddr::from_str(p).expect("error while parsing peer"))
            .collect()
    }

    if let Some(addr) = parse_opt(args, ADDRESS_ARG) {
        config.address = addr
    }

    let matchmaker_arg = parse_opt(args, MATCHMAKER_ARG);
    let tx_template_arg = parse_opt(args, TX_TEMPLATE_ARG);
    let ledger_address_arg = parse_opt(args, LEDGER_ADDRESS_ARG);
    let filter_arg = parse_opt(args, MATCHMAKER_FILTER_ARG);
    if let Some(mut matchmaker_cfg) = config.matchmaker.as_mut()
    {
        if let Some(matchmaker) = matchmaker_arg {
            matchmaker_cfg.matchmaker = matchmaker
        }
        if let Some(tx_template) = tx_template_arg {
            matchmaker_cfg.tx_template = tx_template
        }
        if let Some(ledger_address) = ledger_address_arg {
            matchmaker_cfg.ledger_address = ledger_address
        }
        if let Some(filter) = filter_arg {
            matchmaker_cfg.filter = Some(filter)
        }
    } else if let (
        Some(matchmaker),
        Some(tx_template),
        Some(ledger_address),
        Some(filter),
    ) = (
        matchmaker_arg.as_ref(),
        tx_template_arg.as_ref(),
        ledger_address_arg,
        filter_arg.as_ref(),
    ) {
        let matchmaker_cfg = Some(config::Matchmaker {
            matchmaker: matchmaker.clone(),
            tx_template: tx_template.clone(),
            ledger_address,
            filter: Some(filter.clone()),
        });
        config.matchmaker = matchmaker_cfg
    } else if matchmaker_arg.is_some()
        || tx_template_arg.is_some()
        || ledger_address_arg.is_some()
    // if at least one argument is not none then fail
    {
        panic!(
            "No complete matchmaker configuration found (matchmaker \
             program path, tx template path, and ledger address). Please \
             update the configuration with default value or use all cli \
             argument to use the matchmaker"
        );
    }
    config.rpc = args.is_present(RPC_ARG);
    Ok(())
}
