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

use super::config;

const AUTHOR: &str = "Heliax AG <hello@heliax.dev>";
const APP_NAME: &str = "Anoma";
const CLI_VERSION: &str = "0.1.0";
const NODE_VERSION: &str = "0.1.0";
const CLIENT_VERSION: &str = "0.1.0";

// Commands
pub const NODE_CMD: &str = "node";
pub const CLIENT_CMD: &str = "client";
pub const RUN_GOSSIP_CMD: &str = "run-gossip";
pub const RUN_LEDGER_CMD: &str = "run-ledger";
pub const RESET_LEDGER_CMD: &str = "reset-ledger";
pub const GENERATE_CONFIG_CMD: &str = "generate-config";
pub const INTENT_CMD: &str = "intent";
pub const SUBSCRIBE_TOPIC_CMD: &str = "subscribe-topic";
pub const CRAFT_INTENT_CMD: &str = "craft-intent";
pub const TX_CUSTOM_CMD: &str = "tx";
pub const TX_TRANSFER_CMD: &str = "transfer";
pub const TX_UPDATE_CMD: &str = "update";

// Arguments
const BASE_DIR_ARG: &str = "base-dir";
const DRY_RUN_TX_ARG: &str = "dry-run";
const LEDGER_ADDRESS_ARG: &str = "ledger-address";
const DATA_PATH_ARG: &str = "data-path";
const CODE_PATH_ARG: &str = "code-path";
const PEERS_ARG: &str = "peers";
const ADDRESS_ARG: &str = "address";
const TOPIC_ARG: &str = "topic";
const RPC_ARG: &str = "rpc";
const MATCHMAKER_ARG: &str = "matchmaker-path";
const TX_CODE_ARG: &str = "tx-code-path";
const FILTER_ARG: &str = "filter";
const NODE_ARG: &str = "node";
const TOKEN_SELL_ARG: &str = "token-sell";
const TOKEN_BUY_ARG: &str = "token-buy";
const AMOUNT_SELL_ARG: &str = "amount-sell";
const AMOUNT_BUY_ARG: &str = "amount-buy";
const FILE_ARG: &str = "file-path";
const SOURCE_ARG: &str = "source";
const TARGET_ARG: &str = "target";
const TOKEN_ARG: &str = "token";
const AMOUNT_ARG: &str = "amount";

type App = clap::App<'static>;

/// Global command arguments
pub struct GlobalArgs {
    pub base_dir: String,
}

/// Common transaction arguments
pub struct TxArgs {
    /// Simulate applying the transaction
    pub dry_run: bool,
    /// The address of the ledger node as host:port
    pub ledger_address: String,
}

/// Custom transaction arguments
pub struct TxCustomArgs {
    /// Common tx arguments
    pub tx: TxArgs,
    /// Path to the tx WASM code file
    pub code_path: String,
    /// Path to the data file
    pub data_path: Option<String>,
}

/// Transfer transaction arguments
pub struct TxTransferArgs {
    /// Common tx arguments
    pub tx: TxArgs,
    /// Path to the tx WASM code file
    pub code_path: String,
    /// Transfer source address
    // TODO use `Address`
    pub source: String,
    /// Transfer target address
    pub target: String,
    /// Transferred token address
    pub token: String,
    // TODO use `token::Amount`
    /// Transferred token amount
    pub amount: f64,
}

/// Transaction to update a VP arguments
pub struct TxUpdateVpArgs {
    /// Common tx arguments
    pub tx: TxArgs,
    /// Path to the VP WASM code file
    pub vp_code_path: String,
    /// Address of the account whose VP is to be updated
    pub addr: String,
}

/// Intent arguments
pub struct IntentArgs {
    /// Gossip node address
    pub node_addr: String,
    /// Path to the intent file
    pub data_path: String,
    /// Intent topic
    pub topic: String,
}

/// Subscribe intent topic arguments
pub struct SubscribeTopicArgs {
    /// Gossip node address
    pub node_addr: String,
    /// Intent topic
    pub topic: String,
}

/// Craft intent for token exchange arguments
pub struct CraftIntentArgs {
    /// Source address
    pub addr: String,
    /// Token to sell address
    pub token_sell: String,
    /// Token to sell amount
    pub amount_sell: f64,
    /// Token to buy address
    pub token_buy: String,
    /// Token to buy amount
    pub amount_buy: f64,
    /// Target file path
    pub file: String,
}

/// Extensions for defining commands and arguments.
/// Every function here should have a matcher in [`ArgMatchesExt`].
trait AppExt {
    fn global_args(self) -> Self;
    fn tx_args(self) -> Self;
    fn tx_code_path_arg(self) -> Self;
    fn tx_custom_cmd() -> Self;
    fn tx_transfer_cmd() -> Self;
    fn tx_update_vp_cmd() -> Self;
    fn intent_cmd() -> Self;
    fn subscribe_topic_cmd() -> Self;
    fn craft_intent_cmd() -> Self;
}

/// Extensions for finding matching commands and arguments.
/// The functions match commands and arguments defined in [`AppExt`].
pub trait ArgMatchesExt {
    fn global(&self) -> GlobalArgs;
    fn tx(&self) -> TxArgs;
    fn tx_code_path(&self) -> String;
    fn tx_custom(&self) -> TxCustomArgs;
    fn tx_transfer(&self) -> TxTransferArgs;
    fn tx_update_vp(&self) -> TxUpdateVpArgs;
    fn intent(&self) -> IntentArgs;
    fn subscribe_topic(&self) -> SubscribeTopicArgs;
    fn craft_intent(&self) -> CraftIntentArgs;
}

impl AppExt for App {
    fn global_args(self) -> Self {
        self.arg(
            Arg::new(BASE_DIR_ARG)
                .short('b')
                .long(BASE_DIR_ARG)
                .takes_value(true)
                .required(false)
                .default_value(".anoma")
                .about(
                    "The base directory is where the client and nodes \
                     configuration and state is stored.",
                ),
        )
    }

    fn tx_args(self) -> Self {
        self.arg(
            Arg::new(DRY_RUN_TX_ARG)
                .long(DRY_RUN_TX_ARG)
                .takes_value(false)
                .required(false)
                .about("Simulate the transaction application."),
        )
        .arg(
            Arg::new(LEDGER_ADDRESS_ARG)
                .long(LEDGER_ADDRESS_ARG)
                .multiple(false)
                .takes_value(true)
                .required(false)
                .default_value("127.0.0.1:26657")
                .about("Address of a ledger node as \"{host}:{port}\"."),
        )
    }

    fn tx_code_path_arg(self) -> Self {
        self.arg(
            Arg::new(CODE_PATH_ARG)
                .long(CODE_PATH_ARG)
                .takes_value(true)
                .required(true)
                .about("The path to the transaction's WASM code."),
        )
    }

    fn tx_custom_cmd() -> Self {
        App::new(TX_CUSTOM_CMD)
            .about("Send a transaction with arbitrary data and wasm code")
            .tx_args()
            .tx_code_path_arg()
            .arg(
                Arg::new(DATA_PATH_ARG)
                    .long(DATA_PATH_ARG)
                    .takes_value(true)
                    .required(false)
                    .about(
                        "The data is an arbitrary hex string that will be \
                         passed to the code when it's executed.",
                    ),
            )
    }

    fn tx_transfer_cmd() -> Self {
        App::new(TX_TRANSFER_CMD)
            .about("Send a transfer transaction with a signature")
            .tx_args()
            .tx_code_path_arg()
            .arg(
                Arg::new(SOURCE_ARG)
                    .long(SOURCE_ARG)
                    .takes_value(true)
                    .required(true)
                    .about(
                        "The source account address. The source's key is used \
                         to produce the signature.",
                    ),
            )
            .arg(
                Arg::new(TARGET_ARG)
                    .long(TARGET_ARG)
                    .takes_value(true)
                    .required(true)
                    .about("The target account address."),
            )
            .arg(
                Arg::new(TOKEN_ARG)
                    .long(TOKEN_ARG)
                    .takes_value(true)
                    .required(true)
                    .about("The transfer token."),
            )
            .arg(
                Arg::new(AMOUNT_ARG)
                    .long(AMOUNT_ARG)
                    .takes_value(true)
                    .required(true)
                    .about("The amount to transfer in decimal."),
            )
    }

    fn tx_update_vp_cmd() -> Self {
        App::new(TX_UPDATE_CMD)
            .about("Send a transaction to update account's validity predicate")
            .tx_args()
            .arg(
                Arg::new(CODE_PATH_ARG)
                    .long(CODE_PATH_ARG)
                    .takes_value(true)
                    .required(true)
                    .about("The path to the new validity predicate WASM code."),
            )
            .arg(
                Arg::new(ADDRESS_ARG)
                    .long(ADDRESS_ARG)
                    .takes_value(true)
                    .required(true)
                    .about(
                        "The account's address. It's key is used to produce \
                         the signature.",
                    ),
            )
    }

    fn intent_cmd() -> Self {
        App::new(INTENT_CMD)
            .about("Send an intent.")
            .arg(
                Arg::new(NODE_ARG)
                    .long(NODE_ARG)
                    .takes_value(true)
                    .required(true)
                    .about("The gossip node address."),
            )
            .arg(
                Arg::new(DATA_PATH_ARG)
                    .long(DATA_PATH_ARG)
                    .takes_value(true)
                    .required(true)
                    .about(
                        "The data of the intent, that contains all value \
                         necessary for the matchmaker.",
                    ),
            )
            .arg(
                Arg::new(TOPIC_ARG)
                    .long(TOPIC_ARG)
                    .takes_value(true)
                    .required(true)
                    .about("The subnetwork where the intent should be sent to"),
            )
    }

    fn craft_intent_cmd() -> Self {
        App::new(CRAFT_INTENT_CMD)
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
                Arg::new(FILE_ARG)
                    .long(FILE_ARG)
                    .takes_value(true)
                    .required(false)
                    .default_value("intent.data")
                    .about("The output file"),
            )
    }

    fn subscribe_topic_cmd() -> Self {
        App::new(SUBSCRIBE_TOPIC_CMD)
            .about("subscribe to a topic.")
            .arg(
                Arg::new(NODE_ARG)
                    .long(NODE_ARG)
                    .takes_value(true)
                    .required(true)
                    .about("The gossip node address."),
            )
            .arg(
                Arg::new(TOPIC_ARG)
                    .long(TOPIC_ARG)
                    .takes_value(true)
                    .required(true)
                    .about("The new topic of interest for that node."),
            )
    }
}

impl ArgMatchesExt for ArgMatches {
    fn global(&self) -> GlobalArgs {
        let base_dir = parse_req(self, BASE_DIR_ARG);
        GlobalArgs { base_dir }
    }

    fn tx(&self) -> TxArgs {
        let dry_run = self.is_present(DRY_RUN_TX_ARG);
        let ledger_address = parse_req(self, LEDGER_ADDRESS_ARG);
        TxArgs {
            dry_run,
            ledger_address,
        }
    }

    fn tx_code_path(&self) -> String {
        parse_req(self, CODE_PATH_ARG)
    }

    fn tx_custom(&self) -> TxCustomArgs {
        let tx = self.tx();
        let code_path = self.tx_code_path();
        let data_path = parse_string_opt(self, DATA_PATH_ARG);
        TxCustomArgs {
            tx,
            code_path,
            data_path,
        }
    }

    fn tx_transfer(&self) -> TxTransferArgs {
        let tx = self.tx();
        let code_path = self.tx_code_path();
        let source = parse_req(self, SOURCE_ARG);
        let target = parse_req(self, TARGET_ARG);
        let token = parse_req(self, TOKEN_ARG);
        let amount: f64 = parse_req(self, AMOUNT_ARG);
        TxTransferArgs {
            tx,
            code_path,
            source,
            target,
            token,
            amount,
        }
    }

    fn tx_update_vp(&self) -> TxUpdateVpArgs {
        let tx = self.tx();
        let vp_code_path = parse_req(self, CODE_PATH_ARG);
        let addr = parse_req(self, ADDRESS_ARG);
        TxUpdateVpArgs {
            tx,
            vp_code_path,
            addr,
        }
    }

    fn intent(&self) -> IntentArgs {
        let node_addr = parse_req(self, NODE_ARG);
        let data_path = parse_req(self, DATA_PATH_ARG);
        let topic = parse_req(self, TOPIC_ARG);
        IntentArgs {
            node_addr,
            data_path,
            topic,
        }
    }

    fn craft_intent(&self) -> CraftIntentArgs {
        let addr = parse_req(self, ADDRESS_ARG);
        let token_sell = parse_req(self, TOKEN_SELL_ARG);
        let amount_sell = parse_req(self, AMOUNT_SELL_ARG);
        let token_buy = parse_req(self, TOKEN_BUY_ARG);
        let amount_buy = parse_req(self, AMOUNT_BUY_ARG);
        let file = parse_req(self, FILE_ARG);
        CraftIntentArgs {
            addr,
            token_sell,
            amount_sell,
            token_buy,
            amount_buy,
            file,
        }
    }

    fn subscribe_topic(&self) -> SubscribeTopicArgs {
        let node_addr = parse_req(self, NODE_ARG);
        let topic = parse_req(self, TOPIC_ARG);
        SubscribeTopicArgs { node_addr, topic }
    }
}

pub fn anoma_cli() -> App {
    App::new(APP_NAME)
        .version(CLI_VERSION)
        .author(AUTHOR)
        .about("Anoma command line interface.")
        .global_args()
        // Inlined commands from the node and the client.
        // NOTE: If these are changed, please also update the
        // `handle_command` function in `src/bin/anoma/cli.rs`.
        .subcommand(run_gossip_subcommand())
        .subcommand(run_ledger_subcommand())
        .subcommand(reset_ledger_subcommand())
        .subcommand(App::tx_custom_cmd())
        .subcommand(App::tx_transfer_cmd())
        .subcommand(App::intent_cmd())
        // Node sub-commands
        .subcommand(add_node_commands(
            App::new(NODE_CMD).about("Node sub-commands"),
        ))
        // Client sub-commands
        .subcommand(add_client_commands(
            App::new(CLIENT_CMD).about("Client sub-commands"),
        ))
}

pub fn anoma_client_cli() -> App {
    add_client_commands(
        App::new(APP_NAME)
            .version(CLIENT_VERSION)
            .author(AUTHOR)
            .about("Anoma client command line interface.")
            .global_args(),
    )
}

fn add_client_commands(app: App) -> App {
    app.subcommand(App::tx_custom_cmd())
        .subcommand(App::tx_transfer_cmd())
        .subcommand(App::tx_update_vp_cmd())
        .subcommand(App::intent_cmd())
        .subcommand(App::craft_intent_cmd())
        .subcommand(App::subscribe_topic_cmd())
}

pub fn anoma_node_cli() -> App {
    add_node_commands(
        App::new(APP_NAME)
            .version(NODE_VERSION)
            .author(AUTHOR)
            .about("Anoma node command line interface.")
            .global_args(),
    )
}

fn add_node_commands(app: App) -> App {
    app.subcommand(run_gossip_subcommand())
        .subcommand(run_ledger_subcommand())
        .subcommand(reset_ledger_subcommand())
        .subcommand(generate_config())
}

fn run_gossip_subcommand() -> App {
    App::new(RUN_GOSSIP_CMD)
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
                .takes_value(true)
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
            Arg::new(TX_CODE_ARG)
                .long(TX_CODE_ARG)
                .multiple(false)
                .takes_value(true)
                .about("The transaction code to use with the matchmaker"),
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
            Arg::new(FILTER_ARG)
                .long(FILTER_ARG)
                .multiple(false)
                .takes_value(true)
                .about("The private filter for the matchmaker"),
        )
}

fn run_ledger_subcommand() -> App {
    App::new(RUN_LEDGER_CMD).about("Run Anoma node service.")
}

fn reset_ledger_subcommand() -> App {
    App::new(RESET_LEDGER_CMD).about("Reset Anoma node state.")
}

fn generate_config() -> App {
    App::new(GENERATE_CONFIG_CMD).about("Generate default node config.")
}

pub fn parse_hashset_opt(
    args: &ArgMatches,
    field: &str,
) -> Option<HashSet<String>> {
    args.values_of(field)
        .map(|vs| vs.map(str::to_string).collect::<HashSet<String>>())
}

pub fn parse_opt<F>(args: &ArgMatches, field: &str) -> Option<F>
where
    F: FromStr,
    F::Err: Debug,
{
    args.value_of(field).map(|arg| {
        arg.parse().unwrap_or_else(|e| {
            panic!("failed to parse the argument {}, error: {:?}", arg, e)
        })
    })
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
pub fn update_gossip_config(
    args: &ArgMatches,
    config: &mut config::IntentGossiper,
) -> Result<(), Box<dyn std::error::Error>> {
    if let Some(addr) = parse_opt(args, ADDRESS_ARG) {
        config.address = addr
    }

    let matchmaker_arg = parse_opt(args, MATCHMAKER_ARG);
    let tx_code_arg = parse_opt(args, TX_CODE_ARG);
    let ledger_address_arg = parse_opt(args, LEDGER_ADDRESS_ARG);
    let filter_arg = parse_opt(args, FILTER_ARG);
    if let Some(mut matchmaker_cfg) = config.matchmaker.as_mut() {
        if let Some(matchmaker) = matchmaker_arg {
            matchmaker_cfg.matchmaker = matchmaker
        }
        if let Some(tx_code) = tx_code_arg {
            matchmaker_cfg.tx_code = tx_code
        }
        if let Some(ledger_address) = ledger_address_arg {
            matchmaker_cfg.ledger_address = ledger_address
        }
        if let Some(filter) = filter_arg {
            matchmaker_cfg.filter = Some(filter)
        }
    } else if let (Some(matchmaker), Some(tx_code), Some(ledger_address)) = (
        matchmaker_arg.as_ref(),
        tx_code_arg.as_ref(),
        &ledger_address_arg,
    ) {
        let matchmaker_cfg = Some(config::Matchmaker {
            matchmaker: matchmaker.clone(),
            tx_code: tx_code.clone(),
            ledger_address: ledger_address.clone(),
            filter: filter_arg.clone(),
        });
        config.matchmaker = matchmaker_cfg
    } else if matchmaker_arg.is_some()
        || tx_code_arg.is_some()
        || ledger_address_arg.is_some()
    // if at least one argument is not none then fail
    {
        panic!(
            "No complete matchmaker configuration found (matchmaker code \
             path, tx code path, and ledger address). Please update the \
             configuration with default value or use all cli argument to use \
             the matchmaker"
        );
    }
    if let Some(address) = parse_opt(args, RPC_ARG) {
        config.rpc = Some(config::RpcServer { address });
    }
    Ok(())
}
