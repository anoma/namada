use std::collections::HashMap;
use std::collections::btree_map::VacantEntry;
use std::fs::{self, OpenOptions};
use std::iter::FromIterator;
use std::path::PathBuf;
use std::str::FromStr;

use anoma::types::address::Address;
use anoma::types::key::ed25519::Keypair;
use anoma::types::{address, token};
use rand::prelude::ThreadRng;
use rand::thread_rng;
use serde_json::json;

use crate::cli::{self, args};
use crate::config::genesis::genesis_config::{self, EstablishedAccountConfig, ImplicitAccountConfig, TokenAccountConfig, ValidatorConfig};
use crate::config::{genesis, Config};
use crate::node::ledger::tendermint_node;
use crate::wallet::Wallet;

/// Initialize a new test network with the given validators and faucet accounts.
pub fn init_network(
    global_args: args::Global,
    args::InitNetwork {
        genesis_path,
        chain_id_prefix,
        unsafe_dont_encrypt,
    }: args::InitNetwork,
) {
    let mut config = genesis_config::open_genesis_config(&genesis_path);

    let temp_dir = global_args.base_dir.join("init-network");
    let accounts_dir = temp_dir.join("setup");

    let mut rng: ThreadRng = thread_rng();

    let mut persistent_peers: Vec<tendermint::net::Address> =
        Vec::with_capacity(config.validator.len());
    // Iterate over each validator, generating keys and addresses
    config.validator =
        config.validator.iter().map(|(name, config)| {
            let validator_dir = accounts_dir.join(name);
            let mut new_config = config.to_owned();

            // Generate a node key
            let node_keypair = Keypair::generate(&mut rng);
            let node_pk: ed25519_dalek::PublicKey =
                node_keypair.public.clone().into();
            // add the node public key to genesis config
            new_config.consensus_public_key =
                Some(genesis_config::HexString(hex::encode(node_pk.to_bytes())));

            // Derive the node ID from the node key
            let node_id: tendermint::node::Id = node_pk.into();

            // Convert and write the keypair into Tendermint node_key.json file
            let node_key: ed25519_dalek::Keypair = node_keypair.into();
            let tm_node_key = base64::encode(node_key.to_bytes());
            let tm_node_keypair_json = json!({
                "priv_key": {
                    "type": "tendermint/PrivKeyEd25519",
                    "value": tm_node_key,
                }
            });
            let tm_config_dir = validator_dir
                .join(&temp_dir)
                .join("tendermint")
                .join("config");
            fs::create_dir_all(&tm_config_dir)
                .expect("Couldn't create validator directory");
            let path = tm_config_dir.join("node_key.json");
            let file = OpenOptions::new()
                .create(true)
                .write(true)
                .truncate(true)
                .open(&path)
                .expect("Couldn't create validator node key file");
            serde_json::to_writer_pretty(file, &tm_node_keypair_json)
                .expect("Couldn't write validator node key file");

            // Build the list of persistent peers from the validators' node IDs
            let peer = tendermint::net::Address::from_str(&format!(
                "{}@{}",
                node_id,
                config.net_address.as_ref().unwrap(),
            ))
            .expect("Validator address must be valid");
            persistent_peers.push(peer);

            // Clear the net address from the config now that it's been set
            new_config.net_address = None;

            // Generate the account and reward keys
            let account_keypair = Keypair::generate(&mut rng);
            let reward_keypair = Keypair::generate(&mut rng);
            new_config.account_public_key =
                Some(genesis_config::HexString(account_keypair.public.to_string()));
            new_config.staking_reward_public_key =
                Some(genesis_config::HexString(reward_keypair.public.to_string()));

            // Generate account and reward addresses
            let address = address::gen_established_address("validator account");
            let reward_address = address::gen_established_address("validator reward account");
            new_config.address = Some(address.to_string());
            new_config.staking_reward_address = Some(reward_address.to_string());

            // Write keypairs to wallet
            let mut wallet = Wallet::load_or_new(&validator_dir);
            wallet.add_address(name.to_string(), address);
            wallet.add_address(format!("{}-reward", &name), reward_address);
            // XXX impossible to add actual keys to wallet??? look more
            // can't generate them using wallet methods, have to
            // generate them here to have them for the configuration
            // especially the node key, which is written above

            // write the anoma config here

            (name.to_string(), new_config)
        }).collect();

    let established =
        config.established.unwrap_or(HashMap::default())
        .iter().map(|(name, config)| {
            let address = address::gen_established_address("established");
            let keypair = Keypair::generate(&mut rng);
            // write to wallet here
            let new_config = EstablishedAccountConfig {
                address: Some(address.to_string()),
                vp: Some(config.vp.to_owned().unwrap_or("vp_user".to_string())),
                public_key: Some(genesis_config::HexString(keypair.public.to_string())),
                storage: config.storage.to_owned(),
            };
            (name.to_string(), new_config)
    }).collect();
    config.established = Some(established);

    let token =
        config.token.unwrap_or(HashMap::default())
        .iter().map(|(name, config)| {
            let address = address::gen_established_address("token");
            // write to wallet here
            let new_config = TokenAccountConfig {
                address: Some(address.to_string()),
                vp: Some(config.vp.to_owned().unwrap_or("vp_token".to_string())),
                balances: config.balances.to_owned(),
            };
            (name.to_string(), new_config)
    }).collect();
    config.token = Some(token);

    let implicit =
        config.implicit.unwrap_or(HashMap::default())
        .iter().map(|(name, _config)| {
            let keypair = Keypair::generate(&mut rng);
            // write to wallet here
            let new_config = ImplicitAccountConfig {
                public_key: Some(genesis_config::HexString(keypair.public.to_string())),
            };
            (name.to_string(), new_config)
    }).collect();
    config.implicit = Some(implicit);

    // generate the chain id first
    genesis_config::write_genesis_config(config, genesis_path);
}

/// Initialize genesis validator's address, staking reward address,
/// consensus key, validator account key and staking rewards key and use
/// it in the ledger's node.
pub fn init_genesis_validator(
    global_args: args::Global,
    args::InitGenesisValidator {
        alias,
        chain_id,
        unsafe_dont_encrypt,
    }: args::InitGenesisValidator,
) {
    let chain_dir = global_args.base_dir.join(chain_id.as_str());
    let mut wallet = Wallet::load_or_new(&chain_dir);
    let config = Config::load(&global_args.base_dir, &chain_id);
    init_genesis_validator_aux(
        &mut wallet,
        &config,
        alias,
        unsafe_dont_encrypt,
    );
}

/// Initialize genesis validator's address, staking reward address,
/// consensus key, validator account key and staking rewards key and use
/// it in the ledger's node.
fn init_genesis_validator_aux(
    wallet: &mut Wallet,
    config: &Config,
    alias: String,
    unsafe_dont_encrypt: bool,
) -> genesis::Validator {
    // Generate validator address
    let validator_address =
        address::gen_established_address("genesis validator address");
    let validator_address_alias = alias.clone();
    if !wallet
        .add_address(validator_address_alias.clone(), validator_address.clone())
    {
        cli::safe_exit(1)
    }
    // Generate staking reward address
    let rewards_address =
        address::gen_established_address("genesis validator reward address");
    let rewards_address_alias = format!("{}-rewards", alias);
    if !wallet
        .add_address(rewards_address_alias.clone(), rewards_address.clone())
    {
        cli::safe_exit(1)
    }

    println!("Generating validator account key...");
    let (validator_key_alias, validator_key) = wallet.gen_key(
        Some(format!("{}-validator-key", alias)),
        unsafe_dont_encrypt,
    );
    println!("Generating consensus key...");
    let (consensus_key_alias, consensus_key) = wallet.gen_key(
        Some(format!("{}-consensus-key", alias)),
        unsafe_dont_encrypt,
    );
    println!("Generating staking reward account key...");
    let (rewards_key_alias, rewards_key) = wallet
        .gen_key(Some(format!("{}-rewards-key", alias)), unsafe_dont_encrypt);

    wallet.save().unwrap_or_else(|err| eprintln!("{}", err));

    let tendermint_home = &config.ledger.tendermint;
    tendermint_node::write_validator_key(
        tendermint_home,
        &validator_address,
        &consensus_key,
    );
    tendermint_node::write_validator_state(tendermint_home);

    println!();
    println!("The validator's addresses and keys were stored in the wallet:");
    println!("  Validator address \"{}\"", validator_address_alias);
    println!("  Staking reward address \"{}\"", rewards_address_alias);
    println!("  Validator account key \"{}\"", validator_key_alias);
    println!("  Consensus key \"{}\"", consensus_key_alias);
    println!("  Staking reward key \"{}\"", rewards_key_alias);
    println!(
        "The ledger node has been setup to use this validator's address and \
         consensus key."
    );
    println!();
    let genesis_validator = genesis::Validator {
        pos_data: anoma::ledger::pos::GenesisValidator {
            address: validator_address,
            staking_reward_address: rewards_address,
            tokens: token::Amount::whole(200_000),
            consensus_key: consensus_key.public.clone(),
            staking_reward_key: rewards_key.public.clone(),
        },
        account_key: validator_key.public.clone(),
        non_staked_balance: token::Amount::whole(100_000),
        // TODO replace with https://github.com/anoma/anoma/issues/25)
        validator_vp_code_path: "wasm/vp_user.wasm".into(),
        // TODO: very fake hash
        validator_vp_sha256: [0; 32],
        reward_vp_code_path: "wasm/vp_user.wasm".into(),
        // TODO: very fake hash
        reward_vp_sha256: [0; 32],
    };
    println!("Validator account key {}", validator_key.public);
    println!("Consensus key {}", consensus_key.public);
    println!("Staking reward key {}", rewards_key.public);
    // TODO print in toml format after we have https://github.com/anoma/anoma/issues/425
    println!("Genesis validator config: {:#?}", genesis_validator);
    genesis_validator
}
