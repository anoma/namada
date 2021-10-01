use std::collections::HashMap;
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
use crate::config::{genesis, Config};
use crate::node::ledger::tendermint_node;
use crate::wallet::Wallet;

/// Initialize a new test network with the given validators and faucet accounts.
pub fn init_network(
    global_args: args::Global,
    args::InitNetwork {
        validators,
        chain_id_prefix,
        unsafe_dont_encrypt,
    }: args::InitNetwork,
) {
    let temp_chain_id = chain_id_prefix.temp_chain_id();
    let temp_chain_dir = global_args.base_dir.join(chain_id_prefix.as_str());
    let accounts_dir = temp_chain_dir.join("setup");

    let mut persistent_peers: Vec<tendermint::net::Address> =
        Vec::with_capacity(validators.len());
    // Generated node keys for each validator first to get their node ID
    let validators_aliases_and_dirs: Vec<(String, PathBuf)> =
        validators.iter().enumerate().map(|(n, validator_addr)| {
            let alias = format!("validator_{}", n);
            let validator_dir = accounts_dir.join(&alias);

            // Generate a node key
            let mut rng: ThreadRng = thread_rng();
            let node_key = Keypair::generate(&mut rng);
            let node_pk: ed25519_dalek::PublicKey =
                node_key.public.clone().into();

            // Derive the node ID from the node key
            let node_id: tendermint::node::Id = node_pk.into();

            // Convert and write the keypair into Tendermint node_key.json file
            let node_key: ed25519_dalek::Keypair = node_key.into();
            let tm_node_key = base64::encode(node_key.to_bytes());
            let tm_node_keypair_json = json!({
                "priv_key": {
                    "type": "tendermint/PrivKeyEd25519",
                    "value": tm_node_key,
                }
            });
            // TODO the `temp_chain_id` must be later renamed
            let tm_config_dir = validator_dir
                .join(&temp_chain_dir)
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
                validator_addr.to_string()
            ))
            .expect("Validator address must be valid");
            persistent_peers.push(peer);
            (alias, validator_dir)
        }).collect();

    // Generate genesis validator accounts and faucet account
    let mut faucet_account: Option<genesis::EstablishedAccount> = None;
    let genesis_validators: Vec<genesis::Validator> = validators_aliases_and_dirs
        .into_iter()
        .enumerate()
        .map(|(n, (alias, validator_dir))| {
            // TODO the `temp_chain_id` must be later renamed
            let chain_dir = validator_dir.join(temp_chain_id.as_str());
            let mut wallet = Wallet::load_or_new(&chain_dir);
            // TODO the `temp_chain_id` must be later renamed
            let mut config = Config::load(&validator_dir, &temp_chain_id);
            config.ledger.p2p_persistent_peers = persistent_peers.clone();
            config.write(&validator_dir, &temp_chain_id, true).unwrap();
            let genesis_validator = init_genesis_validator_aux(
                &mut wallet,
                &config,
                alias,
                unsafe_dont_encrypt,
            );
            // Add faucet account to the first validator node
            if n == 0 {
                let (_alias, key) = wallet
                    .gen_key(Some("faucet".to_owned()), unsafe_dont_encrypt);
                let public_key = Some(key.public.clone());
                let faucet = genesis::EstablishedAccount {
                    address: address::gen_established_address(
                        "testnet faucet account",
                    ),
                    vp_code_path: "vp_testnet_faucet.wasm".to_owned(),
                    // TODO: very fake hash
                    vp_sha256: Default::default(),
                    public_key,
                    storage: Default::default(),
                };
                faucet_account = Some(faucet);
                wallet.save().unwrap_or_else(|err| eprintln!("{}", err));
            }
            genesis_validator
        })
        .collect();

    // Token accounts
    let default_faucet_tokens = token::Amount::whole(
        // TODO this could be u64, but toml fails to parse it (https://github.com/alexcrichton/toml-rs/issues/256)
        // i64::MAX - 1 / 10^6
        9223372036854,
    );
    let balances: HashMap<Address, token::Amount> = match faucet_account {
        Some(acc) => {
            HashMap::from_iter([(acc.address.clone(), default_faucet_tokens)])
        }
        None => Default::default(),
    };
    let token_accounts: Vec<genesis::TokenAccount> = address::tokens()
        .into_iter()
        .map(|(address, _)| genesis::TokenAccount {
            address,
            vp_code_path: "vp_token.wasm".into(),
            vp_sha256: Default::default(),
            balances: balances.clone(),
        })
        .collect();

    // Update the ledger config persistent peers and save it
    let mut config = Config::load(&temp_chain_dir, &temp_chain_id);
    config.ledger.p2p_persistent_peers = persistent_peers.clone();
    config.write(&temp_chain_dir, &temp_chain_id, true).unwrap();
    // TODO write the genesis file
    // TODO print the path to the file
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
