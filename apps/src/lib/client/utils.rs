use std::fs::{self, OpenOptions};
use std::str::FromStr;

use anoma::types::chain::ChainId;
use anoma::types::key::ed25519::Keypair;
use anoma::types::{address, token};
use rand::prelude::ThreadRng;
use rand::thread_rng;
use serde_json::json;

use crate::cli::{self, args};
use crate::config::genesis::genesis_config;
use crate::config::global::GlobalConfig;
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
    let temp_chain_id = chain_id_prefix.temp_chain_id();
    let temp_dir = global_args.base_dir.join(temp_chain_id.as_str());
    // The `temp_chain_id` gets renamed after we have chain ID
    let accounts_dir = temp_dir.join("setup");

    let mut rng: ThreadRng = thread_rng();

    let mut persistent_peers: Vec<tendermint::net::Address> =
        Vec::with_capacity(config.validator.len());
    // Iterate over each validator, generating keys and addresses
    config.validator.iter_mut().for_each(|(name, config)| {
        let validator_dir = accounts_dir.join(name);

        // Generate a node key
        let node_keypair = Keypair::generate(&mut rng);
        let node_pk: ed25519_dalek::PublicKey =
            node_keypair.public.clone().into();

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
        let chain_dir = validator_dir.join(&temp_dir);
        let tm_home_dir = chain_dir.join("tendermint");
        let tm_config_dir = tm_home_dir.join("config");
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
        tendermint_node::write_validator_state(tm_home_dir);

        // Build the list of persistent peers from the validators' node IDs
        let peer = tendermint::net::Address::from_str(&format!(
            "{}@{}",
            node_id,
            config.net_address.as_ref().unwrap(),
        ))
        .expect("Validator address must be valid");
        persistent_peers.push(peer);

        // Clear the net address from the config now that it's been set
        config.net_address = None;

        // Generate the consensus, account and reward keys
        // The `temp_chain_id` gets renamed after we have chain ID
        let mut wallet = Wallet::load_or_new(&chain_dir);
        let consensus_key_alias = format!("{}-consensus-key", name);
        let (_alias, consensus_keypair) = wallet.gen_key(Some(consensus_key_alias), unsafe_dont_encrypt);
        let account_key_alias = format!("{}-account-key", name);
        let (_alias, account_keypair) = wallet.gen_key(Some(account_key_alias), unsafe_dont_encrypt);
        let reward_key_alias = format!("{}-reward-key", name);
        let (_alias, reward_keypair) = wallet.gen_key(Some(reward_key_alias), unsafe_dont_encrypt);
        // Add the validator public keys to genesis config
        config.consensus_public_key =
            Some(genesis_config::HexString(consensus_keypair.public.to_string()));
        config.account_public_key =
            Some(genesis_config::HexString(account_keypair.public.to_string()));
        config.staking_reward_public_key =
            Some(genesis_config::HexString(reward_keypair.public.to_string()));

        // Generate account and reward addresses
        let address = address::gen_established_address("validator account");
        let reward_address = address::gen_established_address("validator reward account");
        config.address = Some(address.to_string());
        config.staking_reward_address = Some(reward_address.to_string());

        // Write keypairs to wallet
        wallet.add_address(name.clone(), address);
        wallet.add_address(format!("{}-reward", &name), reward_address);

        wallet.save().unwrap();
    });

    // Generate the ledger and intent gossip config with the persistent peers
    config.validator.iter().for_each(|(name, _config)| {
        let validator_dir = accounts_dir.join(name).join(&global_args.base_dir);
        // The `temp_chain_id` gets renamed after we have chain ID
        let mut config = Config::load(&validator_dir, &temp_chain_id);
        config.ledger.p2p_persistent_peers = persistent_peers.clone();
        config.write(&validator_dir, &temp_chain_id, true).unwrap();
    });

    // Create a wallet for all other account keys
    let mut wallet = Wallet::load_or_new(&accounts_dir.join("other"));
    if let Some(established) = &mut config.established {
        established.iter_mut().for_each(|(name, config)| {
            if config.address.is_none() {
                let address = address::gen_established_address("established");
                config.address = Some(address.to_string());
                wallet.add_address(name.clone(), address);
            }
            if config.public_key.is_none() {
                let (_alias, keypair) = wallet.gen_key(Some(name.clone()), unsafe_dont_encrypt);
                let public_key = genesis_config::HexString(keypair.public.to_string());
                config.public_key = Some(public_key);
            }
            if config.vp.is_none() {
                config.vp = Some("vp_user".to_string());
            }
        })
    }

    if let Some(token) = &mut config.token {
        token.iter_mut().for_each(|(name, config)| {
            if config.address.is_none() {
                let address = address::gen_established_address("token");
                config.address = Some(address.to_string());
                wallet.add_address(name.clone(), address);
            }
            if config.vp.is_none() {
                config.vp = Some("vp_token".to_string());
            }
        })
    }

    if let Some(implicit) = &mut config.implicit {
        implicit.iter_mut().for_each(|(name, config)| {
            if config.public_key.is_none() {
                let (_alias, keypair) = wallet.gen_key(Some(name.clone()), unsafe_dont_encrypt);
                let public_key = genesis_config::HexString(keypair.public.to_string());
                config.public_key = Some(public_key);
            }
        })
    }
    // Save the wallet with other account keys
    wallet.save().unwrap();

    // Generate the chain ID first
    let genesis_bytes = toml::to_vec(&config).unwrap();
    let chain_id =
        ChainId::from_genesis(chain_id_prefix, genesis_bytes);
    let genesis_path = global_args
        .base_dir
        .join(format!("{}.toml", chain_id.as_str()));

    // Write the genesis file
    genesis_config::write_genesis_config(
        &config,
        &genesis_path,
    );

    // Write the global config setting the default chain ID
    let global_config = GlobalConfig::new(chain_id.clone());
    global_config.write(&global_args.base_dir).unwrap();

    // Rename the generated directories for validators from `temp_chain_id` to `chain_id`
    config.validator.iter().for_each(|(name, _config)| {
        let validator_dir = accounts_dir.join(name);
        let temp_chain_dir = validator_dir.join(&temp_dir);
        let chain_dir = validator_dir.join(&chain_id.as_str());
        std::fs::rename(&temp_chain_dir, &chain_dir).unwrap();
        // Write the genesis and global config into validator sub-dirs
        genesis_config::write_genesis_config(
            &config,
            validator_dir.join(&genesis_path),
        );
        global_config.write(validator_dir.join(&global_args.base_dir)).unwrap();
    });

    // Rename the generate chain config dir from `temp_chain_id` to `chain_id`
    let chain_dir = global_args.base_dir.join(chain_id.as_str());
    std::fs::rename(&temp_dir, &chain_dir).unwrap();

    // Update the ledger config persistent peers and save it
    let mut config = Config::load(&global_args.base_dir, &chain_id);
    config.ledger.p2p_persistent_peers = persistent_peers;
    config
        .write(&global_args.base_dir, &chain_id, true)
        .unwrap();

    println!("Derived chain ID: {}", chain_id);
    println!("Genesis file generated at {}", genesis_path.to_string_lossy());
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
