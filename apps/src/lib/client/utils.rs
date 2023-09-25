use std::collections::HashMap;
use std::env;
use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::str::FromStr;

use borsh::BorshSerialize;
use flate2::read::GzDecoder;
use flate2::write::GzEncoder;
use flate2::Compression;
use namada::sdk::wallet::Wallet;
use namada::types::address;
use namada::types::chain::ChainId;
use namada::types::dec::Dec;
use namada::types::key::*;
use namada::vm::validate_untrusted_wasm;
use prost::bytes::Bytes;
use rand::prelude::ThreadRng;
use rand::thread_rng;
use serde_json::json;
use sha2::{Digest, Sha256};

use crate::cli::context::ENV_VAR_WASM_DIR;
use crate::cli::{self, args, safe_exit};
use crate::config::genesis::genesis_config::{
    self, GenesisConfig, HexString, ValidatorPreGenesisConfig,
};
use crate::config::global::GlobalConfig;
use crate::config::{self, get_default_namada_folder, Config, TendermintMode};
use crate::facade::tendermint::node::Id as TendermintNodeId;
use crate::facade::tendermint_config::net::Address as TendermintAddress;
use crate::node::ledger::tendermint_node;
use crate::wallet::{
    pre_genesis, read_and_confirm_encryption_password, CliWalletUtils,
};
use crate::wasm_loader;

pub const NET_ACCOUNTS_DIR: &str = "setup";
pub const NET_OTHER_ACCOUNTS_DIR: &str = "other";
/// Github URL prefix of released Namada network configs
pub const ENV_VAR_NETWORK_CONFIGS_SERVER: &str =
    "NAMADA_NETWORK_CONFIGS_SERVER";
const DEFAULT_NETWORK_CONFIGS_SERVER: &str =
    "https://github.com/heliaxdev/anoma-network-config/releases/download";

/// We do pre-genesis validator set up in this directory
pub const PRE_GENESIS_DIR: &str = "pre-genesis";

/// Configure Namada to join an existing network. The chain must be released in
/// the <https://github.com/heliaxdev/anoma-network-config> repository.
pub async fn join_network(
    global_args: args::Global,
    args::JoinNetwork {
        chain_id,
        genesis_validator,
        pre_genesis_path,
        dont_prefetch_wasm,
    }: args::JoinNetwork,
) {
    use tokio::fs;

    let base_dir = global_args.base_dir;

    // If the base-dir doesn't exist yet, create it
    if let Err(err) = fs::canonicalize(&base_dir).await {
        if err.kind() == std::io::ErrorKind::NotFound {
            fs::create_dir_all(&base_dir).await.unwrap();
        }
    } else {
        // If the base-dir exists, check if it's already got this chain ID
        if fs::canonicalize(base_dir.join(chain_id.as_str()))
            .await
            .is_ok()
        {
            eprintln!("The chain directory for {} already exists.", chain_id);
            cli::safe_exit(1);
        }
    }
    let base_dir_full = fs::canonicalize(&base_dir).await.unwrap();
    let chain_dir = base_dir_full.join(chain_id.as_str());

    let validator_alias_and_dir = pre_genesis_path
        .and_then(|path| {
            let alias = path.components().last()?;
            match alias {
                std::path::Component::Normal(alias) => {
                    let alias = alias.to_string_lossy().to_string();
                    println!(
                        "Using {alias} parsed from the given \
                         --pre-genesis-path"
                    );
                    Some((alias, path))
                }
                _ => None,
            }
        })
        .or_else(|| {
            genesis_validator.as_ref().map(|alias| {
                (
                    alias.clone(),
                    validator_pre_genesis_dir(&base_dir_full, alias),
                )
            })
        });

    // Pre-load the validator pre-genesis wallet and its keys to validate that
    // everything is in place before downloading the network archive
    let validator_alias_and_pre_genesis_wallet =
        validator_alias_and_dir.map(|(validator_alias, pre_genesis_dir)| {
            (
                validator_alias,
                pre_genesis::load(&pre_genesis_dir).unwrap_or_else(|err| {
                    eprintln!(
                        "Error loading validator pre-genesis wallet {err}",
                    );
                    cli::safe_exit(1)
                }),
            )
        });

    let wasm_dir = global_args.wasm_dir.as_ref().cloned().or_else(|| {
        if let Ok(wasm_dir) = env::var(ENV_VAR_WASM_DIR) {
            let wasm_dir: PathBuf = wasm_dir.into();
            Some(wasm_dir)
        } else {
            None
        }
    });

    let release_filename = format!("{}.tar.gz", chain_id);
    let release_url = format!(
        "{}/{}",
        network_configs_url_prefix(&chain_id),
        release_filename
    );

    // Read or download the release archive
    println!("Downloading config release from {} ...", release_url);
    let release = match download_file(release_url).await {
        Ok(contents) => contents,
        Err(error) => {
            eprintln!("Error downloading release: {}", error);
            cli::safe_exit(1);
        }
    };

    // Decode and unpack the archive
    let decoder = GzDecoder::new(&release[..]);
    let mut archive = tar::Archive::new(decoder);

    // If the base-dir is non-default, unpack the archive into a temp dir inside
    // first.
    let cwd = env::current_dir().unwrap();
    let (unpack_dir, non_default_dir) =
        if base_dir_full != cwd.join(config::DEFAULT_BASE_DIR) {
            (base_dir.clone(), true)
        } else {
            (PathBuf::from_str(".").unwrap(), false)
        };
    archive.unpack(&unpack_dir).unwrap();

    // Rename the base-dir from the default and rename wasm-dir, if non-default.
    if non_default_dir {
        // For compatibility for networks released with Namada <= v0.4:
        // The old releases include the WASM directory at root path of the
        // archive. This has been moved into the chain directory, so if the
        // WASM dir is found at the old path, we move it to the new path.
        if let Ok(wasm_dir) =
            fs::canonicalize(unpack_dir.join(config::DEFAULT_WASM_DIR)).await
        {
            fs::rename(
                &wasm_dir,
                unpack_dir
                    .join(config::DEFAULT_BASE_DIR)
                    .join(chain_id.as_str())
                    .join(config::DEFAULT_WASM_DIR),
            )
            .await
            .unwrap();
        }

        // Move the chain dir
        fs::rename(
            unpack_dir
                .join(config::DEFAULT_BASE_DIR)
                .join(chain_id.as_str()),
            &chain_dir,
        )
        .await
        .unwrap();

        // Move the genesis file
        fs::rename(
            unpack_dir
                .join(config::DEFAULT_BASE_DIR)
                .join(format!("{}.toml", chain_id.as_str())),
            base_dir_full.join(format!("{}.toml", chain_id.as_str())),
        )
        .await
        .unwrap();

        // Move the global config
        fs::rename(
            unpack_dir
                .join(config::DEFAULT_BASE_DIR)
                .join(config::global::FILENAME),
            base_dir_full.join(config::global::FILENAME),
        )
        .await
        .unwrap();

        // Remove the default dir
        fs::remove_dir_all(unpack_dir.join(config::DEFAULT_BASE_DIR))
            .await
            .unwrap();
    }

    // Move wasm-dir and update config if it's non-default
    if let Some(wasm_dir) = wasm_dir.as_ref() {
        if wasm_dir.to_string_lossy() != config::DEFAULT_WASM_DIR {
            tokio::fs::rename(
                base_dir_full
                    .join(chain_id.as_str())
                    .join(config::DEFAULT_WASM_DIR),
                chain_dir.join(wasm_dir),
            )
            .await
            .unwrap();

            // Update the config
            let wasm_dir = wasm_dir.clone();
            let base_dir = base_dir.clone();
            let chain_id = chain_id.clone();
            tokio::task::spawn_blocking(move || {
                let mut config = Config::load(&base_dir, &chain_id, None);
                config.wasm_dir = wasm_dir;
                config.write(&base_dir, &chain_id, true).unwrap();
            })
            .await
            .unwrap();
        }
    }

    // Setup the node for a genesis validator, if used
    if let Some((validator_alias, pre_genesis_wallet)) =
        validator_alias_and_pre_genesis_wallet
    {
        let tendermint_node_key: common::SecretKey = pre_genesis_wallet
            .tendermint_node_key
            .try_to_sk()
            .unwrap_or_else(|_err| {
                eprintln!(
                    "Tendermint node key must be common (need to change?)"
                );
                cli::safe_exit(1)
            });

        let genesis_file_path =
            base_dir.join(format!("{}.toml", chain_id.as_str()));
        let genesis_config =
            genesis_config::open_genesis_config(genesis_file_path).unwrap();

        if !is_valid_validator_for_current_chain(
            &tendermint_node_key.ref_to(),
            &genesis_config,
        ) {
            eprintln!(
                "The current validator is not valid for chain {}.",
                chain_id.as_str()
            );
            safe_exit(1)
        }

        let mut wallet =
            crate::wallet::load_or_new_from_genesis(&chain_dir, genesis_config);

        let address = wallet
            .find_address(&validator_alias)
            .unwrap_or_else(|| {
                eprintln!(
                    "Unable to find validator address for alias \
                     {validator_alias}"
                );
                cli::safe_exit(1)
            })
            .clone();

        let tm_home_dir = chain_dir.join("cometbft");

        // Write consensus key to tendermint home
        tendermint_node::write_validator_key(
            &tm_home_dir,
            &pre_genesis_wallet.consensus_key,
        );

        // Derive the node ID from the node key
        let node_id = id_from_pk(&tendermint_node_key.ref_to());
        // Write tendermint node key
        write_tendermint_node_key(&tm_home_dir, tendermint_node_key);

        // Pre-initialize tendermint validator state
        tendermint_node::write_validator_state(&tm_home_dir);

        // Extend the current wallet from the pre-genesis wallet.
        // This takes the validator keys to be usable in future commands (e.g.
        // to sign a tx from validator account using the account key).
        wallet.extend_from_pre_genesis_validator(
            address,
            validator_alias.into(),
            pre_genesis_wallet,
        );

        crate::wallet::save(&wallet).unwrap();

        // Update the config from the default non-validator settings to
        // validator settings
        let base_dir = base_dir.clone();
        let chain_id = chain_id.clone();
        tokio::task::spawn_blocking(move || {
            let mut config = Config::load(&base_dir, &chain_id, None);
            config.ledger.shell.tendermint_mode = TendermintMode::Validator;

            // Remove self from persistent peers
            config.ledger.cometbft.p2p.persistent_peers.retain(|peer| {
                if let TendermintAddress::Tcp {
                    peer_id: Some(peer_id),
                    ..
                } = peer
                {
                    node_id != *peer_id
                } else {
                    true
                }
            });
            config.write(&base_dir, &chain_id, true).unwrap();
        })
        .await
        .unwrap();
    }
    if !dont_prefetch_wasm {
        fetch_wasms_aux(&base_dir, &chain_id).await;
    }

    println!("Successfully configured for chain ID {}", chain_id);
}

pub async fn fetch_wasms(
    global_args: args::Global,
    args::FetchWasms { chain_id }: args::FetchWasms,
) {
    fetch_wasms_aux(&global_args.base_dir, &chain_id).await;
}

pub async fn fetch_wasms_aux(base_dir: &Path, chain_id: &ChainId) {
    println!("Fetching wasms for chain ID {}...", chain_id);
    let wasm_dir = {
        let mut path = base_dir.to_owned();
        path.push(chain_id.as_str());
        path.push("wasm");
        path
    };
    wasm_loader::pre_fetch_wasm(&wasm_dir).await;
}

pub fn validate_wasm(args::ValidateWasm { code_path }: args::ValidateWasm) {
    let code = std::fs::read(code_path).unwrap();
    match validate_untrusted_wasm(code) {
        Ok(()) => println!("Wasm code is valid"),
        Err(e) => {
            eprintln!("Wasm code is invalid: {e}");
            cli::safe_exit(1)
        }
    }
}

/// Length of a Tendermint Node ID in bytes
const TENDERMINT_NODE_ID_LENGTH: usize = 20;

/// Derive Tendermint node ID from public key
pub fn id_from_pk(pk: &common::PublicKey) -> TendermintNodeId {
    let mut bytes = [0u8; TENDERMINT_NODE_ID_LENGTH];

    match pk {
        common::PublicKey::Ed25519(_) => {
            let _pk: ed25519::PublicKey = pk.try_to_pk().unwrap();
            let digest = Sha256::digest(_pk.try_to_vec().unwrap().as_slice());
            bytes.copy_from_slice(&digest[..TENDERMINT_NODE_ID_LENGTH]);
        }
        common::PublicKey::Secp256k1(_) => {
            let _pk: secp256k1::PublicKey = pk.try_to_pk().unwrap();
            let digest = Sha256::digest(_pk.try_to_vec().unwrap().as_slice());
            bytes.copy_from_slice(&digest[..TENDERMINT_NODE_ID_LENGTH]);
        }
    }
    TendermintNodeId::new(bytes)
}

/// Initialize a new test network from the given configuration.
///
/// For any public keys that are not specified in the genesis configuration,
/// this command will generate them and place them in the "setup" directory
/// inside the chain-dir, so it can be used for testing (we're using it in the
/// e2e tests), dev/test-nets and public networks setup.
pub fn init_network(
    global_args: args::Global,
    args::InitNetwork {
        genesis_path,
        wasm_checksums_path,
        chain_id_prefix,
        unsafe_dont_encrypt,
        consensus_timeout_commit,
        localhost,
        allow_duplicate_ip,
        dont_archive,
        archive_dir,
    }: args::InitNetwork,
) {
    let mut config = genesis_config::open_genesis_config(genesis_path).unwrap();

    // Update the WASM checksums
    let checksums =
        wasm_loader::Checksums::read_checksums_file(&wasm_checksums_path);
    config.wasm.iter_mut().for_each(|(name, config)| {
        // Find the sha256 from checksums.json
        let name = format!("{}.wasm", name);
        // Full name in format `{name}.{sha256}.wasm`
        let full_name = checksums.0.get(&name).unwrap();
        let hash = full_name
            .split_once('.')
            .unwrap()
            .1
            .split_once('.')
            .unwrap()
            .0;
        config.sha256 = Some(genesis_config::HexString(hash.to_owned()));
    });

    // The `temp_chain_id` gets renamed after we have chain ID.
    let temp_chain_id = chain_id_prefix.temp_chain_id();
    let temp_dir = global_args.base_dir.join(temp_chain_id.as_str());
    // The `temp_chain_id` gets renamed after we have chain ID
    let accounts_dir = temp_dir.join(NET_ACCOUNTS_DIR);
    // Base dir used in account sub-directories
    let accounts_temp_dir =
        PathBuf::from(config::DEFAULT_BASE_DIR).join(temp_chain_id.as_str());

    let mut rng: ThreadRng = thread_rng();

    // Accumulator of validators' Tendermint P2P addresses
    let mut persistent_peers: Vec<TendermintAddress> =
        Vec::with_capacity(config.validator.len());

    // Iterate over each validator, generating keys and addresses
    config.validator.iter_mut().for_each(|(name, config)| {
        let validator_dir = accounts_dir.join(name);

        let chain_dir = validator_dir.join(&accounts_temp_dir);
        let tm_home_dir = chain_dir.join("cometbft");

        // Find or generate tendermint node key
        let node_pk = try_parse_public_key(
            format!("validator {name} Tendermint node key"),
            &config.tendermint_node_key,
        )
        .unwrap_or_else(|| {
            // Generate a node key with ed25519 as default
            let node_sk = common::SecretKey::Ed25519(
                ed25519::SigScheme::generate(&mut rng),
            );

            let node_pk = write_tendermint_node_key(&tm_home_dir, node_sk);

            tendermint_node::write_validator_state(&tm_home_dir);

            node_pk
        });

        // Derive the node ID from the node key
        let node_id: TendermintNodeId = id_from_pk(&node_pk);

        // Build the list of persistent peers from the validators' node IDs
        let peer = TendermintAddress::from_str(&format!(
            "{}@{}",
            node_id,
            config.net_address.as_ref().unwrap(),
        ))
        .expect("Validator address must be valid");
        persistent_peers.push(peer);

        // Generate account and reward addresses
        let address = address::gen_established_address("validator account");
        config.address = Some(address.to_string());

        // Generate the consensus, account and reward keys, unless they're
        // pre-defined. Do not use mnemonic code / HD derivation path.
        let mut wallet = crate::wallet::load_or_new(&chain_dir);

        let consensus_pk = try_parse_public_key(
            format!("validator {name} consensus key"),
            &config.consensus_public_key,
        )
        .unwrap_or_else(|| {
            let alias = format!("{}-consensus-key", name);
            println!("Generating validator {} consensus key...", name);
            let password =
                read_and_confirm_encryption_password(unsafe_dont_encrypt);
            let (_alias, keypair) = wallet
                .gen_key(SchemeType::Ed25519, Some(alias), true, password, None)
                .expect("Key generation should not fail.")
                .expect("No existing alias expected.");

            // Write consensus key for Tendermint
            tendermint_node::write_validator_key(&tm_home_dir, &keypair);

            keypair.ref_to()
        });

        let account_pk = try_parse_public_key(
            format!("validator {name} account key"),
            &config.account_public_key,
        )
        .unwrap_or_else(|| {
            let alias = format!("{}-account-key", name);
            println!("Generating validator {} account key...", name);
            let password =
                read_and_confirm_encryption_password(unsafe_dont_encrypt);
            let (_alias, keypair) = wallet
                .gen_key(SchemeType::Ed25519, Some(alias), true, password, None)
                .expect("Key generation should not fail.")
                .expect("No existing alias expected.");
            keypair.ref_to()
        });

        let protocol_pk = try_parse_public_key(
            format!("validator {name} protocol key"),
            &config.protocol_public_key,
        )
        .unwrap_or_else(|| {
            let alias = format!("{}-protocol-key", name);
            println!("Generating validator {} protocol signing key...", name);
            let password =
                read_and_confirm_encryption_password(unsafe_dont_encrypt);
            let (_alias, keypair) = wallet
                .gen_key(SchemeType::Ed25519, Some(alias), true, password, None)
                .expect("Key generation should not fail.")
                .expect("No existing alias expected.");
            keypair.ref_to()
        });

        let eth_hot_pk = try_parse_public_key(
            format!("validator {name} eth hot key"),
            &config.eth_hot_key,
        )
        .unwrap_or_else(|| {
            let alias = format!("{}-eth-hot-key", name);
            println!("Generating validator {} eth hot key...", name);
            let password =
                read_and_confirm_encryption_password(unsafe_dont_encrypt);
            let (_alias, keypair) = wallet
                .gen_key(
                    SchemeType::Secp256k1,
                    Some(alias),
                    true,
                    password,
                    None,
                )
                .expect("Key generation should not fail.")
                .expect("No existing alias expected.");
            keypair.ref_to()
        });

        let eth_cold_pk = try_parse_public_key(
            format!("validator {name} eth cold key"),
            &config.eth_cold_key,
        )
        .unwrap_or_else(|| {
            let alias = format!("{}-eth-cold-key", name);
            println!("Generating validator {} eth cold key...", name);
            let password =
                read_and_confirm_encryption_password(unsafe_dont_encrypt);
            let (_alias, keypair) = wallet
                .gen_key(
                    SchemeType::Secp256k1,
                    Some(alias),
                    true,
                    password,
                    None,
                )
                .expect("Key generation should not fail.")
                .expect("No existing alias expected.");
            keypair.ref_to()
        });

        let dkg_pk = &config
            .dkg_public_key
            .as_ref()
            .map(|key| {
                key.to_dkg_public_key().unwrap_or_else(|err| {
                    let label = format!("validator {name} DKG key");
                    eprintln!("Invalid {label} key: {}", err);
                    cli::safe_exit(1)
                })
            })
            .unwrap_or_else(|| {
                println!(
                    "Generating validator {} DKG session keypair...",
                    name
                );

                let validator_keys = crate::wallet::gen_validator_keys(
                    &mut wallet,
                    Some(eth_hot_pk.clone()),
                    Some(protocol_pk.clone()),
                    SchemeType::Ed25519,
                )
                .expect("Generating new validator keys should not fail");
                let pk = validator_keys.dkg_keypair.as_ref().unwrap().public();
                wallet.add_validator_data(address.clone(), validator_keys);
                pk
            });

        // Add the validator public keys to genesis config
        config.consensus_public_key =
            Some(genesis_config::HexString(consensus_pk.to_string()));
        config.account_public_key =
            Some(genesis_config::HexString(account_pk.to_string()));
        config.eth_cold_key =
            Some(genesis_config::HexString(eth_cold_pk.to_string()));
        config.eth_hot_key =
            Some(genesis_config::HexString(eth_hot_pk.to_string()));

        config.protocol_public_key =
            Some(genesis_config::HexString(protocol_pk.to_string()));
        config.dkg_public_key =
            Some(genesis_config::HexString(dkg_pk.to_string()));

        // Write keypairs to wallet
        wallet.add_address(name.clone(), address, true);

        crate::wallet::save(&wallet).unwrap();
    });

    // Create a wallet for all accounts other than validators.
    //  Do not use mnemonic code / HD derivation path.
    let mut wallet =
        crate::wallet::load_or_new(&accounts_dir.join(NET_OTHER_ACCOUNTS_DIR));
    if let Some(established) = &mut config.established {
        established.iter_mut().for_each(|(name, config)| {
            init_established_account(
                name,
                &mut wallet,
                config,
                unsafe_dont_encrypt,
            );
        })
    }

    config.token.iter_mut().for_each(|(_name, config)| {
        if config.address.is_none() {
            let address = address::gen_established_address("token");
            config.address = Some(address.to_string());
        }
        if config.vp.is_none() {
            config.vp = Some("vp_token".to_string());
        }
    });

    if let Some(implicit) = &mut config.implicit {
        implicit.iter_mut().for_each(|(name, config)| {
            if config.public_key.is_none() {
                println!(
                    "Generating implicit account {} key and address ...",
                    name
                );
                let password =
                    read_and_confirm_encryption_password(unsafe_dont_encrypt);
                let (_alias, keypair) = wallet
                    .gen_key(
                        SchemeType::Ed25519,
                        Some(name.clone()),
                        true,
                        password,
                        None,
                    )
                    .expect("Key generation should not fail.")
                    .expect("No existing alias expected.");
                let public_key =
                    genesis_config::HexString(keypair.ref_to().to_string());
                config.public_key = Some(public_key);
            }
        })
    }

    // Make a copy of genesis config without validator net addresses to
    // `write_genesis_config`. Keep the original, because we still need the
    // addresses to configure validators.
    let mut config_clean = config.clone();
    config_clean
        .validator
        .iter_mut()
        .for_each(|(_name, config)| {
            config.net_address = None;
        });

    // Generate the chain ID first
    let genesis = genesis_config::load_genesis_config(config_clean.clone());
    let genesis_bytes = genesis.try_to_vec().unwrap();
    let chain_id = ChainId::from_genesis(chain_id_prefix, genesis_bytes);
    let chain_dir = global_args.base_dir.join(chain_id.as_str());
    let genesis_path = global_args
        .base_dir
        .join(format!("{}.toml", chain_id.as_str()));

    // Write the genesis file
    genesis_config::write_genesis_config(&config_clean, &genesis_path);

    // Add genesis addresses and save the wallet with other account keys
    crate::wallet::add_genesis_addresses(&mut wallet, config_clean.clone());
    crate::wallet::save(&wallet).unwrap();

    // Write the global config setting the default chain ID
    let global_config = GlobalConfig::new(chain_id.clone());
    global_config.write(&global_args.base_dir).unwrap();

    // Rename the generate chain config dir from `temp_chain_id` to `chain_id`
    fs::rename(&temp_dir, &chain_dir).unwrap();

    // Copy the WASM checksums
    let wasm_dir_full = chain_dir.join(config::DEFAULT_WASM_DIR);
    fs::create_dir_all(&wasm_dir_full).unwrap();
    fs::copy(
        &wasm_checksums_path,
        wasm_dir_full.join(config::DEFAULT_WASM_CHECKSUMS_FILE),
    )
    .unwrap();

    config.validator.iter().for_each(|(name, _config)| {
        let validator_dir = global_args
            .base_dir
            .join(chain_id.as_str())
            .join(NET_ACCOUNTS_DIR)
            .join(name)
            .join(config::DEFAULT_BASE_DIR);
        let temp_validator_chain_dir =
            validator_dir.join(temp_chain_id.as_str());
        let validator_chain_dir = validator_dir.join(chain_id.as_str());
        // Rename the generated directories for validators from `temp_chain_id`
        // to `chain_id`
        std::fs::rename(temp_validator_chain_dir, &validator_chain_dir)
            .unwrap();

        // Copy the WASM checksums
        let wasm_dir_full = validator_chain_dir.join(config::DEFAULT_WASM_DIR);
        fs::create_dir_all(&wasm_dir_full).unwrap();
        fs::copy(
            &wasm_checksums_path,
            wasm_dir_full.join(config::DEFAULT_WASM_CHECKSUMS_FILE),
        )
        .unwrap();

        // Write the genesis and global config into validator sub-dirs
        genesis_config::write_genesis_config(
            &config,
            validator_dir.join(format!("{}.toml", chain_id.as_str())),
        );
        global_config.write(validator_dir).unwrap();
        // Add genesis addresses to the validator's wallet
        let mut wallet = crate::wallet::load_or_new(&validator_chain_dir);
        crate::wallet::add_genesis_addresses(&mut wallet, config_clean.clone());
        crate::wallet::save(&wallet).unwrap();
    });

    // Generate the validators' ledger config
    config.validator.iter_mut().enumerate().for_each(
        |(ix, (name, validator_config))| {
            let accounts_dir = chain_dir.join(NET_ACCOUNTS_DIR);
            let validator_dir =
                accounts_dir.join(name).join(config::DEFAULT_BASE_DIR);
            let mut config = Config::load(
                &validator_dir,
                &chain_id,
                Some(TendermintMode::Validator),
            );

            // Configure the ledger
            config.ledger.genesis_time = genesis.genesis_time.into();
            // In `config::Ledger`'s `base_dir`, `chain_id` and `tendermint`,
            // the paths are prefixed with `validator_dir` given in the first
            // parameter. We need to remove this prefix, because
            // these sub-directories will be moved to validators' root
            // directories.
            config.ledger.shell.base_dir = config::DEFAULT_BASE_DIR.into();
            // Add a ledger P2P persistent peers
            config.ledger.cometbft.p2p.persistent_peers = persistent_peers
                    .iter()
                    .enumerate()
                    .filter_map(|(index, peer)|
                        // we do not add the validator in its own persistent peer list
                        if index != ix  {
                            Some(peer.to_owned())
                        } else {
                            None
                        })
                    .collect();

            config.ledger.cometbft.consensus.timeout_commit =
                consensus_timeout_commit;
            config.ledger.cometbft.p2p.allow_duplicate_ip = allow_duplicate_ip;
            config.ledger.cometbft.p2p.addr_book_strict = !localhost;
            // Clear the net address from the config and use it to set ports
            let net_address = validator_config.net_address.take().unwrap();
            let split: Vec<&str> = net_address.split(':').collect();
            let first_port = split[1].parse::<u16>().unwrap();
            if localhost {
                config.ledger.cometbft.p2p.laddr = TendermintAddress::from_str(
                    &format!("127.0.0.1:{}", first_port),
                )
                .unwrap();
            } else {
                config.ledger.cometbft.p2p.laddr = TendermintAddress::from_str(
                    &format!("0.0.0.0:{}", first_port),
                )
                .unwrap();
            }
            if localhost {
                config.ledger.cometbft.rpc.laddr = TendermintAddress::from_str(
                    &format!("127.0.0.1:{}", first_port + 1),
                )
                .unwrap();
            } else {
                config.ledger.cometbft.rpc.laddr = TendermintAddress::from_str(
                    &format!("0.0.0.0:{}", first_port + 1),
                )
                .unwrap();
            }
            if localhost {
                config.ledger.cometbft.proxy_app = TendermintAddress::from_str(
                    &format!("127.0.0.1:{}", first_port + 2),
                )
                .unwrap();
            } else {
                config.ledger.cometbft.proxy_app = TendermintAddress::from_str(
                    &format!("0.0.0.0:{}", first_port + 2),
                )
                .unwrap();
            }
            config.write(&validator_dir, &chain_id, true).unwrap();
        },
    );

    // Update the ledger config persistent peers and save it
    let mut config = Config::load(&global_args.base_dir, &chain_id, None);
    config.ledger.cometbft.p2p.persistent_peers = persistent_peers;
    config.ledger.cometbft.consensus.timeout_commit = consensus_timeout_commit;
    config.ledger.cometbft.p2p.allow_duplicate_ip = allow_duplicate_ip;
    // Open P2P address
    if !localhost {
        config.ledger.cometbft.p2p.laddr =
            TendermintAddress::from_str("0.0.0.0:26656").unwrap();
    }
    config.ledger.cometbft.p2p.addr_book_strict = !localhost;
    config.ledger.genesis_time = genesis.genesis_time.into();
    config
        .write(&global_args.base_dir, &chain_id, true)
        .unwrap();

    println!("Derived chain ID: {}", chain_id);
    println!(
        "Genesis file generated at {}",
        genesis_path.to_string_lossy()
    );

    // Create a release tarball for anoma-network-config
    if !dont_archive {
        let mut release = tar::Builder::new(Vec::new());
        let release_genesis_path = PathBuf::from(config::DEFAULT_BASE_DIR)
            .join(format!("{}.toml", chain_id.as_str()));
        release
            .append_path_with_name(genesis_path, release_genesis_path)
            .unwrap();
        let global_config_path = GlobalConfig::file_path(&global_args.base_dir);
        let release_global_config_path =
            GlobalConfig::file_path(config::DEFAULT_BASE_DIR);
        release
            .append_path_with_name(
                global_config_path,
                release_global_config_path,
            )
            .unwrap();
        let chain_config_path =
            Config::file_path(&global_args.base_dir, &chain_id);
        let release_chain_config_path =
            Config::file_path(config::DEFAULT_BASE_DIR, &chain_id);
        release
            .append_path_with_name(chain_config_path, release_chain_config_path)
            .unwrap();
        let release_wasm_checksums_path =
            PathBuf::from(config::DEFAULT_BASE_DIR)
                .join(chain_id.as_str())
                .join(config::DEFAULT_WASM_DIR)
                .join(config::DEFAULT_WASM_CHECKSUMS_FILE);
        release
            .append_path_with_name(
                &wasm_checksums_path,
                release_wasm_checksums_path,
            )
            .unwrap();

        // Gzip tar release and write to file
        let release_file = archive_dir
            .unwrap_or_else(|| env::current_dir().unwrap())
            .join(format!("{}.tar.gz", chain_id));
        let compressed_file = File::create(&release_file).unwrap();
        let mut encoder =
            GzEncoder::new(compressed_file, Compression::default());
        encoder.write_all(&release.into_inner().unwrap()).unwrap();
        encoder.finish().unwrap();
        println!(
            "Release archive created at {}",
            release_file.to_string_lossy()
        );
    }
}

fn init_established_account(
    name: impl AsRef<str>,
    wallet: &mut Wallet<CliWalletUtils>,
    config: &mut genesis_config::EstablishedAccountConfig,
    unsafe_dont_encrypt: bool,
) {
    if config.address.is_none() {
        let address = address::gen_established_address("established");
        config.address = Some(address.to_string());
        wallet.add_address(&name, address, true);
    }
    if config.public_key.is_none() {
        println!("Generating established account {} key...", name.as_ref());
        let password =
            read_and_confirm_encryption_password(unsafe_dont_encrypt);
        let (_alias, keypair) = wallet
            .gen_key(
                SchemeType::Ed25519,
                Some(format!("{}-key", name.as_ref())),
                true,
                password,
                None, // do not use mnemonic code / HD derivation path
            )
            .expect("Key generation should not fail.")
            .expect("No existing alias expected.");
        let public_key =
            genesis_config::HexString(keypair.ref_to().to_string());
        config.public_key = Some(public_key);
    }
    if config.vp.is_none() {
        config.vp = Some("vp_user".to_string());
    }
}

pub fn pk_to_tm_address(
    _global_args: args::Global,
    args::PkToTmAddress { public_key }: args::PkToTmAddress,
) {
    let tm_addr = tm_consensus_key_raw_hash(&public_key);
    println!("{tm_addr}");
}

pub fn default_base_dir(
    _global_args: args::Global,
    _args: args::DefaultBaseDir,
) {
    println!(
        "{}",
        get_default_namada_folder().to_str().expect(
            "expected a default namada folder to be possible to determine"
        )
    );
}

/// Initialize genesis validator's address, consensus key and validator account
/// key and use it in the ledger's node.
pub fn init_genesis_validator(
    global_args: args::Global,
    args::InitGenesisValidator {
        alias,
        commission_rate,
        max_commission_rate_change,
        net_address,
        unsafe_dont_encrypt,
        key_scheme,
    }: args::InitGenesisValidator,
) {
    // Validate the commission rate data
    if commission_rate > Dec::one() {
        eprintln!("The validator commission rate must not exceed 1.0 or 100%");
        cli::safe_exit(1)
    }
    if max_commission_rate_change > Dec::one() {
        eprintln!(
            "The validator maximum change in commission rate per epoch must \
             not exceed 1.0 or 100%"
        );
        cli::safe_exit(1)
    }
    let pre_genesis_dir =
        validator_pre_genesis_dir(&global_args.base_dir, &alias);
    println!("Generating validator keys...");
    let pre_genesis = pre_genesis::gen_and_store(
        key_scheme,
        unsafe_dont_encrypt,
        &pre_genesis_dir,
    )
    .unwrap_or_else(|err| {
        eprintln!(
            "Unable to generate the validator pre-genesis wallet: {}",
            err
        );
        cli::safe_exit(1)
    });
    println!(
        "The validator's keys were stored in the wallet at {}",
        pre_genesis::validator_file_name(&pre_genesis_dir).to_string_lossy()
    );

    let validator_config = ValidatorPreGenesisConfig {
        validator: HashMap::from_iter([(
            alias,
            genesis_config::ValidatorConfig {
                consensus_public_key: Some(HexString(
                    pre_genesis.consensus_key.ref_to().to_string(),
                )),
                eth_cold_key: Some(HexString(
                    pre_genesis.eth_cold_key.ref_to().to_string(),
                )),
                eth_hot_key: Some(HexString(
                    pre_genesis.eth_hot_key.ref_to().to_string(),
                )),
                account_public_key: Some(HexString(
                    pre_genesis.account_key.ref_to().to_string(),
                )),
                protocol_public_key: Some(HexString(
                    pre_genesis
                        .store
                        .validator_keys
                        .protocol_keypair
                        .ref_to()
                        .to_string(),
                )),
                dkg_public_key: Some(HexString(
                    pre_genesis
                        .store
                        .validator_keys
                        .dkg_keypair
                        .as_ref()
                        .unwrap()
                        .public()
                        .to_string(),
                )),
                commission_rate: Some(commission_rate),
                max_commission_rate_change: Some(max_commission_rate_change),
                tendermint_node_key: Some(HexString(
                    pre_genesis.tendermint_node_key.ref_to().to_string(),
                )),
                net_address: Some(net_address),
                ..Default::default()
            },
        )]),
    };
    let genesis_part = toml::to_string(&validator_config).unwrap();
    println!("Your public partial pre-genesis TOML configuration:");
    println!();
    println!("{genesis_part}");

    let file_name = validator_pre_genesis_file(&pre_genesis_dir);
    fs::write(&file_name, genesis_part).unwrap_or_else(|err| {
        eprintln!(
            "Couldn't write partial pre-genesis file to {}. Failed with: {}",
            file_name.to_string_lossy(),
            err
        );
        cli::safe_exit(1)
    });
    println!();
    println!(
        "Pre-genesis TOML written to {}",
        file_name.to_string_lossy()
    );
}

async fn download_file(url: impl AsRef<str>) -> reqwest::Result<Bytes> {
    let url = url.as_ref();
    let response = reqwest::get(url).await?;
    response.error_for_status_ref()?;
    let contents = response.bytes().await?;
    Ok(contents)
}

fn try_parse_public_key(
    label: impl AsRef<str>,
    value: &Option<HexString>,
) -> Option<common::PublicKey> {
    let label = label.as_ref();
    value.as_ref().map(|key| {
        key.to_public_key().unwrap_or_else(|err| {
            eprintln!("Invalid {label} key: {}", err);
            cli::safe_exit(1)
        })
    })
}

fn network_configs_url_prefix(chain_id: &ChainId) -> String {
    std::env::var(ENV_VAR_NETWORK_CONFIGS_SERVER).unwrap_or_else(|_| {
        format!("{DEFAULT_NETWORK_CONFIGS_SERVER}/{chain_id}")
    })
}

/// Write the node key into tendermint config dir.
pub fn write_tendermint_node_key(
    tm_home_dir: &Path,
    node_sk: common::SecretKey,
) -> common::PublicKey {
    let node_pk: common::PublicKey = node_sk.ref_to();

    // Convert and write the keypair into Tendermint node_key.json file.
    // Tendermint requires concatenating the private-public keys for ed25519
    // but does not for secp256k1.
    let (node_keypair, key_str) = match node_sk {
        common::SecretKey::Ed25519(sk) => (
            [sk.try_to_vec().unwrap(), sk.ref_to().try_to_vec().unwrap()]
                .concat(),
            "Ed25519",
        ),
        common::SecretKey::Secp256k1(sk) => {
            (sk.try_to_vec().unwrap(), "Secp256k1")
        }
    };

    let tm_node_keypair_json = json!({
        "priv_key": {
            "type": format!("tendermint/PrivKey{}",key_str),
            "value": base64::encode(node_keypair),
        }
    });
    let tm_config_dir = tm_home_dir.join("config");
    fs::create_dir_all(&tm_config_dir)
        .expect("Couldn't create validator directory");
    let node_key_path = tm_config_dir.join("node_key.json");
    let file = OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(true)
        .open(node_key_path)
        .expect("Couldn't create validator node key file");
    serde_json::to_writer_pretty(file, &tm_node_keypair_json)
        .expect("Couldn't write validator node key file");
    node_pk
}

/// The default path to a validator pre-genesis file.
pub fn validator_pre_genesis_file(pre_genesis_path: &Path) -> PathBuf {
    pre_genesis_path.join("validator.toml")
}

/// The default validator pre-genesis directory
pub fn validator_pre_genesis_dir(base_dir: &Path, alias: &str) -> PathBuf {
    base_dir.join(PRE_GENESIS_DIR).join(alias)
}

/// Add a spinning wheel to a message for long running commands.
/// Can be turned off for E2E tests by setting the `REDUCED_CLI_PRINTING`
/// environment variable.
pub fn with_spinny_wheel<F, Out>(msg: &str, func: F) -> Out
where
    F: FnOnce() -> Out + Send + 'static,
    Out: Send + 'static,
{
    let task = std::thread::spawn(func);
    let spinny_wheel = "|/-\\";
    print!("{}", msg);
    _ = std::io::stdout().flush();
    for c in spinny_wheel.chars().cycle() {
        print!("{}", c);
        std::thread::sleep(std::time::Duration::from_secs(1));
        print!("{}", (8u8 as char));
        if task.is_finished() {
            break;
        }
    }
    println!();
    task.join().unwrap()
}

fn is_valid_validator_for_current_chain(
    tendermint_node_pk: &common::PublicKey,
    genesis_config: &GenesisConfig,
) -> bool {
    genesis_config.validator.iter().any(|(_alias, config)| {
        if let Some(tm_node_key) = &config.tendermint_node_key {
            tm_node_key.0.eq(&tendermint_node_pk.to_string())
        } else {
            false
        }
    })
}

/// Replace the contents of `addr` with a dummy address.
#[inline]
pub fn take_config_address(addr: &mut TendermintAddress) -> TendermintAddress {
    std::mem::replace(
        addr,
        TendermintAddress::Tcp {
            peer_id: None,
            host: String::new(),
            port: 0,
        },
    )
}
