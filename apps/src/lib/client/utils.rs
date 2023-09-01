use std::env;
use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::str::FromStr;

use borsh::BorshSerialize;
use flate2::read::GzDecoder;
use flate2::write::GzEncoder;
use flate2::Compression;
use namada::ledger::wallet::alias::Alias;
use namada::ledger::wallet::{alias, Wallet};
use namada::types::chain::ChainId;
use namada::types::dec::Dec;
use namada::types::key::*;
use namada::types::token;
use namada::types::token::NATIVE_MAX_DECIMAL_PLACES;
use namada::types::uint::Uint;
use prost::bytes::Bytes;
use serde_json::json;
use sha2::{Digest, Sha256};

use crate::cli::args;
use crate::cli::context::ENV_VAR_WASM_DIR;
use crate::config::global::GlobalConfig;
use crate::config::{
    self, genesis, get_default_namada_folder, Config, TendermintMode,
};
use crate::facade::tendermint::node::Id as TendermintNodeId;
use crate::facade::tendermint_config::net::Address as TendermintAddress;
use crate::node::ledger::tendermint_node;
use crate::wallet::{pre_genesis, CliWalletUtils};
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
        allow_duplicate_ip,
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
            safe_exit(1);
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
                Alias::from(validator_alias),
                pre_genesis::load(&pre_genesis_dir).unwrap_or_else(|err| {
                    eprintln!(
                        "Error loading validator pre-genesis wallet {err}",
                    );
                    safe_exit(1)
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
            safe_exit(1);
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

    // Read the genesis files
    let genesis = genesis::chain::Finalized::read_toml_files(&chain_dir)
        .unwrap_or_else(|err| {
            eprintln!(
                "Failed to read genesis TOML files from {} with {err}.",
                chain_dir.to_string_lossy()
            );
            safe_exit(1)
        });

    // Try to find validator data when using a pre-genesis validator
    let validator_alias = validator_alias_and_pre_genesis_wallet
        .as_ref()
        .map(|(alias, _wallet)| alias.clone());
    let validator_keys = validator_alias_and_pre_genesis_wallet.as_ref().map(
        |(_alias, wallet)| {
            let tendermint_node_key: common::SecretKey = wallet
                .tendermint_node_key
                .try_to_sk()
                .unwrap_or_else(|_err| {
                    eprintln!(
                        "Tendermint node key must be common (need to change?)"
                    );
                    safe_exit(1)
                });
            (tendermint_node_key, wallet.consensus_key.clone())
        },
    );
    let node_mode = if validator_alias.is_some() {
        TendermintMode::Validator
    } else {
        TendermintMode::Full
    };

    // Derive config from genesis
    let config = genesis.derive_config(
        &chain_dir,
        node_mode,
        validator_alias,
        allow_duplicate_ip,
    );

    // Try to load pre-genesis wallet, if any
    let pre_genesis_wallet_path = base_dir.join(PRE_GENESIS_DIR);
    let pre_genesis_wallet = crate::wallet::load(&pre_genesis_wallet_path);
    // Derive wallet from genesis
    let wallet = genesis.derive_wallet(
        &chain_dir,
        pre_genesis_wallet,
        validator_alias_and_pre_genesis_wallet,
    );

    // Save the config and the wallet
    config.write(&base_dir, &chain_id, true).unwrap();
    crate::wallet::save(&wallet).unwrap();

    // Setup the node for a genesis validator, if used
    if let Some((tendermint_node_key, consensus_key)) = validator_keys {
        println!("Setting up validator keys.");
        let tm_home_dir = chain_dir.join("tendermint");

        // Write consensus key to tendermint home
        tendermint_node::write_validator_key(&tm_home_dir, &consensus_key);

        // Write tendermint node key
        write_tendermint_node_key(&tm_home_dir, tendermint_node_key);

        // Pre-initialize tendermint validator state
        tendermint_node::write_validator_state(&tm_home_dir);
    } else {
        println!(
            "No validator keys are being used. Make sure you didn't forget to \
             specify `--genesis-validator`?"
        );
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
        templates_path,
        wasm_checksums_path,
        chain_id_prefix,
        genesis_time,
        consensus_timeout_commit,
        dont_archive,
        archive_dir,
    }: args::InitNetwork,
) {
    // Load and validate the templates
    let templates = genesis::templates::load_and_validate(&templates_path)
        .unwrap_or_else(|| {
            eprintln!("Invalid templates, aborting.");
            safe_exit(1)
        });

    // In addition to standard templates validation, check that there is at
    // least one validator account.
    if !templates.transactions.has_at_least_one_validator() {
        eprintln!("No validator genesis transaction found, aborting.");
        safe_exit(1)
    }

    // Also check that at least one validator account has positive voting power.
    let tm_votes_per_token = templates.parameters.pos_params.tm_votes_per_token;
    if !templates
        .transactions
        .has_validator_with_positive_voting_power(tm_votes_per_token)
    {
        let min_stake = token::Amount::from_uint(
            if tm_votes_per_token > Dec::from(1) {
                Uint::one()
            } else {
                (Dec::from(1) / tm_votes_per_token).ceil().abs()
            },
            NATIVE_MAX_DECIMAL_PLACES,
        )
        .unwrap();
        eprintln!(
            "No validator with positive voting power, aborting. The minimum \
             staked tokens amount required to run the network is {}, because \
             there are {tm_votes_per_token} votes per NAMNAM tokens.",
            min_stake.to_string_native(),
        );
        safe_exit(1)
    }

    // Finalize the genesis config to derive the chain ID
    let genesis = genesis::chain::finalize(
        templates,
        chain_id_prefix,
        genesis_time,
        consensus_timeout_commit,
    );
    let chain_id = &genesis.metadata.chain_id;
    let chain_dir = global_args.base_dir.join(chain_id.as_str());

    // Check that chain dir is empty
    if chain_dir.exists() && chain_dir.read_dir().unwrap().next().is_some() {
        println!(
            "The target chain directory {} already exists and is not empty.",
            chain_dir.to_string_lossy()
        );
        loop {
            let mut buffer = String::new();
            print!(
                "Do you want to override the chain directory? Will exit \
                 otherwise. [y/N]: "
            );
            std::io::stdout().flush().unwrap();
            match std::io::stdin().read_line(&mut buffer) {
                Ok(size) if size > 0 => {
                    // Isolate the single character representing the choice
                    let byte = buffer.chars().next().unwrap();
                    buffer.clear();
                    match byte {
                        'y' | 'Y' => {
                            fs::remove_dir_all(&chain_dir).unwrap();
                            break;
                        }
                        'n' | 'N' => {
                            println!("Exiting.");
                            safe_exit(1)
                        }
                        // Input is senseless fall through to repeat prompt
                        _ => {
                            println!("Unrecognized input.");
                        }
                    };
                }
                _ => {}
            }
        }
    }
    fs::create_dir_all(&chain_dir).unwrap();

    // Write the finalized genesis config to the chain dir
    genesis.write_toml_files(&chain_dir).unwrap_or_else(|err| {
        eprintln!(
            "Failed to write finalized genesis TOML files to {} with {err}.",
            chain_dir.to_string_lossy()
        );
        safe_exit(1)
    });

    // Write the global config setting the default chain ID
    let global_config = GlobalConfig::new(chain_id.clone());
    global_config.write(&global_args.base_dir).unwrap();

    // Copy the WASM checksums
    let wasm_dir_full = chain_dir.join(config::DEFAULT_WASM_DIR);
    fs::create_dir_all(&wasm_dir_full).unwrap();
    fs::copy(
        &wasm_checksums_path,
        wasm_dir_full.join(config::DEFAULT_WASM_CHECKSUMS_FILE),
    )
    .unwrap();

    println!("Derived chain ID: {}", chain_id);
    println!("Genesis files stored at {}", chain_dir.to_string_lossy());

    // Create a release tarball for anoma-network-config
    if !dont_archive {
        // TODO: remove the `config::DEFAULT_BASE_DIR` and instead just archive
        // the chain dir
        let mut release = tar::Builder::new(Vec::new());
        release
            .append_dir_all(
                PathBuf::from(config::DEFAULT_BASE_DIR).join(chain_id.as_str()),
                &chain_dir,
            )
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

    // After the archive is created, try to copy the built WASM, if they're
    // present with the checksums. This is used for local network setup, so
    // that we can use a local WASM build.
    let checksums = wasm_loader::Checksums::read_checksums(&wasm_dir_full);
    for (_, full_name) in checksums.0 {
        // try to copy built file from the Namada WASM root dir
        let file = std::env::current_dir()
            .unwrap()
            .join(crate::config::DEFAULT_WASM_DIR)
            .join(&full_name);
        if file.exists() {
            fs::copy(file, wasm_dir_full.join(&full_name)).unwrap();
        }
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
/// key into a special "pre-genesis" wallet.
pub fn init_genesis_validator(
    global_args: args::Global,
    args::InitGenesisValidator {
        source,
        alias,
        commission_rate,
        max_commission_rate_change,
        net_address,
        unsafe_dont_encrypt,
        key_scheme,
        transfer_from_source_amount,
        self_bond_amount,
    }: args::InitGenesisValidator,
) {
    let (mut source_wallet, wallet_file) =
        load_pre_genesis_wallet_or_exit(&global_args.base_dir);

    let source_key =
        source_wallet.find_key(&source, None).unwrap_or_else(|err| {
            eprintln!(
                "Couldn't find key for source \"{source}\" in the pre-genesis \
                 wallet {}. Failed with {err}.",
                wallet_file.to_string_lossy()
            );
            safe_exit(1)
        });

    // Validate the commission rate data
    if commission_rate > Dec::one() {
        eprintln!("The validator commission rate must not exceed 1.0 or 100%");
        safe_exit(1)
    }
    if max_commission_rate_change > Dec::one() {
        eprintln!(
            "The validator maximum change in commission rate per epoch must \
             not exceed 1.0 or 100%"
        );
        safe_exit(1)
    }
    let pre_genesis_dir =
        validator_pre_genesis_dir(&global_args.base_dir, &alias);
    println!("Generating validator keys...");
    let validator_wallet = pre_genesis::gen_and_store(
        key_scheme,
        unsafe_dont_encrypt,
        &pre_genesis_dir,
    )
    .unwrap_or_else(|err| {
        eprintln!(
            "Unable to generate the validator pre-genesis wallet: {}",
            err
        );
        safe_exit(1)
    });
    println!(
        "The validator's keys were stored in the wallet at {}",
        pre_genesis::validator_file_name(&pre_genesis_dir).to_string_lossy()
    );

    let transactions = genesis::transactions::init_validator(
        genesis::transactions::GenesisValidatorData {
            source_key,
            alias: alias::Alias::from(alias),
            commission_rate,
            max_commission_rate_change,
            net_address,
            transfer_from_source_amount,
            self_bond_amount,
        },
        &mut source_wallet,
        &validator_wallet,
    );

    let genesis_part = toml::to_string(&transactions).unwrap();
    println!("Your public signed pre-genesis transactions TOML:");
    println!();
    println!("{genesis_part}");

    let file_name = validator_pre_genesis_txs_file(&pre_genesis_dir);
    fs::write(&file_name, genesis_part).unwrap_or_else(|err| {
        eprintln!(
            "Couldn't write pre-genesis transactions file to {}. Failed with: \
             {}",
            file_name.to_string_lossy(),
            err
        );
        safe_exit(1)
    });
    println!();
    println!(
        "Pre-genesis transactions TOML written to {}",
        file_name.to_string_lossy()
    );
}

/// Try to load a pre-genesis wallet or terminate if it cannot be found.
pub fn load_pre_genesis_wallet_or_exit(
    base_dir: &Path,
) -> (Wallet<CliWalletUtils>, PathBuf) {
    let pre_genesis_dir = base_dir.join(PRE_GENESIS_DIR);
    let wallet_file = crate::wallet::wallet_file(&pre_genesis_dir);
    (
        crate::wallet::load(&pre_genesis_dir).unwrap_or_else(|| {
            eprintln!(
                "No pre-genesis wallet found at {}.",
                wallet_file.to_string_lossy()
            );
            safe_exit(1)
        }),
        wallet_file,
    )
}

async fn download_file(url: impl AsRef<str>) -> reqwest::Result<Bytes> {
    let url = url.as_ref();
    let response = reqwest::get(url).await?;
    response.error_for_status_ref()?;
    let contents = response.bytes().await?;
    Ok(contents)
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

/// The default path to a validator pre-genesis txs file.
pub fn validator_pre_genesis_txs_file(pre_genesis_path: &Path) -> PathBuf {
    pre_genesis_path.join("transactions.toml")
}

/// The default validator pre-genesis directory
pub fn validator_pre_genesis_dir(base_dir: &Path, alias: &str) -> PathBuf {
    base_dir.join(PRE_GENESIS_DIR).join(alias)
}

/// Validate genesis templates. Exits process if invalid.
pub fn validate_genesis_templates(
    _global_args: args::Global,
    args::ValidateGenesisTemplates { path }: args::ValidateGenesisTemplates,
) {
    if genesis::templates::load_and_validate(&path).is_none() {
        safe_exit(1)
    }
}

/// Sign genesis transactions.
pub fn sign_genesis_tx(
    global_args: args::Global,
    args::SignGenesisTx { path, output }: args::SignGenesisTx,
) {
    let (mut wallet, _wallet_file) =
        load_pre_genesis_wallet_or_exit(&global_args.base_dir);

    let contents = fs::read(&path).unwrap_or_else(|err| {
        eprintln!(
            "Unable to read from file {}. Failed with {err}.",
            path.to_string_lossy()
        );
        safe_exit(1);
    });
    let unsigned = genesis::transactions::parse_unsigned(&contents)
        .unwrap_or_else(|err| {
            eprintln!(
                "Unable to parse the TOML from {}. Failed with {err}.",
                path.to_string_lossy()
            );
            safe_exit(1);
        });
    if unsigned.validator_account.is_some()
        && !unsigned.validator_account.as_ref().unwrap().is_empty()
    {
        eprintln!(
            "Validator transactions must be signed with a validator wallet. \
             You can use `namada client utils init-genesis-validator` \
             supplied with the required arguments to generate a validator \
             wallet and sign the validator genesis transactions."
        );
        safe_exit(1);
    }
    let signed = genesis::transactions::sign_txs(unsigned, &mut wallet);

    match output {
        Some(output_path) => {
            let transactions = toml::to_vec(&signed).unwrap();
            fs::write(&output_path, transactions).unwrap_or_else(|err| {
                eprintln!(
                    "Failed to write output to {} with {err}.",
                    output_path.to_string_lossy()
                );
                safe_exit(1);
            });
            println!(
                "Your public signed transactions TOML has been written to {}",
                output_path.to_string_lossy()
            );
        }
        None => {
            let transactions = toml::to_string(&signed).unwrap();
            println!("Your public signed transactions TOML:");
            println!();
            println!("{transactions}");
        }
    }
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

#[cfg(not(test))]
fn safe_exit(code: i32) -> ! {
    crate::cli::safe_exit(code)
}

#[cfg(test)]
fn safe_exit(code: i32) -> ! {
    panic!("Process exited unsuccesfully with error code: {}", code);
}
