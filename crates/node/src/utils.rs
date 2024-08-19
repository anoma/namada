//! Node utils commands handlers

use std::str::FromStr;

use namada_apps_lib::cli::args::{self, TestGenesis};
use namada_apps_lib::client::utils::PRE_GENESIS_DIR;
use namada_apps_lib::config::genesis::{self, AddrOrPk};
use namada_apps_lib::{cli, wallet};
use namada_sdk::address::{Address, ImplicitAddress};
use namada_sdk::key::common;
use namada_sdk::wallet::FindKeyError;

use crate::facade::tendermint::Timeout;

pub fn test_genesis(args: TestGenesis, global_args: args::Global) {
    let TestGenesis {
        path,
        wasm_dir,
        check_can_sign,
    } = args;

    let templates = genesis::templates::load_and_validate(&path).unwrap();
    let genesis = genesis::chain::finalize(
        templates,
        FromStr::from_str("namada-dryrun").unwrap(),
        Default::default(),
        Timeout::from_str("30s").unwrap(),
    );
    let chain_id = &genesis.metadata.chain_id;
    let test_dir = tempfile::tempdir().unwrap();
    let config = crate::config::Config::load(test_dir.path(), chain_id, None);
    genesis
        .write_toml_files(&test_dir.path().join(chain_id.to_string()))
        .unwrap();
    crate::test_genesis_files(config.ledger, genesis.clone(), wasm_dir);

    if !check_can_sign.is_empty() {
        let wallet_path = global_args.base_dir.join(PRE_GENESIS_DIR);
        let mut wallet = if wallet::exists(&wallet_path) {
            wallet::load(&wallet_path).unwrap()
        } else {
            panic!(
                "Could not find wallet at {}.",
                wallet_path.to_string_lossy()
            );
        };

        let mut all_valid = true;

        type WalletRes = Result<common::SecretKey, FindKeyError>;
        let handle_wallet_result =
            |searched: String, result: WalletRes| match result {
                Ok(_) => {
                    println!("Able to sign with {searched}");
                    true
                }
                Err(err) => {
                    eprintln!("Unable to sign with {searched}. {err}");
                    false
                }
            };

        for addr_or_pk in check_can_sign {
            match &addr_or_pk {
                AddrOrPk::PublicKey(pk) => {
                    if !handle_wallet_result(
                        pk.to_string(),
                        wallet.find_key_by_pk(&pk.raw, None),
                    ) {
                        all_valid = false;
                    }
                }
                AddrOrPk::Address(addr) => {
                    match &addr {
                        Address::Established(_) => {
                            // Find PK(s) of the address in genesis
                            if let Some(txs) = genesis
                                .transactions
                                .established_account
                                .as_ref()
                            {
                                if let Some(tx) =
                                    txs.iter().find(|tx| &tx.address == addr)
                                {
                                    println!(
                                        "Found a matching genesis established \
                                         account tx with {} public key(s).",
                                        tx.tx.public_keys.len()
                                    );
                                    for pk in &tx.tx.public_keys {
                                        if !handle_wallet_result(
                                            format!("{pk} for {addr}"),
                                            wallet
                                                .find_key_by_pk(&pk.raw, None),
                                        ) {
                                            all_valid = false;
                                        }
                                    }
                                } else {
                                    eprintln!(
                                        "No genesis established account txs \
                                         with a matching address {addr} found"
                                    );
                                    all_valid = false;
                                }
                            } else {
                                eprintln!(
                                    "No genesis established account txs \
                                     found. Cannot check address {addr}."
                                );
                                all_valid = false;
                            }
                        }
                        Address::Implicit(ImplicitAddress(pkh)) => {
                            if !handle_wallet_result(
                                addr.to_string(),
                                wallet.find_key_by_pkh(pkh, None),
                            ) {
                                all_valid = false;
                            }
                        }
                        Address::Internal(_) => {
                            eprintln!("Unexpected internal address {addr}");
                            all_valid = false;
                        }
                    }
                }
            }
        }
        if !all_valid {
            cli::safe_exit(1);
        }
    }
}
