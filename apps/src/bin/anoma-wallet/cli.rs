//! Anoma Wallet CLI.

use std::fs::File;
use std::io::{self, Read, Write};
use std::str::FromStr;

use anoma::types::key::ed25519::{Keypair, PublicKey, PublicKeyHash};
#[cfg(feature = "dev")]
use anoma_apps::cli;
use anoma_apps::cli::{args, cmds};
use anoma_apps::wallet::{DecryptionError, Wallet};
use borsh::BorshSerialize;
use color_eyre::eyre::Result;

pub fn main() -> Result<()> {
    let (cmd, global_args) = cli::anoma_wallet_cli();
    match cmd {
        cmds::AnomaWallet::Keypair(cmds::Key::Gen(cmds::KeyGen(args))) => {
            key_gen(global_args, args)
        }
        cmds::AnomaWallet::Keypair(cmds::Key::Find(cmds::KeyFind(args))) => {
            key_find(global_args, args)
        }
        cmds::AnomaWallet::Keypair(cmds::Key::List(cmds::KeyList(args))) => {
            key_list(global_args, args)
        }
        cmds::AnomaWallet::Keypair(cmds::Key::Export(cmds::Export(args))) => {
            key_export(global_args, args)
        }
    }
    Ok(())
}

/// Generate a new keypair and store it in the wallet.
fn key_gen(
    global: args::Global,
    args::KeyGen {
        alias,
        unsafe_dont_encrypt,
    }: args::KeyGen,
) {
    let mut wallet = Wallet::load_or_new(&global.base_dir);
    let alias = wallet.gen_key(alias, unsafe_dont_encrypt);
    wallet.save().unwrap_or_else(|err| eprintln!("{}", err));
    println!("Successfully added a key with alias: \"{}\"", alias);
}

/// Find a keypair in the wallet store.
fn key_find(
    global: args::Global,
    args::KeyFind {
        public_key,
        alias,
        value,
        unsafe_show_secret,
    }: args::KeyFind,
) {
    let wallet = Wallet::load_or_new(&global.base_dir);
    let found_keypair = match public_key {
        Some(pk) => {
            let pk = PublicKey::from_str(&pk).expect("Invalid public key");
            wallet.find_key_by_pk(&pk)
        }
        None => {
            let alias = alias.or(value);
            match alias {
                None => {
                    eprintln!(
                        "An alias, public key or public key hash needs to be \
                         supplied"
                    );
                    cli::safe_exit(1)
                }
                Some(alias) => wallet.find_key(alias),
            }
        }
    };
    match found_keypair {
        Ok(keypair) => {
            let keypair = keypair.get();
            let pkh: PublicKeyHash = (&keypair.public).into();
            println!("Public key hash: {}", pkh);
            println!("Public key: {}", keypair.public);
            if unsafe_show_secret {
                println!("Secret key: {}", keypair.secret);
            }
        }
        Err(err) => {
            eprintln!("{}", err);
        }
    }
}

fn key_list(
    global: args::Global,
    args::KeyList {
        decrypt,
        unsafe_show_secret,
    }: args::KeyList,
) {
    let wallet = Wallet::load_or_new(&global.base_dir);
    let stdout = io::stdout();
    let mut w = stdout.lock();
    writeln!(w, "Known keys:").unwrap();
    for (alias, (stored_keypair, pkh)) in wallet.get_keys() {
        let encrypted = if stored_keypair.is_encrypted() {
            "encrypted"
        } else {
            "not encrypted"
        };
        writeln!(w, "  Alias \"{}\" ({}):", alias, encrypted).unwrap();
        if let Some(pkh) = pkh {
            writeln!(w, "    Public key hash: {}", pkh).unwrap();
        }
        match stored_keypair.get(decrypt) {
            Ok(keypair) => {
                let keypair = keypair.get();
                writeln!(w, "    Public key: {}", keypair.public).unwrap();
                if unsafe_show_secret {
                    writeln!(w, "    Secret key: {}", keypair.secret).unwrap();
                }
            }
            Err(DecryptionError::NotDecrypting) if !decrypt => {
                continue;
            }
            Err(err) => {
                writeln!(w, "    Couldn't decrypt the keypair: {}", err)
                    .unwrap();
            }
        }
    }
}

/// Export a keypair to a file.
fn key_export(global: args::Global, args::Export { alias }: args::Export) {
    let wallet = Wallet::load_or_new(&global.base_dir);
    // TODO make the alias required
    let alias = alias.unwrap_or_else(|| {
        let mut read_alias = String::new();

        io::stdin().read_to_string(&mut read_alias).unwrap();
        read_alias
    });

    wallet
        .find_key(alias.clone())
        .map(|keypair| {
            let keypair: &Keypair = keypair.get();
            let file_data = keypair
                .try_to_vec()
                .expect("Encoding keypair shouldn't fail");
            let mut file = File::create(format!("key_{}", alias)).unwrap();

            file.write_all(file_data.as_ref()).unwrap();
        })
        .unwrap_or_else(|err| {
            eprintln!("{}", err);
            cli::safe_exit(1)
        })
}
