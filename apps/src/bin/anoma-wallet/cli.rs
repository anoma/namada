//! Anoma Wallet CLI.

use std::fs::File;
use std::io::{self, Read, Write};

use anoma::types::key::ed25519::{Keypair, PublicKeyHash};
#[cfg(feature = "dev")]
use anoma_apps::cli;
use anoma_apps::cli::{args, cmds, Context};
use anoma_apps::wallet::DecryptionError;
use borsh::BorshSerialize;
use color_eyre::eyre::Result;

pub fn main() -> Result<()> {
    let (cmd, ctx) = cli::anoma_wallet_cli();
    match cmd {
        cmds::AnomaWallet::Key(sub) => match sub {
            cmds::WalletKey::Gen(cmds::KeyGen(args)) => key_gen(ctx, args),
            cmds::WalletKey::Find(cmds::KeyFind(args)) => key_find(ctx, args),
            cmds::WalletKey::List(cmds::KeyList(args)) => key_list(ctx, args),
            cmds::WalletKey::Export(cmds::Export(args)) => {
                key_export(ctx, args)
            }
        },
        cmds::AnomaWallet::Address(sub) => match sub {
            cmds::WalletAddress::List(cmds::AddressList) => address_list(ctx),
        },
    }
    Ok(())
}

/// Generate a new keypair and store it in the wallet.
fn key_gen(
    ctx: Context,
    args::KeyGen {
        alias,
        unsafe_dont_encrypt,
    }: args::KeyGen,
) {
    let mut wallet = ctx.wallet;
    let alias = wallet.gen_key(alias, unsafe_dont_encrypt);
    wallet.save().unwrap_or_else(|err| eprintln!("{}", err));
    println!("Successfully added a key with alias: \"{}\"", alias);
}

/// Find a keypair in the wallet store.
fn key_find(
    ctx: Context,
    args::KeyFind {
        public_key,
        alias,
        value,
        unsafe_show_secret,
    }: args::KeyFind,
) {
    let wallet = ctx.wallet;
    let found_keypair = match public_key {
        Some(pk) => wallet.find_key_by_pk(&pk),
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

/// List all known keys.
fn key_list(
    ctx: Context,
    args::KeyList {
        decrypt,
        unsafe_show_secret,
    }: args::KeyList,
) {
    let wallet = ctx.wallet;
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
fn key_export(ctx: Context, args::Export { alias }: args::Export) {
    let wallet = ctx.wallet;
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

/// List all known addresses.
fn address_list(ctx: Context) {
    let wallet = ctx.wallet;
    let stdout = io::stdout();
    let mut w = stdout.lock();
    writeln!(w, "Known addresses:").unwrap();
    for (alias, address) in wallet.get_addresses() {
        writeln!(w, "  \"{}\": {}", alias, address.encode()).unwrap();
    }
}
