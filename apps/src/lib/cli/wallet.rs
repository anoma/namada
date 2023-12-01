//! Namada Wallet CLI.

use std::fs::File;
use std::io::{self, Write};
use std::str::FromStr;

use borsh::BorshDeserialize;
use borsh_ext::BorshSerializeExt;
use color_eyre::eyre::Result;
use itertools::sorted;
use ledger_namada_rs::{BIP44Path, NamadaApp};
use ledger_transport_hid::hidapi::HidApi;
use ledger_transport_hid::TransportNativeHID;
use masp_primitives::zip32::ExtendedFullViewingKey;
use namada::types::address::Address;
use namada::types::io::Io;
use namada::types::key::*;
use namada::types::masp::{MaspValue, PaymentAddress};
use namada_sdk::masp::find_valid_diversifier;
use namada_sdk::wallet::{
    DecryptionError, DerivationPath, DerivationPathError, FindKeyError, Wallet,
    WalletIo, WalletStorage,
};
use namada_sdk::{display, display_line, edisplay_line};
use rand_core::OsRng;

use crate::cli;
use crate::cli::api::CliApi;
use crate::cli::args::CliToSdk;
use crate::cli::{args, cmds, Context};
use crate::client::utils::PRE_GENESIS_DIR;
use crate::wallet::{
    self, read_and_confirm_encryption_password, CliWalletUtils,
};

impl CliApi {
    pub async fn handle_wallet_command(
        cmd: cmds::NamadaWallet,
        mut ctx: Context,
        io: &impl Io,
    ) -> Result<()> {
        match cmd {
            cmds::NamadaWallet::Key(sub) => match sub {
                cmds::WalletKey::Derive(cmds::KeyDerive(args)) => {
                    key_and_address_derive(
                        &mut ctx.borrow_mut_chain_or_exit().wallet,
                        io,
                        args,
                    )
                    .await
                }
                cmds::WalletKey::Gen(cmds::KeyGen(args)) => {
                    key_and_address_gen(ctx, io, args)
                }
                cmds::WalletKey::Find(cmds::KeyFind(args)) => {
                    key_find(ctx, io, args)
                }
                cmds::WalletKey::List(cmds::KeyList(args)) => {
                    key_list(ctx, io, args)
                }
                cmds::WalletKey::Export(cmds::Export(args)) => {
                    key_export(ctx, io, args)
                }
            },
            cmds::NamadaWallet::Address(sub) => match sub {
                cmds::WalletAddress::Gen(cmds::AddressGen(args)) => {
                    key_and_address_gen(ctx, io, args)
                }
                cmds::WalletAddress::Derive(cmds::AddressDerive(args)) => {
                    key_and_address_derive(
                        &mut ctx.borrow_mut_chain_or_exit().wallet,
                        io,
                        args,
                    )
                    .await
                }
                cmds::WalletAddress::Find(cmds::AddressOrAliasFind(args)) => {
                    address_or_alias_find(ctx, io, args)
                }
                cmds::WalletAddress::List(cmds::AddressList(args)) => {
                    address_list(ctx, io, args)
                }
                cmds::WalletAddress::Add(cmds::AddressAdd(args)) => {
                    address_add(ctx, io, args)
                }
            },
            cmds::NamadaWallet::Masp(sub) => match sub {
                cmds::WalletMasp::GenSpendKey(cmds::MaspGenSpendKey(args)) => {
                    spending_key_gen(ctx, io, args)
                }
                cmds::WalletMasp::GenPayAddr(cmds::MaspGenPayAddr(args)) => {
                    let args = args.to_sdk(&mut ctx);
                    payment_address_gen(
                        &mut ctx.borrow_mut_chain_or_exit().wallet,
                        io,
                        args,
                    )
                }
                cmds::WalletMasp::AddAddrKey(cmds::MaspAddAddrKey(args)) => {
                    address_key_add(ctx, io, args)
                }
                cmds::WalletMasp::ListPayAddrs(cmds::MaspListPayAddrs(
                    args,
                )) => payment_addresses_list(ctx, io, args),
                cmds::WalletMasp::ListKeys(cmds::MaspListKeys(args)) => {
                    spending_keys_list(ctx, io, args)
                }
                cmds::WalletMasp::FindAddrKey(cmds::MaspFindAddrKey(args)) => {
                    address_key_find(ctx, io, args)
                }
            },
        }
        Ok(())
    }
}

/// Find shielded address or key
fn address_key_find(
    ctx: Context,
    io: &impl Io,
    args::AddrKeyFind {
        alias,
        unsafe_show_secret,
        is_pre_genesis,
    }: args::AddrKeyFind,
) {
    let mut wallet = load_wallet(ctx, is_pre_genesis);
    let alias = alias.to_lowercase();
    if let Ok(viewing_key) = wallet.find_viewing_key(&alias) {
        // Check if alias is a viewing key
        display_line!(io, "Viewing key: {}", viewing_key);
        if unsafe_show_secret {
            // Check if alias is also a spending key
            match wallet.find_spending_key(&alias, None) {
                Ok(spending_key) => {
                    display_line!(io, "Spending key: {}", spending_key)
                }
                Err(FindKeyError::KeyNotFound) => {}
                Err(err) => edisplay_line!(io, "{}", err),
            }
        }
    } else if let Some(payment_addr) = wallet.find_payment_addr(&alias) {
        // Failing that, check if alias is a payment address
        display_line!(io, "Payment address: {}", payment_addr);
    } else {
        // Otherwise alias cannot be referring to any shielded value
        display_line!(
            io,
            "No shielded address or key with alias {} found. Use the commands \
             `masp list-addrs` and `masp list-keys` to see all the known \
             addresses and keys.",
            alias.to_lowercase()
        );
    }
}

/// List spending keys.
fn spending_keys_list(
    ctx: Context,
    io: &impl Io,
    args::MaspKeysList {
        decrypt,
        is_pre_genesis,
        unsafe_show_secret,
    }: args::MaspKeysList,
) {
    let wallet = load_wallet(ctx, is_pre_genesis);
    let known_view_keys = wallet.get_viewing_keys();
    let known_spend_keys = wallet.get_spending_keys();
    if known_view_keys.is_empty() {
        display_line!(
            io,
            "No known keys. Try `masp add --alias my-addr --value ...` to add \
             a new key to the wallet.",
        );
    } else {
        let stdout = io::stdout();
        let mut w = stdout.lock();
        display_line!(io, &mut w; "Known keys:").unwrap();
        for (alias, key) in known_view_keys {
            display!(io, &mut w; "  Alias \"{}\"", alias).unwrap();
            let spending_key_opt = known_spend_keys.get(&alias);
            // If this alias is associated with a spending key, indicate whether
            // or not the spending key is encrypted
            // TODO: consider turning if let into match
            if let Some(spending_key) = spending_key_opt {
                if spending_key.is_encrypted() {
                    display_line!(io, &mut w; " (encrypted):")
                } else {
                    display_line!(io, &mut w; " (not encrypted):")
                }
                .unwrap();
            } else {
                display_line!(io, &mut w; ":").unwrap();
            }
            // Always print the corresponding viewing key
            display_line!(io, &mut w; "    Viewing Key: {}", key).unwrap();
            // A subset of viewing keys will have corresponding spending keys.
            // Print those too if they are available and requested.
            if unsafe_show_secret {
                if let Some(spending_key) = spending_key_opt {
                    match spending_key.get::<CliWalletUtils>(decrypt, None) {
                        // Here the spending key is unencrypted or successfully
                        // decrypted
                        Ok(spending_key) => {
                            display_line!(io,
                                &mut w;
                                "    Spending key: {}", spending_key,
                            )
                            .unwrap();
                        }
                        // Here the key is encrypted but decryption has not been
                        // requested
                        Err(DecryptionError::NotDecrypting) if !decrypt => {
                            continue;
                        }
                        // Here the key is encrypted but incorrect password has
                        // been provided
                        Err(err) => {
                            display_line!(io,
                                &mut w;
                                    "    Couldn't decrypt the spending key: {}",
                                    err,
                            )
                            .unwrap();
                        }
                    }
                }
            }
        }
    }
}

/// List payment addresses.
fn payment_addresses_list(
    ctx: Context,
    io: &impl Io,
    args::MaspListPayAddrs { is_pre_genesis }: args::MaspListPayAddrs,
) {
    let wallet = load_wallet(ctx, is_pre_genesis);
    let known_addresses = wallet.get_payment_addrs();
    if known_addresses.is_empty() {
        display_line!(
            io,
            "No known payment addresses. Try `masp gen-addr --alias my-addr` \
             to generate a new payment address.",
        );
    } else {
        let stdout = io::stdout();
        let mut w = stdout.lock();
        display_line!(io, &mut w; "Known payment addresses:").unwrap();
        for (alias, address) in sorted(known_addresses) {
            display_line!(io, &mut w; "  \"{}\": {}", alias, address).unwrap();
        }
    }
}

/// Generate a spending key.
fn spending_key_gen(
    ctx: Context,
    io: &impl Io,
    args::MaspSpendKeyGen {
        alias,
        alias_force,
        is_pre_genesis,
        unsafe_dont_encrypt,
    }: args::MaspSpendKeyGen,
) {
    let mut wallet = load_wallet(ctx, is_pre_genesis);
    let alias = alias.to_lowercase();
    let password = read_and_confirm_encryption_password(unsafe_dont_encrypt);
    let (alias, _key) =
        wallet.gen_store_spending_key(alias, password, alias_force, &mut OsRng);
    wallet.save().unwrap_or_else(|err| eprintln!("{}", err));
    display_line!(
        io,
        "Successfully added a spending key with alias: \"{}\"",
        alias
    );
}

/// Generate a shielded payment address from the given key.
fn payment_address_gen(
    wallet: &mut Wallet<impl WalletStorage + WalletIo>,
    io: &impl Io,
    args::MaspPayAddrGen {
        alias,
        alias_force,
        viewing_key,
        pin,
        ..
    }: args::MaspPayAddrGen,
) {
    let alias = alias.to_lowercase();
    let viewing_key = ExtendedFullViewingKey::from(viewing_key).fvk.vk;
    let (div, _g_d) = find_valid_diversifier(&mut OsRng);
    let payment_addr = viewing_key
        .to_payment_address(div)
        .expect("a PaymentAddress");
    let alias = wallet
        .insert_payment_addr(
            alias,
            PaymentAddress::from(payment_addr).pinned(pin),
            alias_force,
        )
        .unwrap_or_else(|| {
            edisplay_line!(io, "Payment address not added");
            cli::safe_exit(1);
        });
    wallet.save().unwrap_or_else(|err| eprintln!("{}", err));
    display_line!(
        io,
        "Successfully generated a payment address with the following alias: {}",
        alias,
    );
}

/// Add a viewing key, spending key, or payment address to wallet.
fn address_key_add(
    ctx: Context,
    io: &impl Io,
    args::MaspAddrKeyAdd {
        alias,
        alias_force,
        value,
        is_pre_genesis,
        unsafe_dont_encrypt,
    }: args::MaspAddrKeyAdd,
) {
    let alias = alias.to_lowercase();
    let mut wallet = load_wallet(ctx, is_pre_genesis);
    let (alias, typ) = match value {
        MaspValue::FullViewingKey(viewing_key) => {
            let alias = wallet
                .insert_viewing_key(alias, viewing_key, alias_force)
                .unwrap_or_else(|| {
                    edisplay_line!(io, "Viewing key not added");
                    cli::safe_exit(1);
                });
            (alias, "viewing key")
        }
        MaspValue::ExtendedSpendingKey(spending_key) => {
            let password =
                read_and_confirm_encryption_password(unsafe_dont_encrypt);
            let alias = wallet
                .insert_spending_key(alias, spending_key, password, alias_force)
                .unwrap_or_else(|| {
                    edisplay_line!(io, "Spending key not added");
                    cli::safe_exit(1);
                });
            (alias, "spending key")
        }
        MaspValue::PaymentAddress(payment_addr) => {
            let alias = wallet
                .insert_payment_addr(alias, payment_addr, alias_force)
                .unwrap_or_else(|| {
                    edisplay_line!(io, "Payment address not added");
                    cli::safe_exit(1);
                });
            (alias, "payment address")
        }
    };
    wallet.save().unwrap_or_else(|err| eprintln!("{}", err));
    display_line!(
        io,
        "Successfully added a {} with the following alias to wallet: {}",
        typ,
        alias,
    );
}

/// Decode the derivation path from the given string unless it is "default",
/// in which case use the default derivation path for the given scheme.
pub fn decode_derivation_path(
    scheme: SchemeType,
    derivation_path: String,
) -> Result<DerivationPath, DerivationPathError> {
    let is_default = derivation_path.eq_ignore_ascii_case("DEFAULT");
    let parsed_derivation_path = if is_default {
        DerivationPath::default_for_scheme(scheme)
    } else {
        DerivationPath::from_path_str(scheme, &derivation_path)?
    };
    if !parsed_derivation_path.is_compatible(scheme) {
        println!(
            "WARNING: the specified derivation path may be incompatible with \
             the chosen cryptography scheme."
        )
    }
    println!("Using HD derivation path {}", parsed_derivation_path);
    Ok(parsed_derivation_path)
}

/// Derives a keypair and an implicit address from the mnemonic code in the
/// wallet.
async fn key_and_address_derive(
    wallet: &mut Wallet<impl WalletStorage + WalletIo>,
    io: &impl Io,
    args::KeyAndAddressDerive {
        scheme,
        alias,
        alias_force,
        unsafe_dont_encrypt,
        derivation_path,
        use_device,
    }: args::KeyAndAddressDerive,
) {
    let derivation_path = decode_derivation_path(scheme, derivation_path)
        .unwrap_or_else(|err| {
            edisplay_line!(io, "{}", err);
            cli::safe_exit(1)
        });
    let alias = if !use_device {
        let encryption_password =
            read_and_confirm_encryption_password(unsafe_dont_encrypt);
        wallet
            .derive_key_from_mnemonic_code(
                scheme,
                alias,
                alias_force,
                derivation_path,
                None,
                encryption_password,
            )
            .unwrap_or_else(|err| {
                edisplay_line!(io, "{}", err);
                display_line!(io, "No changes are persisted. Exiting.");
                cli::safe_exit(1)
            })
            .0
    } else {
        let hidapi = HidApi::new().unwrap_or_else(|err| {
            edisplay_line!(io, "Failed to create Hidapi: {}", err);
            cli::safe_exit(1)
        });
        let app = NamadaApp::new(
            TransportNativeHID::new(&hidapi).unwrap_or_else(|err| {
                edisplay_line!(io, "Unable to connect to Ledger: {}", err);
                cli::safe_exit(1)
            }),
        );
        let response = app
            .get_address_and_pubkey(
                &BIP44Path {
                    path: derivation_path.to_string(),
                },
                true,
            )
            .await
            .unwrap_or_else(|err| {
                edisplay_line!(
                    io,
                    "Unable to connect to query address and public key from \
                     Ledger: {}",
                    err
                );
                cli::safe_exit(1)
            });

        let pubkey = common::PublicKey::try_from_slice(&response.public_key)
            .expect("unable to decode public key from hardware wallet");
        let pkh = PublicKeyHash::from(&pubkey);
        let address = Address::from_str(&response.address_str)
            .expect("unable to decode address from hardware wallet");

        wallet
            .insert_public_key(
                alias.unwrap_or_else(|| pkh.to_string()),
                pubkey,
                Some(address),
                Some(derivation_path),
                alias_force,
            )
            .unwrap_or_else(|| {
                display_line!(io, "No changes are persisted. Exiting.");
                cli::safe_exit(1)
            })
    };
    wallet
        .save()
        .unwrap_or_else(|err| edisplay_line!(io, "{}", err));
    display_line!(
        io,
        "Successfully added a key and an address with alias: \"{}\"",
        alias
    );
}

/// Generate a new keypair and derive implicit address from it and store them in
/// the wallet.
fn key_and_address_gen(
    ctx: Context,
    io: &impl Io,
    args::KeyAndAddressGen {
        scheme,
        alias,
        alias_force,
        is_pre_genesis,
        unsafe_dont_encrypt,
        derivation_path,
    }: args::KeyAndAddressGen,
) {
    let mut wallet = load_wallet(ctx, is_pre_genesis);
    let encryption_password =
        read_and_confirm_encryption_password(unsafe_dont_encrypt);
    let derivation_path = decode_derivation_path(scheme, derivation_path)
        .unwrap_or_else(|err| {
            edisplay_line!(io, "{}", err);
            cli::safe_exit(1)
        });
    let mut rng = OsRng;
    let (_mnemonic, seed) = Wallet::<CliWalletUtils>::gen_hd_seed(
        None, &mut rng, unsafe_dont_encrypt,
    )
    .unwrap_or_else(|err| {
        edisplay_line!(io, "{}", err);
        cli::safe_exit(1)
    });
    let alias = wallet
        .derive_store_hd_secret_key(
            scheme,
            alias,
            alias_force,
            seed,
            derivation_path,
            encryption_password,
        )
        .map(|x| x.0)
        .unwrap_or_else(|err| {
            eprintln!("{}", err);
            println!("No changes are persisted. Exiting.");
            cli::safe_exit(0);
        });
    wallet
        .save()
        .unwrap_or_else(|err| edisplay_line!(io, "{}", err));
    display_line!(
        io,
        "Successfully added a key and an address with alias: \"{}\"",
        alias
    );
}

/// Find a keypair in the wallet store.
fn key_find(
    ctx: Context,
    io: &impl Io,
    args::KeyFind {
        public_key,
        alias,
        value,
        is_pre_genesis,
        unsafe_show_secret,
    }: args::KeyFind,
) {
    let mut wallet = load_wallet(ctx, is_pre_genesis);
    let found_keypair = match public_key {
        Some(pk) => wallet.find_key_by_pk(&pk, None),
        None => {
            let alias = alias.or(value);
            match alias {
                None => {
                    edisplay_line!(
                        io,
                        "An alias, public key or public key hash needs to be \
                         supplied",
                    );
                    cli::safe_exit(1)
                }
                Some(alias) => {
                    wallet.find_secret_key(alias.to_lowercase(), None)
                }
            }
        }
    };
    match found_keypair {
        Ok(keypair) => {
            let pkh: PublicKeyHash = (&keypair.ref_to()).into();
            display_line!(io, "Public key hash: {}", pkh);
            display_line!(io, "Public key: {}", keypair.ref_to());
            if unsafe_show_secret {
                display_line!(io, "Secret key: {}", keypair);
            }
        }
        Err(err) => {
            edisplay_line!(io, "{}", err);
        }
    }
}

/// List all known keys.
fn key_list(
    ctx: Context,
    io: &impl Io,
    args::KeyList {
        decrypt,
        is_pre_genesis,
        unsafe_show_secret,
    }: args::KeyList,
) {
    let wallet = load_wallet(ctx, is_pre_genesis);
    let known_public_keys = wallet.get_public_keys();
    if known_public_keys.is_empty() {
        display_line!(
            io,
            "No known keys. Try `key gen --alias my-key` to generate a new \
             key.",
        );
    } else {
        let stdout = io::stdout();
        let mut w = stdout.lock();
        display_line!(io, &mut w; "Known keys:").unwrap();
        let known_secret_keys = wallet.get_secret_keys();
        for (alias, public_key) in known_public_keys {
            let stored_keypair = known_secret_keys.get(&alias);
            let encrypted = match stored_keypair {
                None => "external",
                Some((stored_keypair, _pkh))
                    if stored_keypair.is_encrypted() =>
                {
                    "encrypted"
                }
                Some(_) => "not encrypted",
            };
            display_line!(io,
                &mut w;
                "  Alias \"{}\" ({}):", alias, encrypted,
            )
            .unwrap();
            display_line!(io, &mut w; "    Public key hash: {}", PublicKeyHash::from(&public_key))
                .unwrap();
            display_line!(io, &mut w; "    Public key: {}", public_key)
                .unwrap();
            if let Some((stored_keypair, _pkh)) = stored_keypair {
                match stored_keypair.get::<CliWalletUtils>(decrypt, None) {
                    Ok(keypair) if unsafe_show_secret => {
                        display_line!(io,
                                      &mut w;
                                      "    Secret key: {}", keypair,
                        )
                        .unwrap();
                    }
                    Ok(_keypair) => {}
                    Err(DecryptionError::NotDecrypting) if !decrypt => {
                        continue;
                    }
                    Err(err) => {
                        display_line!(io,
                                      &mut w;
                                      "    Couldn't decrypt the keypair: {}", err,
                        )
                            .unwrap();
                    }
                }
            }
        }
    }
}

/// Export a keypair to a file.
fn key_export(
    ctx: Context,
    io: &impl Io,
    args::KeyExport {
        alias,
        is_pre_genesis,
    }: args::KeyExport,
) {
    let mut wallet = load_wallet(ctx, is_pre_genesis);
    wallet
        .find_secret_key(alias.to_lowercase(), None)
        .map(|keypair| {
            let file_data = keypair.serialize_to_vec();
            let file_name = format!("key_{}", alias.to_lowercase());
            let mut file = File::create(&file_name).unwrap();

            file.write_all(file_data.as_ref()).unwrap();
            display_line!(io, "Exported to file {}", file_name);
        })
        .unwrap_or_else(|err| {
            edisplay_line!(io, "{}", err);
            cli::safe_exit(1)
        })
}

/// List all known addresses.
fn address_list(
    ctx: Context,
    io: &impl Io,
    args::AddressList { is_pre_genesis }: args::AddressList,
) {
    let wallet = load_wallet(ctx, is_pre_genesis);
    let known_addresses = wallet.get_addresses();
    if known_addresses.is_empty() {
        display_line!(
            io,
            "No known addresses. Try `address gen --alias my-addr` to \
             generate a new implicit address.",
        );
    } else {
        let stdout = io::stdout();
        let mut w = stdout.lock();
        display_line!(io, &mut w; "Known addresses:").unwrap();
        for (alias, address) in sorted(known_addresses) {
            display_line!(io,
                &mut w;
                "  \"{}\": {}", alias, address.to_pretty_string(),
            )
            .unwrap();
        }
    }
}

/// Find address (alias) by its alias (address).
fn address_or_alias_find(
    ctx: Context,
    io: &impl Io,
    args::AddressOrAliasFind {
        alias,
        address,
        is_pre_genesis,
    }: args::AddressOrAliasFind,
) {
    let wallet = load_wallet(ctx, is_pre_genesis);
    if address.is_some() && alias.is_some() {
        panic!(
            "This should not be happening: clap should emit its own error \
             message."
        );
    } else if alias.is_some() {
        if let Some(address) = wallet.find_address(alias.as_ref().unwrap()) {
            display_line!(io, "Found address {}", address.to_pretty_string());
        } else {
            display_line!(
                io,
                "No address with alias {} found. Use the command `address \
                 list` to see all the known addresses.",
                alias.unwrap().to_lowercase()
            );
        }
    } else if address.is_some() {
        if let Some(alias) = wallet.find_alias(address.as_ref().unwrap()) {
            display_line!(io, "Found alias {}", alias);
        } else {
            display_line!(
                io,
                "No alias with address {} found. Use the command `address \
                 list` to see all the known addresses.",
                address.unwrap()
            );
        }
    }
}

/// Add an address to the wallet.
fn address_add(
    ctx: Context,
    io: &impl Io,
    args::AddressAdd {
        alias,
        alias_force,
        address,
        is_pre_genesis,
    }: args::AddressAdd,
) {
    let mut wallet = load_wallet(ctx, is_pre_genesis);
    if wallet
        .insert_address(alias.to_lowercase(), address, alias_force)
        .is_none()
    {
        edisplay_line!(io, "Address not added");
        cli::safe_exit(1);
    }
    wallet
        .save()
        .unwrap_or_else(|err| edisplay_line!(io, "{}", err));
    display_line!(
        io,
        "Successfully added a key and an address with alias: \"{}\"",
        alias.to_lowercase()
    );
}

/// Load wallet for chain when `ctx.chain.is_some()` or pre-genesis wallet when
/// `is_pre_genesis || ctx.chain.is_none()`.
fn load_wallet(ctx: Context, is_pre_genesis: bool) -> Wallet<CliWalletUtils> {
    if is_pre_genesis || ctx.chain.is_none() {
        let wallet_path = ctx.global_args.base_dir.join(PRE_GENESIS_DIR);
        wallet::load_or_new(&wallet_path)
    } else {
        ctx.take_chain_or_exit().wallet
    }
}
