//! Namada Wallet CLI.

use color_eyre::eyre::Result;
use namada_apps::cli;
use namada_apps::cli::args::CliToSdk;
use namada_apps::cli::cmds;
use namada_apps::wallet::cli_utils::{
    address_add, address_key_add, address_key_find, address_list,
    address_or_alias_find, key_and_address_gen, key_and_address_restore,
    key_export, key_find, key_list, payment_address_gen,
    payment_addresses_list, spending_key_gen, spending_keys_list,
};

pub fn main() -> Result<()> {
    let (cmd, mut ctx) = cli::namada_wallet_cli()?;
    match cmd {
        cmds::NamadaWallet::Key(sub) => match sub {
            cmds::WalletKey::Restore(cmds::KeyRestore(args)) => {
                key_and_address_restore(ctx, args)
            }
            cmds::WalletKey::Gen(cmds::KeyGen(args)) => {
                key_and_address_gen(ctx, args)
            }
            cmds::WalletKey::Find(cmds::KeyFind(args)) => key_find(ctx, args),
            cmds::WalletKey::List(cmds::KeyList(args)) => key_list(ctx, args),
            cmds::WalletKey::Export(cmds::Export(args)) => {
                key_export(ctx, args)
            }
        },
        cmds::NamadaWallet::Address(sub) => match sub {
            cmds::WalletAddress::Gen(cmds::AddressGen(args)) => {
                key_and_address_gen(ctx, args)
            }
            cmds::WalletAddress::Restore(cmds::AddressRestore(args)) => {
                key_and_address_restore(ctx, args)
            }
            cmds::WalletAddress::Find(cmds::AddressOrAliasFind(args)) => {
                address_or_alias_find(ctx, args)
            }
            cmds::WalletAddress::List(cmds::AddressList) => address_list(ctx),
            cmds::WalletAddress::Add(cmds::AddressAdd(args)) => {
                address_add(ctx, args)
            }
        },
        cmds::NamadaWallet::Masp(sub) => match sub {
            cmds::WalletMasp::GenSpendKey(cmds::MaspGenSpendKey(args)) => {
                spending_key_gen(ctx, args)
            }
            cmds::WalletMasp::GenPayAddr(cmds::MaspGenPayAddr(args)) => {
                let args = args.to_sdk(&mut ctx);
                payment_address_gen(ctx, args)
            }
            cmds::WalletMasp::AddAddrKey(cmds::MaspAddAddrKey(args)) => {
                address_key_add(ctx, args)
            }
            cmds::WalletMasp::ListPayAddrs(cmds::MaspListPayAddrs) => {
                payment_addresses_list(ctx)
            }
            cmds::WalletMasp::ListKeys(cmds::MaspListKeys(args)) => {
                spending_keys_list(ctx, args)
            }
            cmds::WalletMasp::FindAddrKey(cmds::MaspFindAddrKey(args)) => {
                address_key_find(ctx, args)
            }
        },
    }
    Ok(())
}
