//! Anoma Wallet CLI.

#[cfg(feature = "dev")]
use anoma_apps::cli;

use anoma_apps::cli::cmds;
use anoma_apps::wallet_new::store;

use color_eyre::eyre::Result;

pub fn main() -> Result<()> {
    let (cmd, _global_args) = cli::anoma_wallet_cli();
    match cmd {
        cmds::AnomaWallet::Keypair(cmds::Keypair::Generate(
            cmds::Generate(args),
        )) => store::generate_key(args),
    }
    Ok(())
}
