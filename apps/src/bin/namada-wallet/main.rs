use color_eyre::eyre::Result;
use namada_apps::cli;
use namada_apps::cli::api::{CliApi, CliIo};

pub fn main() -> Result<()> {
    color_eyre::install()?;
    let (cmd, ctx) = cli::namada_wallet_cli()?;
    // run the CLI
    CliApi::<CliIo>::handle_wallet_command(cmd, ctx)
}
