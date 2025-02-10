use color_eyre::eyre::Result;
use namada_apps_lib::cli;
use namada_apps_lib::cli::api::{CliApi, CliIo};

#[tokio::main]
pub async fn main() -> Result<()> {
    color_eyre::install()?;
    let (cmd, ctx) = cli::namada_wallet_cli(namada_apps::namada_version())?;
    // run the CLI
    CliApi::handle_wallet_command(cmd, ctx, &CliIo).await
}
