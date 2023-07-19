use color_eyre::eyre::Result;
use namada_apps::cli::api::CliApi;
use namada_apps::facade::tendermint_rpc::HttpClient;
use namada_apps::{cli, logging};
use tracing_subscriber::filter::LevelFilter;

#[tokio::main]
async fn main() -> Result<()> {
    // init error reporting
    color_eyre::install()?;

    // init logging
    let _log_guard = logging::init_from_env_or(LevelFilter::INFO)?;

    // run the CLI
    CliApi::<()>::handle_client_command::<HttpClient>(cli::namada_client_cli()?)
        .await
}
