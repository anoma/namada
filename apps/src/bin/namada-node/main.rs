mod cli;

use color_eyre::eyre::Result;
use namada_apps::logging;
use tracing_subscriber::filter::LevelFilter;

fn main() -> Result<()> {
    // init error reporting
    color_eyre::install()?;

    // init logging
    let _log_guard = logging::init_from_env_or(LevelFilter::INFO)?;

    // run the CLI
    cli::main()
}
