mod cli;

use anoma::logging;
use eyre::Result;
use tracing_subscriber::filter::LevelFilter;

fn main() -> Result<()> {
    color_eyre::install()?;

    // init logging
    logging::init_from_env_or(LevelFilter::INFO)?;

    // run the CLI
    cli::main()
}
