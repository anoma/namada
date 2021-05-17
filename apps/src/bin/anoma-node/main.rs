mod cli;
mod gossip;
mod protocol;
mod shell;
mod vm;

use std::env;

use anoma::logging;
use color_eyre::eyre::Result;
use tracing_subscriber::filter::LevelFilter;

const ABCI_MOD: &str = "tendermint_abci";
fn main() -> Result<()> {
    // init error reporting
    color_eyre::install()?;

    // init logging
    let abci_level = format!("{}=warn", ABCI_MOD).parse()?;
    let filter = logging::filter_from_env_or(LevelFilter::INFO);
    let filter = match env::var(logging::ENV_KEY) {
        // reduce the logging from ABCI unless it's explicitly set
        Ok(log_env_var) if log_env_var.contains(ABCI_MOD) => filter,
        _ => filter.add_directive(abci_level),
    };
    logging::set_subscriber(filter)?;

    // run the CLI
    cli::main()
}
