use anoma::config::Config;

mod cli;
mod gossip;
mod rpc;
mod shell;
use color_eyre::eyre::Result;

fn main() -> Result<()> {
    // init error reporting
    color_eyre::install()?;

    // init logging
    env_logger::init_from_env("ANOMA_LOG");

    let config = Config::default();
    // run the CLI
    cli::main(config)
}
