mod cli;
mod gossip;
mod shell;
mod vm;
use color_eyre::eyre::Result;

fn main() -> Result<()> {
    // init error reporting
    color_eyre::install()?;

    // init logging
    env_logger::init_from_env("ANOMA_LOG");

    // run the CLI
    cli::main()
}
