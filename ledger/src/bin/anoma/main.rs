mod cli;

use eyre::Result;

fn main() -> Result<()> {
    color_eyre::install()?;

    // init logging
    env_logger::init_from_env("ANOMA_LOG");

    // run the CLI
    cli::main()
}
