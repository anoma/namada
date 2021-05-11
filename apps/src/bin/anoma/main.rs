mod cli;

use eyre::Result;
use tracing_subscriber::filter::{EnvFilter, LevelFilter};
use tracing_subscriber::fmt::Subscriber;

fn main() -> Result<()> {
    color_eyre::install()?;

    // init logging
    let filter = EnvFilter::from_env("ANOMA_LOG")
        .add_directive(LevelFilter::INFO.into());
    let my_collector = Subscriber::builder().with_env_filter(filter).finish();
    tracing::subscriber::set_global_default(my_collector)?;

    // run the CLI
    cli::main()
}
