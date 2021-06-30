mod cli;

use std::env;

use anoma::logging;
use color_eyre::eyre::Result;
use tracing_subscriber::filter::LevelFilter;
use tracing_subscriber::EnvFilter;

fn main() -> Result<()> {
    // init error reporting
    color_eyre::install()?;

    // init logging
    let filter = logging::filter_from_env_or(LevelFilter::INFO);
    let log_env_var = env::var(logging::ENV_KEY);

    // Ledger dependencies
    let filter = reduce_log_level("tendermint_abci", filter, &log_env_var)?;
    // Gossip dependencies
    let filter = reduce_log_level("libp2p", filter, &log_env_var)?;
    let filter = reduce_log_level("regalloc", filter, &log_env_var)?;
    let filter =
        reduce_log_level("wasmer_compiler_cranelift", filter, &log_env_var)?;

    logging::set_subscriber(filter)?;
    logging::init_log_tracer()?;

    // run the CLI
    cli::main()
}

/// Reduce the logging from given crate unless it's explicitly set.
fn reduce_log_level(
    crate_name: &str,
    filter: EnvFilter,
    log_env_var: &Result<String, std::env::VarError>,
) -> Result<EnvFilter> {
    let contains_crate = if let Ok(log_env_var) = log_env_var {
        log_env_var.contains(crate_name)
    } else {
        false
    };
    Ok(if !contains_crate {
        filter.add_directive(format!("{}=warn", crate_name).parse()?)
    } else {
        filter
    })
}
