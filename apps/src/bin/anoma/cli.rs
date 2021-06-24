//! The docstrings on types and their fields with `derive(Clap)` are displayed
//! in the CLI `--help`.

use std::env;
use std::process::Command;

use anoma::cli;
use clap::App;
use eyre::{eyre, Context, Result};

pub fn main() -> Result<()> {
    let app = cli::anoma_cli();
    let matches = app.clone().get_matches();

    if let Some(cmd) = matches.subcommand_name() {
        handle_command(app, cmd)
    } else {
        print_help(app)
    }
}

fn handle_command(app: App, cmd: &str) -> Result<()> {
    let args = env::args();

    let is_node_or_client = vec![cli::NODE_CMD, cli::CLIENT_CMD].contains(&cmd);

    // Skip the first arg, which is the name of the binary
    let mut sub_args: Vec<String> = args.skip(1).collect();

    if is_node_or_client {
        // Because there may be global args before the `cmd`, we have to find it
        // before removing it.
        sub_args
            .iter()
            .position(|arg| arg == cmd)
            .map(|e| sub_args.remove(e));
    }

    tracing::debug!("command {} sub args {:?}", cmd, sub_args);

    let is_node_command = cmd == cli::NODE_CMD
        ||
        // inlined node commands
        vec![
            cli::RUN_GOSSIP_CMD,
            cli::RUN_LEDGER_CMD,
            cli::RESET_LEDGER_CMD,
        ]
        .contains(&cmd);

    let is_client_command = cmd == cli::CLIENT_CMD
        ||
        // inlined client commands
        vec![cli::TX_CUSTOM_CMD, cli::TX_TRANSFER_CMD, cli::INTENT_CMD].contains(&cmd);

    if is_node_command {
        handle_subcommand("anoman", sub_args)
    } else if is_client_command {
        handle_subcommand("anomac", sub_args)
    } else {
        print_help(app)
    }
}

fn handle_subcommand(program: &str, mut sub_args: Vec<String>) -> Result<()> {
    let env_vars = env::vars_os();

    #[cfg(feature = "dev")]
    let cmd = if env::var("CARGO").is_ok() {
        // When the command is ran from inside `cargo run`, we also want to
        // call the sub-command via `cargo run` to rebuild if necessary.
        // We do this by prepending the arguments with `cargo run` arguments.
        let mut cargo_args =
            vec!["run".to_string(), format!("--bin={}", program), "--".into()];
        cargo_args.append(&mut sub_args);
        sub_args = cargo_args;
        "cargo"
    } else {
        program
    };
    #[cfg(not(feature = "dev"))]
    let cmd = program;

    let result = Command::new(cmd)
        .args(sub_args)
        .envs(env_vars)
        .status()
        .unwrap_or_else(|_| panic!("Couldn't run {} command.", cmd));
    if result.success() {
        Ok(())
    } else {
        Err(eyre!("{} command failed.", cmd))
    }
}

fn print_help(mut app: App) -> Result<()> {
    app.print_help().wrap_err("Can't display help.")
}
