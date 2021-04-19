//! The docstrings on types and their fields with `derive(Clap)` are displayed
//! in the CLI `--help`.

use std::env;
use std::process::Command;

use anoma::cli;
use clap::App;
use eyre::{eyre, Context, Result};

pub fn main() -> Result<()> {
    let app = cli::anoma_inline_cli();
    let matches = app.clone().get_matches();

    if let Some(cmd) = matches.subcommand_name() {
        handle_command(app, cmd)
    } else {
        print_help(app)
    }
}

fn handle_command(app: App, cmd: &str) -> Result<()> {
    let args = env::args();

    let is_node_or_client =
        vec![cli::NODE_COMMAND, cli::CLIENT_COMMAND].contains(&cmd);

    let sub_args: Vec<String> =
        args.skip(if is_node_or_client { 2 } else { 1 }).collect();

    let is_node_command = cmd == cli::NODE_COMMAND
        ||
        // inlined node commands
        vec![
            cli::RUN_GOSSIP_COMMAND,
            cli::RUN_LEDGER_COMMAND,
            cli::RESET_LEDGER_COMMAND,
        ]
        .contains(&cmd);

    let is_client_command = cmd == cli::CLIENT_COMMAND
        ||
        // inlined client commands
        vec![cli::TX_COMMAND, cli::INTENT_COMMAND].contains(&cmd);

    if is_node_command {
        handle_subcommand("anomad", sub_args)
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
        .expect(&format!("Couldn't run {} command.", cmd));
    if result.success() {
        Ok(())
    } else {
        Err(eyre!("{} command failed.", cmd))
    }
}

fn print_help(mut app: App) -> Result<()> {
    app.print_help().wrap_err("Can't display help.")
}
