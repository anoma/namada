//! The docstrings on types and their fields with `derive(Clap)` are displayed
//! in the CLI `--help`.

use std::env;
use std::process::Command;

use anoma::cli;
use eyre::{eyre, Context, Result};

pub fn main() -> Result<()> {
    let mut app = cli::anoma_inline_cli();
    let matches = app.clone().get_matches();

    let args = env::args();
    let env_vars = env::vars_os();
    let is_cargo = env::var("CARGO").is_ok();

    if let Some(subcommand_name) = matches.subcommand_name() {
        let is_node_or_client = vec![cli::NODE_COMMAND, cli::CLIENT_COMMAND]
            .contains(&subcommand_name);

        let mut sub_args: Vec<String>;
        if is_node_or_client {
            sub_args = args.skip(2).collect();
        } else {
            sub_args = args.skip(1).collect();
        }

        let is_node_command = vec![
            cli::RUN_GOSSIP_COMMAND,
            cli::RUN_LEDGER_COMMAND,
            cli::RESET_LEDGER_COMMAND,
        ]
        .contains(&subcommand_name)
            || subcommand_name == cli::NODE_COMMAND;
        let is_client_command = vec![cli::TX_COMMAND, cli::INTENT_COMMAND]
            .contains(&subcommand_name)
            || subcommand_name == cli::CLIENT_COMMAND;
        if is_node_command {
            let program = if is_cargo {
                let mut cargo_args =
                    vec!["run".to_string(), "--bin=anomad".into(), "--".into()];
                cargo_args.append(&mut sub_args);
                sub_args = cargo_args;

                "cargo"
            } else {
                "anomad"
            };

            let result = Command::new(program)
                .args(sub_args)
                .envs(env_vars)
                .status()
                .expect("Couldn't run node command.");
            if result.success() {
                return Ok(());
            } else {
                return Err(eyre!("Anomad command failed."));
            }
        } else if is_client_command {
            let program = if is_cargo {
                let mut cargo_args =
                    vec!["run".to_string(), "--bin=anomac".into(), "--".into()];
                cargo_args.append(&mut sub_args);
                sub_args = cargo_args;

                "cargo"
            } else {
                "anomac"
            };
            let result = Command::new(program)
                .args(sub_args)
                .envs(env_vars)
                .status()
                .expect("Couldn't run client command.");
            if result.success() {
                return Ok(());
            } else {
                return Err(eyre!("Anomac command failed."));
            }
        }
    }
    app.print_help().wrap_err("Can't display help.")
}
