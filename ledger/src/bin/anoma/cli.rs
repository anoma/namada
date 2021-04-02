//! The docstrings on types and their fields with `derive(Clap)` are displayed
//! in the CLI `--help`.

use anoma::{cli::CliBuilder, config::Config};
use eyre::Result;

pub fn main() -> Result<()> {
    let matches = CliBuilder::new().anoma_inline_cli();

    // let env_vars = env::vars_os();

    match matches.subcommand() {
        Some(("run-gossip", args)) => {
            let home = matches.value_of("base").unwrap_or(".anoma").to_string();
            let config = Config::new(home).unwrap();
            // TODO: parse peers into Vec<String>
            // let peers = m.values_of("peers") ???
            // let rpc = args.is_present("rpc");
            // let address = args.value_of("address").map(|s| s.to_string());
            // let orderbook = args.is_present("orderbook");
            // let dkg = args.is_present("dkg");
            // Command::new("anomad")
            //     .args(args)
            //     .envs(env_vars)
            //     .status()
            //     .unwrap();
            Ok(())
        }
        Some(("run-ledger", _)) => {
            let home = matches.value_of("base").unwrap_or(".anoma").to_string();
            let config = Config::new(home).unwrap();
            // shell::run(config).wrap_err("Failed to run Anoma node")
            Ok(())
        }
        Some(("reset", _)) => {
            let home = matches.value_of("base").unwrap_or(".anoma").to_string();
            let config = Config::new(home).unwrap();
            Ok(())
        }
        Some(("node", sub_command)) => match sub_command.subcommand() {
            Some(("run-gossip", args)) => {
                let home =
                    matches.value_of("base").unwrap_or(".anoma").to_string();
                let config = Config::new(home).unwrap();
                // TODO: parse peers into Vec<String>
                // let peers = m.values_of("peers") ???
                let rpc = args.is_present("rpc");
                let address = args.value_of("address").map(|s| s.to_string());
                let orderbook = args.is_present("orderbook");
                let dkg = args.is_present("dkg");
                Ok(())
            }
            Some(("run-ledger", _)) => {
                let home =
                    matches.value_of("base").unwrap_or(".anoma").to_string();
                let config = Config::new(home).unwrap();
                Ok(())
            }
            Some(("reset", _)) => {
                let home =
                    matches.value_of("base").unwrap_or(".anoma").to_string();
                let config = Config::new(home).unwrap();
                Ok(())
            }
            _ => panic!("No valid arguments"),
        },
        _ => panic!("No valid arguments"),
    }

    // let args = env::args();
    // let env_vars = env::vars_os();
    // // TODO use https://github.com/rust-lang/cargo/blob/ab64d1393b5b77c66b6534ef5023a1b89ee7bf64/src/cargo/util/process_builder.rs to correctly set working dir, etc.

    // let args: Vec<String> = args.skip(1).collect();

    // // Handle "node" and "client" sub-commands
    // if let Some((sub, args)) = args.split_first() {
    //     if sub == "node" {
    //         // TODO when `anoma` is ran with `cargo run`, the
    //         // sub-commands should also run from
    //         // cargo
    //         Command::new("anomad")
    //             .args(args)
    //             .envs(env_vars)
    //             .status()
    //             .unwrap();
    //         return;
    //     } else if sub == "client" {
    //         Command::new("anomac")
    //             .args(args)
    //             .envs(env_vars)
    //             .status()
    //             .unwrap();
    //         return;
    //     }
    // };

    // // Handle inlined commands
    // match AnomaOpts::try_parse() {
    //     Err(_err) => {
    //         AnomaOpts::into_app().print_help().unwrap();
    //     }
    //     Ok(opts) => match opts {
    //         AnomaOpts::InlinedNode(_) => {
    //             Command::new("anomad")
    //                 .args(args)
    //                 .envs(env_vars)
    //                 .status()
    //                 .unwrap();
    //         }
    //         AnomaOpts::InlinedClient(_) => {
    //             Command::new("anomac")
    //                 .args(args)
    //                 .envs(env_vars)
    //                 .status()
    //                 .unwrap();
    //         }
    //     },
    // }
    // Ok(())
}
