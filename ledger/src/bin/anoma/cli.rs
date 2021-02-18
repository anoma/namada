//! The docstrings on types and their fields with `derive(Clap)` are displayed
//! in the CLI `--help`.

use std::env;
use std::process::Command;

use anoma::cli::AnomaOpts;
use clap::{Clap, IntoApp};

pub fn main() {
    let args = env::args();
    let env_vars = env::vars_os();
    // TODO use https://github.com/rust-lang/cargo/blob/ab64d1393b5b77c66b6534ef5023a1b89ee7bf64/src/cargo/util/process_builder.rs to correctly set working dir, etc.
    match AnomaOpts::try_parse() {
        Err(_err) => {
            AnomaOpts::into_app().print_help().unwrap();
        }
        Ok(opts) => match opts {
            AnomaOpts::Node(_) => {
                let args = args.skip(2);
                // TODO when `anoma` is ran with `cargo run`, the sub-commands
                // should also run from cargo
                Command::new("anomad")
                    .args(args)
                    .envs(env_vars)
                    .status()
                    .unwrap();
            }
            AnomaOpts::InlinedNode(_) => {
                let args = args.skip(1);
                Command::new("anomad")
                    .args(args)
                    .envs(env_vars)
                    .status()
                    .unwrap();
            }
            AnomaOpts::Client(_) => {
                let args = args.skip(2);
                Command::new("anomac")
                    .args(args)
                    .envs(env_vars)
                    .status()
                    .unwrap();
            }
            AnomaOpts::InlinedClient(_) => {
                let args = args.skip(1);
                Command::new("anomac")
                    .args(args)
                    .envs(env_vars)
                    .status()
                    .unwrap();
            }
        },
    }
}
