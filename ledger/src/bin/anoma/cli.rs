//! The docstrings on types and their fields with `derive(Clap)` are displayed
//! in the CLI `--help`.

use std::env;
use std::process::Command;

use anoma::cli::{ClientOpts, NodeOpts};
use clap::Clap;

/// Anoma client
#[derive(Clap)]
#[clap(version = "1.0", author = "Heliax <TODO@heliax.dev>")]
enum Opts {
    // TODO don't parse the node and client sub-opts
    /// Anoma node commands
    Node(NodeOpts),
    /// Anoma client commands
    Client(ClientOpts),
    #[clap(flatten)]
    InlinedNode(NodeOpts),
    #[clap(flatten)]
    InlinedClient(ClientOpts),
}

pub fn main() {
    let args = env::args();
    // TODO use https://github.com/rust-lang/cargo/blob/ab64d1393b5b77c66b6534ef5023a1b89ee7bf64/src/cargo/util/process_builder.rs to correctly set env, etc.
    match Opts::parse() {
        Opts::Node(_) => {
            let args = args.skip(2);
            Command::new("anomad").args(args).status().unwrap();
        }
        Opts::InlinedNode(_) => {
            let args = args.skip(1);
            Command::new("anomad").args(args).status().unwrap();
        }
        Opts::Client(_) => {
            let args = args.skip(2);
            Command::new("anomac").args(args).status().unwrap();
        }
        Opts::InlinedClient(_) => {
            let args = args.skip(1);
            Command::new("anomac").args(args).status().unwrap();
        }
    }
}
