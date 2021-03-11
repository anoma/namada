//! The docstrings on types and their fields with `derive(Clap)` are displayed
//! in the CLI `--help`.

use anoma::{
    cli::{InlinedNodeOpts, NodeOpts},
    config::Config,
    protobuf::types::IntentMessage,
};
use clap::Clap;
use std::thread;
use tokio::sync::mpsc::{self, Receiver};

use crate::rpc;
use crate::shell;

pub fn main(config: Config) {
    let NodeOpts { base_dir, rpc, ops } = NodeOpts::parse();
    let rpc_event_receiver = if rpc {
        let (tx, rx) = mpsc::channel(100);
        thread::spawn(|| rpc::rpc_server(tx).unwrap());
        Some(rx)
    } else {
        None
    };
    let config = base_dir.map(Config::new).unwrap_or(config);
    exec_inlined(config, rpc_event_receiver, ops)
}

fn exec_inlined(
    config: Config,
    rpc_event_receiver: Option<Receiver<IntentMessage>>,
    ops: InlinedNodeOpts,
) {
    match ops {
        InlinedNodeOpts::Run => shell::run(config),
        InlinedNodeOpts::Reset => shell::reset(config),
    }
}
