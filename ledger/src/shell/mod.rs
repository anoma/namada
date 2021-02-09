mod shell;
mod tendermint;

use env_logger::Env;
use log::error;
use std::process::Command;

pub fn run() {
    // init logging
    env_logger::Builder::from_env(Env::default().default_filter_or("info")).init();

    // init and run a Tendermint node child process
    // TODO use an explicit node dir
    Command::new("tendermint")
        .args(&["init"])
        .output()
        .map_err(|error| error!("Failed to initialize tendermint node: {:?}", error))
        .unwrap();
    let _tendermin_node = Command::new("tendermint")
        .args(&[
            "node",
            // ! Only produce blocks when there are txs or when the AppHash changes for now
            "--consensus.create_empty_blocks=false",
        ])
        .spawn()
        .unwrap();

    // run our shell via Tendermint ABCI
    let shell = shell::Shell::new();
    let addr = "127.0.0.1:26658".parse().unwrap();
    tendermint::run(addr, shell)
}
