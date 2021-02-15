//! A Tendermint wrapper module that relays Tendermint requests to the Shell.
//!
//! Note that Tendermint implementation details should never be leaked outside
//! of this module.

use std::net::SocketAddr;
use std::process::Command;

use abci;
use abci::{
    RequestCheckTx, RequestCommit, RequestDeliverTx, ResponseCheckTx,
    ResponseCommit, ResponseDeliverTx,
};

use crate::shell::{MempoolTxType, Shell};

pub fn run(addr: SocketAddr, shell: Shell) {
    // init and run a Tendermint node child process
    // TODO use an explicit node dir here and in `fn reset`
    Command::new("tendermint")
        .args(&["init"])
        .output()
        .map_err(|error| {
            log::error!("Failed to initialize tendermint node: {:?}", error)
        })
        .unwrap();
    let _tendermin_node = Command::new("tendermint")
        .args(&[
            "node",
            // ! Only produce blocks when there are txs or when the AppHash
            // changes for now
            "--consensus.create_empty_blocks=false",
        ])
        .spawn()
        .unwrap();

    // run the shell within ABCI
    abci::run(addr, ShellWrapper(shell));
}

pub fn reset() {
    // reset all the Tendermint state, if any
    Command::new("tendermint")
        .args(&["unsafe_reset_all"])
        .output()
        .map_err(|error| {
            log::error!("Failed to reset tendermint node: {:?}", error)
        })
        .unwrap();
}

struct ShellWrapper(Shell);

impl abci::Application for ShellWrapper {
    fn check_tx(&mut self, req: &RequestCheckTx) -> ResponseCheckTx {
        let mut resp = ResponseCheckTx::new();
        let prevalidation_type = match req.get_field_type() {
            abci::CheckTxType::New => MempoolTxType::NewTransaction,
            abci::CheckTxType::Recheck => MempoolTxType::RecheckTransaction,
        };
        match self.0.mempool_validate(req.get_tx(), prevalidation_type) {
            Ok(_) => resp.set_info("Mempool validation passed".to_string()),
            Err(msg) => {
                resp.set_code(1);
                resp.set_log(String::from(msg));
            }
        }
        resp
    }

    fn deliver_tx(&mut self, req: &RequestDeliverTx) -> ResponseDeliverTx {
        let mut resp = ResponseDeliverTx::new();
        match self.0.apply_tx(req.get_tx()) {
            Ok(_) => {
                resp.set_info("Transaction successfully applied".to_string())
            }
            Err(msg) => {
                resp.set_code(1);
                resp.set_log(String::from(msg));
            }
        }
        resp
    }

    fn commit(&mut self, _req: &RequestCommit) -> ResponseCommit {
        let commit_result = self.0.commit();
        let mut resp = ResponseCommit::new();
        resp.set_data(commit_result.0);
        resp
    }
}
