//! A Tendermint wrapper module that relays Tendermint requests to the Shell.
//!
//! Note that Tendermint implementation details should never be leaked outside
//! of this module.

use std::{convert::TryInto, net::SocketAddr};
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
        log::info!("tendermint ABCI check_tx request {:#?}", req);
        log::info!("tendermint ABCI check_tx response {:#?}", resp);
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

    fn info(&mut self, _req: &abci::RequestInfo) -> abci::ResponseInfo {
        abci::ResponseInfo::new()
    }

    fn set_option(
        &mut self,
        _req: &abci::RequestSetOption,
    ) -> abci::ResponseSetOption {
        abci::ResponseSetOption::new()
    }

    fn query(&mut self, _req: &abci::RequestQuery) -> abci::ResponseQuery {
        abci::ResponseQuery::new()
    }

    fn init_chain(
        &mut self,
        _req: &abci::RequestInitChain,
    ) -> abci::ResponseInitChain {
        let params = Shell::init_chain();
        // TODO initialize the validator keys file for the first validator
        // TODO setup custom home directory for that
        let mut resp = abci::ResponseInitChain::new();
        let validators = resp.mut_validators();
        params.validators.iter().for_each(|validator| {
            let mut abci_validator = abci::ValidatorUpdate::new();
            let mut pub_key = abci::PubKey::new();
            pub_key.set_field_type("ed25519".to_string());
            pub_key.set_data(validator.pk.to_bytes().to_vec());
            abci_validator.set_pub_key(pub_key);
            abci_validator.set_power(validator.voting_power.try_into().unwrap());
            validators.push(abci_validator);
        });
        log::info!("tendermint ABCI init_chain");
        resp
    }

    fn begin_block(
        &mut self,
        _req: &abci::RequestBeginBlock,
    ) -> abci::ResponseBeginBlock {
        abci::ResponseBeginBlock::new()
    }

    fn end_block(
        &mut self,
        _req: &abci::RequestEndBlock,
    ) -> abci::ResponseEndBlock {
        abci::ResponseEndBlock::new()
    }
}
