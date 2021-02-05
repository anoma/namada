extern crate abci;
extern crate byteorder;

use crate::shell::shell;
use crate::shell::shell::Shell;

use abci::{
    RequestCheckTx, RequestCommit, RequestDeliverTx, ResponseCheckTx, ResponseCommit,
    ResponseDeliverTx,
};

pub fn run(shell: Shell) {
    abci::run_local(ShellWrapper(shell));
}

struct ShellWrapper(Shell);

impl abci::Application for ShellWrapper {
    fn check_tx(&mut self, req: &RequestCheckTx) -> ResponseCheckTx {
        let mut resp = ResponseCheckTx::new();
        let transaction = shell::Transaction { data: req.get_tx() };
        let prevalidation_type = match req.get_field_type() {
            abci::CheckTxType::New => shell::PrevalidationType::NewTransaction,
            abci::CheckTxType::Recheck => shell::PrevalidationType::RecheckTransaction,
        };
        match self.0.prevalidate_tx(transaction, prevalidation_type) {
            Ok(_) => {}
            Err(msg) => {
                resp.set_code(1);
                resp.set_log(String::from(msg));
            }
        }
        resp
    }

    fn deliver_tx(&mut self, req: &RequestDeliverTx) -> ResponseDeliverTx {
        let mut resp = ResponseDeliverTx::new();
        match self.0.apply_tx(shell::Transaction { data: req.get_tx() }) {
            Ok(_) => {}
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
