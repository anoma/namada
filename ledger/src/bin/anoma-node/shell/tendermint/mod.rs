//! A Tendermint wrapper module that relays Tendermint requests to the Shell.
//!
//! Note that Tendermint implementation details should never be leaked outside
//! of this module.

use anoma::{
    config::Config,
    genesis::{self, Validator},
};
use genesis::Genesis;
use serde_json::json;
use std::process::Command;
use std::{
    convert::TryInto,
    fs::File,
    io::{self, Write},
    net::SocketAddr,
    path::PathBuf,
};

use abci;
use abci::{
    RequestCheckTx, RequestCommit, RequestDeliverTx, ResponseCheckTx,
    ResponseCommit, ResponseDeliverTx,
};

use crate::shell::{MempoolTxType, Shell};

pub fn run(config: Config, addr: SocketAddr, shell: Shell) {
    let home_dir = config.tendermint_home_dir();
    let home_dir_string = home_dir.to_string_lossy().to_string();
    // init and run a Tendermint node child process
    Command::new("tendermint")
        .args(&["init", "--home", &home_dir_string])
        .output()
        .map_err(|error| {
            log::error!("Failed to initialize tendermint node: {:?}", error)
        })
        .unwrap();
    let genesis = genesis::genesis();
    if cfg!(feature = "dev") {
        // override the validator key file
        write_validator_key(home_dir, &genesis.validator).unwrap();
    }
    let _tendermin_node = Command::new("tendermint")
        .args(&[
            "node",
            "--home",
            &home_dir_string,
            // ! Only produce blocks when there are txs or when the AppHash
            // changes for now
            "--consensus.create_empty_blocks=false",
        ])
        .spawn()
        .unwrap();

    // run the shell within ABCI
    abci::run(addr, ShellWrapper { shell, genesis });
}

pub fn reset(config: Config) {
    // reset all the Tendermint state, if any
    Command::new("tendermint")
        .args(&[
            "unsafe_reset_all",
            "--home",
            &config.tendermint_home_dir().to_string_lossy(),
        ])
        .output()
        .map_err(|error| {
            log::error!("Failed to reset tendermint node: {:?}", error)
        })
        .unwrap();
}

struct ShellWrapper {
    shell: Shell,
    genesis: Genesis,
}

impl abci::Application for ShellWrapper {
    fn check_tx(&mut self, req: &RequestCheckTx) -> ResponseCheckTx {
        let mut resp = ResponseCheckTx::new();
        let prevalidation_type = match req.get_field_type() {
            abci::CheckTxType::New => MempoolTxType::NewTransaction,
            abci::CheckTxType::Recheck => MempoolTxType::RecheckTransaction,
        };
        match self
            .shell
            .mempool_validate(req.get_tx(), prevalidation_type)
        {
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
        match self.shell.apply_tx(req.get_tx()) {
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
        let commit_result = self.shell.commit();
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
        let mut resp = abci::ResponseInitChain::new();
        let validators = resp.mut_validators();
        // TODO delete params after initialization?
        let mut abci_validator = abci::ValidatorUpdate::new();
        let mut pub_key = abci::PubKey::new();
        pub_key.set_field_type("ed25519".to_string());
        pub_key.set_data(
            self.genesis.validator.keypair.public.to_bytes().to_vec(),
        );
        abci_validator.set_pub_key(pub_key);
        abci_validator
            .set_power(self.genesis.validator.voting_power.try_into().unwrap());
        validators.push(abci_validator);
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

fn write_validator_key(
    home_dir: PathBuf,
    account: &Validator,
) -> io::Result<()> {
    let path = home_dir.join("config").join("priv_validator_key.json");
    let mut file = File::create(path)?;
    let pk = base64::encode(account.keypair.public.as_bytes());
    let sk = base64::encode(account.keypair.to_bytes());
    let key = json!({
       "address": account.address,
       "pub_key": {
         "type": "tendermint/PubKeyEd25519",
         "value": pk,
       },
       "priv_key": {
         "type": "tendermint/PrivKeyEd25519",
         "value": sk,
      }
    });
    println!("key {}", key);
    file.write(key.to_string().as_bytes()).map(|_| ())
}
