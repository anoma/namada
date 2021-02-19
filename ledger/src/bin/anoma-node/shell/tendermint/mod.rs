//! A Tendermint wrapper module that relays Tendermint requests to the Shell.
//!
//! Note that Tendermint implementation details should never be leaked outside
//! of this module.

use crate::shell::storage::BlockHash;
use crate::shell::{MempoolTxType, Shell};
use abci;
use abci::{
    RequestCheckTx, RequestCommit, RequestDeliverTx, ResponseCheckTx,
    ResponseCommit, ResponseDeliverTx,
};
use anoma::{
    config::Config,
    genesis::{self, Validator},
};
use genesis::Genesis;
use serde_json::json;
use std::{convert::TryFrom, process::Command};
use std::{
    convert::TryInto,
    fs::File,
    io::{self, Write},
    net::SocketAddr,
    path::PathBuf,
};

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
        log::info!("check_tx request {:#?}", req);
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
        log::info!("check_tx response {:#?}", resp);
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
        let mut resp = abci::ResponseInfo::new();
        if let Some((last_hash, last_height)) = self.shell.last_state() {
            resp.set_last_block_height(last_height.try_into().unwrap());
            resp.set_last_block_app_hash(last_hash.0);
        }
        resp
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
        req: &abci::RequestInitChain,
    ) -> abci::ResponseInitChain {
        let mut resp = abci::ResponseInitChain::new();
        // Initialize the chain in shell
        let chain_id = req.get_chain_id();
        self.shell.init_chain(chain_id);
        // Set the initial validator set
        let validators = resp.mut_validators();
        // TODO delete params after initialization? (`Option::take()`?)
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
        req: &abci::RequestBeginBlock,
    ) -> abci::ResponseBeginBlock {
        let resp = abci::ResponseBeginBlock::new();
        let raw_hash = req.get_hash();
        match BlockHash::try_from(raw_hash) {
            Err(err) => {
                log::error!("{}", err);
                return resp;
            }
            Ok(hash) => {
                let raw_height = req.get_header().get_height();
                match raw_height.try_into() {
                    Err(_) => {
                        log::error!("Unexpected block height {}", raw_height)
                    }
                    Ok(height) => self.shell.begin_block(hash, height),
                }
                resp
            }
        }
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
    file.write(key.to_string().as_bytes()).map(|_| ())
}
