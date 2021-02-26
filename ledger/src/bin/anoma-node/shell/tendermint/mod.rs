//! A Tendermint wrapper module that relays Tendermint requests to the Shell.
//!
//! Note that Tendermint implementation details should never be leaked outside
//! of this module.

use crate::shell::storage::BlockHash;
use crate::shell::{MempoolTxType, Shell};
use anoma::{
    config::Config,
    genesis::{self, Validator},
};
use serde_json::json;
use std::{
    convert::{TryFrom, TryInto},
    fs::File,
    io::{self, Write},
    net::SocketAddr,
    path::PathBuf,
};
use std::{
    ops::Deref,
    process::Command,
    sync::{Arc, RwLock},
};
use tendermint_abci::{self, ServerBuilder};

use tendermint_proto::abci::{
    RequestApplySnapshotChunk, RequestBeginBlock, RequestCheckTx,
    RequestDeliverTx, RequestEcho, RequestEndBlock, RequestInfo,
    RequestInitChain, RequestLoadSnapshotChunk, RequestOfferSnapshot,
    RequestQuery, RequestSetOption, ResponseApplySnapshotChunk,
    ResponseBeginBlock, ResponseCheckTx, ResponseCommit, ResponseDeliverTx,
    ResponseEcho, ResponseEndBlock, ResponseFlush, ResponseInfo,
    ResponseInitChain, ResponseListSnapshots, ResponseLoadSnapshotChunk,
    ResponseOfferSnapshot, ResponseQuery, ResponseSetOption,
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
    if cfg!(feature = "dev") {
        // override the validator key file
        write_validator_key(home_dir, &genesis::genesis().validator).unwrap();
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
    let server = ServerBuilder::default()
        .bind(
            addr,
            ShellWrapper {
                shell: Arc::new(RwLock::new(shell)),
            },
        )
        .unwrap();
    server.listen().unwrap()
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
    shell: Arc<RwLock<Shell>>,
}

impl Clone for ShellWrapper {
    fn clone(&self) -> Self {
        Self {
            shell: self.shell.clone(),
        }
    }
}

impl tendermint_abci::Application for ShellWrapper {
    fn echo(&self, request: RequestEcho) -> ResponseEcho {
        ResponseEcho {
            message: request.message,
        }
    }

    fn info(&self, _req: RequestInfo) -> ResponseInfo {
        let mut resp = ResponseInfo::default();
        if let Some((last_hash, last_height)) =
            self.shell.deref().write().unwrap().last_state()
        {
            resp.last_block_height = last_height.try_into().unwrap();
            resp.last_block_app_hash = last_hash.0;
        }
        resp
    }

    fn init_chain(&self, req: RequestInitChain) -> ResponseInitChain {
        let mut resp = ResponseInitChain::default();
        // Initialize the chain in shell
        let chain_id = req.chain_id;
        self.shell.deref().write().unwrap().init_chain(&chain_id);
        // Set the initial validator set
        let genesis = genesis::genesis();
        let mut abci_validator =
            tendermint_proto::abci::ValidatorUpdate::default();
        let mut pub_key = tendermint_proto::crypto::PublicKey::default();
        pub_key.sum = Some(tendermint_proto::crypto::public_key::Sum::Ed25519(
            genesis.validator.keypair.public.to_bytes().to_vec(),
        ));
        abci_validator.pub_key = Some(pub_key);
        abci_validator.power =
            genesis.validator.voting_power.try_into().unwrap();
        resp.validators.push(abci_validator);
        resp
    }

    fn query(&self, _request: RequestQuery) -> ResponseQuery {
        Default::default()
    }

    fn check_tx(&self, req: RequestCheckTx) -> ResponseCheckTx {
        log::info!("check_tx request {:#?}", req);
        let mut resp = ResponseCheckTx::default();
        use tendermint_proto::abci::CheckTxType;
        let prevalidation_type =
            match CheckTxType::from_i32(req.r#type).unwrap() {
                CheckTxType::New => MempoolTxType::NewTransaction,
                CheckTxType::Recheck => MempoolTxType::RecheckTransaction,
            };
        match self
            .shell
            .deref()
            .read()
            .unwrap()
            .mempool_validate(&req.tx, prevalidation_type)
        {
            Ok(_) => resp.info = "Mempool validation passed".to_string(),
            Err(msg) => {
                resp.code = 1;
                resp.log = String::from(msg);
            }
        }
        log::info!("check_tx response {:#?}", resp);
        resp
    }

    fn begin_block(&self, req: RequestBeginBlock) -> ResponseBeginBlock {
        let resp = ResponseBeginBlock::default();
        let raw_hash = req.hash;
        match BlockHash::try_from(raw_hash) {
            Err(err) => {
                log::error!("{:#?}", err);
                return resp;
            }
            Ok(hash) => {
                let raw_height = req.header.unwrap().height;
                match raw_height.try_into() {
                    Err(_) => {
                        log::error!("Unexpected block height {}", raw_height)
                    }
                    Ok(height) => self
                        .shell
                        .deref()
                        .write()
                        .unwrap()
                        .begin_block(hash, height),
                }
                resp
            }
        }
    }

    fn deliver_tx(&self, req: RequestDeliverTx) -> ResponseDeliverTx {
        let mut resp = ResponseDeliverTx::default();
        match self.shell.deref().write().unwrap().apply_tx(&req.tx) {
            Ok(_) => resp.info = "Transaction successfully applied".to_string(),
            Err(msg) => {
                resp.code = 1;
                resp.log = String::from(msg);
            }
        }
        resp
    }

    fn end_block(&self, _request: RequestEndBlock) -> ResponseEndBlock {
        Default::default()
    }

    fn flush(&self) -> ResponseFlush {
        ResponseFlush {}
    }

    fn commit(&self) -> ResponseCommit {
        let commit_result = self.shell.deref().write().unwrap().commit();
        let mut resp = ResponseCommit::default();
        resp.data = commit_result.0;
        resp
    }

    fn set_option(&self, _request: RequestSetOption) -> ResponseSetOption {
        Default::default()
    }

    fn list_snapshots(&self) -> ResponseListSnapshots {
        Default::default()
    }

    fn offer_snapshot(
        &self,
        _request: RequestOfferSnapshot,
    ) -> ResponseOfferSnapshot {
        Default::default()
    }

    fn load_snapshot_chunk(
        &self,
        _request: RequestLoadSnapshotChunk,
    ) -> ResponseLoadSnapshotChunk {
        Default::default()
    }

    fn apply_snapshot_chunk(
        &self,
        _request: RequestApplySnapshotChunk,
    ) -> ResponseApplySnapshotChunk {
        Default::default()
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
