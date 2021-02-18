//! A Tendermint wrapper module that relays Tendermint requests to the Shell.
//!
//! Note that Tendermint implementation details should never be leaked outside
//! of this module.

use crate::shell::storage::{BlockHash, BlockHeight};
use crate::shell::MempoolTxType;
use anoma::{
    config::Config,
    genesis::{self, Validator},
};
use serde_json::json;
use std::process::Command;
use std::{
    convert::{TryFrom, TryInto},
    fs::File,
    io::{self, Write},
    net::SocketAddr,
    path::PathBuf,
    sync::mpsc::{self, channel, Sender},
};
use tendermint_abci::{self, ServerBuilder};
use tendermint_proto::abci::{
    CheckTxType, RequestApplySnapshotChunk, RequestBeginBlock, RequestCheckTx,
    RequestDeliverTx, RequestEcho, RequestEndBlock, RequestInfo,
    RequestInitChain, RequestLoadSnapshotChunk, RequestOfferSnapshot,
    RequestQuery, RequestSetOption, ResponseApplySnapshotChunk,
    ResponseBeginBlock, ResponseCheckTx, ResponseCommit, ResponseDeliverTx,
    ResponseEcho, ResponseEndBlock, ResponseFlush, ResponseInfo,
    ResponseInitChain, ResponseListSnapshots, ResponseLoadSnapshotChunk,
    ResponseOfferSnapshot, ResponseQuery, ResponseSetOption,
};

use super::MerkleRoot;

pub type AbciReceiver = mpsc::Receiver<AbciMsg>;
pub type AbciSender = mpsc::Sender<AbciMsg>;

#[derive(Debug, Clone)]
pub enum AbciMsg {
    /// Get the height and the Merkle root hash of the last committed block, if
    /// any
    GetInfo {
        reply: Sender<Option<(MerkleRoot, u64)>>,
    },
    /// Initialize a chain with the given ID
    InitChain { reply: Sender<()>, chain_id: String },
    /// Validate a given transaction for inclusion in the mempool
    MempoolValidate {
        reply: Sender<Result<(), String>>,
        tx: Vec<u8>,
        r#type: MempoolTxType,
    },
    /// Begin a new block
    BeginBlock {
        reply: Sender<()>,
        hash: BlockHash,
        height: BlockHeight,
    },
    /// Apply a transaction in a block
    ApplyTx {
        reply: Sender<Result<(), String>>,
        tx: Vec<u8>,
    },
    /// End a block
    EndBlock {
        reply: Sender<()>,
        height: BlockHeight,
    },
    /// Commit the current block. The expected result is the Merkle root hash
    /// of the committed block.
    CommitBlock { reply: Sender<MerkleRoot> },
}

/// Run the ABCI server in the current thread (blocking).
pub fn run(sender: AbciSender, config: Config, addr: SocketAddr) {
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
    let _tendermint_node = Command::new("tendermint")
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

    // bind and run the ABCI server
    let server = ServerBuilder::default()
        .bind(addr, AbciWrapper { sender })
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

#[derive(Clone, Debug)]
struct AbciWrapper {
    sender: AbciSender,
}

impl tendermint_abci::Application for AbciWrapper {
    fn echo(&self, request: RequestEcho) -> ResponseEcho {
        ResponseEcho {
            message: request.message,
        }
    }

    fn info(&self, _req: RequestInfo) -> ResponseInfo {
        let mut resp = ResponseInfo::default();

        let (reply, reply_receiver) = channel();
        self.sender.send(AbciMsg::GetInfo { reply }).unwrap();
        if let Some((last_block_app_hash, last_block_height)) =
            reply_receiver.recv().unwrap()
        {
            resp.last_block_height = last_block_height.try_into().unwrap();
            resp.last_block_app_hash = last_block_app_hash.0;
        }

        resp
    }

    fn init_chain(&self, req: RequestInitChain) -> ResponseInitChain {
        let mut resp = ResponseInitChain::default();

        // Initialize the chain in shell
        let chain_id = req.chain_id;
        let (reply, reply_receiver) = channel();
        self.sender
            .send(AbciMsg::InitChain { reply, chain_id })
            .unwrap();
        reply_receiver.recv().unwrap();

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
        let r#type = match CheckTxType::from_i32(req.r#type).unwrap() {
            CheckTxType::New => MempoolTxType::NewTransaction,
            CheckTxType::Recheck => MempoolTxType::RecheckTransaction,
        };

        let (reply, reply_receiver) = channel();
        self.sender
            .send(AbciMsg::MempoolValidate {
                reply,
                tx: req.tx,
                r#type,
            })
            .unwrap();
        let result = reply_receiver.recv().unwrap();

        match result {
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
            }
            Ok(hash) => {
                let raw_height = req.header.unwrap().height;
                match raw_height.try_into() {
                    Err(_) => {
                        log::error!("Unexpected block height {}", raw_height)
                    }
                    Ok(height) => {
                        let (reply, reply_receiver) = channel();
                        self.sender
                            .send(AbciMsg::BeginBlock {
                                reply,
                                hash,
                                height,
                            })
                            .unwrap();
                        reply_receiver.recv().unwrap();
                    }
                }
            }
        }
        resp
    }

    fn deliver_tx(&self, req: RequestDeliverTx) -> ResponseDeliverTx {
        let mut resp = ResponseDeliverTx::default();

        let (reply, reply_receiver) = channel();
        self.sender
            .send(AbciMsg::ApplyTx { reply, tx: req.tx })
            .unwrap();
        let result = reply_receiver.recv().unwrap();

        match result {
            Ok(()) => {
                resp.info = "Transaction successfully
        applied"
                    .to_string()
            }
            Err(msg) => {
                resp.code = 1;
                resp.log = String::from(msg);
            }
        }
        resp
    }

    fn end_block(&self, req: RequestEndBlock) -> ResponseEndBlock {
        let resp = ResponseEndBlock::default();

        let raw_height = req.height;
        match BlockHeight::try_from(raw_height) {
            Err(_) => {
                log::error!("Unexpected block height {}", raw_height)
            }
            Ok(height) => {
                let (reply, reply_receiver) = channel();
                self.sender
                    .send(AbciMsg::EndBlock { reply, height })
                    .unwrap();
                reply_receiver.recv().unwrap();
            }
        }
        resp
    }

    fn flush(&self) -> ResponseFlush {
        ResponseFlush {}
    }

    fn commit(&self) -> ResponseCommit {
        let mut resp = ResponseCommit::default();

        let (reply, reply_receiver) = channel();
        self.sender.send(AbciMsg::CommitBlock { reply }).unwrap();
        let MerkleRoot(result) = reply_receiver.recv().unwrap();

        resp.data = result;
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
