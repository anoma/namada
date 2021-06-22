//! A Tendermint wrapper module that relays Tendermint requests to the Shell.
//!
//! Note that Tendermint implementation details should never be leaked outside
//! of this module.

use std::convert::{TryFrom, TryInto};
use std::fs::{self, File, OpenOptions};
use std::io::{self, Write};
use std::path::Path;
use std::process::Command;
use std::sync::mpsc::{self, channel, Sender};

use anoma_shared::ledger::storage::MerkleRoot;
use anoma_shared::types::storage::{BlockHash, BlockHeight};
use serde_json::json;
use signal_hook::consts::TERM_SIGNALS;
use signal_hook::iterator::Signals;
use tendermint::config::TendermintConfig;
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
use thiserror::Error;

use crate::config;
use crate::genesis::{self, Validator};
use crate::node::ledger::protocol::TxResult;
use crate::node::ledger::MempoolTxType;

#[derive(Error, Debug)]
pub enum Error {
    #[error("Failed to initialize Tendermint: {0}")]
    TendermintInit(std::io::Error),
    #[error("Failed to write Tendermint validator key: {0}")]
    TendermintValidatorKey(std::io::Error),
    #[error("Failed to load Tendermint config file: {0}")]
    TendermintLoadConfig(tendermint::error::Error),
    #[error("Failed to open Tendermint config for writing: {0}")]
    TendermintOpenWriteConfig(std::io::Error),
    #[error("Failed to serialize Tendermint config TOML to string: {0}")]
    TendermintConfigSerializeToml(toml::ser::Error),
    #[error("Failed to write Tendermint config: {0}")]
    TendermintWriteConfig(std::io::Error),
    #[error("Failed to start up Tendermint node: {0}")]
    TendermintStartUp(std::io::Error),
    #[error("Failed to bind ABCI server: {0}")]
    AbciServerBind(eyre::Report),
    #[error("Failed to create OS signal handlers: {0}")]
    SignalsHandlers(std::io::Error),
}

pub type Result<T> = std::result::Result<T, Error>;

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
    InitChain {
        reply: Sender<()>,
        chain_id: String,
    },
    /// Validate a given transaction for inclusion in the mempool
    MempoolValidate {
        reply: Sender<std::result::Result<(), String>>,
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
        reply: Sender<(i64, std::result::Result<TxResult, String>)>,
        tx: Vec<u8>,
    },
    /// End a block
    EndBlock {
        reply: Sender<()>,
        height: BlockHeight,
    },
    AbciQuery {
        reply: Sender<std::result::Result<String, String>>,
        path: String,
        data: Vec<u8>,
        height: BlockHeight,
        prove: bool,
    },
    /// Commit the current block. The expected result is the Merkle root hash
    /// of the committed block.
    CommitBlock {
        reply: Sender<MerkleRoot>,
    },

    Terminate,
}

/// Run the ABCI server in the current thread (blocking).
pub fn run(sender: AbciSender, config: config::Ledger) -> Result<()> {
    let home_dir = config.tendermint;
    let home_dir_string = home_dir.to_string_lossy().to_string();
    // init and run a Tendermint node child process
    Command::new("tendermint")
        .args(&["init", "--home", &home_dir_string])
        .output()
        .map_err(Error::TendermintInit)?;

    if cfg!(feature = "dev") {
        // override the validator key file
        write_validator_key(&home_dir, &genesis::genesis().validator)
            .map_err(Error::TendermintValidatorKey)?;
    }

    update_tendermint_config(&home_dir)?;

    let mut tendermint_node = Command::new("tendermint")
        .args(&["node", "--home", &home_dir_string])
        .spawn()
        .map_err(Error::TendermintStartUp)?;

    // bind and run the ABCI server
    let server = ServerBuilder::default()
        .bind(
            config.address,
            AbciWrapper {
                sender: sender.clone(),
            },
        )
        .map_err(Error::AbciServerBind)?;
    std::thread::spawn(move || {
        if let Err(err) = server.listen() {
            tracing::error!("Failed to start up ABCI server: {}", err);
            sender.send(AbciMsg::Terminate).unwrap()
        }
    });

    let mut signals =
        Signals::new(TERM_SIGNALS).map_err(Error::SignalsHandlers)?;
    for sig in signals.forever() {
        if TERM_SIGNALS.contains(&sig) {
            tracing::info!(
                "Received termination signal, shutting down Tendermint node"
            );
            tendermint_node
                .kill()
                .expect("Tendermint node termination failed");
            break;
        }
    }
    Ok(())
}

pub fn reset(config: config::Ledger) {
    // reset all the Tendermint state, if any
    Command::new("tendermint")
        .args(&[
            "unsafe_reset_all",
            // NOTE: log config: https://docs.tendermint.com/master/nodes/logging.html#configuring-log-levels
            // "--log-level=\"*debug\"",
            "--home",
            &config.tendermint.to_string_lossy(),
        ])
        .output()
        .expect("Failed to reset tendermint node's data");
    fs::remove_dir_all(format!(
        "{}/config",
        &config.tendermint.to_string_lossy()
    ))
    .expect("Failed to reset tendermint node's config");
}

#[derive(Clone, Debug)]
struct AbciWrapper {
    sender: AbciSender,
}

impl Drop for AbciWrapper {
    fn drop(&mut self) {
        // the channel might have been already closed
        let _ = self.sender.send(AbciMsg::Terminate);
    }
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
        self.sender
            .send(AbciMsg::GetInfo { reply })
            .expect("failed to send GetInfo request");
        if let Some((last_block_app_hash, last_block_height)) = reply_receiver
            .recv()
            .expect("failed to receive GetInfo response")
        {
            resp.last_block_height = last_block_height
                .try_into()
                .expect("unexpected height value");
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
            .expect("failed to send InitChain request");
        reply_receiver
            .recv()
            .expect("failed to receive InitChain response");

        // Set the initial validator set
        let genesis = genesis::genesis();
        let mut abci_validator =
            tendermint_proto::abci::ValidatorUpdate::default();
        let pub_key = tendermint_proto::crypto::PublicKey {
            sum: Some(tendermint_proto::crypto::public_key::Sum::Ed25519(
                genesis.validator.keypair.public.to_bytes().to_vec(),
            )),
        };
        abci_validator.pub_key = Some(pub_key);
        abci_validator.power = genesis
            .validator
            .voting_power
            .try_into()
            .expect("unexpected validator's voting power");
        resp.validators.push(abci_validator);
        resp
    }

    fn query(&self, request: RequestQuery) -> ResponseQuery {
        let mut resp = ResponseQuery::default();

        let (reply, reply_receiver) = channel();
        let path = request.path;
        let data = request.data;
        let height = request.height as u64;
        let prove = request.prove;

        self.sender
            .send(AbciMsg::AbciQuery {
                reply,
                path,
                data,
                height: BlockHeight(height),
                prove,
            })
            .expect("failed to send AbciQuery request");

        let result = reply_receiver
            .recv()
            .expect("failed to receive AbciQuery response");

        match result {
            Ok(res) => resp.info = res,
            Err(msg) => {
                resp.code = 1;
                resp.log = msg;
            }
        }

        resp
    }

    fn check_tx(&self, req: RequestCheckTx) -> ResponseCheckTx {
        let mut resp = ResponseCheckTx::default();
        let r#type = match CheckTxType::from_i32(req.r#type)
            .expect("received unexpected CheckTxType from ABCI")
        {
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
            .expect("failed to send MempoolValidate request");
        let result = reply_receiver
            .recv()
            .expect("failed to receive MempoolValidate response");

        match result {
            Ok(_) => resp.info = "Mempool validation passed".to_string(),
            Err(msg) => {
                resp.code = 1;
                resp.log = msg;
            }
        }
        resp
    }

    fn begin_block(&self, req: RequestBeginBlock) -> ResponseBeginBlock {
        let resp = ResponseBeginBlock::default();
        let raw_hash = req.hash;
        match BlockHash::try_from(raw_hash) {
            Err(err) => {
                tracing::error!("{:#?}", err);
            }
            Ok(hash) => {
                let raw_height =
                    req.header.expect("missing block's header").height;
                match raw_height.try_into() {
                    Err(_) => {
                        tracing::error!(
                            "Unexpected block height {}",
                            raw_height
                        )
                    }
                    Ok(height) => {
                        let (reply, reply_receiver) = channel();
                        self.sender
                            .send(AbciMsg::BeginBlock {
                                reply,
                                hash,
                                height,
                            })
                            .expect("failed to send BeginBlock request");
                        reply_receiver
                            .recv()
                            .expect("failed to receive BeginBlock response");
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
            .expect("failed to send ApplyTx request");
        let (gas, result) = reply_receiver
            .recv()
            .expect("failed to receive ApplyTx response");

        resp.gas_used = gas;

        match result {
            Ok(tx_result) => {
                resp.info = tx_result.to_string();
                if !tx_result.is_accepted() {
                    resp.code = 1;
                }
            }
            Err(msg) => {
                resp.code = 1;
                resp.info = msg;
            }
        }
        resp
    }

    fn end_block(&self, req: RequestEndBlock) -> ResponseEndBlock {
        let resp = ResponseEndBlock::default();

        let raw_height = req.height;
        match BlockHeight::try_from(raw_height) {
            Err(_) => {
                tracing::error!("Unexpected block height {}", raw_height)
            }
            Ok(height) => {
                let (reply, reply_receiver) = channel();
                self.sender
                    .send(AbciMsg::EndBlock { reply, height })
                    .expect("failed to send EndBlock request");
                reply_receiver
                    .recv()
                    .expect("failed to receive EndBlock response");
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
        self.sender
            .send(AbciMsg::CommitBlock { reply })
            .expect("failed to send CommitBlock request");
        let MerkleRoot(result) = reply_receiver
            .recv()
            .expect("failed to receive CommitBlock response");

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

fn update_tendermint_config(home_dir: impl AsRef<Path>) -> Result<()> {
    let home_dir = home_dir.as_ref();
    let path = home_dir.join("config").join("config.toml");
    let mut config = TendermintConfig::load_toml_file(&path)
        .map_err(Error::TendermintLoadConfig)?;

    // In "dev", only produce blocks when there are txs or when the AppHash
    // changes
    config.consensus.create_empty_blocks = !cfg!(feature = "dev");

    // We set this to true as we don't want any invalid tx be re-applied. This
    // also implies that it's not possible for an invalid tx to become valid
    // again in the future.
    config.mempool.keep_invalid_txs_in_cache = false;

    let mut file = OpenOptions::new()
        .write(true)
        .truncate(true)
        .open(path)
        .map_err(Error::TendermintOpenWriteConfig)?;
    let config_str = toml::to_string(&config)
        .map_err(Error::TendermintConfigSerializeToml)?;
    file.write(config_str.as_bytes())
        .map(|_| ())
        .map_err(Error::TendermintWriteConfig)
}

#[cfg(feature = "dev")]
fn write_validator_key(
    home_dir: impl AsRef<Path>,
    account: &Validator,
) -> io::Result<()> {
    let home_dir = home_dir.as_ref();
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
