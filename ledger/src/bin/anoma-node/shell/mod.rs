mod storage;
mod tendermint;

use std::sync::mpsc;
use std::{ffi::c_void, path::PathBuf};

use anoma::bytes::ByteBuf;
use anoma::config::Config;
use anoma::rpc_types::{Message, Tx};
use anoma_vm::{TxEnv, TxRunner, VpRunner};
use borsh::BorshDeserialize;
use storage::KeySeg;
use thiserror::Error;

use self::storage::{
    Address, BasicAddress, BlockHash, BlockHeight, Storage, ValidatorAddress,
};
use self::tendermint::{AbciMsg, AbciReceiver};

#[derive(Error, Debug)]
pub enum Error {
    #[error("TEMPORARY error: {error}")]
    Temporary { error: String },
    #[error("Error removing the DB data: {0}")]
    RemoveDB(std::io::Error),
    #[error("Storage error: {0}")]
    StorageError(storage::Error),
    #[error("Shell ABCI channel receiver error: {0}")]
    AbciChannelRecvError(mpsc::RecvError),
    #[error("Shell ABCI channel sender error: {0}")]
    AbciChannelSendError(String),
    #[error("Error decoding a transaction from bytes: {0}")]
    TxDecodingError(prost::DecodeError),
    #[error("Transaction runner error: {0}")]
    TxRunnerError(anoma_vm::Error),
    #[error("Validity predicate for {addr} runner error: {error}")]
    VpRunnerError {
        addr: Address,
        error: anoma_vm::Error,
    },
}

pub type Result<T> = std::result::Result<T, Error>;

pub fn run(config: Config) -> Result<()> {
    // open a channel between ABCI (the sender) and the shell (the receiver)
    let (sender, receiver) = mpsc::channel();
    let shell = Shell::new(receiver, &config.db_home_dir());
    let addr = format!("{}:{}", config.tendermint.host, config.tendermint.port)
        .parse()
        .map_err(|e| Error::Temporary {
            error: format!("cannot parse tendermint address {}", e),
        })?;
    // Run Tendermint ABCI server in another thread
    std::thread::spawn(move || tendermint::run(sender, config, addr));
    shell.run()
}

pub fn reset(config: Config) -> Result<()> {
    // simply nuke the DB files
    let db_path = config.db_home_dir();
    match std::fs::remove_dir_all(&db_path) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => (),
        res => res.map_err(Error::RemoveDB)?,
    };
    // reset Tendermint state
    tendermint::reset(config);
    Ok(())
}

pub struct Shell {
    abci: AbciReceiver,
    storage: storage::Storage,
}

#[derive(Clone, Debug)]
pub enum MempoolTxType {
    /// A transaction that has not been validated by this node before
    NewTransaction,
    /// A transaction that has been validated at some previous level that may
    /// need to be validated again
    RecheckTransaction,
}

pub struct MerkleRoot(pub Vec<u8>);

impl Shell {
    pub fn new(abci: AbciReceiver, db_path: &PathBuf) -> Self {
        let mut storage = Storage::new(db_path);
        // TODO load initial accounts from genesis
        let va = ValidatorAddress::new_address("va".to_owned());
        storage
            .write(
                &va,
                "balance/eth",
                vec![0x10_u8, 0x27_u8, 0_u8, 0_u8, 0_u8, 0_u8, 0_u8, 0_u8],
            )
            .expect("Unable to set the initial balance for validator account");
        let ba = BasicAddress::new_address("ba".to_owned());
        storage
            .write(
                &ba,
                "balance/eth",
                vec![0x64_u8, 0_u8, 0_u8, 0_u8, 0_u8, 0_u8, 0_u8, 0_u8],
            )
            .expect("Unable to set the initial balance for basic account");
        Self { abci, storage }
    }

    /// Run the shell in the current thread (blocking).
    pub fn run(mut self) -> Result<()> {
        loop {
            let msg = self.abci.recv().map_err(Error::AbciChannelRecvError)?;
            match msg {
                AbciMsg::GetInfo { reply } => {
                    let result = self.last_state();
                    reply.send(result).map_err(|e| {
                        Error::AbciChannelSendError(format!("GetInfo {}", e))
                    })?
                }
                AbciMsg::InitChain { reply, chain_id } => {
                    self.init_chain(chain_id)?;
                    reply.send(()).map_err(|e| {
                        Error::AbciChannelSendError(format!("InitChain {}", e))
                    })?
                }
                AbciMsg::MempoolValidate { reply, tx, r#type } => {
                    let result = self
                        .mempool_validate(&tx, r#type)
                        .map_err(|e| format!("{}", e));
                    reply.send(result).map_err(|e| {
                        Error::AbciChannelSendError(format!(
                            "MempoolValidate {}",
                            e
                        ))
                    })?
                }
                AbciMsg::BeginBlock {
                    reply,
                    hash,
                    height,
                } => {
                    self.begin_block(hash, height);
                    reply.send(()).map_err(|e| {
                        Error::AbciChannelSendError(format!("BeginBlock {}", e))
                    })?
                }
                AbciMsg::ApplyTx { reply, tx } => {
                    let result =
                        self.apply_tx(&tx).map_err(|e| format!("{}", e));
                    reply.send(result).map_err(|e| {
                        Error::AbciChannelSendError(format!("ApplyTx {}", e))
                    })?
                }
                AbciMsg::EndBlock { reply, height } => {
                    self.end_block(height);
                    reply.send(()).map_err(|e| {
                        Error::AbciChannelSendError(format!("EndBlock {}", e))
                    })?
                }
                AbciMsg::CommitBlock { reply } => {
                    let result = self.commit();
                    reply.send(result).map_err(|e| {
                        Error::AbciChannelSendError(format!(
                            "CommitBlock {}",
                            e
                        ))
                    })?
                }
            }
        }
    }
}

fn vm_storage_read(
    env: &TxEnv,
    key_ptr: u64,
    key_len: u64,
    result_ptr: u64,
) -> u64 {
    let key = env
        .memory
        .read_string(key_ptr, key_len)
        .expect("Cannot read the key from memory");

    log::info!(
        "vm_storage_read {}, key {}, result_ptr {}, {:#?}",
        key,
        key_ptr,
        result_ptr,
        env.memory
    );

    let shell: &mut Shell = unsafe { &mut *(env.ledger.0 as *mut Shell) };
    let keys = key.split('/').collect::<Vec<&str>>();
    if let [key_a, key_b, key_c] = keys.as_slice() {
        if "balance" == key_b.to_string() {
            let addr = storage::Address::from_key_seg(&key_a.to_string())
                .expect("should be an address");
            let key = format!("{}/{}", key_b, key_c);
            let value = shell
                .storage
                .read(&addr, &key)
                .expect("storage read failed")
                .expect("key not found");
            let bal: u64 = u64::deserialize(&mut &value[..]).unwrap();
            log::info!("key {}/{}/{}, value {}", key_a, key_b, key_c, bal);
            env.memory
                .write_bytes(result_ptr, value)
                .expect("cannot write to memory");
            return 1;
        }
    }
    // fail
    0
}

fn vm_storage_update(
    env: &TxEnv,
    key_ptr: u64,
    key_len: u64,
    val_ptr: u64,
    val_len: u64,
) -> u64 {
    let key = env
        .memory
        .read_string(key_ptr, key_len)
        .expect("Cannot read the key from memory");
    let val = env
        .memory
        .read_bytes(val_ptr, val_len as _)
        .expect("Cannot read the value from memory");
    log::info!("vm_storage_update {}, {:#?}", key, val);

    let shell: &mut Shell = unsafe { &mut *(env.ledger.0 as *mut Shell) };
    let keys = key.split('/').collect::<Vec<&str>>();
    if let [key_a, key_b, key_c] = keys.as_slice() {
        if "balance" == key_b.to_string() {
            let addr = storage::Address::from_key_seg(&key_a.to_string())
                .expect("should be an address");
            let key = format!("{}/{}", key_b, key_c);
            log::info!("key {}/{}/{}", key_a, key_b, key_c);
            shell
                .storage
                .write(&addr, &key, val)
                .expect("VM storage write fail");
            return 1;
        }
    }
    // fail
    0
}

impl Shell {
    pub fn init_chain(&mut self, chain_id: String) -> Result<()> {
        self.storage
            .set_chain_id(&chain_id)
            .map_err(Error::StorageError)
    }

    /// Validate a transaction request. On success, the transaction will
    /// included in the mempool and propagated to peers, otherwise it will be
    /// rejected.
    pub fn mempool_validate(
        &self,
        tx_bytes: &[u8],
        r#_type: MempoolTxType,
    ) -> Result<()> {
        let _tx = Tx::decode(&tx_bytes[..]).map_err(Error::TxDecodingError)?;
        Ok(())
    }

    /// Validate and apply a transaction.
    pub fn apply_tx(&mut self, tx_bytes: &[u8]) -> Result<()> {
        let tx = Tx::decode(&tx_bytes[..]).map_err(Error::TxDecodingError)?;
        let tx_data = tx.data.unwrap_or(vec![]);

        // Execute the transaction code
        let tx_runner = TxRunner::new();
        let ledger = anoma_vm::LedgerWrapper(self as *mut _ as *mut c_void);
        tx_runner
            .run(
                ledger,
                tx.code,
                &tx_data,
                vm_storage_read,
                vm_storage_update,
            )
            .map_err(Error::TxRunnerError)?;

        // TODO gather write log from tx udpates
        let write_log = vec![];

        // TODO determine these from the write log
        let src = "va";
        let dest = "ba";
        let src_addr = Address::new_address(src.into());
        let dest_addr = Address::new_address(dest.into());

        // Run a VP for every account with modified storage sub-space
        // TODO run in parallel for all accounts
        //   - all must return `true` to accept the tx
        //   - cancel all remaining workers and fail if any returns `false`
        let src_vp = self
            .storage
            .validity_predicate(&src_addr)
            .map_err(Error::StorageError)?;
        let dest_vp = self
            .storage
            .validity_predicate(&dest_addr)
            .map_err(Error::StorageError)?;

        let vp_runner = VpRunner::new();
        let (vp_sender, vp_receiver) = mpsc::channel();
        vp_runner
            .run(
                src_vp,
                &tx_data,
                src.to_string(),
                &write_log,
                vp_sender.clone(),
            )
            .map_err(|error| Error::VpRunnerError {
                addr: src_addr.clone(),
                error,
            })?;
        let src_accept = vp_receiver
            .recv()
            .expect("Expected a message from source's VP runner");
        vp_runner
            .run(dest_vp, &tx_data, dest.to_string(), &write_log, vp_sender)
            .map_err(|error| Error::VpRunnerError {
                addr: dest_addr.clone(),
                error,
            })?;
        let dest_accept = vp_receiver
            .recv()
            .expect("Expected a message from destination's VP runner");

        // Apply the transaction if accepted by all the VPs
        if src_accept && dest_accept {
            self.storage
                .transfer(&src_addr, &dest_addr, 10)
                .map_err(Error::StorageError)?;
            log::debug!(
                "all accepted apply_tx storage modification {:#?}",
                self.storage
            );
        } else {
            log::debug!(
                "tx declined by {}",
                if src_accept {
                    "dest"
                } else {
                    if dest_accept {
                        "src"
                    } else {
                        "src and dest"
                    }
                }
            );
        }

        Ok(())
    }

    /// Begin a new block.
    pub fn begin_block(&mut self, hash: BlockHash, height: BlockHeight) {
        self.storage.begin_block(hash, height).unwrap();
    }

    /// End a block.
    pub fn end_block(&mut self, _height: BlockHeight) {}

    /// Commit a block. Persist the application state and return the Merkle root
    /// hash.
    pub fn commit(&mut self) -> MerkleRoot {
        log::debug!("storage to commit {:#?}", self.storage);
        // store the block's data in DB
        // TODO commit async?
        self.storage.commit().unwrap_or_else(|e| {
            log::error!(
                "Encountered a storage error while committing a block {:?}",
                e
            )
        });
        let root = self.storage.merkle_root();
        MerkleRoot(root.as_slice().to_vec())
    }

    /// Load the Merkle root hash and the height of the last committed block, if
    /// any.
    pub fn last_state(&mut self) -> Option<(MerkleRoot, u64)> {
        let result = self.storage.load_last_state().unwrap_or_else(|e| {
            log::error!(
                "Encountered an error while reading last state from
        storage {}",
                e
            );
            None
        });
        match &result {
            Some((root, height)) => {
                log::info!(
                    "Last state root hash: {}, height: {}",
                    ByteBuf(&root.0),
                    height
                )
            }
            None => {
                log::info!("No state could be found")
            }
        }
        result
    }
}
