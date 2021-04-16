pub mod gas;
pub mod storage;
mod tendermint;

use core::fmt;
use std::collections::{HashMap, HashSet};
use std::path::PathBuf;
use std::sync::{mpsc, Arc, Mutex};

use anoma::bytes::ByteBuf;
use anoma::protobuf::types::Tx;
use prost::Message;
use thiserror::Error;

use self::gas::BlockGasMeter;
use self::storage::{Address, BlockHash, BlockHeight, Key, Storage};
use self::tendermint::{AbciMsg, AbciReceiver};
use crate::vm::host_env::write_log::WriteLog;
use crate::vm::{self, TxRunner, VpRunner};

#[derive(Error, Debug)]
pub enum Error {
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
    TxRunnerError(vm::Error),
    #[error("Validity predicate for {addr} runner error: {error}")]
    VpRunnerError { addr: Address, error: vm::Error },
    #[error("Gas error: {0}")]
    GasError(gas::Error),
}

pub type Result<T> = std::result::Result<T, Error>;

pub fn run(config: anoma::config::Ledger) -> Result<()> {
    // open a channel between ABCI (the sender) and the shell (the receiver)
    let (sender, receiver) = mpsc::channel();
    let shell = Shell::new(receiver, &config.db);
    // Run Tendermint ABCI server in another thread
    std::thread::spawn(move || tendermint::run(sender, config));
    shell.run()
}

pub fn reset(config: anoma::config::Ledger) -> Result<()> {
    // simply nuke the DB files
    let db_path = &config.db;
    match std::fs::remove_dir_all(&db_path) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => (),
        res => res.map_err(Error::RemoveDB)?,
    };
    // reset Tendermint state
    tendermint::reset(config);
    Ok(())
}

#[derive(Debug)]
pub struct Shell {
    abci: AbciReceiver,
    storage: storage::Storage,
    // The gas meter is sync with mutex to allow VPs sharing it
    // TODO it should be possible to impl a lock-free gas metering for VPs
    gas_meter: Arc<Mutex<BlockGasMeter>>,
    write_log: WriteLog,
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
        let key11 = Key::parse("@va/balance/eth".to_owned())
            .expect("Unable to convert string into a key");
        storage
            .write(
                &key11,
                vec![0x10_u8, 0x27_u8, 0_u8, 0_u8, 0_u8, 0_u8, 0_u8, 0_u8],
            )
            .expect("Unable to set the initial balance for validator account");
        let key12 = Key::parse("@va/balance/xtz".to_owned())
            .expect("Unable to convert string into a key");
        storage
            .write(
                &key12,
                vec![0x10_u8, 0x27_u8, 0_u8, 0_u8, 0_u8, 0_u8, 0_u8, 0_u8],
            )
            .expect("Unable to set the initial balance for validator account");
        let key21 = Key::parse("@ba/balance/eth".to_owned())
            .expect("Unable to convert string into a key");
        storage
            .write(
                &key21,
                vec![0x64_u8, 0_u8, 0_u8, 0_u8, 0_u8, 0_u8, 0_u8, 0_u8],
            )
            .expect("Unable to set the initial balance for basic account");
        let key22 = Key::parse("@ba/balance/xtz".to_owned())
            .expect("Unable to convert string into a key");
        storage
            .write(
                &key22,
                vec![0x64_u8, 0_u8, 0_u8, 0_u8, 0_u8, 0_u8, 0_u8, 0_u8],
            )
            .expect("Unable to set the initial balance for basic account");
        Self {
            abci,
            storage,
            gas_meter: Arc::new(Mutex::new(BlockGasMeter::default())),
            write_log: WriteLog::new(),
        }
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
                AbciMsg::AbciQuery {
                    reply,
                    path,
                    data,
                    height: _,
                    prove: _,
                } => {
                    if path == "dry_run_tx" {
                        let result = self
                            .dry_run_tx(&data)
                            .map_err(|e| format!("{}", e));

                        reply.send(result).map_err(|e| {
                            Error::AbciChannelSendError(format!(
                                "ApplyTx {}",
                                e
                            ))
                        })?
                    }
                }
            }
        }
    }
}

struct VpResult {
    pub accepted_vps: HashSet<Address>,
    pub rejected_vps: HashSet<Address>,
    pub changed_keys: Vec<String>,
}

impl VpResult {
    pub fn new(
        accepted_vps: HashSet<Address>,
        rejected_vps: HashSet<Address>,
        changed_keys: Vec<String>,
    ) -> Self {
        Self {
            accepted_vps: accepted_vps,
            rejected_vps: rejected_vps,
            changed_keys: changed_keys,
        }
    }
}

impl fmt::Display for VpResult {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "Vps -> accepted: {:?}. rejected: {:?}, keys: {:?}",
            self.accepted_vps, self.rejected_vps, self.changed_keys,
        )
    }
}

impl Default for VpResult {
    fn default() -> Self {
        Self {
            accepted_vps: HashSet::new(),
            rejected_vps: HashSet::new(),
            changed_keys: Vec::new(),
        }
    }
}

struct TxResult {
    // a value of 0 indicates that the transaction overflowed with gas
    gas_used: u64,
    vps: VpResult,
    valid: bool,
}

impl TxResult {
    pub fn new(gas: Result<u64>, vps: Result<VpResult>) -> Self {
        let mut tx_result = TxResult {
            gas_used: gas.unwrap_or(0),
            vps: vps.unwrap_or(VpResult::default()),
            valid: false,
        };
        tx_result.valid = tx_result.is_tx_correct();
        tx_result
    }

    pub fn is_tx_correct(&self) -> bool {
        self.gas_used > 0 && self.vps.rejected_vps.len() == 0
    }
}

impl fmt::Display for TxResult {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "Transaction status is: {}. Gas used: {}, vps: {}",
            self.is_tx_correct(),
            self.gas_used,
            self.vps.to_string(),
        )
    }
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
    pub fn dry_run_tx(&mut self, tx_bytes: &[u8]) -> Result<String> {
        let gas_meter = self.gas_meter.clone();
        let mut cloned_gas_meter =
            gas_meter.lock().expect("Cannot get lock on the gas meter");

        let mut cloned_write_log = self.write_log.clone();

        cloned_gas_meter
            .add_base_transaction_fee(tx_bytes.len())
            .map_err(Error::GasError)?;

        let tx = Tx::decode(&tx_bytes[..]).map_err(Error::TxDecodingError)?;

        // Execute the transaction code
        let verifiers = execute_tx(
            &tx,
            &self.storage,
            &mut cloned_gas_meter,
            &mut cloned_write_log,
        )?;

        // drop the lock on the gas meter, the VPs will access it via the mutex
        drop(cloned_gas_meter);

        let vps_result = check_vps(
            &tx,
            &self.storage,
            gas_meter,
            &mut cloned_write_log,
            &verifiers,
            true,
        );

        // maybe we can return the total gas used by the transaction?
        let mut gas_meter = self
            .gas_meter
            .lock()
            .expect("Cannot get lock on the gas meter");
        let gas = gas_meter.finalize_transaction().map_err(Error::GasError);

        Ok(TxResult::new(gas, vps_result).to_string())
    }

    /// Validate and apply a transaction.
    pub fn apply_tx(&mut self, tx_bytes: &[u8]) -> Result<u64> {
        let mut gas_meter = self
            .gas_meter
            .lock()
            .expect("Cannot get lock on the gas meter");
        gas_meter
            .add_base_transaction_fee(tx_bytes.len())
            .map_err(Error::GasError)?;

        let tx = Tx::decode(&tx_bytes[..]).map_err(Error::TxDecodingError)?;

        // Execute the transaction code
        let verifiers = execute_tx(
            &tx,
            &self.storage,
            &mut gas_meter,
            &mut self.write_log,
        )?;

        // drop the lock on the gas meter, the VPs will access it via the mutex
        drop(gas_meter);

        let vps_result = check_vps(
            &tx,
            &self.storage,
            self.gas_meter.clone(),
            &mut self.write_log,
            &verifiers,
            false,
        );

        // Apply the transaction if accepted by all the VPs
        if vps_result.is_ok() {
            log::debug!(
                "all accepted apply_tx storage modification {:#?}",
                self.storage
            );
            self.write_log.commit_tx();
        } else {
            self.write_log.drop_tx();
        }

        let mut gas_meter = self
            .gas_meter
            .lock()
            .expect("Cannot get lock on the gas meter");
        gas_meter.finalize_transaction().map_err(Error::GasError)
    }

    /// Begin a new block.
    pub fn begin_block(&mut self, hash: BlockHash, height: BlockHeight) {
        let mut gas_meter = self
            .gas_meter
            .lock()
            .expect("Cannot get lock on the gas meter");
        gas_meter.reset();
        self.storage.begin_block(hash, height).unwrap();
    }

    /// End a block.
    pub fn end_block(&mut self, _height: BlockHeight) {}

    /// Commit a block. Persist the application state and return the Merkle root
    /// hash.
    pub fn commit(&mut self) -> MerkleRoot {
        // commit changes from the write-log to storage
        self.write_log
            .commit_block(&mut self.storage)
            .expect("Expected committing block write log success");
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

fn get_verifiers(
    write_log: &WriteLog,
    verifiers: &HashSet<Address>,
) -> HashMap<Address, Vec<String>> {
    let mut verifiers =
        verifiers.iter().fold(HashMap::new(), |mut acc, addr| {
            acc.insert(addr.clone(), vec![]);
            acc
        });
    // get changed keys grouped by the address
    for key in &write_log.get_changed_keys() {
        for addr in &key.find_addresses() {
            match verifiers.get_mut(&addr) {
                Some(keys) => keys.push(key.to_string()),
                None => {
                    verifiers.insert(addr.clone(), vec![key.to_string()]);
                }
            }
        }
    }
    verifiers
}

fn check_vps(
    tx: &Tx,
    storage: &Storage,
    gas_meter: Arc<Mutex<BlockGasMeter>>,
    write_log: &mut WriteLog,
    verifiers: &HashSet<Address>,
    dry_run: bool,
) -> Result<VpResult> {
    let verifiers = get_verifiers(write_log, verifiers);
    let addresses = verifiers.keys().map(|addr| addr.to_string()).collect();

    let tx_data = tx.data.clone().unwrap_or(vec![]);

    let mut rejected_vps = HashSet::new();
    let mut accepted_vps = HashSet::new();
    let mut changed_keys: Vec<String> = Vec::new();

    for (addr, keys) in verifiers {
        let vp = storage
            .validity_predicate(&addr)
            .map_err(Error::StorageError)?;

        let vp_runner = VpRunner::new();
        let accept = vp_runner
            .run(
                vp,
                tx_data.as_ref(),
                addr.clone(),
                storage,
                write_log,
                gas_meter.clone(),
                &keys,
                &addresses,
            )
            .map_err(|error| Error::VpRunnerError {
                addr: addr.clone(),
                error,
            })?;
        if !accept {
            if !dry_run {
                rejected_vps.insert(addr.clone());
                break;
            }
            rejected_vps.insert(addr.clone());
        } else {
            accepted_vps.insert(addr.clone());
            changed_keys.append(&mut keys.clone());
        }
    }
    Ok(VpResult::new(accepted_vps, rejected_vps, changed_keys))
}

fn execute_tx(
    tx: &Tx,
    storage: &Storage,
    gas_meter: &mut BlockGasMeter,
    write_log: &mut WriteLog,
) -> Result<HashSet<Address>> {
    let tx_code = tx.code.clone();
    let tx_data = tx.data.clone().unwrap_or(vec![]);
    let mut verifiers = HashSet::new();

    let tx_runner = TxRunner::new();

    tx_runner
        .run(
            storage,
            write_log,
            &mut verifiers,
            gas_meter,
            tx_code,
            &tx_data,
        )
        .map_err(Error::TxRunnerError)?;

    Ok(verifiers)
}
