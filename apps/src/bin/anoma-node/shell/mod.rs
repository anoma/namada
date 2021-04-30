pub mod gas;
pub mod storage;
mod tendermint;

use core::fmt;
use std::collections::{HashMap, HashSet};
use std::path::Path;
use std::sync::mpsc;
use std::vec;

use anoma::protobuf::types::Tx;
use anoma::wallet;
use anoma_shared::bytes::ByteBuf;
use anoma_shared::types::token::Amount;
use anoma_shared::types::{
    address, key, token, Address, BlockHash, BlockHeight, Key,
};
use borsh::BorshSerialize;
use prost::Message;
use thiserror::Error;

use self::gas::{BlockGasMeter, VpGasMeter};
use self::storage::Storage;
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
    gas_meter: BlockGasMeter,
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
    pub fn new(abci: AbciReceiver, db_path: impl AsRef<Path>) -> Self {
        let mut storage = Storage::new(db_path);

        let token_vp = std::fs::read("vps/vp_token/vp.wasm")
            .expect("cannot load token VP");
        let user_vp =
            std::fs::read("vps/vp_user/vp.wasm").expect("cannot load user VP");

        // TODO load initial accounts from genesis

        // encoded: "a1gezy23f5xvcygdpsgfzr2d6yg4z5zse38qmyx3pexuunqvpnxdzrq33sxerrjvpegyursvpkg5m5x3fkg5mnzd6pggm5xd6yx5crywg8j8uth"
        let ada = Address::from_raw("ada");
        // encoded: "a1g3prgv3nxgurzvfjxymnwsejgsmyvvjxxep5zd6xxve5xwz98qcnqwp5gguyv33ng5cngv3sxger2dp3xvm52v3jxcmnxsjrg5eyxwq69kz8p"
        let alan = Address::from_raw("alan");
        let xan = address::xan();
        let btc = address::btc();

        // default tokens VPs for testing
        let xan_vp = Key::validity_predicate(&xan).expect("expected VP key");
        let btc_vp = Key::validity_predicate(&btc).expect("expected VP key");
        storage
            .write(&xan_vp, token_vp.to_vec())
            .expect("Unable to write token VP");
        storage
            .write(&btc_vp, token_vp.to_vec())
            .expect("Unable to write token VP");

        // default user VPs for testing
        let ada_vp = Key::validity_predicate(&ada).expect("expected VP key");
        let alan_vp = Key::validity_predicate(&alan).expect("expected VP key");
        storage
            .write(&ada_vp, user_vp.to_vec())
            .expect("Unable to write user VP");
        storage
            .write(&alan_vp, user_vp.to_vec())
            .expect("Unable to write user VP");

        // default user's tokens for testing
        let ada_xan = token::balance_key(&xan, &ada);
        let ada_btc = token::balance_key(&btc, &ada);
        let alan_xan = token::balance_key(&xan, &alan);

        storage
            .write(
                &ada_xan,
                Amount::whole(800_000)
                    .try_to_vec()
                    .expect("encode token amount"),
            )
            .expect("Unable to set genesis balance");
        storage
            .write(
                &ada_btc,
                Amount::whole(100)
                    .try_to_vec()
                    .expect("encode token amount"),
            )
            .expect("Unable to set genesis balance");
        storage
            .write(
                &alan_xan,
                Amount::whole(200_000)
                    .try_to_vec()
                    .expect("encode token amount"),
            )
            .expect("Unable to set genesis balance");

        // default user's public keys for testing
        let ada_pk = key::ed25519::pk_key(&ada);
        let alan_pk = key::ed25519::pk_key(&alan);

        storage
            .write(
                &ada_pk,
                wallet::ada_pk().try_to_vec().expect("encode public key"),
            )
            .expect("Unable to set genesis user public key");
        storage
            .write(
                &alan_pk,
                wallet::alan_pk().try_to_vec().expect("encode public key"),
            )
            .expect("Unable to set genesis user public key");

        // Temporary for testing, we have a fixed matchmaker account.
        // This account has a public key for signing matchmaker txs and
        // verifying their signatures in its VP. The VP is the same as
        // the user's VP, which simply checks the signature.
        // We could consider using the same key as the intent broadcaster's p2p
        // key.
        let matchmaker = Address::from_raw("matchmaker");
        let matchmaker_pk = key::ed25519::pk_key(&matchmaker);
        storage
            .write(
                &matchmaker_pk,
                wallet::matchmaker_pk()
                    .try_to_vec()
                    .expect("encode public key"),
            )
            .expect("Unable to set genesis user public key");
        let matchmaker_vp =
            Key::validity_predicate(&matchmaker).expect("expected VP key");
        storage
            .write(&matchmaker_vp, user_vp.to_vec())
            .expect("Unable to write matchmaker VP");

        Self {
            abci,
            storage,
            gas_meter: BlockGasMeter::default(),
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
    pub changed_keys: Vec<Key>,
}

impl VpResult {
    pub fn new(
        accepted_vps: HashSet<Address>,
        rejected_vps: HashSet<Address>,
        changed_keys: Vec<Key>,
    ) -> Self {
        Self {
            accepted_vps,
            rejected_vps,
            changed_keys,
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
            vps: vps.unwrap_or_default(),
            valid: false,
        };
        tx_result.valid = tx_result.is_tx_correct();
        tx_result
    }

    pub fn is_tx_correct(&self) -> bool {
        self.gas_used > 0 && self.vps.rejected_vps.is_empty()
    }
}

impl fmt::Display for TxResult {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "Transaction is valid: {}. Gas used: {}, vps: {}",
            self.valid,
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
        let _tx = Tx::decode(tx_bytes).map_err(Error::TxDecodingError)?;
        Ok(())
    }

    /// Validate and apply a transaction.
    pub fn dry_run_tx(&mut self, tx_bytes: &[u8]) -> Result<String> {
        let mut gas_meter = BlockGasMeter::default();
        let mut write_log = self.write_log.clone();
        let result =
            run_tx(tx_bytes, &mut gas_meter, &mut write_log, &self.storage)?;
        Ok(result.to_string())
    }

    /// Validate and apply a transaction.
    pub fn apply_tx(&mut self, tx_bytes: &[u8]) -> Result<u64> {
        let result = run_tx(
            tx_bytes,
            &mut self.gas_meter.clone(),
            &mut self.write_log,
            &self.storage,
        )?;
        // Apply the transaction if accepted by all the VPs
        if result.vps.rejected_vps.is_empty() {
            log::debug!("all VPs accepted apply_tx storage modification");
            self.write_log.commit_tx();
        } else {
            log::debug!(
                "some VPs rejected apply_tx storage modification {:#?}",
                result.vps.rejected_vps
            );
            self.write_log.drop_tx();
        }
        Ok(result.gas_used)
    }

    /// Begin a new block.
    pub fn begin_block(&mut self, hash: BlockHash, height: BlockHeight) {
        self.gas_meter.reset();
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
        // TODO with VPs in storage, this prints out too much spam
        // log::debug!("storage to commit {:#?}", self.storage);
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
) -> HashMap<Address, Vec<Key>> {
    let mut verifiers =
        verifiers.iter().fold(HashMap::new(), |mut acc, addr| {
            acc.insert(addr.clone(), vec![]);
            acc
        });
    // get changed keys grouped by the address
    for key in write_log.get_changed_keys() {
        for addr in &key.find_addresses() {
            match verifiers.get_mut(&addr) {
                Some(keys) => keys.push(key.clone()),
                None => {
                    verifiers.insert(addr.clone(), vec![key.clone()]);
                }
            }
        }
    }
    verifiers
}

fn run_tx(
    tx_bytes: &[u8],
    block_gas_meter: &mut BlockGasMeter,
    write_log: &mut WriteLog,
    storage: &Storage,
) -> Result<TxResult> {
    block_gas_meter
        .add_base_transaction_fee(tx_bytes.len())
        .map_err(Error::GasError)?;

    let tx = Tx::decode(tx_bytes).map_err(Error::TxDecodingError)?;

    // Execute the transaction code
    let verifiers = execute_tx(&tx, storage, block_gas_meter, write_log)?;

    let vps_result =
        check_vps(&tx, storage, block_gas_meter, write_log, &verifiers, true);

    let gas = block_gas_meter
        .finalize_transaction()
        .map_err(Error::GasError);

    Ok(TxResult::new(gas, vps_result))
}

fn check_vps(
    tx: &Tx,
    storage: &Storage,
    gas_meter: &mut BlockGasMeter,
    write_log: &mut WriteLog,
    verifiers: &HashSet<Address>,
    dry_run: bool,
) -> Result<VpResult> {
    let verifiers = get_verifiers(write_log, verifiers);
    let addresses: HashSet<Address> = verifiers.keys().collect();

    let tx_data = tx.data.clone().unwrap_or_default();

    let mut rejected_vps = HashSet::new();
    let mut accepted_vps = HashSet::new();
    let mut changed_keys: Vec<Key> = Vec::new();

    let verifiers_vps: Vec<(&Address, &Vec<Key>, Vec<u8>)> = verifiers
        .iter()
        .map(|(addr, keys)| {
            let vp = storage
                .validity_predicate(&addr)
                .map_err(Error::StorageError)?;

            gas_meter
                .add_compiling_fee(vp.len())
                .map_err(Error::GasError)?;

            Ok((addr, keys, vp))
        })
        .collect::<std::result::Result<_, _>>()?;

    let initial_gas = gas_meter.get_current_transaction_gas();
    let mut vp_meters: Vec<VpGasMeter> = Vec::new();

    for (addr, keys, vp) in verifiers_vps {
        let mut vp_gas_meter = VpGasMeter::new(initial_gas);

        let vp_runner = VpRunner::new();
        let accept = vp_runner
            .run(
                vp,
                tx_data.clone(),
                &tx.code,
                &addr,
                storage,
                write_log,
                &mut vp_gas_meter,
                keys.clone(),
                addresses.clone(),
            )
            .map_err(|error| Error::VpRunnerError {
                addr: addr.clone(),
                error,
            })?;
        if !accept {
            rejected_vps.insert(addr.clone());
            if !dry_run {
                break;
            }
        } else {
            accepted_vps.insert(addr.clone());
            changed_keys.append(&mut keys.clone());
        }
        vp_meters.push(vp_gas_meter);
    }

    let mut consumed_gas =
        vp_meters.iter().map(|x| x.vp_gas).collect::<Vec<u64>>();
    // sort decresing order
    consumed_gas.sort_by(|a, b| b.cmp(a));

    // I'm assuming that at least 1 VP will always be there
    if let Some((max_gas_used, rest)) = consumed_gas.split_first() {
        gas_meter.add(*max_gas_used).map_err(Error::GasError)?;
        gas_meter
            .add_parallel_fee(&mut rest.to_vec())
            .map_err(Error::GasError)?;
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
    gas_meter
        .add_compiling_fee(tx_code.len())
        .map_err(Error::GasError)?;
    let tx_data = tx.data.clone().unwrap_or_default();
    let mut verifiers = HashSet::new();

    let tx_runner = TxRunner::new();

    tx_runner
        .run(
            storage,
            write_log,
            &mut verifiers,
            gas_meter,
            tx_code,
            tx_data,
        )
        .map_err(Error::TxRunnerError)?;

    Ok(verifiers)
}
