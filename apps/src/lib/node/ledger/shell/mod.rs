//! The ledger shell connects the ABCI++ interface with the Namada ledger app.
//!
//! Any changes applied before [`Shell::finalize_block`] might have to be
//! reverted, so any changes applied in the methods [`Shell::prepare_proposal`]
//! and [`Shell::process_proposal`] must be also reverted
//! (unless we can simply overwrite them in the next block).
//! More info in <https://github.com/anoma/namada/issues/362>.
mod block_space_alloc;
mod finalize_block;
mod governance;
mod init_chain;
mod prepare_proposal;
mod process_proposal;
pub(super) mod queries;
mod stats;
mod vote_extensions;

use std::collections::{BTreeSet, HashSet};
use std::convert::{TryFrom, TryInto};
use std::mem;
use std::path::{Path, PathBuf};
#[allow(unused_imports)]
use std::rc::Rc;

use borsh::{BorshDeserialize, BorshSerialize};
use namada::core::ledger::eth_bridge;
use namada::ledger::eth_bridge::{EthBridgeQueries, EthereumBridgeConfig};
use namada::ledger::events::log::EventLog;
use namada::ledger::events::Event;
use namada::ledger::gas::BlockGasMeter;
use namada::ledger::pos::namada_proof_of_stake::types::{
    ConsensusValidator, ValidatorSetUpdate,
};
use namada::ledger::protocol::ShellParams;
use namada::ledger::storage::write_log::WriteLog;
use namada::ledger::storage::{
    DBIter, Sha256Hasher, Storage, StorageHasher, WlStorage, DB,
};
use namada::ledger::storage_api::{self, StorageRead};
use namada::ledger::{ibc, pos, protocol, replay_protection};
use namada::proof_of_stake::{self, read_pos_params, slash};
use namada::proto::{self, Tx};
use namada::types::address::{masp, masp_tx_key, Address};
use namada::types::chain::ChainId;
use namada::types::ethereum_events::EthereumEvent;
use namada::types::internal::WrapperTxInQueue;
use namada::types::key::*;
use namada::types::storage::{BlockHeight, Key, TxIndex};
use namada::types::token::{self};
#[cfg(not(feature = "mainnet"))]
use namada::types::transaction::MIN_FEE;
use namada::types::transaction::{
    hash_tx, process_tx, verify_decrypted_correctly, AffineCurve, DecryptedTx,
    EllipticCurve, PairingEngine, TxType,
};
use namada::types::{address, hash};
use namada::vm::wasm::{TxCache, VpCache};
use namada::vm::WasmCacheRwAccess;
use num_derive::{FromPrimitive, ToPrimitive};
use num_traits::{FromPrimitive, ToPrimitive};
use thiserror::Error;
use tokio::sync::mpsc::{Receiver, UnboundedSender};

use super::ethereum_oracle::{self as oracle, last_processed_block};
use crate::config::{genesis, TendermintMode};
use crate::facade::tendermint_proto::abci::{
    Misbehavior as Evidence, MisbehaviorType as EvidenceType, ValidatorUpdate,
};
use crate::facade::tendermint_proto::crypto::public_key;
use crate::facade::tendermint_proto::google::protobuf::Timestamp;
use crate::facade::tower_abci::{request, response};
use crate::node::ledger::shims::abcipp_shim_types::shim;
use crate::node::ledger::shims::abcipp_shim_types::shim::response::TxResult;
use crate::node::ledger::{storage, tendermint_node};
#[allow(unused_imports)]
use crate::wallet::{ValidatorData, ValidatorKeys};
use crate::{config, wallet};

fn key_to_tendermint(
    pk: &common::PublicKey,
) -> std::result::Result<public_key::Sum, ParsePublicKeyError> {
    match pk {
        common::PublicKey::Ed25519(_) => ed25519::PublicKey::try_from_pk(pk)
            .map(|pk| public_key::Sum::Ed25519(pk.try_to_vec().unwrap())),
        common::PublicKey::Secp256k1(_) => {
            secp256k1::PublicKey::try_from_pk(pk)
                .map(|pk| public_key::Sum::Secp256k1(pk.try_to_vec().unwrap()))
        }
    }
}

#[derive(Error, Debug)]
pub enum Error {
    #[error("Error removing the DB data: {0}")]
    RemoveDB(std::io::Error),
    #[error("chain ID mismatch: {0}")]
    ChainId(String),
    #[error("Error decoding a transaction from bytes: {0}")]
    TxDecoding(proto::Error),
    #[error("Error trying to apply a transaction: {0}")]
    TxApply(protocol::Error),
    #[error("Gas limit exceeding while applying transactions in block")]
    GasOverflow,
    #[error("{0}")]
    Tendermint(tendermint_node::Error),
    #[error("{0}")]
    Ethereum(super::ethereum_oracle::Error),
    #[error("Server error: {0}")]
    TowerServer(String),
    #[error("{0}")]
    Broadcaster(tokio::sync::mpsc::error::TryRecvError),
    #[error("Error executing proposal {0}: {1}")]
    BadProposal(u64, String),
    #[error("Error reading wasm: {0}")]
    ReadingWasm(#[from] eyre::Error),
    #[error("Error loading wasm: {0}")]
    LoadingWasm(String),
    #[error("Error reading from or writing to storage: {0}")]
    StorageApi(#[from] storage_api::Error),
}

impl From<Error> for TxResult {
    fn from(err: Error) -> Self {
        TxResult {
            code: 1,
            info: err.to_string(),
        }
    }
}

/// The different error codes that the ledger may
/// send back to a client indicating the status
/// of their submitted tx
#[derive(Debug, Copy, Clone, FromPrimitive, ToPrimitive, PartialEq)]
pub enum ErrorCodes {
    Ok = 0,
    InvalidDecryptedChainId = 1,
    ExpiredDecryptedTx = 2,
    WasmRuntimeError = 3,
    InvalidTx = 4,
    InvalidSig = 5,
    InvalidOrder = 6,
    ExtraTxs = 7,
    Undecryptable = 8,
    InvalidVoteExtension = 9,
    AllocationError = 10,
    ReplayTx = 11,
    InvalidChainId = 12,
    ExpiredTx = 13,
}

impl ErrorCodes {
    /// Checks if the given [`ErrorCodes`] value is a protocol level error,
    /// that can be recovered from at the finalize block stage.
    pub const fn is_recoverable(&self) -> bool {
        use ErrorCodes::*;
        // NOTE: pattern match on all `ErrorCodes` variants, in order
        // to catch potential bugs when adding new codes
        match self {
            Ok
            | InvalidDecryptedChainId
            | ExpiredDecryptedTx
            | WasmRuntimeError => true,
            InvalidTx | InvalidSig | InvalidOrder | ExtraTxs
            | Undecryptable | AllocationError | InvalidVoteExtension | ReplayTx | InvalidChainId
            | ExpiredTx => false,
        }
    }
}

impl From<ErrorCodes> for u32 {
    fn from(code: ErrorCodes) -> u32 {
        code.to_u32().unwrap()
    }
}

impl From<ErrorCodes> for String {
    fn from(code: ErrorCodes) -> String {
        u32::from(code).to_string()
    }
}

pub type Result<T> = std::result::Result<T, Error>;

pub fn reset(config: config::Ledger) -> Result<()> {
    // simply nuke the DB files
    let db_path = &config.db_dir();
    match std::fs::remove_dir_all(db_path) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => (),
        res => res.map_err(Error::RemoveDB)?,
    };
    // reset Tendermint state
    tendermint_node::reset(config.tendermint_dir())
        .map_err(Error::Tendermint)?;
    Ok(())
}

pub fn rollback(config: config::Ledger) -> Result<()> {
    // Rollback Tendermint state
    tracing::info!("Rollback Tendermint state");
    let tendermint_block_height =
        tendermint_node::rollback(config.tendermint_dir())
            .map_err(Error::Tendermint)?;

    // Rollback Namada state
    let db_path = config.shell.db_dir(&config.chain_id);
    let mut db = storage::PersistentDB::open(db_path, None);
    tracing::info!("Rollback Namada state");

    db.rollback(tendermint_block_height)
        .map_err(|e| Error::StorageApi(storage_api::Error::new(e)))
}

#[derive(Debug)]
#[allow(dead_code, clippy::large_enum_variant)]
pub(super) enum ShellMode {
    Validator {
        data: ValidatorData,
        broadcast_sender: UnboundedSender<Vec<u8>>,
        eth_oracle: Option<EthereumOracleChannels>,
    },
    Full,
    Seed,
}

/// A channel for pulling events from the Ethereum oracle
/// and queueing them up for inclusion in vote extensions
#[derive(Debug)]
pub(super) struct EthereumReceiver {
    channel: Receiver<EthereumEvent>,
    queue: BTreeSet<EthereumEvent>,
}

impl EthereumReceiver {
    /// Create a new [`EthereumReceiver`] from a channel connected
    /// to an Ethereum oracle
    pub fn new(channel: Receiver<EthereumEvent>) -> Self {
        Self {
            channel,
            queue: BTreeSet::new(),
        }
    }

    /// Pull messages from the channel and add to queue
    /// Since vote extensions require ordering of ethereum
    /// events, we do that here. We also de-duplicate events
    pub fn fill_queue(&mut self) {
        let mut new_events = 0;
        while let Ok(eth_event) = self.channel.try_recv() {
            if self.queue.insert(eth_event) {
                new_events += 1;
            };
        }
        if new_events > 0 {
            tracing::info!(n = new_events, "received Ethereum events");
        }
    }

    /// Get a copy of the queue
    pub fn get_events(&self) -> Vec<EthereumEvent> {
        self.queue.iter().cloned().collect()
    }

    /// Remove the given [`EthereumEvent`] from the queue, if present.
    ///
    /// **INVARIANT:** This method preserves the sorting and de-duplication
    /// of events in the queue.
    pub fn remove_event(&mut self, event: &EthereumEvent) {
        self.queue.remove(event);
    }
}

impl ShellMode {
    /// Get the validator address if ledger is in validator mode
    pub fn get_validator_address(&self) -> Option<&Address> {
        match &self {
            ShellMode::Validator { data, .. } => Some(&data.address),
            _ => None,
        }
    }

    /// Remove an Ethereum event from the internal queue
    pub fn dequeue_eth_event(&mut self, event: &EthereumEvent) {
        if let ShellMode::Validator {
            eth_oracle:
                Some(EthereumOracleChannels {
                    ethereum_receiver, ..
                }),
            ..
        } = self
        {
            ethereum_receiver.remove_event(event);
        }
    }

    /// Get the protocol keypair for this validator.
    pub fn get_protocol_key(&self) -> Option<&common::SecretKey> {
        match self {
            ShellMode::Validator {
                data:
                    ValidatorData {
                        keys:
                            ValidatorKeys {
                                protocol_keypair, ..
                            },
                        ..
                    },
                ..
            } => Some(protocol_keypair),
            _ => None,
        }
    }

    /// Get the Ethereum bridge keypair for this validator.
    #[cfg_attr(not(test), allow(dead_code))]
    pub fn get_eth_bridge_keypair(&self) -> Option<&common::SecretKey> {
        match self {
            ShellMode::Validator {
                data:
                    ValidatorData {
                        keys:
                            ValidatorKeys {
                                eth_bridge_keypair, ..
                            },
                        ..
                    },
                ..
            } => Some(eth_bridge_keypair),
            _ => None,
        }
    }

    /// If this node is a validator, broadcast a tx
    /// to the mempool using the broadcaster subprocess
    #[cfg_attr(feature = "abcipp", allow(dead_code))]
    pub fn broadcast(&self, data: Vec<u8>) {
        if let Self::Validator {
            broadcast_sender, ..
        } = self
        {
            broadcast_sender
                .send(data)
                .expect("The broadcaster should be running for a validator");
        }
    }
}

#[derive(Clone, Debug, Default)]
pub enum MempoolTxType {
    /// A transaction that has not been validated by this node before
    #[default]
    NewTransaction,
    /// A transaction that has been validated at some previous level that may
    /// need to be validated again
    RecheckTransaction,
}

#[derive(Debug)]
pub struct Shell<D = storage::PersistentDB, H = Sha256Hasher>
where
    D: DB + for<'iter> DBIter<'iter> + Sync + 'static,
    H: StorageHasher + Sync + 'static,
{
    /// The id of the current chain
    #[allow(dead_code)]
    chain_id: ChainId,
    /// The persistent storage with write log
    pub(super) wl_storage: WlStorage<D, H>,
    /// Gas meter for the current block
    gas_meter: BlockGasMeter,
    /// Byzantine validators given from ABCI++ `prepare_proposal` are stored in
    /// this field. They will be slashed when we finalize the block.
    byzantine_validators: Vec<Evidence>,
    /// Path to the base directory with DB data and configs
    #[allow(dead_code)]
    base_dir: PathBuf,
    /// Path to the WASM directory for files used in the genesis block.
    pub(super) wasm_dir: PathBuf,
    /// Information about the running shell instance
    #[allow(dead_code)]
    mode: ShellMode,
    /// VP WASM compilation cache
    pub(super) vp_wasm_cache: VpCache<WasmCacheRwAccess>,
    /// Tx WASM compilation cache
    pub(super) tx_wasm_cache: TxCache<WasmCacheRwAccess>,
    /// Taken from config `storage_read_past_height_limit`. When set, will
    /// limit the how many block heights in the past can the storage be
    /// queried for reading values.
    storage_read_past_height_limit: Option<u64>,
    /// Proposal execution tracking
    pub proposal_data: HashSet<u64>,
    /// Log of events emitted by `FinalizeBlock` ABCI calls.
    event_log: EventLog,
}

/// Channels for communicating with an Ethereum oracle.
#[derive(Debug)]
pub struct EthereumOracleChannels {
    ethereum_receiver: EthereumReceiver,
    control_sender: oracle::control::Sender,
    last_processed_block_receiver: last_processed_block::Receiver,
}

impl EthereumOracleChannels {
    pub fn new(
        events_receiver: Receiver<EthereumEvent>,
        control_sender: oracle::control::Sender,
        last_processed_block_receiver: last_processed_block::Receiver,
    ) -> Self {
        Self {
            ethereum_receiver: EthereumReceiver::new(events_receiver),
            control_sender,
            last_processed_block_receiver,
        }
    }
}

impl<D, H> Shell<D, H>
where
    D: DB + for<'iter> DBIter<'iter> + Sync + 'static,
    H: StorageHasher + Sync + 'static,
{
    /// Create a new shell from a path to a database and a chain id. Looks
    /// up the database with this data and tries to load the last state.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        config: config::Ledger,
        wasm_dir: PathBuf,
        broadcast_sender: UnboundedSender<Vec<u8>>,
        eth_oracle: Option<EthereumOracleChannels>,
        db_cache: Option<&D::Cache>,
        vp_wasm_compilation_cache: u64,
        tx_wasm_compilation_cache: u64,
        native_token: Address,
    ) -> Self {
        let chain_id = config.chain_id;
        let db_path = config.shell.db_dir(&chain_id);
        let base_dir = config.shell.base_dir;
        let mode = config.tendermint.tendermint_mode;
        let storage_read_past_height_limit =
            config.shell.storage_read_past_height_limit;
        if !Path::new(&base_dir).is_dir() {
            std::fs::create_dir(&base_dir)
                .expect("Creating directory for Namada should not fail");
        }
        // load last state from storage
        let mut storage = Storage::open(
            db_path,
            chain_id.clone(),
            native_token,
            db_cache,
            config.shell.storage_read_past_height_limit,
        );
        storage
            .load_last_state()
            .map_err(|e| {
                tracing::error!("Cannot load the last state from the DB {}", e);
            })
            .expect("PersistentStorage cannot be initialized");
        let vp_wasm_cache_dir =
            base_dir.join(chain_id.as_str()).join("vp_wasm_cache");
        let tx_wasm_cache_dir =
            base_dir.join(chain_id.as_str()).join("tx_wasm_cache");
        // load in keys and address from wallet if mode is set to `Validator`
        let mode = match mode {
            TendermintMode::Validator => {
                #[cfg(not(feature = "dev"))]
                {
                    let wallet_path = &base_dir.join(chain_id.as_str());
                    let genesis_path =
                        &base_dir.join(format!("{}.toml", chain_id.as_str()));
                    tracing::debug!(
                        "{}",
                        wallet_path.as_path().to_str().unwrap()
                    );
                    let wallet = wallet::Wallet::load_or_new_from_genesis(
                        wallet_path,
                        genesis::genesis_config::open_genesis_config(
                            genesis_path,
                        )
                        .unwrap(),
                    );
                    wallet
                        .take_validator_data()
                        .map(|data| ShellMode::Validator {
                            data,
                            broadcast_sender,
                            eth_oracle,
                        })
                        .expect(
                            "Validator data should have been stored in the \
                             wallet",
                        )
                }
                #[cfg(feature = "dev")]
                {
                    let (protocol_keypair, eth_bridge_keypair, dkg_keypair) =
                        wallet::defaults::validator_keys();
                    ShellMode::Validator {
                        data: wallet::ValidatorData {
                            address: wallet::defaults::validator_address(),
                            keys: wallet::ValidatorKeys {
                                protocol_keypair,
                                eth_bridge_keypair,
                                dkg_keypair: Some(dkg_keypair),
                            },
                        },
                        broadcast_sender,
                        eth_oracle,
                    }
                }
            }
            TendermintMode::Full => ShellMode::Full,
            TendermintMode::Seed => ShellMode::Seed,
        };

        let wl_storage = WlStorage {
            storage,
            write_log: WriteLog::default(),
        };
        let mut shell = Self {
            chain_id,
            wl_storage,
            gas_meter: BlockGasMeter::default(),
            byzantine_validators: vec![],
            base_dir,
            wasm_dir,
            mode,
            vp_wasm_cache: VpCache::new(
                vp_wasm_cache_dir,
                vp_wasm_compilation_cache as usize,
            ),
            tx_wasm_cache: TxCache::new(
                tx_wasm_cache_dir,
                tx_wasm_compilation_cache as usize,
            ),
            storage_read_past_height_limit,
            proposal_data: HashSet::new(),
            // TODO: config event log params
            event_log: EventLog::default(),
        };
        shell.update_eth_oracle();
        shell
    }

    /// Return a reference to the [`EventLog`].
    #[inline]
    pub fn event_log(&self) -> &EventLog {
        &self.event_log
    }

    /// Return a mutable reference to the [`EventLog`].
    #[inline]
    pub fn event_log_mut(&mut self) -> &mut EventLog {
        &mut self.event_log
    }

    /// Iterate over the wrapper txs in order
    #[allow(dead_code)]
    fn iter_tx_queue(&mut self) -> impl Iterator<Item = &WrapperTxInQueue> {
        self.wl_storage.storage.tx_queue.iter()
    }

    /// Load the Merkle root hash and the height of the last committed block, if
    /// any. This is returned when ABCI sends an `info` request.
    pub fn last_state(&mut self) -> response::Info {
        let mut response = response::Info::default();
        let result = self.wl_storage.storage.get_state();

        match result {
            Some((root, height)) => {
                tracing::info!(
                    "Last state root hash: {}, height: {}",
                    root,
                    height
                );
                response.last_block_app_hash = root.0.to_vec();
                response.last_block_height =
                    height.try_into().expect("Invalid block height");
            }
            None => {
                tracing::info!(
                    "No state could be found, chain is not initialized"
                );
            }
        };

        response
    }

    /// Takes the optional tendermint timestamp of the block: if it's Some than
    /// converts it to a [`DateTimeUtc`], otherwise retrieve from self the
    /// time of the last block committed
    pub fn get_block_timestamp(
        &self,
        tendermint_block_time: Option<Timestamp>,
    ) -> DateTimeUtc {
        if let Some(t) = tendermint_block_time {
            if let Ok(t) = t.try_into() {
                return t;
            }
        }
        // Default to last committed block time
        self.wl_storage
            .storage
            .get_last_block_timestamp()
            .expect("Failed to retrieve last block timestamp")
    }

    /// Read the value for a storage key dropping any error
    pub fn read_storage_key<T>(&self, key: &Key) -> Option<T>
    where
        T: Clone + BorshDeserialize,
    {
        let result = self.wl_storage.storage.read(key);

        match result {
            Ok((bytes, _gas)) => match bytes {
                Some(bytes) => match T::try_from_slice(&bytes) {
                    Ok(value) => Some(value),
                    Err(_) => None,
                },
                None => None,
            },
            Err(_) => None,
        }
    }

    /// Read the bytes for a storage key dropping any error
    pub fn read_storage_key_bytes(&self, key: &Key) -> Option<Vec<u8>> {
        let result = self.wl_storage.storage.read(key);

        match result {
            Ok((bytes, _gas)) => bytes,
            Err(_) => None,
        }
    }

    /// Apply PoS slashes from the evidence
    fn slash(&mut self) {
        if !self.byzantine_validators.is_empty() {
            let byzantine_validators =
                mem::take(&mut self.byzantine_validators);
            // TODO: resolve this unwrap() better
            let pos_params = read_pos_params(&self.wl_storage).unwrap();
            let current_epoch = self.wl_storage.storage.block.epoch;
            for evidence in byzantine_validators {
                tracing::info!("Processing evidence {evidence:?}.");
                let evidence_height = match u64::try_from(evidence.height) {
                    Ok(height) => height,
                    Err(err) => {
                        tracing::error!(
                            "Unexpected evidence block height {}",
                            err
                        );
                        continue;
                    }
                };
                let evidence_epoch = match self
                    .wl_storage
                    .storage
                    .block
                    .pred_epochs
                    .get_epoch(BlockHeight(evidence_height))
                {
                    Some(epoch) => epoch,
                    None => {
                        tracing::error!(
                            "Couldn't find epoch for evidence block height {}",
                            evidence_height
                        );
                        continue;
                    }
                };
                if evidence_epoch + pos_params.unbonding_len <= current_epoch {
                    tracing::info!(
                        "Skipping outdated evidence from epoch \
                         {evidence_epoch}"
                    );
                    continue;
                }
                let slash_type = match EvidenceType::from_i32(evidence.r#type) {
                    Some(r#type) => match r#type {
                        EvidenceType::DuplicateVote => {
                            pos::types::SlashType::DuplicateVote
                        }
                        EvidenceType::LightClientAttack => {
                            pos::types::SlashType::LightClientAttack
                        }
                        EvidenceType::Unknown => {
                            tracing::error!(
                                "Unknown evidence: {:#?}",
                                evidence
                            );
                            continue;
                        }
                    },
                    None => {
                        tracing::error!(
                            "Unexpected evidence type {}",
                            evidence.r#type
                        );
                        continue;
                    }
                };
                let validator_raw_hash = match evidence.validator {
                    Some(validator) => tm_raw_hash_to_string(validator.address),
                    None => {
                        tracing::error!(
                            "Evidence without a validator {:#?}",
                            evidence
                        );
                        continue;
                    }
                };
                let validator =
                    match proof_of_stake::find_validator_by_raw_hash(
                        &self.wl_storage,
                        &validator_raw_hash,
                    )
                    .expect("Must be able to read storage")
                    {
                        Some(validator) => validator,
                        None => {
                            tracing::error!(
                                "Cannot find validator's address from raw \
                                 hash {}",
                                validator_raw_hash
                            );
                            continue;
                        }
                    };
                tracing::info!(
                    "Slashing {} for {} in epoch {}, block height {}",
                    validator,
                    slash_type,
                    evidence_epoch,
                    evidence_height
                );
                if let Err(err) = slash(
                    &mut self.wl_storage,
                    &pos_params,
                    current_epoch,
                    evidence_epoch,
                    evidence_height,
                    slash_type,
                    &validator,
                ) {
                    tracing::error!("Error in slashing: {}", err);
                }
            }
        }
    }

    /// Commit a block. Persist the application state and return the Merkle root
    /// hash.
    pub fn commit(&mut self) -> response::Commit {
        let mut response = response::Commit::default();
        // commit block's data from write log and store the in DB
        self.wl_storage.commit_block().unwrap_or_else(|e| {
            tracing::error!(
                "Encountered a storage error while committing a block {:?}",
                e
            )
        });

        // NOTE: the oracle isn't started through governance votes, so we don't
        // check to see if we need to start it after epoch transitions

        let root = self.wl_storage.storage.merkle_root();
        tracing::info!(
            "Committed block hash: {}, height: {}",
            root,
            self.wl_storage.storage.last_height,
        );
        response.data = root.0.to_vec();

        if let ShellMode::Validator {
            eth_oracle: Some(eth_oracle),
            ..
        } = &self.mode
        {
            let last_processed_block = eth_oracle
                .last_processed_block_receiver
                .borrow()
                .as_ref()
                .cloned();
            match last_processed_block {
                Some(eth_height) => {
                    tracing::info!(
                        "Ethereum oracle's most recently processed Ethereum \
                         block is {}",
                        eth_height
                    );
                    self.wl_storage.storage.ethereum_height = Some(eth_height);
                }
                None => tracing::info!(
                    "Ethereum oracle has not yet fully processed any Ethereum \
                     blocks"
                ),
            }
        }

        #[cfg(not(feature = "abcipp"))]
        {
            use crate::node::ledger::shell::vote_extensions::iter_protocol_txs;

            if let ShellMode::Validator { .. } = &self.mode {
                let ext = self.craft_extension();

                let protocol_key = self
                    .mode
                    .get_protocol_key()
                    .expect("Validators should have protocol keys");

                let protocol_txs = iter_protocol_txs(ext).map(|protocol_tx| {
                    protocol_tx.sign(protocol_key).to_bytes()
                });

                for tx in protocol_txs {
                    self.mode.broadcast(tx);
                }
            }
        }
        response
    }

    /// If a handle to an Ethereum oracle was provided to the [`Shell`], attempt
    /// to send it an updated configuration, using an initial configuration
    /// based on Ethereum bridge parameters in blockchain storage.
    ///
    /// This method must be safe to call even before ABCI `InitChain` has been
    /// called (i.e. when storage is empty), as we may want to do this check
    /// every time the shell starts up (including the first time ever at which
    /// time storage will be empty).
    fn update_eth_oracle(&mut self) {
        if let ShellMode::Validator {
            eth_oracle: Some(EthereumOracleChannels { control_sender, .. }),
            ..
        } = &mut self.mode
        {
            // We *always* expect a value describing the status of the Ethereum
            // bridge to be present under [`eth_bridge::storage::active_key`],
            // once a chain has been initialized. We need to explicitly check if
            // this key is present here because we may be starting up the shell
            // for the first time ever, in which case the chain hasn't been
            // initialized yet.
            let has_key = self
                .wl_storage
                .has_key(&eth_bridge::storage::active_key())
                .expect(
                    "We should always be able to check whether a key exists \
                     in storage or not",
                );
            if !has_key {
                tracing::info!(
                    "Not starting oracle yet as storage has not been \
                     initialized"
                );
                return;
            }
            if !self.wl_storage.ethbridge_queries().is_bridge_active() {
                tracing::info!(
                    "Not starting oracle as the Ethereum bridge is disabled"
                );
                return;
            }
            let Some(config) = EthereumBridgeConfig::read(&self.wl_storage) else {
                tracing::info!(
                    "Not starting oracle as the Ethereum bridge config couldn't be found in storage"
                );
                return;
            };
            let start_block = self
                .wl_storage
                .storage
                .ethereum_height
                .clone()
                .unwrap_or_default();
            tracing::info!(
                ?start_block,
                "Found Ethereum height from which the Ethereum oracle should \
                 start"
            );
            let config = namada::eth_bridge::oracle::config::Config {
                min_confirmations: config.min_confirmations.into(),
                bridge_contract: config.contracts.bridge.address,
                governance_contract: config.contracts.governance.address,
                start_block,
            };
            tracing::info!(
                ?config,
                "Starting the Ethereum oracle using values from block storage"
            );
            if let Err(error) = control_sender
                .try_send(oracle::control::Command::UpdateConfig(config))
            {
                match error {
                    tokio::sync::mpsc::error::TrySendError::Full(_) => {
                        panic!(
                            "The Ethereum oracle communication channel is \
                             full!"
                        )
                    }
                    tokio::sync::mpsc::error::TrySendError::Closed(_) => {
                        panic!(
                            "The Ethereum oracle can no longer be \
                             communicated with"
                        )
                    }
                }
            }
        }
    }

    /// Validate a transaction request. On success, the transaction will
    /// included in the mempool and propagated to peers, otherwise it will be
    /// rejected.
    ///
    /// Error codes:
    ///    0: Ok
    ///    1: Invalid tx
    ///    2: Tx is invalidly signed
    ///    7: Replay attack
    ///    8: Invalid chain id in tx
    // TODO: move this to another file, since this method has become fairly
    // large at this point
    pub fn mempool_validate(
        &self,
        tx_bytes: &[u8],
        r#_type: MempoolTxType,
    ) -> response::CheckTx {
        use namada::types::transaction::protocol::ProtocolTx;
        #[cfg(not(feature = "abcipp"))]
        use namada::types::transaction::protocol::ProtocolTxType;

        let mut response = response::CheckTx::default();

        // Tx format check
        let tx = match Tx::try_from(tx_bytes).map_err(Error::TxDecoding) {
            Ok(t) => t,
            Err(msg) => {
                response.code = ErrorCodes::InvalidTx.into();
                response.log = msg.to_string();
                return response;
            }
        };

        // Tx chain id
        if tx.chain_id != self.chain_id {
            response.code = ErrorCodes::InvalidChainId.into();
            response.log = format!(
                "Tx carries a wrong chain id: expected {}, found {}",
                self.chain_id, tx.chain_id
            );
            return response;
        }

        // Tx expiration
        if let Some(exp) = tx.expiration {
            let last_block_timestamp = self.get_block_timestamp(None);

            if last_block_timestamp > exp {
                response.code = ErrorCodes::ExpiredTx.into();
                response.log = format!(
                    "Tx expired at {:#?}, last committed block time: {:#?}",
                    exp, last_block_timestamp
                );
                return response;
            }
        }

        // Tx signature check
        let tx_type = match process_tx(tx) {
            Ok(ty) => ty,
            Err(msg) => {
                response.code = ErrorCodes::InvalidSig.into();
                response.log = msg.to_string();
                return response;
            }
        };

        // Tx type check
        if let TxType::Wrapper(wrapper) = tx_type {
            // Replay protection check
            let inner_hash_key =
                replay_protection::get_tx_hash_key(&wrapper.tx_hash);
            if self
                .wl_storage
                .storage
                .has_key(&inner_hash_key)
                .expect("Error while checking inner tx hash key in storage")
                .0
            {
                response.code = ErrorCodes::ReplayTx.into();
                response.log = format!(
                    "Inner transaction hash {} already in storage, replay \
                     attempt",
                    wrapper.tx_hash
                );
                return response;
            }

            let tx =
                Tx::try_from(tx_bytes).expect("Deserialization shouldn't fail");
            let wrapper_hash = hash::Hash(tx.unsigned_hash());
            let wrapper_hash_key =
                replay_protection::get_tx_hash_key(&wrapper_hash);
            if self
                .wl_storage
                .storage
                .has_key(&wrapper_hash_key)
                .expect("Error while checking wrapper tx hash key in storage")
                .0
            {
                response.code = ErrorCodes::ReplayTx.into();
                response.log = format!(
                    "Wrapper transaction hash {} already in storage, replay \
                     attempt",
                    wrapper_hash
                );
                return response;
            }

            // Check balance for fee
            let fee_payer = if wrapper.pk != masp_tx_key().ref_to() {
                wrapper.fee_payer()
            } else {
                masp()
            };
            // check that the fee payer has sufficient balance
            let balance = self.get_balance(&wrapper.fee.token, &fee_payer);

            // In testnets with a faucet, tx is allowed to skip fees if
            // it includes a valid PoW
            #[cfg(not(feature = "mainnet"))]
            let has_valid_pow = self.has_valid_pow_solution(&wrapper);
            #[cfg(feature = "mainnet")]
            let has_valid_pow = false;

            if !has_valid_pow && self.get_wrapper_tx_fees() > balance {
                response.code = ErrorCodes::InvalidTx.into();
                response.log = String::from(
                    "The given address does not have a sufficient balance to \
                     pay fee",
                );
                return response;
            }
        } else {
            response.code = ErrorCodes::InvalidTx.into();
            response.log = "Unsupported tx type".to_string();
            return response;
        }

        response.log = "Mempool validation passed".to_string();

        response
    }

        response
    }

    /// Lookup a validator's keypair for their established account from their
    /// wallet. If the node is not validator, this function returns None
    #[allow(dead_code)]
    fn get_account_keypair(&self) -> Option<common::SecretKey> {
        let wallet_path = &self.base_dir.join(self.chain_id.as_str());
        let genesis_path = &self
            .base_dir
            .join(format!("{}.toml", self.chain_id.as_str()));
        let mut wallet = wallet::Wallet::load_or_new_from_genesis(
            wallet_path,
            genesis::genesis_config::open_genesis_config(genesis_path).unwrap(),
        );
        self.mode.get_validator_address().map(|addr| {
            let sk: common::SecretKey = self
                .wl_storage
                .read(&pk_key(addr))
                .expect(
                    "A validator should have a public key associated with \
                     it's established account",
                )
                .expect(
                    "A validator should have a public key associated with \
                     it's established account",
                );
            let pk = sk.ref_to();
            wallet.find_key_by_pk(&pk).expect(
                "A validator's established keypair should be stored in its \
                 wallet",
            )
        })
    }

    #[cfg(not(feature = "mainnet"))]
    /// Check if the tx has a valid PoW solution. Unlike
    /// `apply_pow_solution_if_valid`, this won't invalidate the solution.
    fn has_valid_pow_solution(
        &self,
        tx: &namada::types::transaction::WrapperTx,
    ) -> bool {
        if let Some(solution) = &tx.pow_solution {
            if let Some(faucet_address) =
                namada::ledger::parameters::read_faucet_account_parameter(
                    &self.wl_storage,
                )
                .expect("Must be able to read faucet account parameter")
            {
                let source = Address::from(&tx.pk);
                return solution
                    .validate(&self.wl_storage, &faucet_address, source)
                    .expect("Must be able to validate PoW solutions");
            }
        }
        false
    }

    #[cfg(not(feature = "mainnet"))]
    /// Get fixed amount of fees for wrapper tx
    fn get_wrapper_tx_fees(&self) -> token::Amount {
        let fees = namada::ledger::parameters::read_wrapper_tx_fees_parameter(
            &self.wl_storage,
        )
        .expect("Must be able to read wrapper tx fees parameter");
        fees.unwrap_or(token::Amount::whole(MIN_FEE))
    }

    #[cfg(not(feature = "mainnet"))]
    /// Check if the tx has a valid PoW solution and if so invalidate it to
    /// prevent replay.
    fn invalidate_pow_solution_if_valid(
        &mut self,
        tx: &namada::types::transaction::WrapperTx,
    ) -> bool {
        if let Some(solution) = &tx.pow_solution {
            if let Some(faucet_address) =
                namada::ledger::parameters::read_faucet_account_parameter(
                    &self.wl_storage,
                )
                .expect("Must be able to read faucet account parameter")
            {
                let source = Address::from(&tx.pk);
                return solution
                    .invalidate_if_valid(
                        &mut self.wl_storage,
                        &faucet_address,
                        &source,
                    )
                    .expect("Must be able to validate PoW solutions");
            }
        }
        false
    }
}

impl<'a, D, H> From<&'a mut Shell<D, H>>
    for ShellParams<'a, D, H, namada::vm::WasmCacheRwAccess>
where
    D: 'static + DB + for<'iter> DBIter<'iter> + Sync,
    H: 'static + StorageHasher + Sync,
{
    fn from(shell: &'a mut Shell<D, H>) -> Self {
        ShellParams::Mutating {
            block_gas_meter: &mut shell.gas_meter,
            wl_storage: &mut shell.wl_storage,
            vp_wasm_cache: &mut shell.vp_wasm_cache,
            tx_wasm_cache: &mut shell.tx_wasm_cache,
        }
    }
}

/// Helper functions and types for writing unit tests
/// for the shell
#[cfg(test)]
mod test_utils {
    use std::ops::{Deref, DerefMut};
    use std::path::PathBuf;

    use namada::ledger::storage::mockdb::MockDB;
    use namada::ledger::storage::{update_allowed_conversions, BlockStateWrite, MerkleTree, Sha256Hasher};
    use namada::ledger::storage_api::StorageWrite;
    use namada::proto::{SignedTxData, Tx};
    use namada::types::address::{self, EstablishedAddressGen};
    use namada::types::chain::ChainId;
    use namada::types::ethereum_events::Uint;
    use namada::types::hash::Hash;
    use namada::types::keccak::KeccakHash;
    use namada::types::key::*;
    use namada::types::storage::{BlockHash, BlockResults, Epoch, Header};
    use namada::types::time::DateTimeUtc;
    use namada::types::transaction::protocol::ProtocolTxType;
    use namada::types::transaction::{Fee, TxType, WrapperTx};
    use namada::types::vote_extensions::ethereum_events;
    use tempfile::tempdir;
    use tokio::sync::mpsc::{Sender, UnboundedReceiver};

    use super::*;
    use crate::config::ethereum_bridge::ledger::ORACLE_CHANNEL_BUFFER_SIZE;
    use crate::facade::tendermint_proto::abci::{
        RequestInitChain, RequestProcessProposal,
    };
    use crate::facade::tendermint_proto::google::protobuf::Timestamp;
    use crate::node::ledger::shims::abcipp_shim_types::shim::request::{
        FinalizeBlock, ProcessedTx,
    };
    use crate::node::ledger::shims::abcipp_shim_types::shim::TxBytes;
    use crate::node::ledger::storage::{PersistentDB, PersistentStorageHasher};

    #[derive(Error, Debug)]
    pub enum TestError {
        #[error("Proposal rejected with tx results: {0:?}")]
        #[allow(dead_code)]
        RejectProposal(Vec<ProcessedTx>),
    }

    /// Gets the absolute path to root directory
    pub fn top_level_directory() -> PathBuf {
        let mut current_path = std::env::current_dir()
            .expect("Current directory should exist")
            .canonicalize()
            .expect("Current directory should exist");
        while current_path.file_name().unwrap() != "apps" {
            current_path.pop();
        }
        current_path.pop();
        current_path
    }

    /// Generate a random public/private keypair
    #[inline]
    pub(super) fn gen_keypair() -> common::SecretKey {
        gen_ed25519_keypair()
    }

    /// Generate a random ed25519 public/private keypair
    pub(super) fn gen_ed25519_keypair() -> common::SecretKey {
        use rand::prelude::ThreadRng;
        use rand::thread_rng;

        let mut rng: ThreadRng = thread_rng();
        ed25519::SigScheme::generate(&mut rng).try_to_sk().unwrap()
    }

    /// Generate a random secp256k1 public/private keypair
    pub(super) fn gen_secp256k1_keypair() -> common::SecretKey {
        use rand::prelude::ThreadRng;
        use rand::thread_rng;

        let mut rng: ThreadRng = thread_rng();
        secp256k1::SigScheme::generate(&mut rng)
            .try_to_sk()
            .unwrap()
    }

    /// Invalidate a valid signature `sig`.
    pub(super) fn invalidate_signature(
        sig: common::Signature,
    ) -> common::Signature {
        match sig {
            common::Signature::Ed25519(ed25519::Signature(ref sig)) => {
                let mut sig_bytes = sig.to_bytes();
                sig_bytes[0] = sig_bytes[0].wrapping_add(1);
                common::Signature::Ed25519(ed25519::Signature(sig_bytes.into()))
            }
            common::Signature::Secp256k1(secp256k1::Signature(
                ref sig,
                ref recovery_id,
            )) => {
                let mut sig_bytes = sig.serialize();
                let recovery_id_bytes = recovery_id.serialize();
                sig_bytes[0] = sig_bytes[0].wrapping_add(1);
                let bytes: [u8; 65] =
                    [sig_bytes.as_slice(), [recovery_id_bytes].as_slice()]
                        .concat()
                        .try_into()
                        .unwrap();
                common::Signature::Secp256k1((&bytes).try_into().unwrap())
            }
        }
    }

    /// Get the default bridge pool vext bytes to be signed.
    pub fn get_bp_bytes_to_sign() -> KeccakHash {
        use namada::types::keccak::{Hasher, Keccak};

        let root = [0; 32];
        let nonce = Uint::from(0).to_bytes();

        let mut output = [0u8; 32];
        let mut hasher = Keccak::v256();
        hasher.update(&root);
        hasher.update(&nonce);
        hasher.finalize(&mut output);

        KeccakHash(output)
    }

    /// Extract an [`ethereum_events::SignedVext`], from a set of
    /// serialized [`TxBytes`].
    #[allow(dead_code)]
    pub fn extract_eth_events_vext(
        tx_bytes: TxBytes,
    ) -> ethereum_events::SignedVext {
        let got = Tx::try_from(&tx_bytes[..]).unwrap();
        let got_signed_tx =
            SignedTxData::try_from_slice(&got.data.unwrap()[..]).unwrap();
        let protocol_tx =
            TxType::try_from_slice(&got_signed_tx.data.unwrap()[..]).unwrap();
        let protocol_tx = match protocol_tx {
            TxType::Protocol(protocol_tx) => protocol_tx.tx,
            _ => panic!("Test failed"),
        };
        match protocol_tx {
            ProtocolTxType::EthEventsVext(ext) => ext,
            _ => panic!("Test failed"),
        }
    }

    /// A wrapper around the shell that implements
    /// Drop so as to clean up the files that it
    /// generates. Also allows illegal state
    /// modifications for testing purposes
    pub(super) struct TestShell {
        pub shell: Shell<MockDB, Sha256Hasher>,
    }

    impl Deref for TestShell {
        type Target = Shell<MockDB, Sha256Hasher>;

        fn deref(&self) -> &Self::Target {
            &self.shell
        }
    }

    impl DerefMut for TestShell {
        fn deref_mut(&mut self) -> &mut Self::Target {
            &mut self.shell
        }
    }

    #[derive(Clone)]
    /// Helper for testing process proposal which has very different
    /// input types depending on whether the ABCI++ feature is on or not.
    pub struct ProcessProposal {
        pub txs: Vec<Vec<u8>>,
    }

    impl TestShell {
        /// Returns a new shell with
        ///    - A broadcast receiver, which will receive any protocol txs sent
        ///      by the shell.
        ///    - A sender that can send Ethereum events into the ledger, mocking
        ///      the Ethereum fullnode process
        ///    - A receiver for control commands sent by the shell to the
        ///      Ethereum oracle
        pub fn new_at_height<H: Into<BlockHeight>>(
            height: H,
        ) -> (
            Self,
            UnboundedReceiver<Vec<u8>>,
            Sender<EthereumEvent>,
            Receiver<oracle::control::Command>,
        ) {
            let (sender, receiver) = tokio::sync::mpsc::unbounded_channel();
            let (eth_sender, eth_receiver) =
                tokio::sync::mpsc::channel(ORACLE_CHANNEL_BUFFER_SIZE);
            let (_, last_processed_block_receiver) =
                last_processed_block::channel();
            let (control_sender, control_receiver) = oracle::control::channel();
            let eth_oracle = EthereumOracleChannels::new(
                eth_receiver,
                control_sender,
                last_processed_block_receiver,
            );
            let base_dir = tempdir().unwrap().as_ref().canonicalize().unwrap();
            let vp_wasm_compilation_cache = 50 * 1024 * 1024; // 50 kiB
            let tx_wasm_compilation_cache = 50 * 1024 * 1024; // 50 kiB
            let mut shell = Shell::<MockDB, Sha256Hasher>::new(
                config::Ledger::new(
                    base_dir,
                    Default::default(),
                    TendermintMode::Validator,
                ),
                top_level_directory().join("wasm"),
                sender,
                Some(eth_oracle),
                None,
                vp_wasm_compilation_cache,
                tx_wasm_compilation_cache,
                address::nam(),
            );
            shell.wl_storage.storage.block.height = height.into();
            (Self { shell }, receiver, eth_sender, control_receiver)
        }

        /// Same as [`TestShell::new_at_height`], but returns a shell at block
        /// height 0.
        #[inline]
        #[allow(dead_code)]
        pub fn new() -> (
            Self,
            UnboundedReceiver<Vec<u8>>,
            Sender<EthereumEvent>,
            Receiver<oracle::control::Command>,
        ) {
            Self::new_at_height(BlockHeight(1))
        }

        /// Forward a InitChain request and expect a success
        pub fn init_chain(
            &mut self,
            req: RequestInitChain,
            #[cfg(feature = "dev")] num_validators: u64,
        ) {
            self.shell
                .init_chain(req, num_validators)
                .expect("Test shell failed to initialize");
        }

        /// Forward a ProcessProposal request and extract the relevant
        /// response data to return
        pub fn process_proposal(
            &mut self,
            req: ProcessProposal,
        ) -> std::result::Result<Vec<ProcessedTx>, TestError> {
            let resp = self.shell.process_proposal(RequestProcessProposal {
                txs: req.txs.clone(),
                ..Default::default()
            });
            let results = resp
                .tx_results
                .into_iter()
                .zip(req.txs.into_iter())
                .map(|(res, tx_bytes)| ProcessedTx {
                    result: res,
                    tx: tx_bytes,
                })
                .collect();
            if resp.status != 1 {
                Err(TestError::RejectProposal(results))
            } else {
                Ok(results)
            }
        }

        /// Forward a FinalizeBlock request return a vector of
        /// the events created for each transaction
        pub fn finalize_block(
            &mut self,
            req: FinalizeBlock,
        ) -> Result<Vec<Event>> {
            match self.shell.finalize_block(req) {
                Ok(resp) => Ok(resp.events),
                Err(err) => Err(err),
            }
        }

        /// Add a wrapper tx to the queue of txs to be decrypted
        /// in the current block proposal
        #[cfg(test)]
        pub fn enqueue_tx(&mut self, wrapper: WrapperTx) {
            self.shell
                .wl_storage
                .storage
                .tx_queue
                .push(WrapperTxInQueue {
                    tx: wrapper,
                    #[cfg(not(feature = "mainnet"))]
                    has_valid_pow: false,
                });
        }
    }

    /// Get the only validator's voting power.
    #[inline]
    #[cfg(not(feature = "abcipp"))]
    #[allow(dead_code)]
    pub fn get_validator_bonded_stake() -> namada::types::token::Amount {
        200_000_000_000.into()
    }

    /// Start a new test shell and initialize it. Returns the shell paired with
    /// a broadcast receiver, which will receives any protocol txs sent by the
    /// shell.
    pub(super) fn setup_at_height<H: Into<BlockHeight>>(
        height: H,
        num_validators: u64,
    ) -> (
        TestShell,
        UnboundedReceiver<Vec<u8>>,
        Sender<EthereumEvent>,
        Receiver<oracle::control::Command>,
    ) {
        let (mut test, receiver, eth_receiver, control_receiver) =
            TestShell::new_at_height(height);
        test.init_chain(RequestInitChain {
            time: Some(Timestamp {
                seconds: 0,
                nanos: 0,
            }),
            chain_id: ChainId::default().to_string(),
            ..Default::default(),
        });
        test.wl_storage.commit_block().expect("Test failed");
        (test, receiver, eth_receiver, control_receiver)
    }

    /// Same as [`setup`], but returns a shell at block height 0.
    #[inline]
    pub(super) fn setup() -> (
        TestShell,
        UnboundedReceiver<Vec<u8>>,
        Sender<EthereumEvent>,
        Receiver<oracle::control::Command>,
    ) {
        setup_at_height(BlockHeight(0))
    }

    /// This is just to be used in testing. It is not
    /// a meaningful default.
    impl Default for FinalizeBlock {
        fn default() -> Self {
            FinalizeBlock {
                hash: BlockHash([0u8; 32]),
                header: Header {
                    hash: Hash([0; 32]),
                    time: DateTimeUtc::now(),
                    next_validators_hash: Hash([0; 32]),
                },
                byzantine_validators: vec![],
                txs: vec![],
                proposer_address: vec![],
                votes: vec![],
            }
        }
    }

    /// Set the Ethereum bridge to be inactive
    pub(super) fn deactivate_bridge(shell: &mut TestShell) {
        use namada::eth_bridge::storage::active_key;
        use namada::eth_bridge::storage::eth_bridge_queries::EthBridgeStatus;
        shell
            .wl_storage
            .write_bytes(
                &active_key(),
                EthBridgeStatus::Disabled.try_to_vec().expect("Test failed"),
            )
            .expect("Test failed");
    }

    /// We test that on shell shutdown, the tx queue gets persisted in a DB, and
    /// on startup it is read successfully
    #[test]
    fn test_tx_queue_persistence() {
        let base_dir = tempdir().unwrap().as_ref().canonicalize().unwrap();
        // we have to use RocksDB for this test
        let (sender, _) = tokio::sync::mpsc::unbounded_channel();
        let (_, eth_receiver) =
            tokio::sync::mpsc::channel(ORACLE_CHANNEL_BUFFER_SIZE);
        let (control_sender, _) = oracle::control::channel();
        let (_, last_processed_block_receiver) =
            last_processed_block::channel();
        let eth_oracle = EthereumOracleChannels::new(
            eth_receiver,
            control_sender,
            last_processed_block_receiver,
        );
        let vp_wasm_compilation_cache = 50 * 1024 * 1024; // 50 kiB
        let tx_wasm_compilation_cache = 50 * 1024 * 1024; // 50 kiB
        let native_token = address::nam();
        let mut shell = Shell::<PersistentDB, PersistentStorageHasher>::new(
            config::Ledger::new(
                base_dir.clone(),
                Default::default(),
                TendermintMode::Validator,
            ),
            top_level_directory().join("wasm"),
            sender.clone(),
            Some(eth_oracle),
            None,
            vp_wasm_compilation_cache,
            tx_wasm_compilation_cache,
            native_token.clone(),
        );
        shell
            .wl_storage
            .storage
            .begin_block(BlockHash::default(), BlockHeight(1))
            .expect("begin_block failed");
        let keypair = gen_keypair();
        // enqueue a wrapper tx
        let tx = Tx::new(
            "wasm_code".as_bytes().to_owned(),
            Some("transaction data".as_bytes().to_owned()),
            shell.chain_id.clone(),
            None,
        );
        let wrapper = WrapperTx::new(
            Fee {
                amount: 0.into(),
                token: native_token,
            },
            &keypair,
            Epoch(0),
            0.into(),
            tx,
            Default::default(),
            #[cfg(not(feature = "mainnet"))]
            None,
        );
        shell.wl_storage.storage.tx_queue.push(WrapperTxInQueue {
            tx: wrapper,
            #[cfg(not(feature = "mainnet"))]
            has_valid_pow: false,
        });
        // Artificially increase the block height so that chain
        // will read the new block when restarted
        let mut pred_epochs: Epochs = Default::default();
        pred_epochs.new_epoch(BlockHeight(1), 1000);
        update_allowed_conversions(&mut shell.wl_storage)
            .expect("update conversions failed");
        shell.wl_storage.commit_block().expect("commit failed");
        let merkle_tree = MerkleTree::<Sha256Hasher>::default();
        let stores = merkle_tree.stores();
        let hash = BlockHash([0; 32]);
        let pred_epochs = Default::default();
        let address_gen = EstablishedAddressGen::new("test");
        shell
            .wl_storage
            .storage
            .db
            .write_block(BlockStateWrite {
                merkle_tree_stores: stores,
                header: None,
                hash: &hash,
                height: BlockHeight(1),
                epoch: Epoch(0),
                pred_epochs: &pred_epochs,
                next_epoch_min_start_height: BlockHeight(3),
                next_epoch_min_start_time: DateTimeUtc::now(),
                address_gen: &address_gen,
                results: &BlockResults::default(),
                tx_queue: &shell.wl_storage.storage.tx_queue,
                ethereum_height: shell
                    .wl_storage
                    .storage
                    .ethereum_height
                    .as_ref(),
            })
            .expect("Test failed");

        // Drop the shell
        std::mem::drop(shell);
        let (_, eth_receiver) =
            tokio::sync::mpsc::channel(ORACLE_CHANNEL_BUFFER_SIZE);
        let (control_sender, _) = oracle::control::channel();
        let (_, last_processed_block_receiver) =
            last_processed_block::channel();
        let eth_oracle = EthereumOracleChannels::new(
            eth_receiver,
            control_sender,
            last_processed_block_receiver,
        );
        // Reboot the shell and check that the queue was restored from DB
        let shell = Shell::<PersistentDB, PersistentStorageHasher>::new(
            config::Ledger::new(
                base_dir,
                Default::default(),
                TendermintMode::Validator,
            ),
            top_level_directory().join("wasm"),
            sender,
            Some(eth_oracle),
            None,
            vp_wasm_compilation_cache,
            tx_wasm_compilation_cache,
            address::nam(),
        );
        assert!(!shell.wl_storage.storage.tx_queue.is_empty());
    }
}

/// Test the failure cases of [`mempool_validate`]
#[cfg(test)]
mod test_mempool_validate {
    use namada::proof_of_stake::Epoch;
    use namada::proto::SignedTxData;
    use namada::types::transaction::{Fee, WrapperTx};

    use super::test_utils::TestShell;
    use super::{MempoolTxType, *};

    /// Mempool validation must reject unsigned wrappers
    #[test]
    fn test_missing_signature() {
        let (shell, _) = TestShell::new();

        let keypair = super::test_utils::gen_keypair();

        let tx = Tx::new(
            "wasm_code".as_bytes().to_owned(),
            Some("transaction data".as_bytes().to_owned()),
            shell.chain_id.clone(),
            None,
        );

        let mut wrapper = WrapperTx::new(
            Fee {
                amount: 100.into(),
                token: shell.wl_storage.storage.native_token.clone(),
            },
            &keypair,
            Epoch(0),
            0.into(),
            tx,
            Default::default(),
            #[cfg(not(feature = "mainnet"))]
            None,
        )
        .sign(&keypair, shell.chain_id.clone(), None)
        .expect("Wrapper signing failed");

        let unsigned_wrapper = if let Some(Ok(SignedTxData {
            data: Some(data),
            sig: _,
        })) = wrapper
            .data
            .take()
            .map(|data| SignedTxData::try_from_slice(&data[..]))
        {
            Tx::new(vec![], Some(data), shell.chain_id.clone(), None)
        } else {
            panic!("Test failed")
        };

        let mut result = shell.mempool_validate(
            unsigned_wrapper.to_bytes().as_ref(),
            MempoolTxType::NewTransaction,
        );
        assert_eq!(result.code, u32::from(ErrorCodes::InvalidSig));
        result = shell.mempool_validate(
            unsigned_wrapper.to_bytes().as_ref(),
            MempoolTxType::RecheckTransaction,
        );
        assert_eq!(result.code, u32::from(ErrorCodes::InvalidSig));
    }

    /// Mempool validation must reject wrappers with an invalid signature
    #[test]
    fn test_invalid_signature() {
        let (shell, _) = TestShell::new();

        let keypair = super::test_utils::gen_keypair();

        let tx = Tx::new(
            "wasm_code".as_bytes().to_owned(),
            Some("transaction data".as_bytes().to_owned()),
            shell.chain_id.clone(),
            None,
        );

        let mut wrapper = WrapperTx::new(
            Fee {
                amount: 100.into(),
                token: shell.wl_storage.storage.native_token.clone(),
            },
            &keypair,
            Epoch(0),
            0.into(),
            tx,
            Default::default(),
            #[cfg(not(feature = "mainnet"))]
            None,
        )
        .sign(&keypair, shell.chain_id.clone(), None)
        .expect("Wrapper signing failed");

        let invalid_wrapper = if let Some(Ok(SignedTxData {
            data: Some(data),
            sig,
        })) = wrapper
            .data
            .take()
            .map(|data| SignedTxData::try_from_slice(&data[..]))
        {
            let mut new_wrapper = if let TxType::Wrapper(wrapper) =
                <TxType as BorshDeserialize>::deserialize(&mut data.as_ref())
                    .expect("Test failed")
            {
                wrapper
            } else {
                panic!("Test failed")
            };

            // we mount a malleability attack to try and remove the fee
            new_wrapper.fee.amount = 0.into();
            let new_data = TxType::Wrapper(new_wrapper)
                .try_to_vec()
                .expect("Test failed");
            Tx::new(
                vec![],
                Some(
                    SignedTxData {
                        sig,
                        data: Some(new_data),
                    }
                    .try_to_vec()
                    .expect("Test failed"),
                ),
                shell.chain_id.clone(),
                None,
            )
        } else {
            panic!("Test failed");
        };

        let mut result = shell.mempool_validate(
            invalid_wrapper.to_bytes().as_ref(),
            MempoolTxType::NewTransaction,
        );
        assert_eq!(result.code, u32::from(ErrorCodes::InvalidSig));
        result = shell.mempool_validate(
            invalid_wrapper.to_bytes().as_ref(),
            MempoolTxType::RecheckTransaction,
        );
        assert_eq!(result.code, u32::from(ErrorCodes::InvalidSig));
    }

    /// Mempool validation must reject non-wrapper txs
    #[test]
    fn test_wrong_tx_type() {
        let (shell, _) = TestShell::new();

        // Test Raw TxType
        let tx = Tx::new(
            "wasm_code".as_bytes().to_owned(),
            None,
            shell.chain_id.clone(),
            None,
        );

        let result = shell.mempool_validate(
            tx.to_bytes().as_ref(),
            MempoolTxType::NewTransaction,
        );
        assert_eq!(result.code, u32::from(ErrorCodes::InvalidTx));
        assert_eq!(result.log, "Unsupported tx type")
    }

    /// Mempool validation must reject already applied wrapper and decrypted
    /// transactions
    #[test]
    fn test_replay_attack() {
        let (mut shell, _) = TestShell::new();

        let keypair = super::test_utils::gen_keypair();

        let tx = Tx::new(
            "wasm_code".as_bytes().to_owned(),
            Some("transaction data".as_bytes().to_owned()),
            shell.chain_id.clone(),
            None,
        );

        let wrapper = WrapperTx::new(
            Fee {
                amount: 100.into(),
                token: shell.wl_storage.storage.native_token.clone(),
            },
            &keypair,
            Epoch(0),
            0.into(),
            tx,
            Default::default(),
            #[cfg(not(feature = "mainnet"))]
            None,
        )
        .sign(&keypair, shell.chain_id.clone(), None)
        .expect("Wrapper signing failed");

        let tx_type = match process_tx(wrapper.clone()).expect("Test failed") {
            TxType::Wrapper(t) => t,
            _ => panic!("Test failed"),
        };

        // Write wrapper hash to storage
        let wrapper_hash = hash::Hash(wrapper.unsigned_hash());
        let wrapper_hash_key =
            replay_protection::get_tx_hash_key(&wrapper_hash);
        shell
            .wl_storage
            .storage
            .write(&wrapper_hash_key, &wrapper_hash)
            .expect("Test failed");

        // Try wrapper tx replay attack
        let result = shell.mempool_validate(
            wrapper.to_bytes().as_ref(),
            MempoolTxType::NewTransaction,
        );
        assert_eq!(result.code, u32::from(ErrorCodes::ReplayTx));
        assert_eq!(
            result.log,
            format!(
                "Wrapper transaction hash {} already in storage, replay \
                 attempt",
                wrapper_hash
            )
        );

        let result = shell.mempool_validate(
            wrapper.to_bytes().as_ref(),
            MempoolTxType::RecheckTransaction,
        );
        assert_eq!(result.code, u32::from(ErrorCodes::ReplayTx));
        assert_eq!(
            result.log,
            format!(
                "Wrapper transaction hash {} already in storage, replay \
                 attempt",
                wrapper_hash
            )
        );

        // Write inner hash in storage
        let inner_hash_key =
            replay_protection::get_tx_hash_key(&tx_type.tx_hash);
        shell
            .wl_storage
            .storage
            .write(&inner_hash_key, &tx_type.tx_hash)
            .expect("Test failed");

        // Try inner tx replay attack
        let result = shell.mempool_validate(
            wrapper.to_bytes().as_ref(),
            MempoolTxType::NewTransaction,
        );
        assert_eq!(result.code, u32::from(ErrorCodes::ReplayTx));
        assert_eq!(
            result.log,
            format!(
                "Inner transaction hash {} already in storage, replay attempt",
                tx_type.tx_hash
            )
        );

        let result = shell.mempool_validate(
            wrapper.to_bytes().as_ref(),
            MempoolTxType::RecheckTransaction,
        );
        assert_eq!(result.code, u32::from(ErrorCodes::ReplayTx));
        assert_eq!(
            result.log,
            format!(
                "Inner transaction hash {} already in storage, replay attempt",
                tx_type.tx_hash
            )
        )
    }

    /// Check that a transaction with a wrong chain id gets discarded
    #[test]
    fn test_wrong_chain_id() {
        let (shell, _) = TestShell::new();

        let keypair = super::test_utils::gen_keypair();

        let wrong_chain_id = ChainId("Wrong chain id".to_string());
        let tx = Tx::new(
            "wasm_code".as_bytes().to_owned(),
            Some("transaction data".as_bytes().to_owned()),
            wrong_chain_id.clone(),
            None,
        )
        .sign(&keypair);

        let result = shell.mempool_validate(
            tx.to_bytes().as_ref(),
            MempoolTxType::NewTransaction,
        );
        assert_eq!(result.code, u32::from(ErrorCodes::InvalidChainId));
        assert_eq!(
            result.log,
            format!(
                "Tx carries a wrong chain id: expected {}, found {}",
                shell.chain_id, wrong_chain_id
            )
        )
    }

    /// Check that an expired transaction gets rejected
    #[test]
    fn test_expired_tx() {
        let (shell, _) = TestShell::new();

        let keypair = super::test_utils::gen_keypair();

        let tx = Tx::new(
            "wasm_code".as_bytes().to_owned(),
            Some("transaction data".as_bytes().to_owned()),
            shell.chain_id.clone(),
            Some(DateTimeUtc::now()),
        )
        .sign(&keypair);

        let result = shell.mempool_validate(
            tx.to_bytes().as_ref(),
            MempoolTxType::NewTransaction,
        );
        assert_eq!(result.code, u32::from(ErrorCodes::ExpiredTx));
    }
}

#[cfg(all(test, not(feature = "abcipp")))]
mod mempool_tests {
    use borsh::BorshSerialize;
    use namada::proto::{SignableEthMessage, Signed, Tx};
    use namada::types::ethereum_events::EthereumEvent;
    use namada::types::key::RefTo;
    use namada::types::storage::{BlockHeight, Epoch};
    use namada::types::transaction::protocol::ProtocolTxType;
    use namada::types::transaction::{Fee, WrapperTx};
    use namada::types::vote_extensions::{bridge_pool_roots, ethereum_events};

    use crate::node::ledger::shell::test_utils;
    use crate::wallet;

    /// Test that we do not include protocol txs in the mempool,
    /// voting on ethereum events or signing bridge pool roots
    /// and nonces if the bridge is inactive.
    #[test]
    fn test_mempool_filter_protocol_txs_bridge_inactive() {
        let (mut shell, _, _, _) = test_utils::setup_at_height(3);
        test_utils::deactivate_bridge(&mut shell);
        let address = shell
            .mode
            .get_validator_address()
            .expect("Test failed")
            .clone();
        let protocol_key = shell.mode.get_protocol_key().expect("Test failed");
        let ethereum_event = EthereumEvent::TransfersToNamada {
            nonce: 1u64.into(),
            transfers: vec![],
            valid_transfers_map: vec![],
        };
        let eth_vext = ProtocolTxType::EthEventsVext(
            ethereum_events::Vext {
                validator_addr: address.clone(),
                block_height: shell.wl_storage.storage.last_height,
                ethereum_events: vec![ethereum_event],
            }
            .sign(protocol_key),
        )
        .sign(protocol_key)
        .to_bytes();

        let to_sign = test_utils::get_bp_bytes_to_sign();
        let hot_key = shell.mode.get_eth_bridge_keypair().expect("Test failed");
        let sig = Signed::<_, SignableEthMessage>::new(hot_key, to_sign).sig;
        let bp_vext = ProtocolTxType::BridgePoolVext(
            bridge_pool_roots::Vext {
                block_height: shell.wl_storage.storage.last_height,
                validator_addr: address,
                sig,
            }
            .sign(protocol_key),
        )
        .sign(protocol_key)
        .to_bytes();
        let txs_to_validate = [
            (eth_vext, "Incorrectly validated eth events vext"),
            (bp_vext, "Incorrectly validated bp roots vext"),
        ];
        for (tx_bytes, err_msg) in txs_to_validate {
            let rsp = shell.mempool_validate(&tx_bytes, Default::default());
            assert!(rsp.code == 1, "{err_msg}");
        }
    }

    /// Test that the mempool rejects invalid txs.
    #[test]
    fn test_mempool_rejects_invalid_tx() {
        let (shell, _recv, _, _) = test_utils::setup_at_height(3u64);
        let non_wrapper_tx = Tx::new(
            "wasm_code".as_bytes().to_owned(),
            Some("transaction_data".as_bytes().to_owned()),
        )
        .to_bytes();
        let rsp = shell.mempool_validate(&non_wrapper_tx, Default::default());
        assert_eq!(rsp.code, 1);
    }

    /// Test that if an error is encountered while trying to process a tx,
    /// it is prohibited from making its way onto the mempool.
    #[test]
    fn test_mempool_error_in_processing_tx() {
        let (shell, _recv, _, _) = test_utils::setup_at_height(3u64);
        let keypair = test_utils::gen_keypair();
        let tx = Tx::new(
            "wasm_code".as_bytes().to_owned(),
            Some("transaction_data".as_bytes().to_owned()),
        );
        // an unsigned wrapper will cause an error in processing
        let wrapper = Tx::new(
            "".as_bytes().to_owned(),
            Some(
                WrapperTx::new(
                    Fee {
                        amount: 0.into(),
                        token: shell.wl_storage.storage.native_token.clone(),
                    },
                    &keypair,
                    Epoch(0),
                    0.into(),
                    tx,
                    Default::default(),
                    #[cfg(not(feature = "mainnet"))]
                    None,
                )
                .try_to_vec()
                .expect("Test failed"),
            ),
        )
        .to_bytes();
        let rsp = shell.mempool_validate(&wrapper, Default::default());
        assert_eq!(rsp.code, 1);
    }

    /// Test if Ethereum events validation behaves as expected,
    /// considering honest validators.
    #[test]
    fn test_mempool_eth_events_vext_normal_op() {
        const LAST_HEIGHT: BlockHeight = BlockHeight(3);

        let (shell, _recv, _, _) = test_utils::setup_at_height(LAST_HEIGHT);

        let (protocol_key, _, _) = wallet::defaults::validator_keys();
        let validator_addr = wallet::defaults::validator_address();

        let ethereum_event = EthereumEvent::TransfersToNamada {
            nonce: 1u64.into(),
            transfers: vec![],
            valid_transfers_map: vec![],
        };
        let ext = {
            let ext = ethereum_events::Vext {
                validator_addr,
                block_height: LAST_HEIGHT,
                ethereum_events: vec![ethereum_event],
            }
            .sign(&protocol_key);
            assert!(ext.verify(&protocol_key.ref_to()).is_ok());
            ext
        };
        let tx = ProtocolTxType::EthEventsVext(ext)
            .sign(&protocol_key)
            .to_bytes();
        let rsp = shell.mempool_validate(&tx, Default::default());
        assert_eq!(rsp.code, 0);
    }
}
