//! The ledger shell connects the ABCI++ interface with the Namada ledger app.
//!
//! Any changes applied before [`Shell::finalize_block`] might have to be
//! reverted, so any changes applied in the methods [`Shell::prepare_proposal`]
//! and [`Shell::process_proposal`] must be also reverted
//! (unless we can simply overwrite them in the next block).
//! More info in <https://github.com/anoma/namada/issues/362>.
pub mod block_alloc;
mod finalize_block;
mod governance;
mod init_chain;
pub mod prepare_proposal;
pub mod process_proposal;
pub(super) mod queries;
mod stats;
#[cfg(any(test, feature = "testing"))]
#[allow(dead_code)]
pub mod testing;
pub mod utils;
mod vote_extensions;

use std::collections::{BTreeSet, HashSet};
use std::convert::{TryFrom, TryInto};
use std::mem;
use std::path::{Path, PathBuf};
#[allow(unused_imports)]
use std::rc::Rc;

use borsh::{BorshDeserialize, BorshSerialize};
use masp_primitives::transaction::Transaction;
use namada::core::hints;
use namada::core::ledger::eth_bridge;
use namada::ledger::eth_bridge::{EthBridgeQueries, EthereumOracleConfig};
use namada::ledger::events::log::EventLog;
use namada::ledger::events::Event;
use namada::ledger::gas::{Gas, TxGasMeter};
use namada::ledger::pos::into_tm_voting_power;
use namada::ledger::pos::namada_proof_of_stake::types::{
    ConsensusValidator, ValidatorSetUpdate,
};
use namada::ledger::protocol::{
    apply_wasm_tx, get_fee_unshielding_transaction,
    get_transfer_hash_from_storage, ShellParams,
};
use namada::ledger::storage::write_log::WriteLog;
use namada::ledger::storage::{
    DBIter, Sha256Hasher, Storage, StorageHasher, TempWlStorage, WlStorage, DB,
    EPOCH_SWITCH_BLOCKS_DELAY,
};
use namada::ledger::storage_api::{self, StorageRead};
use namada::ledger::{parameters, pos, protocol, replay_protection};
use namada::proof_of_stake::{self, process_slashes, read_pos_params, slash};
use namada::proto::{self, Section, Tx};
use namada::types::address::Address;
use namada::types::chain::ChainId;
use namada::types::ethereum_events::EthereumEvent;
use namada::types::internal::{ExpiredTx, TxInQueue};
use namada::types::key::*;
use namada::types::storage::{BlockHeight, Key, TxIndex};
use namada::types::time::DateTimeUtc;
use namada::types::transaction::protocol::EthereumTxData;
use namada::types::transaction::{
    hash_tx, verify_decrypted_correctly, AffineCurve, DecryptedTx,
    EllipticCurve, PairingEngine, TxType, WrapperTx,
};
use namada::types::{address, hash, token};
use namada::vm::wasm::{TxCache, VpCache};
use namada::vm::{WasmCacheAccess, WasmCacheRwAccess};
use num_derive::{FromPrimitive, ToPrimitive};
use num_traits::{FromPrimitive, ToPrimitive};
use thiserror::Error;
use tokio::sync::mpsc::{Receiver, UnboundedSender};

use super::ethereum_oracle::{self as oracle, last_processed_block};
use crate::config;
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
#[cfg(feature = "dev")]
use crate::wallet;
#[allow(unused_imports)]
use crate::wallet::{ValidatorData, ValidatorKeys};

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
    #[error("Transaction replay attempt: {0}")]
    ReplayAttempt(String),
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
#[derive(Debug, Copy, Clone, FromPrimitive, ToPrimitive, PartialEq, Eq)]
pub enum ErrorCodes {
    Ok = 0,
    InvalidDecryptedChainId = 1,
    ExpiredDecryptedTx = 2,
    DecryptedTxGasLimit = 3,
    WasmRuntimeError = 4,
    InvalidTx = 5,
    InvalidSig = 6,
    InvalidOrder = 7,
    ExtraTxs = 8,
    Undecryptable = 9,
    AllocationError = 10,
    ReplayTx = 11,
    InvalidChainId = 12,
    ExpiredTx = 13,
    TxGasLimit = 14,
    FeeError = 15,
    InvalidVoteExtension = 16,
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
            | WasmRuntimeError
            | DecryptedTxGasLimit => true,
            InvalidTx | InvalidSig | InvalidOrder | ExtraTxs
            | Undecryptable | AllocationError | ReplayTx | InvalidChainId
            | ExpiredTx | TxGasLimit | FeeError | InvalidVoteExtension => false,
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
    tendermint_node::reset(config.cometbft_dir()).map_err(Error::Tendermint)?;
    Ok(())
}

pub fn rollback(config: config::Ledger) -> Result<()> {
    // Rollback Tendermint state
    tracing::info!("Rollback Tendermint state");
    let tendermint_block_height =
        tendermint_node::rollback(config.cometbft_dir())
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
    pub wl_storage: WlStorage<D, H>,
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
    pub vp_wasm_cache: VpCache<WasmCacheRwAccess>,
    /// Tx WASM compilation cache
    pub tx_wasm_cache: TxCache<WasmCacheRwAccess>,
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
        let mode = config.shell.tendermint_mode;
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
                    let mut wallet = crate::wallet::load_or_new_from_genesis(
                        wallet_path,
                        genesis::genesis_config::open_genesis_config(
                            genesis_path,
                        )
                        .unwrap(),
                    );
                    wallet
                        .take_validator_data()
                        .map(|data| ShellMode::Validator {
                            data: data.clone(),
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
    fn iter_tx_queue(&mut self) -> impl Iterator<Item = &TxInQueue> {
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
    fn record_slashes_from_evidence(&mut self) {
        if !self.byzantine_validators.is_empty() {
            let byzantine_validators =
                mem::take(&mut self.byzantine_validators);
            // TODO: resolve this unwrap() better
            let pos_params = read_pos_params(&self.wl_storage).unwrap();
            let current_epoch = self.wl_storage.storage.block.epoch;
            for evidence in byzantine_validators {
                // dbg!(&evidence);
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
                // Disregard evidences that should have already been processed
                // at this time
                if evidence_epoch + pos_params.slash_processing_epoch_offset()
                    - pos_params.cubic_slashing_window_length
                    <= current_epoch
                {
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
                // Check if we're gonna switch to a new epoch after a delay
                let validator_set_update_epoch = if let Some(delay) =
                    self.wl_storage.storage.update_epoch_blocks_delay
                {
                    if delay == EPOCH_SWITCH_BLOCKS_DELAY {
                        // If we're about to update validator sets for the
                        // upcoming epoch, we can still remove the validator
                        current_epoch.next()
                    } else {
                        // If we're waiting to switch to a new epoch, it's too
                        // late to update validator sets
                        // on the next epoch, so we need to
                        // wait for the one after.
                        current_epoch.next().next()
                    }
                } else {
                    current_epoch.next()
                };
                tracing::info!(
                    "Slashing {} for {} in epoch {}, block height {} (current \
                     epoch = {}, validator set update epoch = \
                     {validator_set_update_epoch})",
                    validator,
                    slash_type,
                    evidence_epoch,
                    evidence_height,
                    current_epoch
                );
                if let Err(err) = slash(
                    &mut self.wl_storage,
                    &pos_params,
                    current_epoch,
                    evidence_epoch,
                    evidence_height,
                    slash_type,
                    &validator,
                    validator_set_update_epoch,
                ) {
                    tracing::error!("Error in slashing: {}", err);
                }
            }
        }
    }

    /// Process and apply slashes that have already been recorded for the
    /// current epoch
    fn process_slashes(&mut self) {
        let current_epoch = self.wl_storage.storage.block.epoch;
        if let Err(err) = process_slashes(&mut self.wl_storage, current_epoch) {
            tracing::error!(
                "Error while processing slashes queued for epoch {}: {}",
                current_epoch,
                err
            );
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

        let root = self.wl_storage.storage.merkle_root();
        tracing::info!(
            "Committed block hash: {}, height: {}",
            root,
            self.wl_storage.storage.get_last_block_height(),
        );
        response.data = root.0.to_vec();

        // validator specific actions
        if let ShellMode::Validator {
            eth_oracle: Some(eth_oracle),
            ..
        } = &self.mode
        {
            // update the oracle's last processed eth block
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

            // broadcast any queued txs
            self.broadcast_queued_txs();
        }

        response
    }

    /// Empties all the ledger's queues of transactions to be broadcasted
    /// via CometBFT's P2P network.
    #[inline]
    fn broadcast_queued_txs(&mut self) {
        self.broadcast_protocol_txs();
        self.broadcast_expired_txs();
    }

    /// Broadcast any pending protocol transactions.
    fn broadcast_protocol_txs(&mut self) {
        use crate::node::ledger::shell::vote_extensions::iter_protocol_txs;

        let ext = self.craft_extension();

        let protocol_key = self
            .mode
            .get_protocol_key()
            .expect("Validators should have protocol keys");

        let protocol_txs = iter_protocol_txs(ext).map(|protocol_tx| {
            protocol_tx
                .sign(protocol_key, self.chain_id.clone())
                .to_bytes()
        });

        for tx in protocol_txs {
            self.mode.broadcast(tx);
        }
    }

    /// Broadcast any expired transactions.
    fn broadcast_expired_txs(&mut self) {
        let eth_events = {
            let mut events: Vec<_> = self
                .wl_storage
                .storage
                .expired_txs_queue
                .drain()
                .map(|expired_tx| match expired_tx {
                    ExpiredTx::EthereumEvent(event) => event,
                })
                .collect();
            events.sort();
            events
        };
        if hints::likely(eth_events.is_empty()) {
            // more often than not, there won't by any expired
            // Ethereum events to retransmit
            return;
        }
        if let Some(vote_extension) = self.sign_ethereum_events(eth_events) {
            let protocol_key = self
                .mode
                .get_protocol_key()
                .expect("Validators should have protocol keys");

            let signed_tx = EthereumTxData::EthEventsVext(vote_extension)
                .sign(protocol_key, self.chain_id.clone())
                .to_bytes();

            self.mode.broadcast(signed_tx);
        }
    }

    /// Checks that neither the wrapper nor the inner transaction have already
    /// been applied. Requires a [`TempWlStorage`] to perform the check during
    /// block construction and validation
    pub fn replay_protection_checks(
        &self,
        wrapper: &Tx,
        tx_bytes: &[u8],
        temp_wl_storage: &mut TempWlStorage<D, H>,
    ) -> Result<()> {
        let inner_tx_hash =
            wrapper.clone().update_header(TxType::Raw).header_hash();
        if temp_wl_storage
            .has_replay_protection_entry(&inner_tx_hash)
            .expect("Error while checking inner tx hash key in storage")
        {
            return Err(Error::ReplayAttempt(format!(
                "Inner transaction hash {} already in storage",
                &inner_tx_hash,
            )));
        }

        // Write inner hash to tx WAL
        let inner_hash_key =
            replay_protection::get_replay_protection_last_key(&inner_tx_hash);
        temp_wl_storage
            .write_log
            .write(&inner_hash_key, vec![])
            .expect("Couldn't write inner transaction hash to write log");

        let tx =
            Tx::try_from(tx_bytes).expect("Deserialization shouldn't fail");
        let wrapper_hash = tx.header_hash();
        if temp_wl_storage
            .has_replay_protection_entry(&wrapper_hash)
            .expect("Error while checking wrapper tx hash key in storage")
        {
            return Err(Error::ReplayAttempt(format!(
                "Wrapper transaction hash {} already in storage",
                wrapper_hash
            )));
        }

        // Write wrapper hash to tx WAL
        let wrapper_hash_key =
            replay_protection::get_replay_protection_last_key(&wrapper_hash);
        temp_wl_storage
            .write_log
            .write(&wrapper_hash_key, vec![])
            .expect("Couldn't write wrapper tx hash to write log");

        Ok(())
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
            let config = EthereumOracleConfig::read(&self.wl_storage).expect(
                "The oracle config must be present in storage, since the \
                 bridge is enabled",
            );
            let start_block = self
                .wl_storage
                .storage
                .ethereum_height
                .clone()
                .unwrap_or(config.eth_start_height);
            tracing::info!(
                ?start_block,
                "Found Ethereum height from which the Ethereum oracle should \
                 start"
            );
            let config = namada::eth_bridge::oracle::config::Config {
                min_confirmations: config.min_confirmations.into(),
                bridge_contract: config.contracts.bridge.address,
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
    pub fn mempool_validate(
        &self,
        tx_bytes: &[u8],
        r#_type: MempoolTxType,
    ) -> response::CheckTx {
        #[cfg(not(feature = "abcipp"))]
        use namada::types::transaction::protocol::{
            ethereum_tx_data_variants, ProtocolTxType,
        };

        let mut response = response::CheckTx::default();

        const VALID_MSG: &str = "Mempool validation passed";
        const INVALID_MSG: &str = "Mempool validation failed";

        // Tx format check
        let tx = match Tx::try_from(tx_bytes).map_err(Error::TxDecoding) {
            Ok(t) => t,
            Err(msg) => {
                response.code = ErrorCodes::InvalidTx.into();
                response.log = format!("{INVALID_MSG}: {msg}");
                return response;
            }
        };

        let tx_chain_id = tx.header.chain_id.clone();
        let tx_expiration = tx.header.expiration;

        // Tx chain id
        if tx_chain_id != self.chain_id {
            response.code = ErrorCodes::InvalidChainId.into();
            response.log = format!(
                "{INVALID_MSG}: Tx carries a wrong chain id: expected {}, \
                 found {}",
                self.chain_id, tx_chain_id
            );
            return response;
        }

        // Tx expiration
        if let Some(exp) = tx_expiration {
            let last_block_timestamp = self.get_block_timestamp(None);

            if last_block_timestamp > exp {
                response.code = ErrorCodes::ExpiredTx.into();
                response.log = format!(
                    "{INVALID_MSG}: Tx expired at {exp:#?}, last committed \
                     block time: {last_block_timestamp:#?}",
                );
                return response;
            }
        }

        // Tx signature check
        let tx_type = match tx.validate_tx() {
            Ok(_) => tx.header(),
            Err(msg) => {
                response.code = ErrorCodes::InvalidSig.into();
                response.log = format!("{INVALID_MSG}: {msg}");
                return response;
            }
        };

        // try to parse a vote extension protocol tx from
        // the provided tx data
        macro_rules! try_vote_extension {
            ($kind:expr, $rsp:expr, $result:expr $(,)?) => {
                match $result {
                    Ok(ext) => ext,
                    Err(err) => {
                        $rsp.code = ErrorCodes::InvalidVoteExtension.into();
                        $rsp.log = format!(
                            "{INVALID_MSG}: Invalid {} vote extension: {err}",
                            $kind,
                        );
                        return $rsp;
                    }
                }
            };
        }

        match tx_type.tx_type {
            TxType::Protocol(protocol_tx) => match protocol_tx.tx {
                #[cfg(not(feature = "abcipp"))]
                ProtocolTxType::EthEventsVext => {
                    let ext = try_vote_extension!(
                        "Ethereum events",
                        response,
                        ethereum_tx_data_variants::EthEventsVext::try_from(&tx),
                    );
                    if let Err(err) = self
                        .validate_eth_events_vext_and_get_it_back(
                            ext,
                            self.wl_storage.storage.get_last_block_height(),
                        )
                    {
                        response.code = ErrorCodes::InvalidVoteExtension.into();
                        response.log = format!(
                            "{INVALID_MSG}: Invalid Ethereum events vote \
                             extension: {err}",
                        );
                    } else {
                        response.log = String::from(VALID_MSG);
                    }
                }
                #[cfg(not(feature = "abcipp"))]
                ProtocolTxType::BridgePoolVext => {
                    let ext = try_vote_extension!(
                        "Bridge pool roots",
                        response,
                        ethereum_tx_data_variants::BridgePoolVext::try_from(
                            &tx
                        ),
                    );
                    if let Err(err) = self
                        .validate_bp_roots_vext_and_get_it_back(
                            ext,
                            self.wl_storage.storage.get_last_block_height(),
                        )
                    {
                        response.code = ErrorCodes::InvalidVoteExtension.into();
                        response.log = format!(
                            "{INVALID_MSG}: Invalid Brige pool roots vote \
                             extension: {err}",
                        );
                    } else {
                        response.log = String::from(VALID_MSG);
                    }
                }
                #[cfg(not(feature = "abcipp"))]
                ProtocolTxType::ValSetUpdateVext => {
                    let ext = try_vote_extension!(
                        "validator set update",
                        response,
                        ethereum_tx_data_variants::ValSetUpdateVext::try_from(
                            &tx
                        ),
                    );
                    if let Err(err) = self
                        .validate_valset_upd_vext_and_get_it_back(
                            ext,
                            // n.b. only accept validator set updates
                            // issued at the last committed epoch
                            // (signing off on the validators of the
                            // next epoch). at the second height
                            // within an epoch, the new epoch is
                            // committed to storage, so `last_epoch`
                            // reflects the current value of the
                            // epoch.
                            self.wl_storage.storage.last_epoch,
                        )
                    {
                        response.code = ErrorCodes::InvalidVoteExtension.into();
                        response.log = format!(
                            "{INVALID_MSG}: Invalid validator set update vote \
                             extension: {err}",
                        );
                    } else {
                        response.log = String::from(VALID_MSG);
                        // validator set update votes should be decided
                        // as soon as possible
                        response.priority = i64::MAX;
                    }
                }
                _ => {
                    response.code = ErrorCodes::InvalidTx.into();
                    response.log = format!(
                        "{INVALID_MSG}: The given protocol tx cannot be added \
                         to the mempool"
                    );
                }
            },
            TxType::Wrapper(wrapper) => {
                // Tx gas limit
                let mut gas_meter = TxGasMeter::new(wrapper.gas_limit);
                if gas_meter.add_tx_size_gas(tx_bytes).is_err() {
                    response.code = ErrorCodes::TxGasLimit.into();
                    response.log = "{INVALID_MSG}: Wrapper transactions \
                                    exceeds its gas limit"
                        .to_string();
                    return response;
                }

                // Max block gas
                let block_gas_limit: Gas = Gas::from_whole_units(
                    namada::core::ledger::gas::get_max_block_gas(
                        &self.wl_storage,
                    )
                    .unwrap(),
                );
                if gas_meter.tx_gas_limit > block_gas_limit {
                    response.code = ErrorCodes::AllocationError.into();
                    response.log = "{INVALID_MSG}: Wrapper transaction \
                                    exceeds the maximum block gas limit"
                        .to_string();
                    return response;
                }

                // Replay protection check
                let mut inner_tx = tx;
                inner_tx.update_header(TxType::Raw);
                let inner_tx_hash = &inner_tx.header_hash();
                let inner_hash_key =
                    replay_protection::get_replay_protection_last_key(
                        inner_tx_hash,
                    );
                if self
                    .wl_storage
                    .storage
                    .has_key(&inner_hash_key)
                    .expect("Error while checking inner tx hash key in storage")
                    .0
                {
                    response.code = ErrorCodes::ReplayTx.into();
                    response.log = format!(
                        "{INVALID_MSG}: Inner transaction hash {} already in \
                         storage, replay attempt",
                        inner_tx_hash
                    );
                    return response;
                }

                let tx = Tx::try_from(tx_bytes)
                    .expect("Deserialization shouldn't fail");
                let wrapper_hash = hash::Hash(tx.header_hash().0);
                let wrapper_hash_key =
                    replay_protection::get_replay_protection_last_key(
                        &wrapper_hash,
                    );
                if self
                    .wl_storage
                    .storage
                    .has_key(&wrapper_hash_key)
                    .expect(
                        "Error while checking wrapper tx hash key in storage",
                    )
                    .0
                {
                    response.code = ErrorCodes::ReplayTx.into();
                    response.log = format!(
                        "{INVALID_MSG}: Wrapper transaction hash {} already \
                         in storage, replay attempt",
                        wrapper_hash
                    );
                    return response;
                }

                // Validate wrapper fees
                if let Err(e) = self.wrapper_fee_check(
                    &wrapper,
                    get_fee_unshielding_transaction(&tx, &wrapper),
                    &mut TempWlStorage::new(&self.wl_storage.storage),
                    &mut self.vp_wasm_cache.clone(),
                    &mut self.tx_wasm_cache.clone(),
                    None,
                ) {
                    response.code = ErrorCodes::FeeError.into();
                    response.log = format!("{INVALID_MSG}: {e}");
                    return response;
                }
            }
            TxType::Raw => {
                response.code = ErrorCodes::InvalidTx.into();
                response.log = format!(
                    "{INVALID_MSG}: Raw transactions cannot be accepted into \
                     the mempool"
                );
            }
            TxType::Decrypted(_) => {
                response.code = ErrorCodes::InvalidTx.into();
                response.log = format!(
                    "{INVALID_MSG}: Decrypted txs cannot be sent by clients"
                );
            }
        }

        if response.code == u32::from(ErrorCodes::Ok) {
            response.log = VALID_MSG.into();
        }
        response
    }

    /// Check that the Wrapper's signer has enough funds to pay fees. If a block
    /// proposer is provided, updates the balance of the fee payer
    #[allow(clippy::too_many_arguments)]
    pub fn wrapper_fee_check<CA>(
        &self,
        wrapper: &WrapperTx,
        masp_transaction: Option<Transaction>,
        temp_wl_storage: &mut TempWlStorage<D, H>,
        vp_wasm_cache: &mut VpCache<CA>,
        tx_wasm_cache: &mut TxCache<CA>,
        block_proposer: Option<&Address>,
    ) -> Result<()>
    where
        CA: 'static + WasmCacheAccess + Sync,
    {
        // Check that fee token is an allowed one
        let minimum_gas_price = namada::ledger::parameters::read_gas_cost(
            &self.wl_storage,
            &wrapper.fee.token,
        )
        .expect("Must be able to read gas cost parameter")
        .ok_or(Error::TxApply(protocol::Error::FeeError(format!(
            "The provided {} token is not allowed for fee payment",
            wrapper.fee.token
        ))))?;

        if wrapper.fee.amount_per_gas_unit < minimum_gas_price {
            // The fees do not match the minimum required
            return Err(Error::TxApply(protocol::Error::FeeError(format!(
                "Fee amount {:?} do not match the minimum required amount \
                 {:?} for token {}",
                wrapper.fee.amount_per_gas_unit,
                minimum_gas_price,
                wrapper.fee.token
            ))));
        }

        if let Some(transaction) = masp_transaction {
            // Validation of the commitment to this section is done when
            // checking the aggregated signature of the wrapper, no need for
            // further validation

            // Validate data and generate unshielding tx
            let transfer_code_hash =
                get_transfer_hash_from_storage(temp_wl_storage);

            let descriptions_limit = self.wl_storage.read(&parameters::storage::get_fee_unshielding_descriptions_limit_key()).expect("Error reading the storage").expect("Missing fee unshielding descriptions limit param in storage");

            let unshield = wrapper
                .check_and_generate_fee_unshielding(
                    transfer_code_hash,
                    descriptions_limit,
                    transaction,
                )
                .map_err(|e| {
                    Error::TxApply(protocol::Error::FeeUnshieldingError(e))
                })?;

            let fee_unshielding_gas_limit = temp_wl_storage
                .read(&parameters::storage::get_fee_unshielding_gas_limit_key())
                .expect("Error reading from storage")
                .expect("Missing fee unshielding gas limit in storage");

            // Runtime check
            // NOTE: A clean tx write log must be provided to this call for a
            // correct vp validation. Block write log, instead, should contain
            // any prior changes (if any). This is to simulate the
            // unshielding tx (to prevent the already written keys
            // from being passed/triggering VPs) but we cannot
            // commit the tx write log yet cause the tx could still
            // be invalid.
            temp_wl_storage.write_log.precommit_tx();

            match apply_wasm_tx(
                unshield,
                &TxIndex::default(),
                ShellParams::new(
                    &mut TxGasMeter::new(fee_unshielding_gas_limit),
                    temp_wl_storage,
                    vp_wasm_cache,
                    tx_wasm_cache,
                ),
            ) {
                Ok(result) => {
                    if !result.is_accepted() {
                        return Err(Error::TxApply(
                            protocol::Error::FeeUnshieldingError(namada::types::transaction::WrapperTxErr::InvalidUnshield(format!(
                            "Some VPs rejected fee unshielding: {:#?}",
                            result.vps_result.rejected_vps
                        ))),
                        ));
                    }
                }
                Err(e) => {
                    return Err(Error::TxApply(
                        protocol::Error::FeeUnshieldingError(namada::types::transaction::WrapperTxErr::InvalidUnshield(format!(
                        "Wasm run failed: {}",
                        e
                    ))),
                    ));
                }
            }
        }

        let result = match block_proposer {
            Some(proposer) => {
                protocol::transfer_fee(temp_wl_storage, proposer, wrapper)
            }
            None => protocol::check_fees(temp_wl_storage, wrapper),
        };

        result.map_err(Error::TxApply)
    }

    fn get_abci_validator_updates(
        &self,
        is_genesis: bool,
    ) -> storage_api::Result<Vec<namada::tendermint_proto::abci::ValidatorUpdate>>
    {
        use namada::ledger::pos::namada_proof_of_stake;

        use crate::facade::tendermint_proto::crypto::PublicKey as TendermintPublicKey;

        let (current_epoch, _gas) = self.wl_storage.storage.get_current_epoch();
        let pos_params =
            namada_proof_of_stake::read_pos_params(&self.wl_storage)
                .expect("Could not find the PoS parameters");

        let validator_set_update_fn = if is_genesis {
            namada_proof_of_stake::genesis_validator_set_tendermint
        } else {
            namada_proof_of_stake::validator_set_update_tendermint
        };

        validator_set_update_fn(
            &self.wl_storage,
            &pos_params,
            current_epoch,
            |update| {
                let (consensus_key, power) = match update {
                    ValidatorSetUpdate::Consensus(ConsensusValidator {
                        consensus_key,
                        bonded_stake,
                    }) => {
                        let power: i64 = into_tm_voting_power(
                            pos_params.tm_votes_per_token,
                            bonded_stake,
                        );
                        (consensus_key, power)
                    }
                    ValidatorSetUpdate::Deactivated(consensus_key) => {
                        // Any validators that have been dropped from the
                        // consensus set must have voting power set to 0 to
                        // remove them from the conensus set
                        let power = 0_i64;
                        (consensus_key, power)
                    }
                };
                let pub_key = TendermintPublicKey {
                    sum: Some(key_to_tendermint(&consensus_key).unwrap()),
                };
                let pub_key = Some(pub_key);
                ValidatorUpdate { pub_key, power }
            },
        )
    }
}

/// for the shell
#[cfg(test)]
mod test_utils {
    use std::ops::{Deref, DerefMut};
    use std::path::PathBuf;

    use data_encoding::HEXUPPER;
    use namada::core::ledger::storage::EPOCH_SWITCH_BLOCKS_DELAY;
    use namada::ledger::storage::mockdb::MockDB;
    use namada::ledger::storage::{
        update_allowed_conversions, LastBlock, Sha256Hasher,
    };
    use namada::ledger::storage_api::StorageWrite;
    use namada::proof_of_stake::parameters::PosParams;
    use namada::proof_of_stake::validator_consensus_key_handle;
    use namada::proto::{Code, Data};
    use namada::tendermint_proto::abci::VoteInfo;
    use namada::types::address;
    use namada::types::chain::ChainId;
    use namada::types::ethereum_events::Uint;
    use namada::types::hash::Hash;
    use namada::types::keccak::KeccakHash;
    use namada::types::key::*;
    use namada::types::storage::{BlockHash, Epoch, Header};
    use namada::types::time::DateTimeUtc;
    use namada::types::transaction::{Fee, TxType, WrapperTx};
    use tempfile::tempdir;
    use tokio::sync::mpsc::{Sender, UnboundedReceiver};

    use super::*;
    use crate::config::ethereum_bridge::ledger::ORACLE_CHANNEL_BUFFER_SIZE;
    use crate::facade::tendermint_proto::abci::{
        Misbehavior, RequestInitChain, RequestPrepareProposal,
        RequestProcessProposal,
    };
    use crate::facade::tendermint_proto::google::protobuf::Timestamp;
    use crate::node::ledger::shims::abcipp_shim_types;
    use crate::node::ledger::shims::abcipp_shim_types::shim::request::{
        FinalizeBlock, ProcessedTx,
    };
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
            num_validators: u64,
        ) {
            self.shell
                .init_chain(req, num_validators)
                .expect("Test shell failed to initialize");
        }

        /// Forward a ProcessProposal request and extract the relevant
        /// response data to return
        pub fn process_proposal(
            &self,
            req: ProcessProposal,
        ) -> std::result::Result<Vec<ProcessedTx>, TestError> {
            let resp = self.shell.process_proposal(RequestProcessProposal {
                txs: req.txs.clone(),
                proposer_address: HEXUPPER
                    .decode(
                        crate::wallet::defaults::validator_keypair()
                            .to_public()
                            .tm_raw_hash()
                            .as_bytes(),
                    )
                    .unwrap(),
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

        /// Forward a PrepareProposal request
        pub fn prepare_proposal(
            &self,
            mut req: RequestPrepareProposal,
        ) -> abcipp_shim_types::shim::response::PrepareProposal {
            req.proposer_address = HEXUPPER
                .decode(
                    crate::wallet::defaults::validator_keypair()
                        .to_public()
                        .tm_raw_hash()
                        .as_bytes(),
                )
                .unwrap();
            self.shell.prepare_proposal(req)
        }

        /// Add a wrapper tx to the queue of txs to be decrypted
        /// in the current block proposal. Takes the length of the encoded
        /// wrapper as parameter.
        #[cfg(test)]
        pub fn enqueue_tx(&mut self, tx: Tx, inner_tx_gas: Gas) {
            self.shell.wl_storage.storage.tx_queue.push(TxInQueue {
                tx,
                gas: inner_tx_gas,
            });
        }

        /// Start a counter for the next epoch in `num_blocks`.
        pub fn start_new_epoch_in(&mut self, num_blocks: u64) {
            self.wl_storage.storage.next_epoch_min_start_height =
                self.wl_storage.storage.get_last_block_height() + num_blocks;
            self.wl_storage.storage.next_epoch_min_start_time =
                DateTimeUtc::now();
        }

        /// Simultaneously call the `FinalizeBlock` and
        /// `Commit` handlers.
        pub fn finalize_and_commit(&mut self, req: Option<FinalizeBlock>) {
            let mut req = req.unwrap_or_default();
            req.header.time = DateTimeUtc::now();
            self.finalize_block(req).expect("Test failed");
            self.commit();
        }

        /// Immediately change to the next epoch.
        pub fn start_new_epoch(&mut self, req: Option<FinalizeBlock>) -> Epoch {
            self.start_new_epoch_in(1);

            let next_epoch_min_start_height =
                self.wl_storage.storage.next_epoch_min_start_height;
            if let Some(LastBlock { height, .. }) =
                self.wl_storage.storage.last_block.as_mut()
            {
                *height = next_epoch_min_start_height;
            }
            self.finalize_and_commit(req.clone());

            for _i in 0..EPOCH_SWITCH_BLOCKS_DELAY {
                self.finalize_and_commit(req.clone());
            }
            self.wl_storage.storage.get_current_epoch().0
        }
    }

    /// Get the only validator's voting power.
    #[inline]
    #[cfg(not(feature = "abcipp"))]
    #[allow(dead_code)]
    pub fn get_validator_bonded_stake() -> namada::types::token::Amount {
        200_000_000_000.into()
    }

    /// Config parameters to set up a test shell.
    pub struct SetupCfg<H> {
        /// The last comitted block height.
        pub last_height: H,
        /// The number of validators to configure
        // in `InitChain`.
        pub num_validators: u64,
    }

    impl<H: Default> Default for SetupCfg<H> {
        fn default() -> Self {
            Self {
                last_height: H::default(),
                num_validators: 1,
            }
        }
    }

    /// Start a new test shell and initialize it. Returns the shell paired with
    /// a broadcast receiver, which will receives any protocol txs sent by the
    /// shell.
    pub(super) fn setup_with_cfg<H: Into<BlockHeight>>(
        SetupCfg {
            last_height,
            num_validators,
        }: SetupCfg<H>,
    ) -> (
        TestShell,
        UnboundedReceiver<Vec<u8>>,
        Sender<EthereumEvent>,
        Receiver<oracle::control::Command>,
    ) {
        let (mut test, receiver, eth_receiver, control_receiver) =
            TestShell::new_at_height(last_height);
        test.init_chain(
            RequestInitChain {
                time: Some(Timestamp {
                    seconds: 0,
                    nanos: 0,
                }),
                chain_id: ChainId::default().to_string(),
                ..Default::default()
            },
            num_validators,
        );
        test.wl_storage.commit_block().expect("Test failed");
        (test, receiver, eth_receiver, control_receiver)
    }

    /// Same as [`setup_at_height`], but returns a shell at the given block
    /// height, with a single validator.
    #[inline]
    pub(super) fn setup_at_height<H: Into<BlockHeight>>(
        last_height: H,
    ) -> (
        TestShell,
        UnboundedReceiver<Vec<u8>>,
        Sender<EthereumEvent>,
        Receiver<oracle::control::Command>,
    ) {
        let last_height = last_height.into();
        setup_with_cfg(SetupCfg {
            last_height,
            ..Default::default()
        })
    }

    /// Same as [`setup_with_cfg`], but returns a shell at block height 0,
    /// with a single validator.
    #[inline]
    pub(super) fn setup() -> (
        TestShell,
        UnboundedReceiver<Vec<u8>>,
        Sender<EthereumEvent>,
        Receiver<oracle::control::Command>,
    ) {
        setup_with_cfg(SetupCfg::<u64>::default())
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
                proposer_address: HEXUPPER
                    .decode(
                        crate::wallet::defaults::validator_keypair()
                            .to_public()
                            .tm_raw_hash()
                            .as_bytes(),
                    )
                    .unwrap(),
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
        let mut wrapper =
            Tx::from_type(TxType::Wrapper(Box::new(WrapperTx::new(
                Fee {
                    amount_per_gas_unit: Default::default(),
                    token: native_token,
                },
                keypair.ref_to(),
                Epoch(0),
                300_000.into(),
                None,
            ))));
        wrapper.header.chain_id = shell.chain_id.clone();
        wrapper.set_code(Code::new("wasm_code".as_bytes().to_owned()));
        wrapper.set_data(Data::new("transaction data".as_bytes().to_owned()));

        shell.wl_storage.storage.tx_queue.push(TxInQueue {
            tx: wrapper,
            gas: u64::MAX.into(),
        });
        // Artificially increase the block height so that chain
        // will read the new block when restarted
        shell
            .wl_storage
            .storage
            .block
            .pred_epochs
            .new_epoch(BlockHeight(1));
        update_allowed_conversions(&mut shell.wl_storage)
            .expect("update conversions failed");
        shell.wl_storage.commit_block().expect("commit failed");

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

    pub(super) fn get_pkh_from_address<S>(
        storage: &S,
        params: &PosParams,
        address: Address,
        epoch: Epoch,
    ) -> Vec<u8>
    where
        S: StorageRead,
    {
        let ck = validator_consensus_key_handle(&address)
            .get(storage, epoch, params)
            .unwrap()
            .unwrap();
        let hash_string = tm_consensus_key_raw_hash(&ck);
        HEXUPPER.decode(hash_string.as_bytes()).unwrap()
    }

    pub(super) fn next_block_for_inflation(
        shell: &mut TestShell,
        proposer_address: Vec<u8>,
        votes: Vec<VoteInfo>,
        byzantine_validators: Option<Vec<Misbehavior>>,
    ) {
        // Let the header time be always ahead of the next epoch min start time
        let header = Header {
            time: shell
                .wl_storage
                .storage
                .next_epoch_min_start_time
                .next_second(),
            ..Default::default()
        };
        let mut req = FinalizeBlock {
            header,
            proposer_address,
            votes,
            ..Default::default()
        };
        if let Some(byz_vals) = byzantine_validators {
            req.byzantine_validators = byz_vals;
        }
        shell.finalize_block(req).unwrap();
        shell.commit();
    }
}

#[cfg(all(test, not(feature = "abcipp")))]
mod abciplus_mempool_tests {
    use namada::proto::{
        Data, Section, SignableEthMessage, Signature, Signed, Tx,
    };
    use namada::types::ethereum_events::EthereumEvent;
    use namada::types::key::RefTo;
    use namada::types::storage::BlockHeight;
    use namada::types::transaction::protocol::{
        ethereum_tx_data_variants, ProtocolTx, ProtocolTxType,
    };
    use namada::types::vote_extensions::{bridge_pool_roots, ethereum_events};

    use super::*;
    use crate::node::ledger::shell::test_utils;
    use crate::wallet;

    /// Check that broadcasting expired Ethereum events works
    /// as expected.
    #[test]
    fn test_commit_broadcasts_expired_eth_events() {
        let (mut shell, mut broadcaster_rx, _, _) =
            test_utils::setup_at_height(5);

        // push expired events to queue
        let ethereum_event_0 = EthereumEvent::TransfersToNamada {
            nonce: 0u64.into(),
            transfers: vec![],
        };
        let ethereum_event_1 = EthereumEvent::TransfersToNamada {
            nonce: 1u64.into(),
            transfers: vec![],
        };
        shell
            .wl_storage
            .storage
            .expired_txs_queue
            .push(ExpiredTx::EthereumEvent(ethereum_event_0.clone()));
        shell
            .wl_storage
            .storage
            .expired_txs_queue
            .push(ExpiredTx::EthereumEvent(ethereum_event_1.clone()));

        // broadcast them
        shell.broadcast_expired_txs();

        // attempt to receive vote extension tx aggregating
        // all expired events
        let serialized_tx = broadcaster_rx.blocking_recv().unwrap();
        let tx = Tx::try_from(&serialized_tx[..]).unwrap();

        // check data inside tx
        let vote_extension =
            ethereum_tx_data_variants::EthEventsVext::try_from(&tx).unwrap();
        assert_eq!(
            vote_extension.data.ethereum_events,
            vec![ethereum_event_0, ethereum_event_1]
        );
    }

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
            nonce: 0u64.into(),
            transfers: vec![],
        };
        let eth_vext = EthereumTxData::EthEventsVext(
            ethereum_events::Vext {
                validator_addr: address.clone(),
                block_height: shell.wl_storage.storage.get_last_block_height(),
                ethereum_events: vec![ethereum_event],
            }
            .sign(protocol_key),
        )
        .sign(protocol_key, shell.chain_id.clone())
        .to_bytes();

        let to_sign = test_utils::get_bp_bytes_to_sign();
        let hot_key = shell.mode.get_eth_bridge_keypair().expect("Test failed");
        let sig = Signed::<_, SignableEthMessage>::new(hot_key, to_sign).sig;
        let bp_vext = EthereumTxData::BridgePoolVext(
            bridge_pool_roots::Vext {
                block_height: shell.wl_storage.storage.get_last_block_height(),
                validator_addr: address,
                sig,
            }
            .sign(protocol_key),
        )
        .sign(protocol_key, shell.chain_id.clone())
        .to_bytes();
        let txs_to_validate = [
            (eth_vext, "Incorrectly validated eth events vext"),
            (bp_vext, "Incorrectly validated bp roots vext"),
        ];
        for (tx_bytes, err_msg) in txs_to_validate {
            let rsp = shell.mempool_validate(&tx_bytes, Default::default());
            assert!(
                rsp.code == u32::from(ErrorCodes::InvalidVoteExtension),
                "{err_msg}"
            );
        }
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
            nonce: 0u64.into(),
            transfers: vec![],
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
        let tx = EthereumTxData::EthEventsVext(ext)
            .sign(&protocol_key, shell.chain_id.clone())
            .to_bytes();
        let rsp = shell.mempool_validate(&tx, Default::default());
        assert_eq!(rsp.code, 0);
    }

    /// Test if Ethereum events validation fails, if the underlying
    /// protocol transaction type is different from the vote extension
    /// contained in the transaction's data field.
    #[test]
    fn test_mempool_eth_events_vext_data_mismatch() {
        const LAST_HEIGHT: BlockHeight = BlockHeight(3);

        let (shell, _recv, _, _) = test_utils::setup_at_height(LAST_HEIGHT);

        let (protocol_key, _, _) = wallet::defaults::validator_keys();
        let validator_addr = wallet::defaults::validator_address();

        let ethereum_event = EthereumEvent::TransfersToNamada {
            nonce: 0u64.into(),
            transfers: vec![],
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
        let tx = {
            let mut tx =
                Tx::from_type(TxType::Protocol(Box::new(ProtocolTx {
                    pk: protocol_key.ref_to(),
                    tx: ProtocolTxType::BridgePoolVext,
                })));
            // invalid tx type, it doesn't match the
            // tx type declared in the header
            tx.set_data(Data::new(ext.try_to_vec().expect("Test falied")));
            tx.add_section(Section::Signature(Signature::new(
                tx.sechashes(),
                [(0, protocol_key)].into_iter().collect(),
                None,
            )));
            tx
        }
        .to_bytes();
        let rsp = shell.mempool_validate(&tx, Default::default());
        assert_eq!(rsp.code, u32::from(ErrorCodes::InvalidVoteExtension));
    }
}

#[cfg(test)]
mod tests {
    use namada::proof_of_stake::Epoch;
    use namada::proto::{Code, Data, Section, Signature, Tx};
    use namada::types::transaction::{Fee, WrapperTx};

    use super::*;

    const GAS_LIMIT_MULTIPLIER: u64 = 100_000;

    /// Mempool validation must reject unsigned wrappers
    #[test]
    fn test_missing_signature() {
        let (shell, _recv, _, _) = test_utils::setup();

        let keypair = super::test_utils::gen_keypair();

        let mut unsigned_wrapper =
            Tx::from_type(TxType::Wrapper(Box::new(WrapperTx::new(
                Fee {
                    amount_per_gas_unit: token::Amount::from_uint(100, 0)
                        .expect("This can't fail"),
                    token: shell.wl_storage.storage.native_token.clone(),
                },
                keypair.ref_to(),
                Epoch(0),
                Default::default(),
                None,
            ))));
        unsigned_wrapper.header.chain_id = shell.chain_id.clone();
        unsigned_wrapper.set_code(Code::new("wasm_code".as_bytes().to_owned()));
        unsigned_wrapper
            .set_data(Data::new("transaction data".as_bytes().to_owned()));

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
        let (shell, _recv, _, _) = test_utils::setup();

        let keypair = super::test_utils::gen_keypair();

        let mut invalid_wrapper =
            Tx::from_type(TxType::Wrapper(Box::new(WrapperTx::new(
                Fee {
                    amount_per_gas_unit: token::Amount::from_uint(100, 0)
                        .expect("This can't fail"),
                    token: shell.wl_storage.storage.native_token.clone(),
                },
                keypair.ref_to(),
                Epoch(0),
                Default::default(),
                None,
            ))));
        invalid_wrapper.header.chain_id = shell.chain_id.clone();
        invalid_wrapper.set_code(Code::new("wasm_code".as_bytes().to_owned()));
        invalid_wrapper
            .set_data(Data::new("transaction data".as_bytes().to_owned()));
        invalid_wrapper.add_section(Section::Signature(Signature::new(
            invalid_wrapper.sechashes(),
            [(0, keypair)].into_iter().collect(),
            None,
        )));

        // we mount a malleability attack to try and remove the fee
        let mut new_wrapper =
            invalid_wrapper.header().wrapper().expect("Test failed");
        new_wrapper.fee.amount_per_gas_unit = Default::default();
        invalid_wrapper.update_header(TxType::Wrapper(Box::new(new_wrapper)));

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
        let (shell, _recv, _, _) = test_utils::setup();

        let mut tx = Tx::new(shell.chain_id.clone(), None);
        tx.add_code("wasm_code".as_bytes().to_owned());

        let result = shell.mempool_validate(
            tx.to_bytes().as_ref(),
            MempoolTxType::NewTransaction,
        );
        assert_eq!(result.code, u32::from(ErrorCodes::InvalidTx),);
        assert_eq!(
            result.log,
            "Mempool validation failed: Raw transactions cannot be accepted \
             into the mempool"
        )
    }

    /// Mempool validation must reject already applied wrapper and decrypted
    /// transactions
    #[test]
    fn test_replay_attack() {
        let (mut shell, _recv, _, _) = test_utils::setup();

        let keypair = super::test_utils::gen_keypair();

        let mut wrapper =
            Tx::from_type(TxType::Wrapper(Box::new(WrapperTx::new(
                Fee {
                    amount_per_gas_unit: token::Amount::from_uint(100, 0)
                        .expect("This can't fail"),
                    token: shell.wl_storage.storage.native_token.clone(),
                },
                keypair.ref_to(),
                Epoch(0),
                GAS_LIMIT_MULTIPLIER.into(),
                None,
            ))));
        wrapper.header.chain_id = shell.chain_id.clone();
        wrapper.set_code(Code::new("wasm_code".as_bytes().to_owned()));
        wrapper.set_data(Data::new("transaction data".as_bytes().to_owned()));
        wrapper.add_section(Section::Signature(Signature::new(
            wrapper.sechashes(),
            [(0, keypair)].into_iter().collect(),
            None,
        )));

        // Write wrapper hash to storage
        let wrapper_hash = wrapper.header_hash();
        let wrapper_hash_key =
            replay_protection::get_replay_protection_last_key(&wrapper_hash);
        shell
            .wl_storage
            .storage
            .write(&wrapper_hash_key, wrapper_hash)
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
                "Mempool validation failed: Wrapper transaction hash {} \
                 already in storage, replay attempt",
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
                "Mempool validation failed: Wrapper transaction hash {} \
                 already in storage, replay attempt",
                wrapper_hash
            )
        );

        let inner_tx_hash =
            wrapper.clone().update_header(TxType::Raw).header_hash();
        // Write inner hash in storage
        let inner_hash_key =
            replay_protection::get_replay_protection_last_key(&inner_tx_hash);
        shell
            .wl_storage
            .storage
            .write(&inner_hash_key, inner_tx_hash)
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
                "Mempool validation failed: Inner transaction hash {} already \
                 in storage, replay attempt",
                inner_tx_hash
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
                "Mempool validation failed: Inner transaction hash {} already \
                 in storage, replay attempt",
                inner_tx_hash
            )
        )
    }

    /// Check that a transaction with a wrong chain id gets discarded
    #[test]
    fn test_wrong_chain_id() {
        let (shell, _recv, _, _) = test_utils::setup();

        let keypair = super::test_utils::gen_keypair();

        let wrong_chain_id = ChainId("Wrong chain id".to_string());
        let mut tx = Tx::new(wrong_chain_id.clone(), None);
        tx.add_code("wasm_code".as_bytes().to_owned())
            .add_data("transaction data".as_bytes().to_owned())
            .sign_wrapper(keypair);

        let result = shell.mempool_validate(
            tx.to_bytes().as_ref(),
            MempoolTxType::NewTransaction,
        );
        assert_eq!(result.code, u32::from(ErrorCodes::InvalidChainId));
        assert_eq!(
            result.log,
            format!(
                "Mempool validation failed: Tx carries a wrong chain id: \
                 expected {}, found {}",
                shell.chain_id, wrong_chain_id
            )
        )
    }

    /// Check that an expired transaction gets rejected
    #[test]
    fn test_expired_tx() {
        let (shell, _recv, _, _) = test_utils::setup();

        let keypair = super::test_utils::gen_keypair();

        let mut tx =
            Tx::new(shell.chain_id.clone(), Some(DateTimeUtc::default()));
        tx.add_code("wasm_code".as_bytes().to_owned())
            .add_data("transaction data".as_bytes().to_owned())
            .sign_wrapper(keypair);

        let result = shell.mempool_validate(
            tx.to_bytes().as_ref(),
            MempoolTxType::NewTransaction,
        );
        assert_eq!(result.code, u32::from(ErrorCodes::ExpiredTx));
    }

    /// Check that a tx requiring more gas than the block limit gets rejected
    #[test]
    fn test_exceeding_max_block_gas_tx() {
        let (shell, _recv, _, _) = test_utils::setup();

        let block_gas_limit =
            namada::core::ledger::gas::get_max_block_gas(&shell.wl_storage)
                .unwrap();
        let keypair = super::test_utils::gen_keypair();

        let mut wrapper =
            Tx::from_type(TxType::Wrapper(Box::new(WrapperTx::new(
                Fee {
                    amount_per_gas_unit: 100.into(),
                    token: shell.wl_storage.storage.native_token.clone(),
                },
                keypair.ref_to(),
                Epoch(0),
                (block_gas_limit + 1).into(),
                None,
            ))));
        wrapper.header.chain_id = shell.chain_id.clone();
        wrapper.set_code(Code::new("wasm_code".as_bytes().to_owned()));
        wrapper.set_data(Data::new("transaction data".as_bytes().to_owned()));
        wrapper.add_section(Section::Signature(Signature::new(
            wrapper.sechashes(),
            [(0, keypair)].into_iter().collect(),
            None,
        )));

        let result = shell.mempool_validate(
            wrapper.to_bytes().as_ref(),
            MempoolTxType::NewTransaction,
        );
        assert_eq!(result.code, u32::from(ErrorCodes::AllocationError));
    }

    // Check that a tx requiring more gas than its limit gets rejected
    #[test]
    fn test_exceeding_gas_limit_tx() {
        let (shell, _recv, _, _) = test_utils::setup();
        let keypair = super::test_utils::gen_keypair();

        let mut wrapper =
            Tx::from_type(TxType::Wrapper(Box::new(WrapperTx::new(
                Fee {
                    amount_per_gas_unit: 100.into(),
                    token: shell.wl_storage.storage.native_token.clone(),
                },
                keypair.ref_to(),
                Epoch(0),
                0.into(),
                None,
            ))));
        wrapper.header.chain_id = shell.chain_id.clone();
        wrapper.set_code(Code::new("wasm_code".as_bytes().to_owned()));
        wrapper.set_data(Data::new("transaction data".as_bytes().to_owned()));
        wrapper.add_section(Section::Signature(Signature::new(
            wrapper.sechashes(),
            [(0, keypair)].into_iter().collect(),
            None,
        )));

        let result = shell.mempool_validate(
            wrapper.to_bytes().as_ref(),
            MempoolTxType::NewTransaction,
        );
        assert_eq!(result.code, u32::from(ErrorCodes::TxGasLimit));
    }

    // Check that a wrapper using a non-whitelisted token for fee payment is
    // rejected
    #[test]
    fn test_fee_non_whitelisted_token() {
        let (shell, _recv, _, _) = test_utils::setup();

        let mut wrapper =
            Tx::from_type(TxType::Wrapper(Box::new(WrapperTx::new(
                Fee {
                    amount_per_gas_unit: 100.into(),
                    token: address::btc(),
                },
                crate::wallet::defaults::albert_keypair().ref_to(),
                Epoch(0),
                GAS_LIMIT_MULTIPLIER.into(),
                None,
            ))));
        wrapper.header.chain_id = shell.chain_id.clone();
        wrapper.set_code(Code::new("wasm_code".as_bytes().to_owned()));
        wrapper.set_data(Data::new("transaction data".as_bytes().to_owned()));
        wrapper.add_section(Section::Signature(Signature::new(
            wrapper.sechashes(),
            [(0, crate::wallet::defaults::albert_keypair())]
                .into_iter()
                .collect(),
            None,
        )));

        let result = shell.mempool_validate(
            wrapper.to_bytes().as_ref(),
            MempoolTxType::NewTransaction,
        );
        assert_eq!(result.code, u32::from(ErrorCodes::FeeError));
    }

    // Check that a wrapper setting a fee amount lower than the minimum required
    // is rejected
    #[test]
    fn test_fee_wrong_minimum_amount() {
        let (shell, _recv, _, _) = test_utils::setup();

        let mut wrapper =
            Tx::from_type(TxType::Wrapper(Box::new(WrapperTx::new(
                Fee {
                    amount_per_gas_unit: 0.into(),
                    token: shell.wl_storage.storage.native_token.clone(),
                },
                crate::wallet::defaults::albert_keypair().ref_to(),
                Epoch(0),
                GAS_LIMIT_MULTIPLIER.into(),
                None,
            ))));
        wrapper.header.chain_id = shell.chain_id.clone();
        wrapper.set_code(Code::new("wasm_code".as_bytes().to_owned()));
        wrapper.set_data(Data::new("transaction data".as_bytes().to_owned()));
        wrapper.add_section(Section::Signature(Signature::new(
            wrapper.sechashes(),
            [(0, crate::wallet::defaults::albert_keypair())]
                .into_iter()
                .collect(),
            None,
        )));

        let result = shell.mempool_validate(
            wrapper.to_bytes().as_ref(),
            MempoolTxType::NewTransaction,
        );
        assert_eq!(result.code, u32::from(ErrorCodes::FeeError));
    }

    // Check that a wrapper transactions whose fees cannot be paid is rejected
    #[test]
    fn test_insufficient_balance_for_fee() {
        let (shell, _recv, _, _) = test_utils::setup();

        let mut wrapper =
            Tx::from_type(TxType::Wrapper(Box::new(WrapperTx::new(
                Fee {
                    amount_per_gas_unit: 1_000_000_000.into(),
                    token: shell.wl_storage.storage.native_token.clone(),
                },
                crate::wallet::defaults::albert_keypair().ref_to(),
                Epoch(0),
                150_000.into(),
                None,
            ))));
        wrapper.header.chain_id = shell.chain_id.clone();
        wrapper.set_code(Code::new("wasm_code".as_bytes().to_owned()));
        wrapper.set_data(Data::new("transaction data".as_bytes().to_owned()));
        wrapper.add_section(Section::Signature(Signature::new(
            wrapper.sechashes(),
            [(0, crate::wallet::defaults::albert_keypair())]
                .into_iter()
                .collect(),
            None,
        )));

        let result = shell.mempool_validate(
            wrapper.to_bytes().as_ref(),
            MempoolTxType::NewTransaction,
        );
        assert_eq!(result.code, u32::from(ErrorCodes::FeeError));
    }

    // Check that a fee overflow in the wrapper transaction is rejected
    #[test]
    fn test_wrapper_fee_overflow() {
        let (shell, _recv, _, _) = test_utils::setup();

        let mut wrapper =
            Tx::from_type(TxType::Wrapper(Box::new(WrapperTx::new(
                Fee {
                    amount_per_gas_unit: token::Amount::max(),
                    token: shell.wl_storage.storage.native_token.clone(),
                },
                crate::wallet::defaults::albert_keypair().ref_to(),
                Epoch(0),
                GAS_LIMIT_MULTIPLIER.into(),
                None,
            ))));
        wrapper.header.chain_id = shell.chain_id.clone();
        wrapper.set_code(Code::new("wasm_code".as_bytes().to_owned()));
        wrapper.set_data(Data::new("transaction data".as_bytes().to_owned()));
        wrapper.add_section(Section::Signature(Signature::new(
            wrapper.sechashes(),
            [(0, crate::wallet::defaults::albert_keypair())]
                .into_iter()
                .collect(),
            None,
        )));

        let result = shell.mempool_validate(
            wrapper.to_bytes().as_ref(),
            MempoolTxType::NewTransaction,
        );
        assert_eq!(result.code, u32::from(ErrorCodes::FeeError));
    }
}
