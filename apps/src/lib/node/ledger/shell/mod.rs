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
mod queries;
mod stats;

use std::borrow::Cow;
use std::collections::{BTreeMap, HashSet};
use std::convert::{TryFrom, TryInto};
use std::mem;
use std::path::{Path, PathBuf};
#[allow(unused_imports)]
use std::rc::Rc;

use borsh::{BorshDeserialize, BorshSerialize};
use masp_primitives::transaction::Transaction;
use namada::ledger::events::log::EventLog;
use namada::ledger::events::Event;
use namada::ledger::gas::TxGasMeter;
use namada::ledger::pos::namada_proof_of_stake::types::{
    ConsensusValidator, ValidatorSetUpdate,
};
use namada::ledger::protocol::{apply_tx, get_transfer_hash_from_storage};
use namada::ledger::storage::write_log::WriteLog;
use namada::ledger::storage::{
    DBIter, Sha256Hasher, Storage, StorageHasher, TempWlStorage, WlStorage, DB,
};
use namada::ledger::storage_api::{self, StorageRead, StorageWrite};
use namada::ledger::{ibc, parameters, pos, protocol, replay_protection};
use namada::proof_of_stake::{self, process_slashes, read_pos_params, slash};
use namada::proto::{self, Section, Tx};
use namada::types::address::Address;
use namada::types::chain::ChainId;
use namada::types::internal::TxInQueue;
use namada::types::key::*;
use namada::types::storage::{BlockHeight, Key, TxIndex};
use namada::types::time::{DateTimeUtc, TimeZone, Utc};
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
use tokio::sync::mpsc::UnboundedSender;

use crate::config;
use crate::config::{genesis, TendermintMode};
#[cfg(feature = "abcipp")]
use crate::facade::tendermint_proto::abci::response_verify_vote_extension::VerifyStatus;
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
use crate::wallet::ValidatorData;

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
#[derive(Debug, Copy, Clone, FromPrimitive, ToPrimitive, PartialEq)]
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
            | ExpiredTx | TxGasLimit | FeeError => false,
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
    },
    Full,
    Seed,
}

#[allow(dead_code)]
impl ShellMode {
    /// Get the validator address if ledger is in validator mode
    pub fn get_validator_address(&self) -> Option<&address::Address> {
        match &self {
            ShellMode::Validator { data, .. } => Some(&data.address),
            _ => None,
        }
    }
}

#[derive(Clone, Debug)]
pub enum MempoolTxType {
    /// A transaction that has not been validated by this node before
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
    wasm_dir: PathBuf,
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

impl<D, H> Shell<D, H>
where
    D: DB + for<'iter> DBIter<'iter> + Sync + 'static,
    H: StorageHasher + Sync + 'static,
{
    /// Create a new shell from a path to a database and a chain id. Looks
    /// up the database with this data and tries to load the last state.
    pub fn new(
        config: config::Ledger,
        wasm_dir: PathBuf,
        broadcast_sender: UnboundedSender<Vec<u8>>,
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
                        })
                        .expect(
                            "Validator data should have been stored in the \
                             wallet",
                        )
                }
                #[cfg(feature = "dev")]
                {
                    let validator_keys =
                        crate::wallet::defaults::validator_keys();
                    ShellMode::Validator {
                        data: crate::wallet::ValidatorData {
                            address: crate::wallet::defaults::validator_address(
                            ),
                            keys: crate::wallet::ValidatorKeys {
                                protocol_keypair: validator_keys.0,
                                dkg_keypair: Some(validator_keys.1),
                            },
                        },
                        broadcast_sender,
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
        Self {
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
        }
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
                response.last_block_app_hash = root.0;
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
                tracing::info!(
                    "Slashing {} for {} in epoch {}, block height {} (current \
                     epoch = {})",
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

    /// INVARIANT: This method must be stateless.
    #[cfg(feature = "abcipp")]
    pub fn extend_vote(
        &self,
        _req: request::ExtendVote,
    ) -> response::ExtendVote {
        Default::default()
    }

    /// INVARIANT: This method must be stateless.
    #[cfg(feature = "abcipp")]
    pub fn verify_vote_extension(
        &self,
        _req: request::VerifyVoteExtension,
    ) -> response::VerifyVoteExtension {
        response::VerifyVoteExtension {
            status: VerifyStatus::Accept as i32,
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
        response.data = root.0;
        response
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
        let inner_hash_key = replay_protection::get_tx_hash_key(&inner_tx_hash);
        if temp_wl_storage
            .has_key(&inner_hash_key)
            .expect("Error while checking inner tx hash key in storage")
        {
            return Err(Error::ReplayAttempt(format!(
                "Inner transaction hash {} already in storage",
                &inner_tx_hash,
            )));
        }

        // Write inner hash to tx WAL
        temp_wl_storage
            .write_log
            .write(&inner_hash_key, vec![])
            .expect("Couldn't write inner transaction hash to write log");

        let tx =
            Tx::try_from(tx_bytes).expect("Deserialization shouldn't fail");
        let wrapper_hash = tx.header_hash();
        let wrapper_hash_key =
            replay_protection::get_tx_hash_key(&wrapper_hash);
        if temp_wl_storage
            .has_key(&wrapper_hash_key)
            .expect("Error while checking wrapper tx hash key in storage")
        {
            return Err(Error::ReplayAttempt(format!(
                "Wrapper transaction hash {} already in storage",
                wrapper_hash
            )));
        }

        // Write wrapper hash to tx WAL
        temp_wl_storage
            .write_log
            .write(&wrapper_hash_key, vec![])
            .expect("Couldn't write wrapper tx hash to write log");

        Ok(())
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
    pub fn mempool_validate(
        &self,
        tx_bytes: &[u8],
        r#_type: MempoolTxType,
    ) -> response::CheckTx {
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

        let tx_chain_id = tx.header.chain_id.clone();
        let tx_expiration = tx.header.expiration;

        // Tx chain id
        if tx_chain_id != self.chain_id {
            response.code = ErrorCodes::InvalidChainId.into();
            response.log = format!(
                "Tx carries a wrong chain id: expected {}, found {}",
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
                    "Tx expired at {:#?}, last committed block time: {:#?}",
                    exp, last_block_timestamp
                );
                return response;
            }
        }

        // Tx signature check
        let tx_type = match tx.validate_header() {
            Ok(()) => tx.header(),
            Err(msg) => {
                response.code = ErrorCodes::InvalidSig.into();
                response.log = msg.to_string();
                return response;
            }
        };

        // Tx type check
        if let TxType::Wrapper(wrapper) = tx_type.tx_type {
            // Tx gas limit
            let mut gas_meter = TxGasMeter::new(u64::from(&wrapper.gas_limit));
            if gas_meter.add_tx_size_gas(tx_bytes).is_err() {
                response.code = ErrorCodes::TxGasLimit.into();
                response.log =
                    "Wrapper transactions exceeds its gas limit".to_string();
                return response;
            }

            // Max block gas
            let block_gas_limit: u64 = self
                .wl_storage
                .read(&parameters::storage::get_max_block_gas_key())
                .expect("Error while reading from storage")
                .expect("Missing max_block_gas parameter in storage");
            if gas_meter.tx_gas_limit > block_gas_limit {
                response.code = ErrorCodes::AllocationError.into();
                response.log = "Wrapper transaction exceeds the maximum block \
                                gas limit"
                    .to_string();
                return response;
            }

            // Replay protection check
            let mut inner_tx = tx;
            inner_tx.update_header(TxType::Raw);
            let inner_tx_hash = &inner_tx.header_hash();
            let inner_hash_key =
                replay_protection::get_tx_hash_key(inner_tx_hash);
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
                    inner_tx_hash
                );
                return response;
            }

            let tx =
                Tx::try_from(tx_bytes).expect("Deserialization shouldn't fail");
            let wrapper_hash = hash::Hash(tx.header_hash().0);
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

            let fee_unshield = wrapper
                .unshield_section_hash
                .map(|ref hash| tx.get_section(hash))
                .flatten()
                .map(|section| {
                    if let Section::MaspTx(transaction) = section {
                        Some(transaction.to_owned())
                    } else {
                        None
                    }
                })
                .flatten();
            // Validate wrapper fees
            if let Err(e) = self.wrapper_fee_check(
                &wrapper,
                fee_unshield,
                &mut TempWlStorage::new(&self.wl_storage.storage),
                None,
                &mut self.vp_wasm_cache.clone(),
                &mut self.tx_wasm_cache.clone(),
                None,
            ) {
                response.code = ErrorCodes::FeeError.into();
                response.log = e.to_string();
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

    #[allow(dead_code)]
    /// Simulate validation and application of a transaction.
    fn dry_run_tx(&self, tx_bytes: &[u8]) -> response::Query {
        let mut response = response::Query::default();
        let gas_table: BTreeMap<String, u64> = self
            .wl_storage
            .read(&parameters::storage::get_gas_table_storage_key())
            .expect("Error while reading from storage")
            .expect("Missing gas table in storage");
        let mut write_log = WriteLog::default();
        let mut cumulated_gas = 0;
        let mut vp_wasm_cache = self.vp_wasm_cache.read_only();
        let mut tx_wasm_cache = self.tx_wasm_cache.read_only();
        let mut tx = match Tx::try_from(tx_bytes) {
            Ok(tx) => tx,
            Err(err) => {
                response.code = 1;
                response.log = format!("{}", Error::TxDecoding(err));
                return response;
            }
        };
        if let Err(e) = tx.validate_header() {
            response.code = 1;
            response.log = e.to_string();
            return response;
        };

        // Wrapper dry run to allow estimating the gas cost of a transaction
        let mut tx_gas_meter = match tx.header().tx_type {
            TxType::Wrapper(ref wrapper) => {
                let mut tx_gas_meter =
                    TxGasMeter::new(wrapper.gas_limit.to_owned().into());
                if let Err(e) = protocol::apply_tx(
                    tx.clone(),
                    tx_bytes,
                    TxIndex::default(),
                    &mut tx_gas_meter,
                    &gas_table,
                    &mut write_log,
                    &self.wl_storage.storage,
                    &mut self.vp_wasm_cache.clone(),
                    &mut self.tx_wasm_cache.clone(),
                    None,
                    #[cfg(not(feature = "mainnet"))]
                    false,
                ) {
                    response.code = 1;
                    response.log = format!("{}", e);
                    return response;
                };

                write_log.commit_tx();
                cumulated_gas = tx_gas_meter.get_current_transaction_gas();

                // NOTE: the encryption key for a dry-run should always be an hardcoded, dummy one
                let privkey =
            <EllipticCurve as PairingEngine>::G2Affine::prime_subgroup_generator();

                tx.update_header(TxType::Decrypted(DecryptedTx::Decrypted {
                    // To be able to dry-run testnet faucet withdrawal, pretend
                    // that we got a valid PoW
                    #[cfg(not(feature = "mainnet"))]
                    has_valid_pow: true,
                }));
                TxGasMeter::new(
                    tx_gas_meter
                        .tx_gas_limit
                        .checked_sub(tx_gas_meter.get_current_transaction_gas())
                        .unwrap_or_default(),
                )
            }
            TxType::Protocol(_) | TxType::Decrypted(_) => {
                // If dry run only the inner tx, use the max block gas as the gas limit
                TxGasMeter::new(
                    self.wl_storage
                        .read(&parameters::storage::get_max_block_gas_key())
                        .expect("Error while reading storage key")
                        .expect("Missing parameter in storage"),
                )
            }
            TxType::Raw => {
                // Cast tx to a decrypted for execution
                tx.update_header(TxType::Decrypted(DecryptedTx::Decrypted {
                    // To be able to dry-run testnet faucet withdrawal, pretend
                    // that we got a valid PoW
                    #[cfg(not(feature = "mainnet"))]
                    has_valid_pow: true,
                }));

                // If dry run only the inner tx, use the max block gas as the gas limit
                TxGasMeter::new(
                    self.wl_storage
                        .read(&parameters::storage::get_max_block_gas_key())
                        .expect("Error while reading storage key")
                        .expect("Missing parameter in storage"),
                )
            }
        };

        match protocol::apply_tx(
            tx,
            &vec![],
            TxIndex::default(),
            &mut tx_gas_meter,
            &gas_table,
            &mut write_log,
            &self.wl_storage.storage,
            &mut vp_wasm_cache,
            &mut tx_wasm_cache,
            None,
            #[cfg(not(feature = "mainnet"))]
            false,
        )
        .map_err(Error::TxApply)
        {
            Ok(mut result) => {
                cumulated_gas += tx_gas_meter.get_current_transaction_gas();
                // Account gas for both inner and wrapper (if available)
                result.gas_used = cumulated_gas;
                response.info = format!("{}", result.to_string(),);
            }
            Err(error) => {
                response.code = 1;
                response.log = format!("{}", error);
            }
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
        let mut wallet = crate::wallet::load_or_new_from_genesis(
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
            wallet.find_key_by_pk(&pk, None).expect(
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

    /// Check that the Wrapper's signer has enough funds to pay fees. If a block proposer is provided, updates the balance of the fee payer
    #[allow(clippy::too_many_arguments)]
    pub fn wrapper_fee_check<CA>(
        &self,
        wrapper: &WrapperTx,
        masp_transaction: Option<Transaction>,
        temp_wl_storage: &mut TempWlStorage<D, H>,
        gas_table: Option<Cow<BTreeMap<String, u64>>>,
        vp_wasm_cache: &mut VpCache<CA>,
        tx_wasm_cache: &mut TxCache<CA>,
        block_proposer: Option<&Address>,
    ) -> Result<()>
    where
        CA: 'static + WasmCacheAccess + Sync,
    {
        // Check that fee token is an allowed one
        let gas_cost = namada::ledger::parameters::read_gas_cost(
            &self.wl_storage,
            &wrapper.fee.token,
        )
        .expect("Must be able to read gas cost parameter")
        .ok_or(Error::TxApply(protocol::Error::FeeError(format!(
            "The provided {} token is not allowed for fee payment",
            wrapper.fee.token
        ))))?;

        if wrapper.fee.amount_per_gas_unit < gas_cost {
            // The fees do not match the minimum required
            return Err(Error::TxApply(protocol::Error::FeeError(format!("Fee amount {} do not match the minimum required amount {} for token {}", wrapper.fee.amount_per_gas_unit, gas_cost, wrapper.fee.token))));
        }

        let balance = storage_api::token::read_balance(
            temp_wl_storage,
            &wrapper.fee.token,
            &wrapper.fee_payer(),
        )
        .expect("Token balance read in the protocol must not fail");

        if let Some(transaction) = masp_transaction {
            // Validation of the commitment to this section is done when checking the aggregated signature of the wrapper, no need for further validation

            // Validate data and generate unshielding tx
            let transfer_code_hash =
                get_transfer_hash_from_storage(temp_wl_storage);

            let descriptions_limit = self.wl_storage.read(&parameters::storage::get_fee_unshielding_descriptions_limit_key()).expect("Error reading the storage").expect("Missing fee unshielding descriptions limit param in storage");

            let unshield = wrapper
                .check_and_generate_fee_unshielding(
                    balance,
                    transfer_code_hash,
                    descriptions_limit,
                    transaction,
                )
                .map_err(|e| {
                    Error::TxApply(protocol::Error::FeeUnshieldingError(e))
                })?;

            let gas_table = gas_table.unwrap_or_else(|| {
                temp_wl_storage
                    .read(&parameters::storage::get_gas_table_storage_key())
                    .expect("Error reading from storage")
                    .expect("Missing gas table in storage")
            });

            let fee_unshielding_gas_limit = temp_wl_storage
                .read(&parameters::storage::get_fee_unshielding_gas_limit_key())
                .expect("Error reading from storage")
                .expect("Missing fee unshielding gas limit in storage");

            // Runtime check
            // NOTE: A clean tx write log must be provided to this call for a correct vp validation. Block write log, instead, should contain any prior changes (if any).
            // This is to simulate the unshielding tx (to
            // prevent the already written keys from being
            // passed/triggering VPs) but we cannot commit the tx write
            // log yet cause the tx could still be invalid. As a
            // workaround, we dump the tx write log and merge it with
            // the previous one in case of success
            let previous_tx_log = temp_wl_storage.write_log.take_tx_log();

            match apply_tx(
                unshield,
                &vec![],
                TxIndex::default(),
                &mut TxGasMeter::new(fee_unshielding_gas_limit),
                &gas_table,
                &mut temp_wl_storage.write_log,
                temp_wl_storage.storage,
                vp_wasm_cache,
                tx_wasm_cache,
                None,
                #[cfg(not(feature = "mainnet"))]
                false,
            ) {
                Ok(result) => {
                    if result.is_accepted() {
                        // Rejoin tx write logs
                        temp_wl_storage.write_log.merge_tx_log(previous_tx_log);
                    } else {
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
            Some(proposer) => protocol::transfer_fee(
                temp_wl_storage,
                proposer,
                #[cfg(not(feature = "mainnet"))]
                self.has_valid_pow_solution(&wrapper),
                &wrapper,
            ),
            None => protocol::check_fees(
                temp_wl_storage,
                #[cfg(not(feature = "mainnet"))]
                self.has_valid_pow_solution(&wrapper),
                &wrapper,
            ),
        };

        result.map_err(Error::TxApply)
    }
}

/// for the shell
#[cfg(test)]
mod test_utils {
    use crate::facade::tendermint_proto::abci::RequestPrepareProposal;
    use data_encoding::HEXUPPER;
    use std::ops::{Deref, DerefMut};
    use std::path::PathBuf;

    use namada::ledger::storage::mockdb::MockDB;
    use namada::ledger::storage::{update_allowed_conversions, Sha256Hasher};
    use namada::proto::{Code, Data};
    use namada::types::chain::ChainId;
    use namada::types::hash::Hash;
    use namada::types::key::*;
    use namada::types::storage::{BlockHash, Epoch, Epochs, Header};
    use namada::types::transaction::{Fee, WrapperTx};
    use tempfile::tempdir;
    use tokio::sync::mpsc::UnboundedReceiver;

    use super::*;
    use crate::facade::tendermint_proto::abci::{
        RequestInitChain, RequestProcessProposal,
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
    pub(super) fn gen_keypair() -> common::SecretKey {
        use rand::prelude::ThreadRng;
        use rand::thread_rng;

        let mut rng: ThreadRng = thread_rng();
        ed25519::SigScheme::generate(&mut rng).try_to_sk().unwrap()
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
        /// Returns a new shell paired with a broadcast receiver, which will
        /// receives any protocol txs sent by the shell.
        pub fn new() -> (Self, UnboundedReceiver<Vec<u8>>) {
            let (sender, receiver) = tokio::sync::mpsc::unbounded_channel();
            let base_dir = tempdir().unwrap().as_ref().canonicalize().unwrap();
            let vp_wasm_compilation_cache = 50 * 1024 * 1024; // 50 kiB
            let tx_wasm_compilation_cache = 50 * 1024 * 1024; // 50 kiB
            (
                Self {
                    shell: Shell::<MockDB, Sha256Hasher>::new(
                        config::Ledger::new(
                            base_dir,
                            Default::default(),
                            TendermintMode::Validator,
                        ),
                        top_level_directory().join("wasm"),
                        sender,
                        None,
                        vp_wasm_compilation_cache,
                        tx_wasm_compilation_cache,
                        address::nam(),
                    ),
                },
                receiver,
            )
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
        pub fn enqueue_tx(&mut self, tx: Tx, inner_tx_gas: u64) {
            self.shell.wl_storage.storage.tx_queue.push(TxInQueue {
                tx,
                gas: inner_tx_gas,
                #[cfg(not(feature = "mainnet"))]
                has_valid_pow: false,
            });
        }
    }

    /// Start a new test shell and initialize it. Returns the shell paired with
    /// a broadcast receiver, which will receives any protocol txs sent by the
    /// shell.
    pub(super) fn setup(
        num_validators: u64,
    ) -> (TestShell, UnboundedReceiver<Vec<u8>>) {
        let (mut test, receiver) = TestShell::new();
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
        test.commit();

        (test, receiver)
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

    /// We test that on shell shutdown, the tx queue gets persisted in a DB, and
    /// on startup it is read successfully
    #[test]
    fn test_tx_queue_persistence() {
        let base_dir = tempdir().unwrap().as_ref().canonicalize().unwrap();
        // we have to use RocksDB for this test
        let (sender, _) = tokio::sync::mpsc::unbounded_channel();
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
        let mut wrapper = Tx::new(TxType::Wrapper(Box::new(WrapperTx::new(
            Fee {
                amount_per_gas_unit: 0.into(),
                token: native_token,
            },
            &keypair,
            Epoch(0),
            300_000.into(),
            #[cfg(not(feature = "mainnet"))]
            None,
            None,
        ))));
        wrapper.header.chain_id = shell.chain_id.clone();
        wrapper.set_code(Code::new("wasm_code".as_bytes().to_owned()));
        wrapper.set_data(Data::new("transaction data".as_bytes().to_owned()));
        wrapper.encrypt(&Default::default());
        let gas_limit =
            u64::from(&wrapper.header().wrapper().unwrap().gas_limit)
                - wrapper.to_bytes().len() as u64;

        shell.wl_storage.storage.tx_queue.push(TxInQueue {
            tx: wrapper,
            gas: gas_limit,
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

        // Drop the shell
        std::mem::drop(shell);

        // Reboot the shell and check that the queue was restored from DB
        let shell = Shell::<PersistentDB, PersistentStorageHasher>::new(
            config::Ledger::new(
                base_dir,
                Default::default(),
                TendermintMode::Validator,
            ),
            top_level_directory().join("wasm"),
            sender,
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
    use namada::proto::{Code, Data, Section, Signature, Tx};
    use namada::types::transaction::{Fee, WrapperTx};

    use super::test_utils::TestShell;
    use super::{MempoolTxType, *};

    const GAS_LIMIT_MULTIPLIER: u64 = 300_000;

    /// Mempool validation must reject unsigned wrappers
    #[test]
    fn test_missing_signature() {
        let (shell, _) = TestShell::new();

        let keypair = super::test_utils::gen_keypair();

        let mut unsigned_wrapper =
            Tx::new(TxType::Wrapper(Box::new(WrapperTx::new(
                Fee {
                    amount_per_gas_unit: 100.into(),
                    token: shell.wl_storage.storage.native_token.clone(),
                },
                &keypair,
                Epoch(0),
                0.into(),
                #[cfg(not(feature = "mainnet"))]
                None,
                None,
            ))));
        unsigned_wrapper.header.chain_id = shell.chain_id.clone();
        unsigned_wrapper.set_code(Code::new("wasm_code".as_bytes().to_owned()));
        unsigned_wrapper
            .set_data(Data::new("transaction data".as_bytes().to_owned()));
        unsigned_wrapper.encrypt(&Default::default());

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

        let mut invalid_wrapper =
            Tx::new(TxType::Wrapper(Box::new(WrapperTx::new(
                Fee {
                    amount_per_gas_unit: 100.into(),
                    token: shell.wl_storage.storage.native_token.clone(),
                },
                &keypair,
                Epoch(0),
                0.into(),
                #[cfg(not(feature = "mainnet"))]
                None,
                None,
            ))));
        invalid_wrapper.header.chain_id = shell.chain_id.clone();
        invalid_wrapper.set_code(Code::new("wasm_code".as_bytes().to_owned()));
        invalid_wrapper
            .set_data(Data::new("transaction data".as_bytes().to_owned()));
        invalid_wrapper.add_section(Section::Signature(Signature::new(
            &invalid_wrapper.header_hash(),
            &keypair,
        )));
        invalid_wrapper.encrypt(&Default::default());

        // we mount a malleability attack to try and remove the fee
        let mut new_wrapper =
            invalid_wrapper.header().wrapper().expect("Test failed");
        new_wrapper.fee.amount_per_gas_unit = 0.into();
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
        let (shell, _) = TestShell::new();

        // Test Raw TxType
        let mut tx = Tx::new(TxType::Raw);
        tx.header.chain_id = shell.chain_id.clone();
        tx.set_code(Code::new("wasm_code".as_bytes().to_owned()));

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
        let (mut shell, _) = test_utils::setup(1);
        let keypair = super::test_utils::gen_keypair();

        let mut wrapper = Tx::new(TxType::Wrapper(Box::new(WrapperTx::new(
            Fee {
                amount_per_gas_unit: 100.into(),
                token: shell.wl_storage.storage.native_token.clone(),
            },
            &keypair,
            Epoch(0),
            GAS_LIMIT_MULTIPLIER.into(),
            #[cfg(not(feature = "mainnet"))]
            None,
            None,
        ))));
        wrapper.header.chain_id = shell.chain_id.clone();
        wrapper.set_code(Code::new("wasm_code".as_bytes().to_owned()));
        wrapper.set_data(Data::new("transaction data".as_bytes().to_owned()));
        wrapper.add_section(Section::Signature(Signature::new(
            &wrapper.header_hash(),
            &keypair,
        )));
        wrapper.encrypt(&Default::default());

        // Write wrapper hash to storage
        let wrapper_hash = wrapper.header_hash();
        let wrapper_hash_key =
            replay_protection::get_tx_hash_key(&wrapper_hash);
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

        let inner_tx_hash =
            wrapper.clone().update_header(TxType::Raw).header_hash();
        // Write inner hash in storage
        let inner_hash_key = replay_protection::get_tx_hash_key(&inner_tx_hash);
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
                "Inner transaction hash {} already in storage, replay attempt",
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
                "Inner transaction hash {} already in storage, replay attempt",
                inner_tx_hash
            )
        )
    }

    /// Check that a transaction with a wrong chain id gets discarded
    #[test]
    fn test_wrong_chain_id() {
        let (shell, _) = TestShell::new();

        let keypair = super::test_utils::gen_keypair();

        let wrong_chain_id = ChainId("Wrong chain id".to_string());
        let mut tx = Tx::new(TxType::Raw);
        tx.header.chain_id = wrong_chain_id.clone();
        tx.set_code(Code::new("wasm_code".as_bytes().to_owned()));
        tx.set_data(Data::new("transaction data".as_bytes().to_owned()));
        tx.add_section(Section::Signature(Signature::new(
            &tx.header_hash(),
            &keypair,
        )));

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

        let mut tx = Tx::new(TxType::Raw);
        tx.header.expiration = Some(DateTimeUtc::now());
        tx.header.chain_id = shell.chain_id.clone();
        tx.set_code(Code::new("wasm_code".as_bytes().to_owned()));
        tx.set_data(Data::new("transaction data".as_bytes().to_owned()));
        tx.add_section(Section::Signature(Signature::new(
            &tx.header_hash(),
            &keypair,
        )));

        let result = shell.mempool_validate(
            tx.to_bytes().as_ref(),
            MempoolTxType::NewTransaction,
        );
        assert_eq!(result.code, u32::from(ErrorCodes::ExpiredTx));
    }

    /// Check that a tx requiring more gas than the block limit gets rejected
    #[test]
    fn test_exceeding_max_block_gas_tx() {
        let (shell, _) = test_utils::setup(1);

        let block_gas_limit: u64 = shell
            .wl_storage
            .read(&parameters::storage::get_max_block_gas_key())
            .expect("Error while reading from storage")
            .expect("Missing max_block_gas parameter in storage");
        let keypair = super::test_utils::gen_keypair();

        let mut wrapper = Tx::new(TxType::Wrapper(Box::new(WrapperTx::new(
            Fee {
                amount_per_gas_unit: 100.into(),
                token: shell.wl_storage.storage.native_token.clone(),
            },
            &keypair,
            Epoch(0),
            (block_gas_limit + 1).into(),
            #[cfg(not(feature = "mainnet"))]
            None,
            None,
        ))));
        wrapper.header.chain_id = shell.chain_id.clone();
        wrapper.set_code(Code::new("wasm_code".as_bytes().to_owned()));
        wrapper.set_data(Data::new("transaction data".as_bytes().to_owned()));
        wrapper.add_section(Section::Signature(Signature::new(
            &wrapper.header_hash(),
            &keypair,
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
        let (shell, _) = test_utils::setup(1);
        let keypair = super::test_utils::gen_keypair();

        let mut wrapper = Tx::new(TxType::Wrapper(Box::new(WrapperTx::new(
            Fee {
                amount_per_gas_unit: 100.into(),
                token: shell.wl_storage.storage.native_token.clone(),
            },
            &keypair,
            Epoch(0),
            0.into(),
            #[cfg(not(feature = "mainnet"))]
            None,
            None,
        ))));
        wrapper.header.chain_id = shell.chain_id.clone();
        wrapper.set_code(Code::new("wasm_code".as_bytes().to_owned()));
        wrapper.set_data(Data::new("transaction data".as_bytes().to_owned()));
        wrapper.add_section(Section::Signature(Signature::new(
            &wrapper.header_hash(),
            &keypair,
        )));

        let result = shell.mempool_validate(
            wrapper.to_bytes().as_ref(),
            MempoolTxType::NewTransaction,
        );
        assert_eq!(result.code, u32::from(ErrorCodes::TxGasLimit));
    }

    // Check that a wrapper using a non-whitelisted token for fee payment is rejected
    #[test]
    fn test_fee_non_whitelisted_token() {
        let (shell, _) = test_utils::setup(1);

        let mut wrapper = Tx::new(TxType::Wrapper(Box::new(WrapperTx::new(
            Fee {
                amount_per_gas_unit: 100.into(),
                token: address::btc(),
            },
            &crate::wallet::defaults::albert_keypair(),
            Epoch(0),
            GAS_LIMIT_MULTIPLIER.into(),
            #[cfg(not(feature = "mainnet"))]
            None,
            None,
        ))));
        wrapper.header.chain_id = shell.chain_id.clone();
        wrapper.set_code(Code::new("wasm_code".as_bytes().to_owned()));
        wrapper.set_data(Data::new("transaction data".as_bytes().to_owned()));
        wrapper.add_section(Section::Signature(Signature::new(
            &wrapper.header_hash(),
            &crate::wallet::defaults::albert_keypair(),
        )));

        let result = shell.mempool_validate(
            wrapper.to_bytes().as_ref(),
            MempoolTxType::NewTransaction,
        );
        assert_eq!(result.code, u32::from(ErrorCodes::FeeError));
    }

    // Check that a wrapper setting a fee amount lower than the minimum required is rejected
    #[test]
    fn test_fee_wrong_minimum_amount() {
        let (shell, _) = test_utils::setup(1);

        let mut wrapper = Tx::new(TxType::Wrapper(Box::new(WrapperTx::new(
            Fee {
                amount_per_gas_unit: 0.into(),
                token: shell.wl_storage.storage.native_token.clone(),
            },
            &crate::wallet::defaults::albert_keypair(),
            Epoch(0),
            GAS_LIMIT_MULTIPLIER.into(),
            #[cfg(not(feature = "mainnet"))]
            None,
            None,
        ))));
        wrapper.header.chain_id = shell.chain_id.clone();
        wrapper.set_code(Code::new("wasm_code".as_bytes().to_owned()));
        wrapper.set_data(Data::new("transaction data".as_bytes().to_owned()));
        wrapper.add_section(Section::Signature(Signature::new(
            &wrapper.header_hash(),
            &crate::wallet::defaults::albert_keypair(),
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
        let (shell, _) = test_utils::setup(1);

        let mut wrapper = Tx::new(TxType::Wrapper(Box::new(WrapperTx::new(
            Fee {
                amount_per_gas_unit: 1_000_000.into(),
                token: shell.wl_storage.storage.native_token.clone(),
            },
            &crate::wallet::defaults::albert_keypair(),
            Epoch(0),
            GAS_LIMIT_MULTIPLIER.into(),
            #[cfg(not(feature = "mainnet"))]
            None,
            None,
        ))));
        wrapper.header.chain_id = shell.chain_id.clone();
        wrapper.set_code(Code::new("wasm_code".as_bytes().to_owned()));
        wrapper.set_data(Data::new("transaction data".as_bytes().to_owned()));
        wrapper.add_section(Section::Signature(Signature::new(
            &wrapper.header_hash(),
            &crate::wallet::defaults::albert_keypair(),
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
        let (shell, _) = test_utils::setup(1);

        let mut wrapper = Tx::new(TxType::Wrapper(Box::new(WrapperTx::new(
            Fee {
                amount_per_gas_unit: token::Amount::max(),
                token: shell.wl_storage.storage.native_token.clone(),
            },
            &crate::wallet::defaults::albert_keypair(),
            Epoch(0),
            GAS_LIMIT_MULTIPLIER.into(),
            #[cfg(not(feature = "mainnet"))]
            None,
            None,
        ))));
        wrapper.header.chain_id = shell.chain_id.clone();
        wrapper.set_code(Code::new("wasm_code".as_bytes().to_owned()));
        wrapper.set_data(Data::new("transaction data".as_bytes().to_owned()));
        wrapper.add_section(Section::Signature(Signature::new(
            &wrapper.header_hash(),
            &crate::wallet::defaults::albert_keypair(),
        )));

        let result = shell.mempool_validate(
            wrapper.to_bytes().as_ref(),
            MempoolTxType::NewTransaction,
        );
        assert_eq!(result.code, u32::from(ErrorCodes::FeeError));
    }
}
