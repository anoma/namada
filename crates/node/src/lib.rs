//! Library code for a Namada node.

#![doc(html_favicon_url = "https://dev.namada.net/master/favicon.png")]
#![doc(html_logo_url = "https://dev.namada.net/master/rustdoc-logo.png")]
#![deny(rustdoc::broken_intra_doc_links)]
#![deny(rustdoc::private_intra_doc_links)]
#![warn(
    rust_2018_idioms,
    clippy::cast_sign_loss,
    clippy::cast_possible_truncation,
    clippy::cast_possible_wrap,
    clippy::cast_lossless,
    clippy::arithmetic_side_effects
)]

mod abortable;
#[cfg(feature = "benches")]
pub mod bench_utils;
mod broadcaster;
mod dry_run_tx;
pub mod ethereum_oracle;
pub mod protocol;
pub mod shell;
pub mod shims;
pub mod storage;
pub mod tendermint_node;
pub mod utils;

use std::convert::TryInto;
use std::net::SocketAddr;
use std::path::PathBuf;

use byte_unit::{Byte, UnitType};
use data_encoding::HEXUPPER;
pub use dry_run_tx::dry_run_tx;
use futures::future::TryFutureExt;
use namada_apps_lib::cli::args;
use namada_apps_lib::config::utils::{
    convert_tm_addr_to_socket_addr, num_of_threads,
};
use namada_apps_lib::{config, wasm_loader};
pub use namada_apps_lib::{
    tendermint, tendermint_config, tendermint_proto, tendermint_rpc,
};
use namada_sdk::chain::BlockHeight;
use namada_sdk::eth_bridge::ethers::providers::{Http, Provider};
use namada_sdk::migrations::ScheduledMigration;
use namada_sdk::state::{ProcessProposalCachedResult, StateRead, DB};
use namada_sdk::storage::DbColFam;
use namada_sdk::tendermint::abci::request::CheckTxKind;
use namada_sdk::tendermint::abci::response::ProcessProposal;
use namada_sdk::time::DateTimeUtc;
use once_cell::unsync::Lazy;
use sysinfo::{MemoryRefreshKind, RefreshKind, System};
use tokio::sync::mpsc;

use self::abortable::AbortableSpawner;
use self::ethereum_oracle::last_processed_block;
use self::shell::EthereumOracleChannels;
use self::shims::abcipp_shim::AbciService;
use crate::broadcaster::Broadcaster;
use crate::config::{ethereum_bridge, TendermintMode};
use crate::ethereum_oracle as oracle;
use crate::shell::{Error, MempoolTxType, Shell};
use crate::shims::abcipp_shim::AbcippShim;
use crate::shims::abcipp_shim_types::shim::{Request, Response};
use crate::tendermint::abci::response;
use crate::tower_abci::{split, Server};
pub mod tower_abci {
    pub use tower_abci::v037::*;
    pub use tower_abci::BoxError;
}

/// Env. var to set a number of Tokio RT worker threads
const ENV_VAR_TOKIO_THREADS: &str = "NAMADA_TOKIO_THREADS";

/// Env. var to set a number of Rayon global worker threads
const ENV_VAR_RAYON_THREADS: &str = "NAMADA_RAYON_THREADS";

// Until ABCI++ is ready, the shim provides the service implementation.
// We will add this part back in once the shim is no longer needed.
//```
// impl Service<Request> for Shell {
//     type Error = Error;
//     type Future =
//         Pin<Box<dyn Future<Output = Result<Response, BoxError>> + Send +
// 'static>>;    type Response = Response;
//
//     fn poll_ready(
//         &mut self,
//         _cx: &mut Context<'_>,
//     ) -> Poll<Result<(), Self::Error>> {
//         Poll::Ready(Ok(()))
//     }
//```
impl Shell {
    fn call(&mut self, req: Request) -> Result<Response, Error> {
        match req {
            Request::InitChain(init) => {
                tracing::debug!("Request InitChain");
                self.init_chain(
                    init,
                    #[cfg(any(
                        test,
                        feature = "testing",
                        feature = "benches"
                    ))]
                    1,
                )
                .map(Response::InitChain)
            }
            Request::Info(_) => Ok(Response::Info(self.last_state())),
            Request::Query(query) => Ok(Response::Query(self.query(query))),
            Request::PrepareProposal(block) => {
                tracing::debug!("Request PrepareProposal");
                // TODO: use TM domain type in the handler
                Ok(Response::PrepareProposal(
                    self.prepare_proposal(block.into()),
                ))
            }
            Request::VerifyHeader(_req) => {
                Ok(Response::VerifyHeader(self.verify_header(_req)))
            }
            Request::ProcessProposal(block) => {
                tracing::debug!("Request ProcessProposal");
                // TODO: use TM domain type in the handler
                // NOTE: make sure to put any checks inside process_proposal
                // since that function is called in other places to rerun the
                // checks if (when) needed. Every check living outside that
                // function will not be correctly replicated in the other
                // locations
                let block_hash = block.hash.try_into();
                let (response, tx_results) =
                    self.process_proposal(block.into());
                // Cache the response in case of future calls from Namada. If
                // hash conversion fails avoid caching
                if let Ok(block_hash) = block_hash {
                    let result = if let ProcessProposal::Accept = response {
                        ProcessProposalCachedResult::Accepted(
                            tx_results
                                .into_iter()
                                .map(|res| res.into())
                                .collect(),
                        )
                    } else {
                        ProcessProposalCachedResult::Rejected
                    };

                    self.state
                        .in_mem_mut()
                        .block_proposals_cache
                        .put(block_hash, result);
                }
                Ok(Response::ProcessProposal(response))
            }
            Request::RevertProposal(_req) => {
                Ok(Response::RevertProposal(self.revert_proposal(_req)))
            }
            Request::FinalizeBlock(finalize) => {
                tracing::debug!("Request FinalizeBlock");

                self.try_recheck_process_proposal(&finalize)?;
                self.finalize_block(finalize).map(Response::FinalizeBlock)
            }
            Request::Commit => {
                tracing::debug!("Request Commit");
                Ok(self.commit())
            }
            Request::Flush => Ok(Response::Flush),
            Request::Echo(msg) => Ok(Response::Echo(response::Echo {
                message: msg.message,
            })),
            Request::CheckTx(tx) => {
                let mempool_tx_type = match tx.kind {
                    CheckTxKind::New => MempoolTxType::NewTransaction,
                    CheckTxKind::Recheck => MempoolTxType::RecheckTransaction,
                };
                let r#type = mempool_tx_type;
                Ok(Response::CheckTx(self.mempool_validate(&tx.tx, r#type)))
            }
            Request::ListSnapshots => {
                Ok(Response::ListSnapshots(self.list_snapshots()))
            }
            Request::OfferSnapshot(req) => {
                Ok(Response::OfferSnapshot(self.offer_snapshot(req)))
            }
            Request::LoadSnapshotChunk(req) => {
                Ok(Response::LoadSnapshotChunk(self.load_snapshot_chunk(req)))
            }
            Request::ApplySnapshotChunk(req) => {
                Ok(Response::ApplySnapshotChunk(self.apply_snapshot_chunk(req)))
            }
        }
    }

    // Checks if a run of process proposal is required before finalize block
    // (recheck) and, in case, performs it. Clears the cache before returning
    fn try_recheck_process_proposal(
        &mut self,
        finalize_req: &shims::abcipp_shim_types::shim::request::FinalizeBlock,
    ) -> Result<(), Error> {
        let recheck_process_proposal = match self.mode {
            shell::ShellMode::Validator {
                ref local_config, ..
            } => local_config
                .as_ref()
                .map(|cfg| cfg.recheck_process_proposal)
                .unwrap_or_default(),
            shell::ShellMode::Full { ref local_config } => local_config
                .as_ref()
                .map(|cfg| cfg.recheck_process_proposal)
                .unwrap_or_default(),
            shell::ShellMode::Seed => false,
        };

        if recheck_process_proposal {
            let process_proposal_result = match self
                .state
                .in_mem_mut()
                .block_proposals_cache
                .get(&finalize_req.block_hash)
            {
                // We already have the result of process proposal for this block
                // cached in memory
                Some(res) => res.to_owned(),
                None => {
                    let process_req = finalize_req
                        .clone()
                        .cast_to_process_proposal_req()
                        .map_err(|_| Error::InvalidBlockProposal)?;
                    // No need to cache the result since this is the last step
                    // before finalizing the block
                    if let ProcessProposal::Accept =
                        self.process_proposal(process_req.into()).0
                    {
                        ProcessProposalCachedResult::Accepted(vec![])
                    } else {
                        ProcessProposalCachedResult::Rejected
                    }
                }
            };

            if let ProcessProposalCachedResult::Rejected =
                process_proposal_result
            {
                return Err(Error::RejectedBlockProposal);
            }
        }

        // Clear the cache of proposed blocks' results
        self.state.in_mem_mut().block_proposals_cache.clear();

        Ok(())
    }
}

/// Determine if the ledger is migrating state.
pub fn migrating_state() -> Option<BlockHeight> {
    const ENV_INITIAL_HEIGHT: &str = "NAMADA_INITIAL_HEIGHT";
    let height = std::env::var(ENV_INITIAL_HEIGHT).ok()?;
    height.parse::<u64>().ok().map(BlockHeight)
}

/// Emit a header of warning log msgs if the host does not have
/// a 64-bit CPU.
fn emit_warning_on_non_64bit_cpu() {
    if std::mem::size_of::<usize>() != 8 {
        tracing::warn!("");
        #[allow(clippy::arithmetic_side_effects)]
        {
            tracing::warn!(
                "Your machine has a {}-bit CPU...",
                8 * std::mem::size_of::<usize>()
            );
        }
        tracing::warn!("");
        tracing::warn!("A majority of nodes will run on 64-bit hardware!");
        tracing::warn!("");
        tracing::warn!("While not immediately being problematic, non 64-bit");
        tracing::warn!("nodes may run into spurious consensus failures.");
        tracing::warn!("");
    }
}

/// Run the ledger with an async runtime
pub fn run(
    config: config::Config,
    wasm_dir: PathBuf,
    scheduled_migration: Option<ScheduledMigration>,
    namada_version: &'static str,
) {
    handle_tendermint_mode_change(&config);

    emit_warning_on_non_64bit_cpu();

    let logical_cores = num_cpus::get();
    tracing::info!("Available logical cores: {}", logical_cores);

    let rayon_threads = num_of_threads(
        ENV_VAR_RAYON_THREADS,
        // If not set, default to half of logical CPUs count
        logical_cores / 2,
    );
    tracing::info!("Using {} threads for Rayon.", rayon_threads);

    let tokio_threads = num_of_threads(
        ENV_VAR_TOKIO_THREADS,
        // If not set, default to half of logical CPUs count
        logical_cores / 2,
    );
    tracing::info!("Using {} threads for Tokio.", tokio_threads);

    // Configure number of threads for rayon (used in `par_iter` when running
    // VPs)
    rayon::ThreadPoolBuilder::new()
        .num_threads(rayon_threads)
        .thread_name(|i| format!("ledger-rayon-worker-{}", i))
        .build_global()
        .unwrap();

    // Start tokio runtime with the `run_aux` function
    tokio::runtime::Builder::new_multi_thread()
        .worker_threads(tokio_threads)
        .thread_name("ledger-tokio-worker")
        // Enable time and I/O drivers
        .enable_all()
        .build()
        .unwrap()
        .block_on(run_aux(
            config.ledger,
            wasm_dir,
            scheduled_migration,
            namada_version,
        ));
}

/// Check the `tendermint_mode` has changed from validator to non-validator
/// mode, in which case we replace and backup the validator keys and state to
/// avoid CometBFT running as a validator. We also persist the
/// `last_tendermint_node` in the config for the next run.
fn handle_tendermint_mode_change(config: &config::Config) {
    // Check if the node was previously ran as a Validator, but isn't anymore
    if !matches!(
        config.ledger.shell.tendermint_mode,
        TendermintMode::Validator
    ) && matches!(
        config.ledger.shell.last_tendermint_mode,
        Some(TendermintMode::Validator)
    ) {
        // Backup and replace CometBFT validator key and state
        let cometbft_dir = config.ledger.cometbft_dir();
        namada_apps_lib::tendermint_node::backup_validator_key_and_state(
            &cometbft_dir,
        );
        namada_apps_lib::tendermint_node::write_dummy_validator_key_and_state(
            &cometbft_dir,
        );
    }

    if config.ledger.shell.last_tendermint_mode.is_none()
        || config.ledger.shell.last_tendermint_mode
            != Some(config.ledger.shell.tendermint_mode)
    {
        let mut config = config.clone();
        config.ledger.shell.last_tendermint_mode =
            Some(config.ledger.shell.tendermint_mode);
        // Remove this field in case it's set from running `ledger run-until` -
        // it shouldn't be persisted
        config.ledger.shell.action_at_height = None;
        let replace = true;
        config
            .write(
                &config.ledger.shell.base_dir,
                &config.ledger.chain_id,
                replace,
            )
            .expect(
                "Must be able to persist config with changed \
                 `last_tendermint_mode`.",
            );
    }
}

/// Resets the tendermint_node state and removes database files
pub fn reset(
    config: config::Config,
    args::LedgerReset { full_reset }: args::LedgerReset,
) -> Result<(), shell::Error> {
    shell::reset(config, full_reset)
}

/// Dump Namada ledger node's DB from a block into a file
pub fn dump_db(
    config: config::Ledger,
    args::LedgerDumpDb {
        block_height,
        out_file_path,
        historic,
    }: args::LedgerDumpDb,
) {
    let chain_id = config.chain_id;
    let db_path = config.shell.db_dir(&chain_id);

    let db = storage::PersistentDB::open(db_path, None);
    db.dump_block(out_file_path, historic, block_height);
}

#[cfg(feature = "migrations")]
pub fn query_db(
    config: config::Ledger,
    key: &namada_sdk::storage::Key,
    type_hash: &[u8; 32],
    cf: &DbColFam,
) {
    use namada_apps_lib::storage::DBUpdateVisitor;

    let chain_id = config.chain_id;
    let db_path = config.shell.db_dir(&chain_id);

    let db = storage::PersistentDB::open(db_path, None);
    let db_visitor = storage::RocksDBUpdateVisitor::default();
    let bytes = db_visitor.read(&db, key, cf).unwrap();

    let deserializer = namada_migrations::get_deserializer(type_hash)
        .unwrap_or_else(|| {
            panic!(
                "Could not find a deserializer for the type provided with key \
                 <{}>",
                key
            )
        });
    let hex_bytes = HEXUPPER.encode(&bytes);
    let value = deserializer(bytes).unwrap_or_else(|| {
        panic!("Unable to deserialize the value under key <{}>", key)
    });
    tracing::info!(
        "Key <{}>: {}\nThe value in bytes is {}",
        key,
        value,
        hex_bytes
    );
}

/// Roll Namada state back to the previous height
pub fn rollback(config: config::Ledger) -> Result<(), shell::Error> {
    shell::rollback(config)
}

/// Runs and monitors a few concurrent tasks.
///
/// This includes:
///   - A Tendermint node.
///   - A shell which contains an ABCI server, for talking to the Tendermint
///     node.
///   - A [`Broadcaster`], for the ledger to submit txs to Tendermint's mempool.
///   - An Ethereum full node.
///   - An oracle, to receive events from the Ethereum full node, and forward
///     them to the ledger.
///
/// All must be alive for correct functioning.
async fn run_aux(
    config: config::Ledger,
    wasm_dir: PathBuf,
    scheduled_migration: Option<ScheduledMigration>,
    namada_version: &'static str,
) {
    let setup_data =
        run_aux_setup(&config, &wasm_dir, scheduled_migration).await;

    // Create an `AbortableSpawner` for signalling shut down from the shell or
    // from Tendermint
    let mut spawner = AbortableSpawner::new();

    // Start Tendermint node
    start_tendermint(&mut spawner, &config, namada_version);

    // Start oracle if necessary
    let eth_oracle_channels =
        match maybe_start_ethereum_oracle(&mut spawner, &config).await {
            EthereumOracleTask::NotEnabled => None,
            EthereumOracleTask::Enabled { channels } => Some(channels),
        };

    tracing::info!("Loading MASP verifying keys.");
    let _ = namada_sdk::token::validation::preload_verifying_keys();
    tracing::info!("Done loading MASP verifying keys.");

    // Start ABCI server and broadcaster (the latter only if we are a validator
    // node)
    start_abci_broadcaster_shell(
        &mut spawner,
        eth_oracle_channels,
        wasm_dir,
        setup_data,
        config,
    );

    spawner.run_to_completion().await;
}

/// A [`RunAuxSetup`] stores some variables used to start child
/// processes of the ledger.
struct RunAuxSetup {
    vp_wasm_compilation_cache: u64,
    tx_wasm_compilation_cache: u64,
    db_block_cache_size_bytes: u64,
    scheduled_migration: Option<ScheduledMigration>,
}

/// Return some variables used to start child processes of the ledger.
async fn run_aux_setup(
    config: &config::Ledger,
    wasm_dir: &PathBuf,
    scheduled_migration: Option<ScheduledMigration>,
) -> RunAuxSetup {
    wasm_loader::validate_wasm_artifacts(wasm_dir).await;

    // Find the system available memory
    let available_memory_bytes = Lazy::new(|| {
        let sys = System::new_with_specifics(
            RefreshKind::nothing().with_memory(MemoryRefreshKind::everything()),
        );
        let available_memory_bytes = sys.available_memory();
        tracing::info!(
            "Available memory: {}",
            Byte::from_u128(u128::from(available_memory_bytes))
                .unwrap()
                .get_appropriate_unit(UnitType::Binary)
        );
        available_memory_bytes
    });

    // Find the VP WASM compilation cache size
    let vp_wasm_compilation_cache =
        match config.shell.vp_wasm_compilation_cache_bytes {
            Some(vp_wasm_compilation_cache) => {
                tracing::info!(
                    "VP WASM compilation cache size set from the configuration"
                );
                vp_wasm_compilation_cache
            }
            None => {
                tracing::info!(
                    "VP WASM compilation cache size not configured, using 1/6 \
                     of available memory."
                );
                *available_memory_bytes / 6
            }
        };
    tracing::info!(
        "VP WASM compilation cache size: {}",
        Byte::from_u128(u128::from(vp_wasm_compilation_cache))
            .unwrap()
            .get_appropriate_unit(UnitType::Binary)
    );

    // Find the tx WASM compilation cache size
    let tx_wasm_compilation_cache =
        match config.shell.tx_wasm_compilation_cache_bytes {
            Some(tx_wasm_compilation_cache) => {
                tracing::info!(
                    "Tx WASM compilation cache size set from the configuration"
                );
                tx_wasm_compilation_cache
            }
            None => {
                tracing::info!(
                    "Tx WASM compilation cache size not configured, using 1/6 \
                     of available memory."
                );
                *available_memory_bytes / 6
            }
        };
    tracing::info!(
        "Tx WASM compilation cache size: {}",
        Byte::from_u128(u128::from(tx_wasm_compilation_cache))
            .unwrap()
            .get_appropriate_unit(UnitType::Binary)
    );

    // Find the RocksDB block cache size
    let db_block_cache_size_bytes = match config.shell.block_cache_bytes {
        Some(block_cache_bytes) => {
            tracing::info!("Block cache set from the configuration.");
            block_cache_bytes
        }
        None => {
            tracing::info!(
                "Block cache size not configured, using 1/3 of available \
                 memory."
            );
            *available_memory_bytes / 3
        }
    };
    tracing::info!(
        "RocksDB block cache size: {}",
        Byte::from_u128(u128::from(db_block_cache_size_bytes))
            .unwrap()
            .get_appropriate_unit(UnitType::Binary)
    );

    RunAuxSetup {
        vp_wasm_compilation_cache,
        tx_wasm_compilation_cache,
        db_block_cache_size_bytes,
        scheduled_migration,
    }
}

/// This function spawns an ABCI server and a [`Broadcaster`] into the
/// asynchronous runtime. Additionally, it executes a shell in
/// a new OS thread, to drive the ABCI server.
fn start_abci_broadcaster_shell(
    spawner: &mut AbortableSpawner,
    eth_oracle: Option<EthereumOracleChannels>,
    wasm_dir: PathBuf,
    setup_data: RunAuxSetup,
    config: config::Ledger,
) {
    let rpc_address =
        convert_tm_addr_to_socket_addr(&config.cometbft.rpc.laddr);
    let RunAuxSetup {
        vp_wasm_compilation_cache,
        tx_wasm_compilation_cache,
        db_block_cache_size_bytes,
        scheduled_migration,
    } = setup_data;

    // Channels for validators to send protocol txs to be broadcast to the
    // broadcaster service
    let (broadcaster_sender, broadcaster_receiver) = mpsc::unbounded_channel();
    let genesis_time = DateTimeUtc::try_from(config.genesis_time.clone())
        .expect("Should be able to parse genesis time");
    // Start broadcaster
    if matches!(
        config.shell.tendermint_mode,
        TendermintMode::Validator { .. }
    ) {
        let (bc_abort_send, bc_abort_recv) =
            tokio::sync::oneshot::channel::<()>();

        spawner
            .abortable("Broadcaster", move |aborter| async move {
                // Construct a service for broadcasting protocol txs from
                // the ledger
                let mut broadcaster =
                    Broadcaster::new(rpc_address, broadcaster_receiver);
                broadcaster.run(bc_abort_recv, genesis_time).await;
                tracing::info!("Broadcaster is no longer running.");

                drop(aborter);

                Ok(())
            })
            .with_cleanup(async move {
                let _ = bc_abort_send.send(());
            })
            .spawn();
    }

    // Setup DB cache, it must outlive the DB instance that's in the shell
    let db_cache = rocksdb::Cache::new_lru_cache(
        usize::try_from(db_block_cache_size_bytes)
            .expect("`db_block_cache_size_bytes` must not exceed `usize::MAX`"),
    );

    // Construct our ABCI application.
    let tendermint_mode = config.shell.tendermint_mode;
    let proxy_app_address =
        convert_tm_addr_to_socket_addr(&config.cometbft.proxy_app);

    let (shell, abci_service, service_handle) = AbcippShim::new(
        config,
        wasm_dir,
        broadcaster_sender,
        eth_oracle,
        &db_cache,
        scheduled_migration,
        vp_wasm_compilation_cache,
        tx_wasm_compilation_cache,
    );

    // Channel for signalling shut down to ABCI server
    let (abci_abort_send, abci_abort_recv) = tokio::sync::oneshot::channel();

    // Start the ABCI server
    spawner
        .abortable("ABCI", move |aborter| async move {
            let res = run_abci(
                abci_service,
                service_handle,
                proxy_app_address,
                abci_abort_recv,
            )
            .await;

            drop(aborter);
            res
        })
        .with_cleanup(async move {
            let _ = abci_abort_send.send(());
        })
        .spawn();

    // Start the shell in a new OS thread
    spawner
        .abortable("Shell", move |_aborter| {
            tracing::info!("Namada ledger node started.");
            match tendermint_mode {
                TendermintMode::Validator { .. } => {
                    tracing::info!("This node is a validator");
                }
                TendermintMode::Full | TendermintMode::Seed => {
                    tracing::info!("This node is not a validator");
                }
            }
            shell.run();
            Ok(())
        })
        .with_cleanup(async {
            tracing::info!("Namada ledger node has shut down.");
        })
        // NB: pin the shell's task to allow
        // resuming unwinding on panic
        .pin()
        .spawn_blocking();
}

/// Runs the an asynchronous ABCI server with four sub-components for consensus,
/// mempool, snapshot, and info.
async fn run_abci(
    abci_service: AbciService,
    service_handle: tokio::sync::broadcast::Sender<()>,
    proxy_app_address: SocketAddr,
    abort_recv: tokio::sync::oneshot::Receiver<()>,
) -> shell::ShellResult<()> {
    // Split it into components.
    let (consensus, mempool, snapshot, info) = split::service(abci_service, 5);

    // Hand those components to the ABCI server, but customize request behavior
    // for each category
    let server = Server::builder()
        .consensus(consensus)
        .snapshot(snapshot)
        .mempool(mempool) // don't load_shed, it will make CometBFT crash
        .info(info) // don't load_shed, it will make tower-abci crash
        .finish()
        .unwrap();
    tokio::select! {
        // Run the server with the ABCI service
        status = server.listen_tcp(proxy_app_address) => {
            status.map_err(|err| Error::TowerServer(err.to_string()))
        },
        resp_sender = abort_recv => {
            _ = service_handle.send(());
            match resp_sender {
                Ok(()) => {
                    tracing::info!("Shutting down ABCI server...");
                },
                Err(err) => {
                    tracing::error!("The ABCI server abort sender has unexpectedly dropped: {}", err);
                    tracing::info!("Shutting down ABCI server...");
                }
            }
            Ok(())
        }
    }
}

/// Launches a new task managing a Tendermint process into the asynchronous
/// runtime, and returns its [`task::JoinHandle`].
fn start_tendermint(
    spawner: &mut AbortableSpawner,
    config: &config::Ledger,
    namada_version: &'static str,
) {
    let tendermint_dir = config.cometbft_dir();
    let chain_id = config.chain_id.clone();
    let proxy_app_address = config.cometbft.proxy_app.to_string();
    let config = config.clone();
    let genesis_time = config
        .genesis_time
        .clone()
        .try_into()
        .expect("expected RFC3339 genesis_time");

    // Channel for signalling shut down to cometbft process
    let (tm_abort_send, tm_abort_recv) =
        tokio::sync::oneshot::channel::<tokio::sync::oneshot::Sender<()>>();

    spawner
        .abortable("Tendermint", move |aborter| async move {
            let res = tendermint_node::run(
                tendermint_dir,
                chain_id,
                genesis_time,
                proxy_app_address,
                config,
                tm_abort_recv,
                namada_version,
            )
            .map_err(Error::Tendermint)
            .await;
            tracing::info!("Tendermint node is no longer running.");

            drop(aborter);
            if res.is_err() {
                tracing::error!("{:?}", &res);
            }
            res
        })
        .with_cleanup(async move {
            // Shutdown tendermint_node via a message to ensure that the child
            // process is properly cleaned-up.
            let (tm_abort_resp_send, tm_abort_resp_recv) =
                tokio::sync::oneshot::channel::<()>();
            // Ask to shutdown tendermint node cleanly. Ignore error, which can
            // happen if the tendermint_node task has already
            // finished.
            if let Ok(()) = tm_abort_send.send(tm_abort_resp_send) {
                match tm_abort_resp_recv.await {
                    Ok(()) => {}
                    Err(err) => {
                        tracing::error!(
                            "Failed to receive a response from tendermint: {}",
                            err
                        );
                    }
                }
            }
        })
        .spawn();
}

/// Represents a [`tokio::task`] in which an Ethereum oracle may be running, and
/// if so, channels for communicating with it.
enum EthereumOracleTask {
    NotEnabled,
    Enabled { channels: EthereumOracleChannels },
}

/// Potentially starts an Ethereum event oracle.
async fn maybe_start_ethereum_oracle(
    spawner: &mut AbortableSpawner,
    config: &config::Ledger,
) -> EthereumOracleTask {
    if !matches!(
        config.shell.tendermint_mode,
        TendermintMode::Validator { .. }
    ) {
        return EthereumOracleTask::NotEnabled;
    }

    let ethereum_url = config.ethereum_bridge.oracle_rpc_endpoint.clone();

    // Start the oracle for listening to Ethereum events
    let (eth_sender, eth_receiver) =
        mpsc::channel(config.ethereum_bridge.channel_buffer_size);
    let (last_processed_block_sender, last_processed_block_receiver) =
        last_processed_block::channel();
    let (control_sender, control_receiver) = oracle::control::channel();

    match config.ethereum_bridge.mode {
        ethereum_bridge::ledger::Mode::RemoteEndpoint => {
            oracle::run_oracle::<Provider<Http>>(
                ethereum_url,
                eth_sender,
                control_receiver,
                last_processed_block_sender,
                spawner,
            );

            EthereumOracleTask::Enabled {
                channels: EthereumOracleChannels::new(
                    eth_receiver,
                    control_sender,
                    last_processed_block_receiver,
                ),
            }
        }
        ethereum_bridge::ledger::Mode::SelfHostedEndpoint => {
            let (oracle_abort_send, oracle_abort_recv) =
                tokio::sync::oneshot::channel::<tokio::sync::oneshot::Sender<()>>(
                );
            spawner
                .abortable(
                    "Ethereum Events Endpoint",
                    move |aborter| async move {
                        oracle::test_tools::events_endpoint::serve(
                            ethereum_url,
                            eth_sender,
                            control_receiver,
                            oracle_abort_recv,
                        )
                        .await;
                        tracing::info!(
                            "Ethereum events endpoint is no longer running."
                        );

                        drop(aborter);

                        Ok(())
                    },
                )
                .with_cleanup(async move {
                    let (oracle_abort_resp_send, oracle_abort_resp_recv) =
                        tokio::sync::oneshot::channel::<()>();

                    if let Ok(()) =
                        oracle_abort_send.send(oracle_abort_resp_send)
                    {
                        match oracle_abort_resp_recv.await {
                            Ok(()) => {}
                            Err(err) => {
                                tracing::error!(
                                    "Failed to receive an abort response from \
                                     the Ethereum events endpoint task: {}",
                                    err
                                );
                            }
                        }
                    }
                })
                .spawn();
            EthereumOracleTask::Enabled {
                channels: EthereumOracleChannels::new(
                    eth_receiver,
                    control_sender,
                    last_processed_block_receiver,
                ),
            }
        }
        ethereum_bridge::ledger::Mode::Off => EthereumOracleTask::NotEnabled,
    }
}

/// This function runs `Shell::init_chain` on the provided genesis files.
/// This is to check that all the transactions included therein run
/// successfully on chain initialization.
pub fn test_genesis_files(
    config: config::Ledger,
    genesis: config::genesis::chain::Finalized,
    wasm_dir: PathBuf,
) {
    use namada_sdk::hash::Sha256Hasher;
    use namada_sdk::state::mockdb::MockDB;

    // Channels for validators to send protocol txs to be broadcast to the
    // broadcaster service
    let (broadcast_sender, _broadcaster_receiver) = mpsc::unbounded_channel();

    let chain_id = config.chain_id.to_string();
    // start an instance of the ledger
    let mut shell = Shell::<MockDB, Sha256Hasher>::new(
        config,
        wasm_dir,
        broadcast_sender,
        None,
        None,
        None,
        50 * 1024 * 1024,
        50 * 1024 * 1024,
    );
    let mut initializer = shell::InitChainValidation::new(&mut shell, true);
    initializer.run_validation(chain_id, genesis);
    initializer.report();
}
