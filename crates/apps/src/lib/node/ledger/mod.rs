mod abortable;
mod broadcaster;
pub mod ethereum_oracle;
pub mod shell;
pub mod shims;
pub mod storage;
pub mod tendermint_node;

use std::convert::TryInto;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::str::FromStr;
use std::thread;

use byte_unit::Byte;
use futures::future::TryFutureExt;
use namada::core::storage::Key;
use namada::core::time::DateTimeUtc;
use namada::eth_bridge::ethers::providers::{Http, Provider};
use namada::governance::storage::keys as governance_storage;
use namada::tendermint::abci::request::CheckTxKind;
use namada_sdk::state::StateRead;
use once_cell::unsync::Lazy;
use sysinfo::{RefreshKind, System, SystemExt};
use tokio::sync::mpsc;
use tokio::task;
use tower::ServiceBuilder;

use self::abortable::AbortableSpawner;
use self::ethereum_oracle::last_processed_block;
use self::shell::EthereumOracleChannels;
use self::shims::abcipp_shim::AbciService;
use crate::cli::args;
use crate::config::utils::{convert_tm_addr_to_socket_addr, num_of_threads};
use crate::config::{ethereum_bridge, TendermintMode};
use crate::facade::tendermint::v0_37::abci::response;
use crate::facade::tower_abci::{split, Server};
use crate::node::ledger::broadcaster::Broadcaster;
use crate::node::ledger::ethereum_oracle as oracle;
use crate::node::ledger::shell::{Error, MempoolTxType, Shell};
use crate::node::ledger::shims::abcipp_shim::AbcippShim;
use crate::node::ledger::shims::abcipp_shim_types::shim::{Request, Response};
use crate::{config, wasm_loader};

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
    fn load_proposals(&mut self) {
        let proposals_key = governance_storage::get_commiting_proposals_prefix(
            self.state.in_mem().last_epoch.0,
        );

        let (proposal_iter, _) = self.state.db_iter_prefix(&proposals_key);
        for (key, _, _) in proposal_iter {
            let key =
                Key::from_str(key.as_str()).expect("Key should be parsable");
            if governance_storage::get_commit_proposal_epoch(&key).unwrap()
                != self.state.in_mem().last_epoch.0
            {
                // NOTE: `iter_prefix` iterate over the matching prefix. In this
                // case  a proposal with grace_epoch 110 will be
                // matched by prefixes  1, 11 and 110. Thus we
                // have to skip to the next iteration of
                //  the cycle for all the prefixes that don't actually match
                //  the desired epoch.
                continue;
            }

            let proposal_id = governance_storage::get_commit_proposal_id(&key);
            if let Some(id) = proposal_id {
                self.proposal_data.insert(id);
            }
        }
    }

    fn call(&mut self, req: Request) -> Result<Response, Error> {
        match req {
            Request::InitChain(init) => {
                tracing::debug!("Request InitChain");
                self.init_chain(
                    init,
                    #[cfg(any(test, feature = "testing"))]
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
                let (response, _tx_results) =
                    self.process_proposal(block.into());
                Ok(Response::ProcessProposal(response))
            }
            Request::RevertProposal(_req) => {
                Ok(Response::RevertProposal(self.revert_proposal(_req)))
            }
            Request::FinalizeBlock(finalize) => {
                tracing::debug!("Request FinalizeBlock");
                self.load_proposals();
                self.finalize_block(finalize).map(Response::FinalizeBlock)
            }
            Request::Commit => {
                tracing::debug!("Request Commit");
                Ok(Response::Commit(self.commit()))
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
                Ok(Response::ListSnapshots(Default::default()))
            }
            Request::OfferSnapshot(_) => {
                Ok(Response::OfferSnapshot(Default::default()))
            }
            Request::LoadSnapshotChunk(_) => {
                Ok(Response::LoadSnapshotChunk(Default::default()))
            }
            Request::ApplySnapshotChunk(_) => {
                Ok(Response::ApplySnapshotChunk(Default::default()))
            }
        }
    }
}

/// Run the ledger with an async runtime
pub fn run(config: config::Ledger, wasm_dir: PathBuf) {
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
        .block_on(run_aux(config, wasm_dir));
}

/// Resets the tendermint_node state and removes database files
pub fn reset(config: config::Ledger) -> Result<(), shell::Error> {
    shell::reset(config)
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
    use namada::state::DB;

    let chain_id = config.chain_id;
    let db_path = config.shell.db_dir(&chain_id);

    let db = storage::PersistentDB::open(db_path, None);
    db.dump_block(out_file_path, historic, block_height);
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
async fn run_aux(config: config::Ledger, wasm_dir: PathBuf) {
    let setup_data = run_aux_setup(&config, &wasm_dir).await;

    // Create an `AbortableSpawner` for signalling shut down from the shell or
    // from Tendermint
    let mut spawner = AbortableSpawner::new();

    // Start Tendermint node
    let tendermint_node = start_tendermint(&mut spawner, &config);

    // Start oracle if necessary
    let (eth_oracle_channels, eth_oracle) =
        match maybe_start_ethereum_oracle(&mut spawner, &config).await {
            EthereumOracleTask::NotEnabled { handle } => (None, handle),
            EthereumOracleTask::Enabled { handle, channels } => {
                (Some(channels), handle)
            }
        };

    tracing::info!("Loading MASP verifying keys.");
    let _ = namada_sdk::masp::preload_verifying_keys();
    tracing::info!("Done loading MASP verifying keys.");

    // Start ABCI server and broadcaster (the latter only if we are a validator
    // node)
    let (abci, broadcaster, shell_handler) = start_abci_broadcaster_shell(
        &mut spawner,
        eth_oracle_channels,
        wasm_dir,
        setup_data,
        config,
    );

    // Wait for interrupt signal or abort message
    let aborted = spawner.wait_for_abort().await.child_terminated();

    // Wait for all managed tasks to finish.
    let res = tokio::try_join!(tendermint_node, abci, eth_oracle, broadcaster);

    match res {
        Ok((tendermint_res, abci_res, _, _)) => {
            // we ignore errors on user-initiated shutdown
            if aborted {
                if let Err(err) = tendermint_res {
                    tracing::error!("Tendermint error: {}", err);
                }
                if let Err(err) = abci_res {
                    tracing::error!("ABCI error: {}", err);
                }
            }
        }
        Err(err) => {
            // Ignore cancellation errors
            if !err.is_cancelled() {
                tracing::error!("Ledger error: {}", err);
            }
        }
    }

    tracing::info!("Namada ledger node has shut down.");

    let res = task::block_in_place(move || shell_handler.join());

    if let Err(err) = res {
        std::panic::resume_unwind(err)
    }
}

/// A [`RunAuxSetup`] stores some variables used to start child
/// processes of the ledger.
struct RunAuxSetup {
    vp_wasm_compilation_cache: u64,
    tx_wasm_compilation_cache: u64,
    db_block_cache_size_bytes: u64,
}

/// Return some variables used to start child processes of the ledger.
async fn run_aux_setup(
    config: &config::Ledger,
    wasm_dir: &PathBuf,
) -> RunAuxSetup {
    // Prefetch needed wasm artifacts
    wasm_loader::pre_fetch_wasm(wasm_dir).await;

    // Find the system available memory
    let available_memory_bytes = Lazy::new(|| {
        let sys = System::new_with_specifics(RefreshKind::new().with_memory());
        let available_memory_bytes = sys.available_memory();
        tracing::info!(
            "Available memory: {}",
            Byte::from_bytes(available_memory_bytes as u128)
                .get_appropriate_unit(true)
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
        Byte::from_bytes(vp_wasm_compilation_cache as u128)
            .get_appropriate_unit(true)
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
        Byte::from_bytes(tx_wasm_compilation_cache as u128)
            .get_appropriate_unit(true)
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
        Byte::from_bytes(db_block_cache_size_bytes as u128)
            .get_appropriate_unit(true)
    );

    RunAuxSetup {
        vp_wasm_compilation_cache,
        tx_wasm_compilation_cache,
        db_block_cache_size_bytes,
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
) -> (
    task::JoinHandle<shell::Result<()>>,
    task::JoinHandle<()>,
    thread::JoinHandle<()>,
) {
    let rpc_address =
        convert_tm_addr_to_socket_addr(&config.cometbft.rpc.laddr);
    let RunAuxSetup {
        vp_wasm_compilation_cache,
        tx_wasm_compilation_cache,
        db_block_cache_size_bytes,
    } = setup_data;

    // Channels for validators to send protocol txs to be broadcast to the
    // broadcaster service
    let (broadcaster_sender, broadcaster_receiver) = mpsc::unbounded_channel();
    let genesis_time = DateTimeUtc::try_from(config.genesis_time.clone())
        .expect("Should be able to parse genesis time");
    // Start broadcaster
    let broadcaster = if matches!(
        config.shell.tendermint_mode,
        TendermintMode::Validator { .. }
    ) {
        let (bc_abort_send, bc_abort_recv) =
            tokio::sync::oneshot::channel::<()>();

        spawner
            .spawn_abortable("Broadcaster", move |aborter| async move {
                // Construct a service for broadcasting protocol txs from
                // the ledger
                let mut broadcaster =
                    Broadcaster::new(rpc_address, broadcaster_receiver);
                broadcaster.run(bc_abort_recv, genesis_time).await;
                tracing::info!("Broadcaster is no longer running.");

                drop(aborter);
            })
            .with_cleanup(async move {
                let _ = bc_abort_send.send(());
            })
    } else {
        spawn_dummy_task(())
    };

    // Setup DB cache, it must outlive the DB instance that's in the shell
    let db_cache =
        rocksdb::Cache::new_lru_cache(db_block_cache_size_bytes as usize);

    // Construct our ABCI application.
    let tendermint_mode = config.shell.tendermint_mode.clone();
    let proxy_app_address =
        convert_tm_addr_to_socket_addr(&config.cometbft.proxy_app);

    let (shell, abci_service, service_handle) = AbcippShim::new(
        config,
        wasm_dir,
        broadcaster_sender,
        eth_oracle,
        &db_cache,
        vp_wasm_compilation_cache,
        tx_wasm_compilation_cache,
    );

    // Channel for signalling shut down to ABCI server
    let (abci_abort_send, abci_abort_recv) = tokio::sync::oneshot::channel();

    // Start the ABCI server
    let abci = spawner
        .spawn_abortable("ABCI", move |aborter| async move {
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
        });

    // Start the shell in a new OS thread
    let thread_builder = thread::Builder::new().name("ledger-shell".into());
    let shell_handler = thread_builder
        .spawn(move || {
            tracing::info!("Namada ledger node started.");
            match tendermint_mode {
                TendermintMode::Validator { .. } => {
                    tracing::info!("This node is a validator");
                }
                TendermintMode::Full | TendermintMode::Seed => {
                    tracing::info!("This node is not a validator");
                }
            }
            shell.run()
        })
        .expect("Must be able to start a thread for the shell");

    (abci, broadcaster, shell_handler)
}

/// Runs the an asynchronous ABCI server with four sub-components for consensus,
/// mempool, snapshot, and info.
async fn run_abci(
    abci_service: AbciService,
    service_handle: tokio::sync::broadcast::Sender<()>,
    proxy_app_address: SocketAddr,
    abort_recv: tokio::sync::oneshot::Receiver<()>,
) -> shell::Result<()> {
    // Split it into components.
    let (consensus, mempool, snapshot, info) = split::service(abci_service, 5);

    // Hand those components to the ABCI server, but customize request behavior
    // for each category
    let server = Server::builder()
        .consensus(consensus)
        .snapshot(snapshot)
        .mempool(mempool) // don't load_shed, it will make CometBFT crash
        .info(
            ServiceBuilder::new()
                .load_shed()
                .buffer(100)
                .rate_limit(50, std::time::Duration::from_secs(1))
                .service(info),
        )
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
) -> task::JoinHandle<shell::Result<()>> {
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
        .spawn_abortable("Tendermint", move |aborter| async move {
            let res = tendermint_node::run(
                tendermint_dir,
                chain_id,
                genesis_time,
                proxy_app_address,
                config,
                tm_abort_recv,
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
}

/// Represents a [`tokio::task`] in which an Ethereum oracle may be running, and
/// if so, channels for communicating with it.
enum EthereumOracleTask {
    NotEnabled {
        // TODO(namada#459): we have to return a dummy handle for the moment,
        // until `run_aux` is refactored - at which point, we no longer need an
        // enum to represent the Ethereum oracle being on/off.
        handle: task::JoinHandle<()>,
    },
    Enabled {
        handle: task::JoinHandle<()>,
        channels: EthereumOracleChannels,
    },
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
        return EthereumOracleTask::NotEnabled {
            handle: spawn_dummy_task(()),
        };
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
            let handle = oracle::run_oracle::<Provider<Http>>(
                ethereum_url,
                eth_sender,
                control_receiver,
                last_processed_block_sender,
                spawner,
            );

            EthereumOracleTask::Enabled {
                handle,
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
            let handle = spawner
                .spawn_abortable(
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
                });
            EthereumOracleTask::Enabled {
                handle,
                channels: EthereumOracleChannels::new(
                    eth_receiver,
                    control_sender,
                    last_processed_block_receiver,
                ),
            }
        }
        ethereum_bridge::ledger::Mode::Off => EthereumOracleTask::NotEnabled {
            handle: spawn_dummy_task(()),
        },
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
    use namada::core::hash::Sha256Hasher;
    use namada::state::mockdb::MockDB;

    // Channels for validators to send protocol txs to be broadcast to the
    // broadcaster service
    let (broadcast_sender, _broadcaster_receiver) = mpsc::unbounded_channel();

    // Start dummy broadcaster
    let _broadcaster = spawn_dummy_task(());
    let chain_id = config.chain_id.to_string();
    // start an instance of the ledger
    let mut shell = Shell::<MockDB, Sha256Hasher>::new(
        config,
        wasm_dir,
        broadcast_sender,
        None,
        None,
        50 * 1024 * 1024,
        50 * 1024 * 1024,
    );
    let mut initializer = shell::InitChainValidation::new(&mut shell, true);
    initializer.run_validation(chain_id, genesis);
    initializer.report();
}

/// Spawn a dummy asynchronous task into the runtime,
/// which will resolve instantly.
fn spawn_dummy_task<T: Send + 'static>(ready: T) -> task::JoinHandle<T> {
    tokio::spawn(async { std::future::ready(ready).await })
}
