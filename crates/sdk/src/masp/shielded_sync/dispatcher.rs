use std::collections::BTreeMap;
use std::future::Future;
use std::ops::ControlFlow;
use std::pin::Pin;
use std::sync::atomic::{self, AtomicBool, AtomicUsize};
use std::sync::Arc;
use std::task::{Context, Poll};

use borsh::{BorshDeserialize, BorshSerialize};
use futures::future::{select, Either};
use futures::task::AtomicWaker;
use masp_primitives::merkle_tree::{CommitmentTree, IncrementalWitness};
use masp_primitives::sapling::{Node, ViewingKey};
use masp_primitives::transaction::Transaction;
use masp_primitives::zip32::ExtendedSpendingKey;
use namada_core::collections::HashMap;
use namada_core::hints;
use namada_core::storage::BlockHeight;
use namada_tx::IndexedTx;

use super::utils::{IndexedNoteEntry, MaspClient};
use crate::control_flow::ShutdownSignal;
use crate::error::Error;
use crate::masp::shielded_sync::trial_decrypt;
use crate::masp::utils::{
    blocks_left_to_fetch, DecryptedData, Fetched, RetryStrategy, TrialDecrypted,
};
use crate::masp::{
    to_viewing_key, ShieldedContext, ShieldedUtils, TxNoteMap, WitnessMap,
};
use crate::task_env::TaskSpawner;

struct AsyncCounterInner {
    waker: AtomicWaker,
    count: AtomicUsize,
}

impl AsyncCounterInner {
    fn increment(&self) {
        self.count.fetch_add(1, atomic::Ordering::Relaxed);
    }

    fn decrement_then_wake(&self) -> bool {
        // NB: if the prev value is 1, the new value
        // is eq to 0, which means we must wake the
        // waiting future
        self.count.fetch_sub(1, atomic::Ordering::Relaxed) == 1
    }

    fn value(&self) -> usize {
        self.count.load(atomic::Ordering::Relaxed)
    }
}

struct AsyncCounter {
    inner: Arc<AsyncCounterInner>,
}

impl AsyncCounter {
    fn new() -> Self {
        Self {
            inner: Arc::new(AsyncCounterInner {
                waker: AtomicWaker::new(),
                count: AtomicUsize::new(0),
            }),
        }
    }
}

impl Clone for AsyncCounter {
    fn clone(&self) -> Self {
        let inner = Arc::clone(&self.inner);
        inner.increment();
        Self { inner }
    }
}

impl Drop for AsyncCounter {
    fn drop(&mut self) {
        if self.inner.decrement_then_wake() {
            self.inner.waker.wake();
        }
    }
}

impl Future for AsyncCounter {
    type Output = ();

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<()> {
        if self.inner.value() == 0 {
            Poll::Ready(())
        } else {
            self.inner.waker.register(cx.waker());
            Poll::Pending
        }
    }
}

#[derive(Clone, Default)]
pub struct AtomicFlag {
    inner: Arc<AtomicBool>,
}

impl AtomicFlag {
    pub fn set(&self) {
        self.inner.store(true, atomic::Ordering::Relaxed)
    }

    pub fn get(&self) -> bool {
        self.inner.load(atomic::Ordering::Relaxed)
    }
}

#[derive(Clone, Default)]
struct PanicFlag {
    #[cfg(not(target_family = "wasm"))]
    inner: AtomicFlag,
}

impl PanicFlag {
    #[inline(always)]
    fn panicked(&self) -> bool {
        #[cfg(target_family = "wasm")]
        {
            false
        }

        #[cfg(not(target_family = "wasm"))]
        {
            self.inner.get()
        }
    }
}

#[cfg(not(target_family = "wasm"))]
impl Drop for PanicFlag {
    fn drop(&mut self) {
        if std::thread::panicking() {
            self.inner.set();
        }
    }
}

struct TaskError<C> {
    error: Error,
    context: C,
}

// TODO: avoid cloning viewing keys w/ arc-swap+lazy_static or
// rwlock+lazy_static
#[allow(clippy::large_enum_variant)]
enum Message {
    UpdateCommitmentTree(Result<CommitmentTree<Node>, TaskError<BlockHeight>>),
    UpdateNotesMap(Result<BTreeMap<IndexedTx, usize>, TaskError<BlockHeight>>),
    UpdateWitnessMap(
        Result<
            HashMap<usize, IncrementalWitness<Node>>,
            TaskError<BlockHeight>,
        >,
    ),
    FetchTxs(Result<Vec<IndexedNoteEntry>, TaskError<[BlockHeight; 2]>>),
    TrialDecrypt(IndexedTx, ViewingKey, ControlFlow<(), Vec<DecryptedData>>),
}

struct DispatcherTasks<Spawner> {
    spawner: Spawner,
    message_receiver: flume::Receiver<Message>,
    message_sender: flume::Sender<Message>,
    active_tasks: AsyncCounter,
    panic_flag: PanicFlag,
}

impl<Spawner> DispatcherTasks<Spawner> {
    async fn get_next_message(&mut self) -> Option<Message> {
        if let Either::Left((maybe_message, _)) =
            select(self.message_receiver.recv_async(), &mut self.active_tasks)
                .await
        {
            let Ok(message) = maybe_message else {
                unreachable!("There must be at least one sender alive");
            };
            Some(message)
        } else {
            None
        }
    }
}

#[derive(Default, BorshSerialize, BorshDeserialize)]
pub struct DispatcherCache {
    pub(crate) commitment_tree: Option<(BlockHeight, CommitmentTree<Node>)>,
    pub(crate) witness_map: Option<(BlockHeight, WitnessMap)>,
    pub(crate) tx_note_map: Option<(BlockHeight, TxNoteMap)>,
    pub(crate) fetched: Fetched,
    pub(crate) trial_decrypted: TrialDecrypted,
}

#[derive(Debug)]
enum DispatcherState {
    Normal,
    Interrupted,
    Errored(Error),
}

#[derive(Default, Debug)]
struct InitialState {
    last_witnessed_tx: Option<IndexedTx>,
    start_height: BlockHeight,
    last_query_height: BlockHeight,
}

pub struct Config {
    pub retry_strategy: RetryStrategy,
    pub block_batch_size: usize,
    pub channel_buffer_size: usize,
}

pub struct Dispatcher<M, U, S>
where
    U: ShieldedUtils,
{
    client: M,
    state: DispatcherState,
    tasks: DispatcherTasks<S>,
    ctx: ShieldedContext<U>,
    config: Config,
    cache: DispatcherCache,
    /// We are syncing up to this height
    height_to_sync: BlockHeight,
    interrupt_flag: AtomicFlag,
}

/// Create a new dispatcher in the initial state.
///
/// This function assumes that the provided shielded context has
/// already been loaded from storage.
pub async fn new<S, M, U>(
    spawner: S,
    client: M,
    utils: &U,
    config: Config,
) -> Dispatcher<M, U, S>
where
    U: ShieldedUtils,
{
    let ctx = {
        let mut ctx = ShieldedContext {
            utils: utils.clone(),
            ..Default::default()
        };

        // TODO: defer loading of shielded context;
        // the only thing we need from it are potentially
        // viewking keys that had been stored on it
        if ctx.load_confirmed().await.is_err() {
            ctx = ShieldedContext {
                utils: utils.clone(),
                ..Default::default()
            };
        }

        ctx
    };

    let state = DispatcherState::Normal;

    let (message_sender, message_receiver) =
        flume::bounded(config.channel_buffer_size);

    let tasks = DispatcherTasks {
        spawner,
        message_receiver,
        message_sender,
        active_tasks: AsyncCounter::new(),
        panic_flag: PanicFlag::default(),
    };

    let cache = ctx.utils.cache_load().await.unwrap_or_default();

    Dispatcher {
        height_to_sync: BlockHeight(0),
        state,
        ctx,
        tasks,
        client,
        config,
        cache,
        // TODO: add progress tracking mechanism to
        // `handle_incoming_message`
        interrupt_flag: Default::default(),
    }
}

impl<M, U, S> Dispatcher<M, U, S>
where
    M: MaspClient + Send + Sync + Unpin + 'static,
    U: ShieldedUtils,
    S: TaskSpawner,
{
    pub async fn run(
        mut self,
        mut shutdown_signal: ShutdownSignal,
        start_query_height: Option<BlockHeight>,
        last_query_height: Option<BlockHeight>,
        sks: &[ExtendedSpendingKey],
        fvks: &[ViewingKey],
    ) -> Result<Option<ShieldedContext<U>>, Error> {
        let initial_state = self
            .perform_initial_setup(
                start_query_height,
                last_query_height,
                sks,
                fvks,
            )
            .await?;
        self.check_exit_conditions(&mut shutdown_signal);
        while let Some(message) = self.tasks.get_next_message().await {
            self.check_exit_conditions(&mut shutdown_signal);
            self.handle_incoming_message(message);
        }

        match std::mem::replace(&mut self.state, DispatcherState::Normal) {
            DispatcherState::Errored(err) => {
                self.save_cache().await;
                Err(err)
            }
            DispatcherState::Interrupted => {
                self.save_cache().await;
                Ok(None)
            }
            DispatcherState::Normal => {
                self.apply_cache_to_shielded_context(&initial_state)?;
                self.ctx.save().await.map_err(|err| {
                    Error::Other(format!(
                        "Failed to save the shielded context: {err}"
                    ))
                })?;
                self.save_cache().await;
                Ok(Some(self.ctx))
            }
        }
    }

    async fn save_cache(&self) {
        if let Err(e) = self.ctx.utils.cache_save(&self.cache).await {
            tracing::error!(
                "Failed to save shielded sync cache with error {e}"
            );
        }
    }

    fn apply_cache_to_shielded_context(
        &mut self,
        InitialState {
            last_witnessed_tx, ..
        }: &InitialState,
    ) -> Result<(), Error> {
        if let Some((_, cmt)) = self.cache.commitment_tree.take() {
            self.ctx.tree = cmt;
        }
        if let Some((_, wm)) = self.cache.witness_map.take() {
            self.ctx.witness_map = wm;
        }
        if let Some((_, nm)) = self.cache.tx_note_map.take() {
            self.ctx.tx_note_map = nm;
        }

        for (indexed_tx, stx_batch) in self.cache.fetched.take() {
            if self.client.capabilities().needs_witness_map_update()
                && Some(&indexed_tx) > last_witnessed_tx.as_ref()
            {
                self.ctx.update_witness_map(indexed_tx, &stx_batch)?;
            }
            let mut note_pos = self.ctx.tx_note_map[&indexed_tx];
            let mut vk_heights = BTreeMap::new();
            std::mem::swap(&mut vk_heights, &mut self.ctx.vk_heights);
            for (vk, h) in vk_heights
                .iter_mut()
                .filter(|(_vk, h)| h.as_ref() < Some(&indexed_tx))
            {
                for (note, pa, memo) in self
                    .cache
                    .trial_decrypted
                    .take(&indexed_tx, vk)
                    .unwrap_or_default()
                {
                    self.ctx.save_decrypted_shielded_outputs(
                        vk, note_pos, note, pa, memo,
                    )?;
                    note_pos += 1;
                }
                *h = Some(indexed_tx);
            }
            self.ctx.save_shielded_spends(&stx_batch);
            std::mem::swap(&mut vk_heights, &mut self.ctx.vk_heights);
        }

        Ok(())
    }

    async fn perform_initial_setup(
        &mut self,
        start_query_height: Option<BlockHeight>,
        last_query_height: Option<BlockHeight>,
        sks: &[ExtendedSpendingKey],
        fvks: &[ViewingKey],
    ) -> Result<InitialState, Error> {
        if start_query_height > last_query_height {
            return Err(Error::Other(format!(
                "The start height {start_query_height:?} cannot be higher \
                 than the ending height {last_query_height:?} in the shielded \
                 sync"
            )));
        }

        for esk in sks {
            let vk = to_viewing_key(esk).vk;
            self.ctx.vk_heights.entry(vk).or_default();
        }
        for vk in fvks {
            self.ctx.vk_heights.entry(*vk).or_default();
        }

        // the latest block height which has been added to the witness Merkle
        // tree
        let last_witnessed_tx = self.ctx.tx_note_map.keys().max().cloned();

        // Query for the last produced block height
        let Some(last_block_height) = self.client.last_block_height().await?
        else {
            return Err(Error::Other(
                "No block has been committed yet".to_string(),
            ));
        };

        let last_query_height = last_query_height
            .unwrap_or(last_block_height)
            // NB: limit fetching until the last committed height
            .min(last_block_height);

        let start_height = start_query_height
            .map_or_else(|| self.ctx.min_height_to_sync_from(), Ok)?
            // NB: the start height cannot be greater than
            // `last_query_height`
            .min(last_query_height);

        let initial_state = InitialState {
            last_witnessed_tx,
            last_query_height,
            start_height,
        };

        self.height_to_sync = initial_state.last_query_height;
        self.spawn_initial_set_of_tasks(&initial_state);

        Ok(initial_state)
    }

    fn check_exit_conditions(&mut self, shutdown_signal: &mut ShutdownSignal) {
        if hints::unlikely(self.tasks.panic_flag.panicked()) {
            self.state = DispatcherState::Errored(Error::Other(
                "A worker thread panicked during the shielded sync".into(),
            ));
        }
        if matches!(
            &self.state,
            DispatcherState::Interrupted | DispatcherState::Errored(_)
        ) {
            return;
        }
        if shutdown_signal.received() {
            tracing::info!("Interrupt received, shutting down shielded sync");
            self.state = DispatcherState::Interrupted;
            self.interrupt_flag.set();
        }
    }

    fn spawn_initial_set_of_tasks(&mut self, initial_state: &InitialState) {
        if self.client.capabilities().may_fetch_pre_built_notes_map() {
            self.spawn_update_tx_notes_map(initial_state.last_query_height);
        }

        if self.client.capabilities().may_fetch_pre_built_tree() {
            self.spawn_update_commitment_tree(initial_state.last_query_height);
        }

        if self.client.capabilities().may_fetch_pre_built_witness_map() {
            self.spawn_update_witness_map(initial_state.last_query_height);
        }

        let batch_size = self.config.block_batch_size;
        for from in (initial_state.start_height.0
            ..=initial_state.last_query_height.0)
            .step_by(batch_size)
        {
            let to = (from + batch_size as u64 - 1)
                .min(initial_state.last_query_height.0);
            self.spawn_fetch_txs(BlockHeight(from), BlockHeight(to));
        }

        for (itx, txs) in self.cache.fetched.iter() {
            self.spawn_trial_decryptions(*itx, txs);
        }
    }

    fn handle_incoming_message(&mut self, message: Message) {
        match message {
            Message::UpdateCommitmentTree(Ok(ct)) => {
                _ = self
                    .cache
                    .commitment_tree
                    .insert((self.height_to_sync, ct));
            }
            Message::UpdateCommitmentTree(Err(TaskError {
                error,
                context: height,
            })) => {
                if self.can_launch_new_fetch_retry(error) {
                    self.spawn_update_commitment_tree(height);
                }
            }
            Message::UpdateNotesMap(Ok(nm)) => {
                _ = self.cache.tx_note_map.insert((self.height_to_sync, nm));
            }
            Message::UpdateNotesMap(Err(TaskError {
                error,
                context: height,
            })) => {
                if self.can_launch_new_fetch_retry(error) {
                    self.spawn_update_tx_notes_map(height);
                }
            }
            Message::UpdateWitnessMap(Ok(wm)) => {
                _ = self.cache.witness_map.insert((self.height_to_sync, wm));
            }
            Message::UpdateWitnessMap(Err(TaskError {
                error,
                context: height,
            })) => {
                if self.can_launch_new_fetch_retry(error) {
                    self.spawn_update_witness_map(height);
                }
            }
            Message::FetchTxs(Ok(tx_batch)) => {
                for (itx, txs) in &tx_batch {
                    self.spawn_trial_decryptions(*itx, txs);
                }
                self.cache.fetched.extend(tx_batch);
            }
            Message::FetchTxs(Err(TaskError {
                error,
                context: [from, to],
            })) => {
                if self.can_launch_new_fetch_retry(error) {
                    self.spawn_fetch_txs(from, to);
                }
            }
            Message::TrialDecrypt(itx, vk, decrypted_data) => {
                if let ControlFlow::Continue(decrypted_data) = decrypted_data {
                    self.cache.trial_decrypted.insert(itx, vk, decrypted_data);
                }
            }
        }
    }

    /// Check if we can launch a new fetch task retry.
    fn can_launch_new_fetch_retry(&mut self, error: Error) -> bool {
        if matches!(
            self.state,
            DispatcherState::Errored(_) | DispatcherState::Interrupted
        ) {
            return false;
        }

        if self.config.retry_strategy.may_retry() {
            tracing::warn!(reason = %error, "Fetch failure, retrying...");
            true
        } else {
            // NB: store last encountered error
            self.state = DispatcherState::Errored(error);
            false
        }
    }

    fn spawn_update_witness_map(&mut self, height: BlockHeight) {
        if pre_built_in_cache(self.cache.witness_map.as_ref(), height) {
            return;
        }
        let client = self.client.clone();
        self.spawn_async(Box::pin(async move {
            Message::UpdateWitnessMap(
                client.fetch_witness_map(height).await.map_err(|error| {
                    TaskError {
                        error,
                        context: height,
                    }
                }),
            )
        }));
    }

    fn spawn_update_commitment_tree(&mut self, height: BlockHeight) {
        if pre_built_in_cache(self.cache.commitment_tree.as_ref(), height) {
            return;
        }
        let client = self.client.clone();
        self.spawn_async(Box::pin(async move {
            Message::UpdateCommitmentTree(
                client.fetch_commitment_tree(height).await.map_err(|error| {
                    TaskError {
                        error,
                        context: height,
                    }
                }),
            )
        }));
    }

    fn spawn_update_tx_notes_map(&mut self, height: BlockHeight) {
        if pre_built_in_cache(self.cache.tx_note_map.as_ref(), height) {
            return;
        }
        let client = self.client.clone();
        self.spawn_async(Box::pin(async move {
            Message::UpdateNotesMap(
                client.fetch_tx_notes_map(height).await.map_err(|error| {
                    TaskError {
                        error,
                        context: height,
                    }
                }),
            )
        }));
    }

    fn spawn_fetch_txs(&self, from: BlockHeight, to: BlockHeight) {
        for [from, to] in blocks_left_to_fetch(from, to, &self.cache.fetched) {
            let client = self.client.clone();
            self.spawn_async(Box::pin(async move {
                Message::FetchTxs(
                    client.fetch_shielded_transfers(from, to).await.map_err(
                        |error| TaskError {
                            error,
                            context: [from, to],
                        },
                    ),
                )
            }));
        }
    }

    fn spawn_trial_decryptions(&self, itx: IndexedTx, txs: &[Transaction]) {
        for tx in txs {
            for vk in self.ctx.vk_heights.keys() {
                let vk = *vk;

                if self.cache.trial_decrypted.get(&itx, &vk).is_none() {
                    let tx = tx.clone();
                    self.spawn_sync(move |interrupt| {
                        Message::TrialDecrypt(
                            itx,
                            vk,
                            trial_decrypt(tx, vk, || interrupt.get()),
                        )
                    })
                }
            }
        }
    }

    fn spawn_async<F>(&self, mut fut: F)
    where
        F: Future<Output = Message> + Unpin + 'static,
    {
        let sender = self.tasks.message_sender.clone();
        let guard = (
            self.tasks.active_tasks.clone(),
            self.tasks.panic_flag.clone(),
        );
        let interrupt = self.interrupt_flag.clone();
        self.tasks.spawner.spawn_async(async move {
            let _guard = guard;
            let wrapped_fut = std::future::poll_fn(move |cx| {
                if interrupt.get() {
                    Poll::Ready(None)
                } else {
                    Pin::new(&mut fut).poll(cx).map(Some)
                }
            });
            if let Some(msg) = wrapped_fut.await {
                sender.send_async(msg).await.unwrap()
            }
        });
    }

    fn spawn_sync<F>(&self, job: F)
    where
        F: FnOnce(AtomicFlag) -> Message + Send + 'static,
    {
        let sender = self.tasks.message_sender.clone();
        let guard = (
            self.tasks.active_tasks.clone(),
            self.tasks.panic_flag.clone(),
        );
        let interrupt = self.interrupt_flag.clone();
        self.tasks.spawner.spawn_sync(move || {
            let _guard = guard;
            sender.send(job(interrupt)).unwrap();
        });
    }
}

#[inline(always)]
fn pre_built_in_cache<T>(
    pre_built_data: Option<&(BlockHeight, T)>,
    desired_height: BlockHeight,
) -> bool {
    matches!(pre_built_data, Some((h, _)) if *h == desired_height)
}

#[cfg(test)]
mod dispatcher_tests {
    use std::collections::{BTreeMap, BTreeSet};
    use std::hint::spin_loop;

    use futures::join;
    use namada_core::storage::{BlockHeight, TxIndex};
    use namada_tx::IndexedTx;
    use tempfile::tempdir;

    use super::*;
    use crate::control_flow::testing_shutdown_signal;
    use crate::masp::fs::FsShieldedUtils;
    use crate::masp::test_utils::{
        arbitrary_masp_tx, arbitrary_masp_tx_with_fee_unshielding,
        arbitrary_vk, TestingMaspClient,
    };
    use crate::masp::{MaspLocalTaskEnv, ShieldedSyncConfig};
    use crate::task_env::TaskEnvironment;

    #[tokio::test]
    async fn test_applying_cache_drains_decrypted_data() {
        let (client, _) = TestingMaspClient::new(BlockHeight::first());
        let config = ShieldedSyncConfig::builder().client(client).build();
        let temp_dir = tempdir().unwrap();
        let utils = FsShieldedUtils {
            context_dir: temp_dir.path().to_path_buf(),
        };
        MaspLocalTaskEnv::new(4)
            .expect("Test failed")
            .run(|s| async {
                let mut dispatcher = config.dispatcher(s, &utils).await;
                dispatcher.ctx.vk_heights =
                    BTreeMap::from([(arbitrary_vk(), None)]);
                // fill up the dispatcher's cache
                for h in 0u64..10 {
                    let itx = IndexedTx {
                        height: h.into(),
                        index: Default::default(),
                    };
                    dispatcher.cache.fetched.insert((itx, vec![]));
                    dispatcher.ctx.tx_note_map.insert(itx, h as usize);
                    dispatcher.cache.trial_decrypted.insert(
                        itx,
                        arbitrary_vk(),
                        vec![],
                    )
                }

                dispatcher
                    .apply_cache_to_shielded_context(&Default::default())
                    .expect("Test failed");
                assert!(dispatcher.cache.fetched.is_empty());
                assert!(dispatcher.cache.trial_decrypted.is_empty());
                let expected = BTreeMap::from([(
                    arbitrary_vk(),
                    Some(IndexedTx {
                        height: 9.into(),
                        index: Default::default(),
                    }),
                )]);
                assert_eq!(expected, dispatcher.ctx.vk_heights);
            })
            .await;
    }

    #[tokio::test]
    async fn test_async_counter_on_async_interrupt() {
        MaspLocalTaskEnv::new(1)
            .expect("Test failed")
            .run(|spawner| async move {
                let active_tasks = AsyncCounter::new();
                let interrupt = {
                    let int = AtomicFlag::default();

                    // preemptively set the task to an
                    // interrupted state
                    int.set();

                    int
                };

                // clone the active tasks handle,
                // to increment its internal ref count
                let guard = active_tasks.clone();

                let mut future = Box::pin(async move {
                    let _guard = guard;

                    // this future never yields, so the only
                    // wait to early exit is to be interrupted
                    // through the wrapped future
                    std::future::pending::<()>().await;
                });
                let interruptable_future = std::future::poll_fn(move |cx| {
                    if interrupt.get() {
                        // early exit here, by checking the interrupt state,
                        // which we immediately set above
                        Poll::Ready(())
                    } else {
                        Pin::new(&mut future).poll(cx)
                    }
                });

                spawner.spawn_async(interruptable_future);

                // sync with the spawned future by waiting
                // for the active tasks counter to reach zero
                active_tasks.await;
            })
            .await;
    }

    /// This test checks that a (sync / async) thread panicking
    /// * allows existing tasks to finish,
    /// * sets the panic flag
    /// * dispatcher returns the expected error
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn test_panic_flag() {
        test_panic_flag_aux(true).await;
        test_panic_flag_aux(false).await;
    }

    async fn test_panic_flag_aux(sync: bool) {
        let (client, _) = TestingMaspClient::new(BlockHeight::first());
        let config = ShieldedSyncConfig::builder().client(client).build();
        let temp_dir = tempdir().unwrap();
        let utils = FsShieldedUtils {
            context_dir: temp_dir.path().to_path_buf(),
        };
        _ = MaspLocalTaskEnv::new(4)
            .expect("Test failed")
            .run(|s| async {
                let dispatcher = config.dispatcher(s, &utils).await;

                let barrier = Arc::new(tokio::sync::Barrier::new(11));
                for _ in 0..10 {
                    let barrier = barrier.clone();
                    dispatcher.spawn_async(Box::pin(async move {
                        barrier.wait().await;
                        Message::UpdateWitnessMap(Err(TaskError {
                            error: Error::Other("Test".to_string()),
                            context: BlockHeight::first(),
                        }))
                    }));
                }
                assert!(!dispatcher.tasks.panic_flag.panicked());
                // panic a thread
                if sync {
                    dispatcher.spawn_sync(|_| panic!("OH NOES!"));
                } else {
                    dispatcher
                        .spawn_async(Box::pin(async { panic!("OH NOES!") }));
                }

                // run the dispatcher
                let (_sender, shutdown_signal) = testing_shutdown_signal();
                let flag = dispatcher.tasks.panic_flag.clone();
                let dispatcher_fut = dispatcher.run(
                    shutdown_signal,
                    Some(BlockHeight::first()),
                    Some(BlockHeight(10)),
                    &[],
                    &[],
                );

                // we poll the dispatcher future until the panic thread has
                // panicked.
                let wanker = Arc::new(AtomicWaker::new());
                let _ = {
                    let flag = flag.clone();
                    let wanker = wanker.clone();
                    std::thread::spawn(move || {
                        while !flag.panicked() {
                            spin_loop();
                        }
                        wanker.wake()
                    })
                };
                let panicked_fut = std::future::poll_fn(move |cx| {
                    if flag.panicked() {
                        Poll::Ready(())
                    } else {
                        wanker.register(cx.waker());
                        Poll::Pending
                    }
                });

                // we assert that the panic thread panicked and retrieve the
                // dispatcher future
                let Either::Right((_, fut)) =
                    select(Box::pin(dispatcher_fut), Box::pin(panicked_fut))
                        .await
                else {
                    panic!("Test failed")
                };

                let (_, res) = join! {
                    barrier.wait(),
                    fut,
                };

                let Err(Error::Other(ref msg)) = res else {
                    panic!("Test failed")
                };

                assert_eq!(
                    msg,
                    "A worker thread panicked during the shielded sync",
                );
            })
            .await;
    }

    /// Test that upon each retry, we either resume from the
    /// latest height that had been previously stored in the
    /// `tx_note_map`, or from the minimum height stored in
    /// `vk_heights`.
    #[test]
    fn test_min_height_to_sync_from() {
        let temp_dir = tempdir().unwrap();
        let mut shielded_ctx =
            FsShieldedUtils::new(temp_dir.path().to_path_buf());

        let vk = arbitrary_vk();

        // pretend we start with a tx observed at height 4 whose
        // notes cannot be decrypted with `vk`
        shielded_ctx.tx_note_map.insert(
            IndexedTx {
                height: 4.into(),
                index: TxIndex(0),
            },
            0,
        );

        // the min height here should be 1, since
        // this vk hasn't decrypted any note yet
        shielded_ctx.vk_heights.insert(vk, None);

        let height = shielded_ctx.min_height_to_sync_from().unwrap();
        assert_eq!(height, BlockHeight(1));

        // let's bump the vk height past 4
        *shielded_ctx.vk_heights.get_mut(&vk).unwrap() = Some(IndexedTx {
            height: 6.into(),
            index: TxIndex(0),
        });

        // the min height should now be 4
        let height = shielded_ctx.min_height_to_sync_from().unwrap();
        assert_eq!(height, BlockHeight(4));

        // and now we bump the last seen tx to height 8
        shielded_ctx.tx_note_map.insert(
            IndexedTx {
                height: 8.into(),
                index: TxIndex(0),
            },
            1,
        );

        // the min height should now be 6
        let height = shielded_ctx.min_height_to_sync_from().unwrap();
        assert_eq!(height, BlockHeight(6));
    }

    /// We test that if a masp transaction is only partially trial-decrypted
    /// before the process is interrupted, we discard the partial results.
    #[test]
    fn test_discard_partial_decryption() {
        let tx = arbitrary_masp_tx_with_fee_unshielding();
        let vk = arbitrary_vk();
        let guard = AtomicFlag::default();
        let interrupt = || {
            if guard.get() {
                true
            } else {
                guard.set();
                false
            }
        };
        let res = trial_decrypt(tx, vk, interrupt);
        assert_eq!(res, ControlFlow::Break(()));
    }

    /// Test that if fetching fails before finishing,
    /// we re-establish the fetching process
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_retry_fetch() {
        let temp_dir = tempdir().unwrap();
        let utils = FsShieldedUtils {
            context_dir: temp_dir.path().to_path_buf(),
        };
        let (client, masp_tx_sender) = TestingMaspClient::new(2.into());
        let mut config = ShieldedSyncConfig::builder()
            .client(client)
            .retry_strategy(RetryStrategy::Times(0))
            .build();
        let vk = arbitrary_vk();

        // we first test that with no retries, a fetching failure
        // stops process
        MaspLocalTaskEnv::new(4)
            .expect("Test failed")
            .run(|s| async {
                masp_tx_sender.send(None).expect("Test failed");
                let dispatcher = config.clone().dispatcher(s, &utils).await;

                let (_send, shutdown_sig) = testing_shutdown_signal();
                let result =
                    dispatcher.run(shutdown_sig, None, None, &[], &[vk]).await;
                match result {
                    Err(Error::Other(msg)) => assert_eq!(
                        msg.as_str(),
                        "After retrying, could not fetch all MASP txs."
                    ),
                    other => {
                        panic!("{:?} does not match Error::Other(_)", other)
                    }
                }
            })
            .await;

        MaspLocalTaskEnv::new(4)
            .expect("Test failed")
            .run(|s| async {
                // We now have a fetch failure followed by two successful
                // masp txs from the same block.
                let masp_tx = arbitrary_masp_tx();
                masp_tx_sender.send(None).expect("Test failed");
                masp_tx_sender
                    .send(Some((
                        IndexedTx {
                            height: 1.into(),
                            index: TxIndex(1),
                        },
                        vec![masp_tx.clone()],
                    )))
                    .expect("Test failed");
                masp_tx_sender
                    .send(Some((
                        IndexedTx {
                            height: 1.into(),
                            index: TxIndex(2),
                        },
                        vec![masp_tx.clone()],
                    )))
                    .expect("Test failed");
                config.retry_strategy = RetryStrategy::Times(1);
                let dispatcher = config.dispatcher(s, &utils).await;
                let (_send, shutdown_sig) = testing_shutdown_signal();
                // This should complete successfully
                let ctx = dispatcher
                    .run(shutdown_sig, None, None, &[], &[vk])
                    .await
                    .expect("Test failed")
                    .expect("Test failed");
                let keys =
                    ctx.tx_note_map.keys().cloned().collect::<BTreeSet<_>>();
                let expected = BTreeSet::from([
                    IndexedTx {
                        height: 1.into(),
                        index: TxIndex(1),
                    },
                    IndexedTx {
                        height: 1.into(),
                        index: TxIndex(2),
                    },
                ]);

                assert_eq!(keys, expected);
                assert_eq!(
                    *ctx.vk_heights[&vk].as_ref().unwrap(),
                    IndexedTx {
                        height: 1.into(),
                        index: TxIndex(2),
                    }
                );
                assert_eq!(ctx.note_map.len(), 2);
            })
            .await;
    }

    /// Test that if we don't scan all fetched notes, they
    /// are persisted in a cache
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_unscanned_cache() {
        let temp_dir = tempdir().unwrap();
        let utils = FsShieldedUtils {
            context_dir: temp_dir.path().to_path_buf(),
        };
        let (client, masp_tx_sender) = TestingMaspClient::new(3.into());
        let config = ShieldedSyncConfig::builder()
            .client(client)
            .retry_strategy(RetryStrategy::Times(0))
            .block_batch_size(1)
            .build();

        let vk = arbitrary_vk();
        MaspLocalTaskEnv::new(4)
            .expect("Test failed")
            .run(|s| async {
                let dispatcher = config.clone().dispatcher(s, &utils).await;

                let masp_tx = arbitrary_masp_tx();
                masp_tx_sender
                    .send(Some((
                        IndexedTx {
                            height: 1.into(),
                            index: TxIndex(1),
                        },
                        vec![masp_tx.clone()],
                    )))
                    .expect("Test failed");
                masp_tx_sender
                    .send(Some((
                        IndexedTx {
                            height: 1.into(),
                            index: TxIndex(2),
                        },
                        vec![masp_tx.clone()],
                    )))
                    .expect("Test failed");
                masp_tx_sender.send(None).expect("Test failed");
                let (_send, shutdown_sig) = testing_shutdown_signal();
                let result =
                    dispatcher.run(shutdown_sig, None, None, &[], &[vk]).await;
                match result {
                    Err(Error::Other(msg)) => assert_eq!(
                        msg.as_str(),
                        "After retrying, could not fetch all MASP txs."
                    ),
                    other => {
                        panic!("{:?} does not match Error::Other(_)", other)
                    }
                }
                let cache = utils.cache_load().await.expect("Test failed");
                let expected = BTreeMap::from([
                    (
                        IndexedTx {
                            height: 1.into(),
                            index: TxIndex(1),
                        },
                        vec![masp_tx.clone()],
                    ),
                    (
                        IndexedTx {
                            height: 1.into(),
                            index: TxIndex(2),
                        },
                        vec![masp_tx.clone()],
                    ),
                ]);
                assert_eq!(cache.fetched.txs, expected);
            })
            .await;
    }

    /// Test that we can successfully interrupt the dispatcher
    /// and that it cleans up after itself.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_interrupt() {
        let temp_dir = tempdir().unwrap();
        let utils = FsShieldedUtils {
            context_dir: temp_dir.path().to_path_buf(),
        };
        let (client, masp_tx_sender) = TestingMaspClient::new(2.into());
        let config = ShieldedSyncConfig::builder()
            .client(client)
            .retry_strategy(RetryStrategy::Times(0))
            .block_batch_size(2)
            .build();

        MaspLocalTaskEnv::new(4)
            .expect("Test failed")
            .run(|s| async {
                let dispatcher = config.clone().dispatcher(s, &utils).await;

                // we expect a batch of two blocks, but we only send one
                let masp_tx = arbitrary_masp_tx();
                masp_tx_sender
                    .send(Some((
                        IndexedTx {
                            height: 1.into(),
                            index: TxIndex(1),
                        },
                        vec![masp_tx.clone()],
                    )))
                    .expect("Test failed");

                let (send, shutdown_sig) = testing_shutdown_signal();
                send.send(()).expect("Test failed");
                let res = dispatcher
                    .run(shutdown_sig, None, None, &[], &[arbitrary_vk()])
                    .await
                    .expect("Test failed");
                assert!(res.is_none());

                let DispatcherCache {
                    commitment_tree,
                    witness_map,
                    tx_note_map,
                    fetched,
                    trial_decrypted,
                } = utils.cache_load().await.expect("Test failed");
                assert!(commitment_tree.is_none());
                assert!(witness_map.is_none());
                assert!(tx_note_map.is_none());
                assert!(fetched.is_empty());
                assert!(trial_decrypted.is_empty());
            })
            .await;
    }
}
