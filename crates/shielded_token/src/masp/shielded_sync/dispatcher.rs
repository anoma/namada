use std::cell::RefCell;
use std::collections::BTreeMap;
use std::future::Future;
use std::ops::ControlFlow;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{self, AtomicBool, AtomicUsize};
use std::task::{Context, Poll};

use borsh::{BorshDeserialize, BorshSerialize};
use eyre::{WrapErr, eyre};
use futures::future::{Either, select};
use futures::task::AtomicWaker;
use kassandra::IndexList;
use masp_primitives::merkle_tree::{CommitmentTree, IncrementalWitness};
use masp_primitives::sapling::{Node, ViewingKey};
use masp_primitives::transaction::Transaction;
use namada_core::chain::BlockHeight;
use namada_core::collections::HashMap;
use namada_core::control_flow::ShutdownSignal;
use namada_core::control_flow::time::{Duration, LinearBackoff, Sleep};
use namada_core::hints;
use namada_core::task_env::TaskSpawner;
use namada_io::{MaybeSend, MaybeSync, ProgressBar};
use namada_tx::IndexedTx;
use namada_wallet::{DatedKeypair, DatedSpendingKey};

use super::utils::{IndexedNoteEntry, MaspClient, MaspIndexedTx, MaspTxKind};
use crate::masp::shielded_sync::trial_decrypt;
use crate::masp::shielded_wallet::KeySyncData;
use crate::masp::utils::{
    DecryptedData, Fetched, RetryStrategy, TrialDecrypted, blocks_left_to_fetch,
};
use crate::masp::{
    MaspExtendedSpendingKey, NoteIndex, ShieldedUtils, ShieldedWallet,
    WitnessMap, to_viewing_key,
};

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
    error: eyre::Error,
    context: C,
}

#[allow(clippy::large_enum_variant)]
enum Message {
    UpdateCommitmentTree(Result<CommitmentTree<Node>, TaskError<BlockHeight>>),
    UpdateNotesMap(
        Result<BTreeMap<MaspIndexedTx, usize>, TaskError<BlockHeight>>,
    ),
    UpdateWitnessMap(
        Result<
            HashMap<usize, IncrementalWitness<Node>>,
            TaskError<BlockHeight>,
        >,
    ),
    FetchTxs(
        Result<
            (BlockHeight, BlockHeight, Vec<IndexedNoteEntry>),
            TaskError<[BlockHeight; 2]>,
        >,
    ),
    TrialDecrypt(
        MaspIndexedTx,
        ViewingKey,
        ControlFlow<(), BTreeMap<usize, DecryptedData>>,
    ),
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
            // NB: queueing a message to a channel doesn't mean we
            // actually consume it. we must wait for the channel to
            // be drained when all tasks have returned. the spin loop
            // hint below helps the compiler to optimize the `try_recv`
            // branch, to avoid maxing out the cpu.
            std::hint::spin_loop();
            self.message_receiver.try_recv().ok()
        }
    }
}

/// Shielded sync cache.
#[derive(Default, BorshSerialize, BorshDeserialize)]
pub struct DispatcherCache {
    pub(crate) commitment_tree: Option<(BlockHeight, CommitmentTree<Node>)>,
    pub(crate) witness_map: Option<(BlockHeight, WitnessMap)>,
    pub(crate) note_index: Option<(BlockHeight, NoteIndex)>,
    pub(crate) fetched: Fetched,
    pub(crate) trial_decrypted: TrialDecrypted,
}

#[derive(Debug)]
enum DispatcherState {
    Normal,
    Interrupted,
    Errored(eyre::Error),
}

#[derive(Default, Debug)]
struct InitialState {
    last_witnessed_tx: Option<MaspIndexedTx>,
    start_height: BlockHeight,
    last_query_height: BlockHeight,
}

pub struct Config<T, I> {
    pub wait_for_last_query_height: bool,
    pub retry_strategy: RetryStrategy,
    pub block_batch_size: usize,
    pub channel_buffer_size: usize,
    pub fetched_tracker: T,
    pub scanned_tracker: T,
    pub applied_tracker: T,
    pub shutdown_signal: I,
}

/// Shielded sync message dispatcher.
pub struct Dispatcher<S, M, U, T, I>
where
    U: ShieldedUtils,
{
    client: M,
    state: DispatcherState,
    tasks: DispatcherTasks<S>,
    ctx: ShieldedWallet<U>,
    config: Config<T, I>,
    cache: DispatcherCache,
    /// We are syncing up to this height
    height_to_sync: BlockHeight,
    interrupt_flag: AtomicFlag,
}

/// Create a new dispatcher in the initial state.
///
/// This function assumes that the provided shielded context has
/// already been loaded from storage.
pub async fn new<S, M, U, T, I>(
    spawner: S,
    client: M,
    utils: &U,
    config: Config<T, I>,
) -> Dispatcher<S, M, U, T, I>
where
    U: ShieldedUtils + MaybeSend + MaybeSync,
{
    let ctx = {
        let mut ctx = ShieldedWallet {
            utils: utils.clone(),
            ..Default::default()
        };

        _ = ctx.load_confirmed().await;

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

    #[allow(clippy::disallowed_methods)]
    let cache = ctx.utils.cache_load().await.unwrap_or_default();

    Dispatcher {
        height_to_sync: BlockHeight(0),
        state,
        ctx,
        tasks,
        client,
        config,
        cache,
        interrupt_flag: Default::default(),
    }
}

impl<S, M, U, T, I> Dispatcher<S, M, U, T, I>
where
    S: TaskSpawner,
    M: MaspClient + Send + Sync + Unpin + 'static,
    U: ShieldedUtils + MaybeSend + MaybeSync,
    T: ProgressBar,
    I: ShutdownSignal,
{
    /// Run the dispatcher
    pub async fn run(
        mut self,
        start_query_height: Option<BlockHeight>,
        last_query_height: Option<BlockHeight>,
        sks: &[(DatedSpendingKey, Option<IndexList>)],
        fvks: &[(DatedKeypair<ViewingKey>, Option<IndexList>)],
    ) -> Result<Option<ShieldedWallet<U>>, eyre::Error> {
        let initial_state = self
            .perform_initial_setup(
                start_query_height,
                last_query_height,
                sks,
                fvks,
            )
            .await?;

        self.check_exit_conditions();

        while let Some(message) = self.tasks.get_next_message().await {
            self.check_exit_conditions();
            self.handle_incoming_message(message);
        }

        match std::mem::replace(&mut self.state, DispatcherState::Normal) {
            DispatcherState::Errored(err) => {
                self.finish_progress_bars();
                self.save_cache().await;
                Err(err)
            }
            DispatcherState::Interrupted => {
                self.finish_progress_bars();
                self.save_cache().await;
                Ok(None)
            }
            DispatcherState::Normal => {
                self.apply_cache_to_shielded_context(&initial_state).await?;
                self.finish_progress_bars();
                self.ctx.save().await.map_err(|err| {
                    eyre!("Failed to save the shielded context: {err}")
                })?;
                self.save_cache().await;
                Ok(Some(self.ctx))
            }
        }
    }

    fn force_redraw_progress_bars(&mut self) {
        self.config.fetched_tracker.increment_by(0);
        self.config.scanned_tracker.increment_by(0);
        self.config.applied_tracker.increment_by(0);
    }

    fn finish_progress_bars(&mut self) {
        self.config.fetched_tracker.finish();
        self.config.scanned_tracker.finish();
        self.config.applied_tracker.finish();
    }

    async fn save_cache(&mut self) {
        if let Err(e) = self.ctx.utils.cache_save(&self.cache).await {
            self.config.fetched_tracker.message(format!(
                "Failed to save shielded sync cache with error {e}"
            ));
        }
    }

    async fn apply_cache_to_shielded_context(
        &mut self,
        InitialState {
            last_witnessed_tx,
            last_query_height,
            ..
        }: &InitialState,
    ) -> Result<(), eyre::Error> {
        if let Some((_, cmt)) = self.cache.commitment_tree.take() {
            self.ctx.tree = cmt;
        }
        if let Some((_, wm)) = self.cache.witness_map.take() {
            self.ctx.witness_map = wm;
        }
        if let Some((_, nm)) = self.cache.note_index.take() {
            self.ctx.note_index = nm;
        }

        for (masp_indexed_tx, stx_batch) in self.cache.fetched.take() {
            let needs_witness_map_update =
                self.client.capabilities().needs_witness_map_update();
            self.ctx
                .save_shielded_spends(&stx_batch, needs_witness_map_update);
            if needs_witness_map_update
                && Some(&masp_indexed_tx) > last_witnessed_tx.as_ref()
            {
                self.ctx.update_witness_map(masp_indexed_tx, &stx_batch)?;
            }
            let first_note_pos = self.ctx.note_index[&masp_indexed_tx];
            let mut vk_sync = BTreeMap::new();
            std::mem::swap(&mut vk_sync, &mut self.ctx.vk_sync);
            for (vk, _) in vk_sync
                .iter()
                // NB: skip keys that are synced past the given `indexed_tx`
                .filter(|(_vk, h)| h.height < masp_indexed_tx)
            {
                for (note_pos_offset, (note, pa, memo)) in self
                    .cache
                    .trial_decrypted
                    .take(&masp_indexed_tx, vk)
                    .unwrap_or_default()
                {
                    self.ctx.save_decrypted_shielded_outputs(
                        vk,
                        first_note_pos + note_pos_offset,
                        note,
                        pa,
                        memo,
                    )?;
                    self.config.applied_tracker.increment_by(1);
                }
            }
            std::mem::swap(&mut vk_sync, &mut self.ctx.vk_sync);
        }

        for (_, h) in self
            .ctx
            .vk_sync
            .iter_mut()
            // NB: skip keys that are synced past the last input height
            .filter(|(_vk, h)| {
                h.height.indexed_tx.block_height < *last_query_height
            })
        {
            // NB: the entire block is synced
            *h = KeySyncData {
                height: MaspIndexedTx {
                    indexed_tx: IndexedTx::entire_block(*last_query_height),
                    kind: MaspTxKind::Transfer,
                },
                fmd_indices: h.fmd_indices.take(),
            };
        }

        Ok(())
    }

    async fn perform_initial_setup(
        &mut self,
        start_query_height: Option<BlockHeight>,
        last_query_height: Option<BlockHeight>,
        sks: &[(DatedSpendingKey, Option<IndexList>)],
        fvks: &[(DatedKeypair<ViewingKey>, Option<IndexList>)],
    ) -> Result<InitialState, eyre::Error> {
        if start_query_height > last_query_height {
            return Err(eyre!(
                "The start height {start_query_height:?} cannot be higher \
                 than the ending height {last_query_height:?} in the shielded \
                 sync"
            ));
        }

        for (vk, mut fmd) in sks
            .iter()
            .map(|(esk, fmd)| {
                (
                    esk.map(|k| {
                        to_viewing_key(&MaspExtendedSpendingKey::from(k)).vk
                    }),
                    fmd.clone(),
                )
            })
            .chain(fvks.iter().cloned())
        {
            if let Some(h) = self.ctx.vk_sync.get_mut(&vk.key) {
                let birthday = IndexedTx::entire_block(vk.birthday);
                if birthday > h.height.indexed_tx {
                    h.height.indexed_tx = birthday;
                }
                if let Some(ixs) = fmd.as_mut() {
                    ixs.retain(|ix| {
                        ix.height >= h.height.indexed_tx.block_height.0
                    });
                }
                h.fmd_indices = fmd;
            } else {
                self.ctx.vk_sync.insert(
                    vk.key,
                    KeySyncData {
                        height: MaspIndexedTx {
                            indexed_tx: IndexedTx::entire_block(vk.birthday),
                            kind: MaspTxKind::Transfer,
                        },
                        fmd_indices: fmd,
                    },
                );
            }
        }

        // Add the fmd indices to the client
        self.client.set_fmd_indices(self.ctx.combined_fmd_indices());

        // the latest block height which has been added to the witness Merkle
        // tree
        let last_witnessed_tx = self.ctx.note_index.keys().max().cloned();

        let shutdown_signal = RefCell::new(&mut self.config.shutdown_signal);

        let last_block_height = Sleep {
            strategy: LinearBackoff {
                delta: Duration::from_millis(100),
            },
        }
        .run(|| async {
            if self.config.wait_for_last_query_height
                && shutdown_signal.borrow_mut().received()
            {
                return ControlFlow::Break(Err(eyre!(
                    "Interrupted while waiting for last query height",
                )));
            }

            // Query for the last produced block height
            let last_block_height = match self
                .client
                .last_block_height()
                .await
                .wrap_err("Failed to fetch last  block height")
            {
                Ok(Some(last_block_height)) => last_block_height,
                Ok(None) => {
                    return if self.config.wait_for_last_query_height {
                        ControlFlow::Continue(())
                    } else {
                        ControlFlow::Break(Err(eyre!(
                            "No block has been committed yet",
                        )))
                    };
                }
                Err(err) => return ControlFlow::Break(Err(err)),
            };

            if self.config.wait_for_last_query_height
                && Some(last_block_height) < last_query_height
            {
                ControlFlow::Continue(())
            } else {
                ControlFlow::Break(Ok(last_block_height))
            }
        })
        .await?;

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

        self.config
            .scanned_tracker
            .set_upper_limit(self.cache.fetched.len() as u64);
        self.config.applied_tracker.set_upper_limit(
            self.cache.trial_decrypted.successful_decryptions() as u64,
        );

        self.force_redraw_progress_bars();

        Ok(initial_state)
    }

    fn check_exit_conditions(&mut self) {
        if hints::unlikely(self.tasks.panic_flag.panicked()) {
            self.state = DispatcherState::Errored(eyre!(
                "A worker thread panicked during the shielded sync".to_string(),
            ));
        }
        if matches!(
            &self.state,
            DispatcherState::Interrupted | DispatcherState::Errored(_)
        ) {
            return;
        }
        if self.config.shutdown_signal.received() {
            self.config.fetched_tracker.message(
                "Interrupt received, shutting down shielded sync".to_string(),
            );
            self.state = DispatcherState::Interrupted;
            self.interrupt_flag.set();
        }
    }

    fn spawn_initial_set_of_tasks(&mut self, initial_state: &InitialState) {
        if self.client.capabilities().may_fetch_pre_built_notes_index() {
            self.spawn_update_note_index(initial_state.last_query_height);
        }

        if self.client.capabilities().may_fetch_pre_built_tree() {
            self.spawn_update_commitment_tree(initial_state.last_query_height);
        }

        if self.client.capabilities().may_fetch_pre_built_witness_map() {
            self.spawn_update_witness_map(initial_state.last_query_height);
        }

        let mut number_of_fetches = 0;
        let batch_size = self.config.block_batch_size;
        for from in (initial_state.start_height.0
            ..=initial_state.last_query_height.0)
            .step_by(batch_size)
        {
            let to = (from + batch_size as u64 - 1)
                .min(initial_state.last_query_height.0);
            number_of_fetches +=
                self.spawn_fetch_txs(BlockHeight(from), BlockHeight(to));
        }

        self.config
            .fetched_tracker
            .set_upper_limit(number_of_fetches);

        for (itx, tx) in self.cache.fetched.iter() {
            self.spawn_trial_decryptions(*itx, tx);
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
                _ = self.cache.note_index.insert((self.height_to_sync, nm));
            }
            Message::UpdateNotesMap(Err(TaskError {
                error,
                context: height,
            })) => {
                if self.can_launch_new_fetch_retry(error) {
                    self.spawn_update_note_index(height);
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
            Message::FetchTxs(Ok((from, to, tx_batch))) => {
                for (itx, tx) in &tx_batch {
                    self.spawn_trial_decryptions(*itx, tx);
                }
                self.cache.fetched.extend(tx_batch);

                self.config.fetched_tracker.increment_by(to.0 - from.0 + 1);
                self.config
                    .scanned_tracker
                    .set_upper_limit(self.cache.fetched.len() as u64);
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
                    self.config.applied_tracker.set_upper_limit(
                        self.config.applied_tracker.upper_limit()
                            + decrypted_data.len() as u64,
                    );
                    self.cache.trial_decrypted.insert(itx, vk, decrypted_data);
                    self.config.scanned_tracker.increment_by(1);
                }
            }
        }
    }

    /// Check if we can launch a new fetch task retry.
    fn can_launch_new_fetch_retry(&mut self, error: eyre::Error) -> bool {
        if matches!(
            self.state,
            DispatcherState::Errored(_) | DispatcherState::Interrupted
        ) {
            return false;
        }

        if self.config.retry_strategy.may_retry() {
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
                client
                    .fetch_witness_map(height)
                    .await
                    .wrap_err("Failed to fetch witness map")
                    .map_err(|error| TaskError {
                        error,
                        context: height,
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
                client
                    .fetch_commitment_tree(height)
                    .await
                    .wrap_err("Failed to fetch commitment tree")
                    .map_err(|error| TaskError {
                        error,
                        context: height,
                    }),
            )
        }));
    }

    fn spawn_update_note_index(&mut self, height: BlockHeight) {
        if pre_built_in_cache(self.cache.note_index.as_ref(), height) {
            return;
        }
        let client = self.client.clone();
        self.spawn_async(Box::pin(async move {
            Message::UpdateNotesMap(
                client
                    .fetch_note_index(height)
                    .await
                    .wrap_err("Failed to fetch note index")
                    .map_err(|error| TaskError {
                        error,
                        context: height,
                    }),
            )
        }));
    }

    fn spawn_fetch_txs(&self, from: BlockHeight, to: BlockHeight) -> u64 {
        let mut spawned_tasks = 0;

        for [from, to] in blocks_left_to_fetch(from, to, &self.cache.fetched) {
            let client = self.client.clone();
            spawned_tasks += to.0 - from.0 + 1;
            self.spawn_async(Box::pin(async move {
                Message::FetchTxs(
                    client
                        .fetch_shielded_transfers(from, to)
                        .await
                        .wrap_err("Failed to fetch shielded transfers")
                        .map_err(|error| TaskError {
                            error,
                            context: [from, to],
                        })
                        .map(|batch| (from, to, batch)),
                )
            }));
        }

        spawned_tasks
    }

    fn spawn_trial_decryptions(&self, itx: MaspIndexedTx, tx: &Transaction) {
        for (vk, vk_sync) in self.ctx.vk_sync.iter() {
            let key_is_outdated = vk_sync.height < itx;
            let cached = self.cache.trial_decrypted.get(&itx, vk).is_some();
            if key_is_outdated && !cached && vk_sync.flagged(&itx) {
                let tx = tx.clone();
                let vk = *vk;

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
    use kassandra::Index;
    use namada_core::chain::BlockHeight;
    use namada_core::control_flow::testing::shutdown_signal;
    use namada_core::storage::TxIndex;
    use namada_core::task_env::TaskEnvironment;
    use namada_io::DevNullProgressBar;
    use namada_tx::IndexedTx;
    use namada_wallet::StoredKeypair;
    use tempfile::tempdir;

    use super::*;
    use crate::masp::fs::FsShieldedUtils;
    use crate::masp::test_utils::{
        TestingMaspClient, arbitrary_masp_tx,
        arbitrary_masp_tx_with_fee_unshielding, arbitrary_vk,
        dated_arbitrary_vk,
    };
    use crate::masp::utils::MaspIndexedTx;
    use crate::masp::{MaspLocalTaskEnv, ShieldedSyncConfig};

    /// Test that we prune the fmd indices based on the
    /// height a key is synced to when starting up.
    #[tokio::test]
    async fn test_fmd_filtered_on_initial_setup() {
        let (client, _) = TestingMaspClient::new(BlockHeight::first());
        let (_sender, shutdown_sig) = shutdown_signal();
        let config = ShieldedSyncConfig::builder()
            .client(client)
            .fetched_tracker(DevNullProgressBar)
            .scanned_tracker(DevNullProgressBar)
            .applied_tracker(DevNullProgressBar)
            .shutdown_signal(shutdown_sig)
            .build();
        let temp_dir = tempdir().unwrap();
        let utils = FsShieldedUtils {
            context_dir: temp_dir.path().to_path_buf(),
        };
        MaspLocalTaskEnv::new(4)
            .expect("Test failed")
            .run(|s| async {
                let mut dispatcher = config.dispatcher(s, &utils).await;
                dispatcher.ctx.vk_sync = BTreeMap::from([(
                    arbitrary_vk(),
                    KeySyncData {
                        height: MaspIndexedTx {
                            kind: Default::default(),
                            indexed_tx: IndexedTx::entire_block(10.into()),
                        },
                        fmd_indices: Some(
                            [
                                Index { height: 5, tx: 0 },
                                Index { height: 15, tx: 0 },
                            ]
                            .into_iter()
                            .collect(),
                        ),
                    },
                )]);
                dispatcher
                    .perform_initial_setup(
                        None,
                        None,
                        &[],
                        &[(
                            arbitrary_vk().into(),
                            Some(
                                [
                                    Index { height: 5, tx: 0 },
                                    Index { height: 15, tx: 0 },
                                    Index { height: 20, tx: 0 },
                                ]
                                .into_iter()
                                .collect(),
                            ),
                        )],
                    )
                    .await
                    .expect("Test failed");

                let expected = BTreeMap::from([(
                    arbitrary_vk(),
                    KeySyncData {
                        height: MaspIndexedTx {
                            kind: Default::default(),
                            indexed_tx: IndexedTx::entire_block(10.into()),
                        },
                        fmd_indices: Some(
                            [
                                Index { height: 15, tx: 0 },
                                Index { height: 20, tx: 0 },
                            ]
                            .into_iter()
                            .collect(),
                        ),
                    },
                )]);
                assert_eq!(expected, dispatcher.ctx.vk_sync);
            })
            .await;
    }

    #[tokio::test]
    async fn test_applying_cache_drains_decrypted_data() {
        let (client, _) = TestingMaspClient::new(BlockHeight::first());
        let (_sender, shutdown_sig) = shutdown_signal();
        let config = ShieldedSyncConfig::builder()
            .client(client)
            .fetched_tracker(DevNullProgressBar)
            .scanned_tracker(DevNullProgressBar)
            .applied_tracker(DevNullProgressBar)
            .shutdown_signal(shutdown_sig)
            .build();
        let temp_dir = tempdir().unwrap();
        let utils = FsShieldedUtils {
            context_dir: temp_dir.path().to_path_buf(),
        };
        MaspLocalTaskEnv::new(4)
            .expect("Test failed")
            .run(|s| async {
                let mut dispatcher = config.dispatcher(s, &utils).await;
                dispatcher.ctx.vk_sync =
                    BTreeMap::from([(arbitrary_vk(), Default::default())]);
                // fill up the dispatcher's cache
                for h in 2u64..=10 {
                    let itx = MaspIndexedTx {
                        indexed_tx: IndexedTx {
                            block_height: h.into(),
                            block_index: Default::default(),
                            batch_index: None,
                        },
                        kind: MaspTxKind::Transfer,
                    };
                    dispatcher.cache.fetched.insert((itx, arbitrary_masp_tx()));
                    dispatcher.ctx.note_index.insert(itx, h as usize);
                    dispatcher.cache.trial_decrypted.insert(
                        itx,
                        arbitrary_vk(),
                        BTreeMap::new(),
                    )
                }

                dispatcher
                    .apply_cache_to_shielded_context(&InitialState {
                        last_witnessed_tx: None,
                        start_height: Default::default(),
                        last_query_height: 10.into(),
                    })
                    .await
                    .expect("Test failed");
                assert!(dispatcher.cache.fetched.is_empty());
                assert!(dispatcher.cache.trial_decrypted.is_empty());
                let expected = BTreeMap::from([(
                    arbitrary_vk(),
                    KeySyncData {
                        height: MaspIndexedTx {
                            indexed_tx: IndexedTx::entire_block(10.into()),
                            kind: MaspTxKind::Transfer,
                        },
                        ..Default::default()
                    },
                )]);
                assert_eq!(expected, dispatcher.ctx.vk_sync);
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

                let mut never_yielding_future = Box::pin(async move {
                    let _guard = guard;

                    // this future never yields, so the only
                    // way to early exit is to be interrupted
                    // through the wrapped future
                    std::future::pending::<()>().await;
                });
                let interruptable_future = std::future::poll_fn(move |cx| {
                    if interrupt.get() {
                        // early exit here, by checking the interrupt state,
                        // which we immediately set above
                        Poll::Ready(())
                    } else {
                        Pin::new(&mut never_yielding_future).poll(cx)
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
        let (_sender, shutdown_signal) = shutdown_signal();
        let config = ShieldedSyncConfig::builder()
            .fetched_tracker(DevNullProgressBar)
            .scanned_tracker(DevNullProgressBar)
            .applied_tracker(DevNullProgressBar)
            .shutdown_signal(shutdown_signal)
            .client(client)
            .build();
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
                            error: eyre!("Test"),
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
                let flag = dispatcher.tasks.panic_flag.clone();
                let dispatcher_fut = dispatcher.run(
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

                let Err(msg) = res else { panic!("Test failed") };

                assert_eq!(
                    msg.to_string(),
                    "A worker thread panicked during the shielded sync",
                );
            })
            .await;
    }

    /// Test that upon each retry, we either resume from the
    /// latest height that had been previously stored in the
    /// `vk_sync`.
    #[test]
    fn test_min_height_to_sync_from() {
        let temp_dir = tempdir().unwrap();
        let mut shielded_ctx =
            FsShieldedUtils::new(temp_dir.path().to_path_buf());

        let vk = arbitrary_vk();

        // Test that this function errors if not keys are
        // present in the shielded context
        assert!(shielded_ctx.min_height_to_sync_from().is_err());

        // the min height here should be 1, since
        // this vk hasn't decrypted any note yet
        shielded_ctx.vk_sync.insert(vk, KeySyncData::default());

        let height = shielded_ctx.min_height_to_sync_from().unwrap();
        assert_eq!(height, BlockHeight(1));

        // let's bump the vk height
        shielded_ctx.vk_sync.get_mut(&vk).unwrap().height = MaspIndexedTx {
            indexed_tx: IndexedTx {
                block_height: 6.into(),
                block_index: TxIndex(0),
                batch_index: None,
            },
            kind: MaspTxKind::Transfer,
        };

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
        let (client, masp_tx_sender) = TestingMaspClient::new(3.into());
        let (_send, shutdown_sig) = shutdown_signal();
        let mut config = ShieldedSyncConfig::builder()
            .fetched_tracker(DevNullProgressBar)
            .scanned_tracker(DevNullProgressBar)
            .applied_tracker(DevNullProgressBar)
            .shutdown_signal(shutdown_sig)
            .client(client)
            .retry_strategy(RetryStrategy::Times(0))
            .build();
        let vk = dated_arbitrary_vk();

        // we first test that with no retries, a fetching failure
        // stops process
        MaspLocalTaskEnv::new(4)
            .expect("Test failed")
            .run(|s| async {
                masp_tx_sender.send(None).expect("Test failed");
                let dispatcher = config.clone().dispatcher(s, &utils).await;

                let result =
                    dispatcher.run(None, None, &[], &[(vk, None)]).await;
                match result {
                    Err(msg) => assert_eq!(
                        msg.to_string(),
                        "Failed to fetch shielded transfers"
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
                        MaspIndexedTx {
                            indexed_tx: IndexedTx {
                                block_height: 2.into(),
                                block_index: TxIndex(1),
                                batch_index: None,
                            },
                            kind: MaspTxKind::Transfer,
                        },
                        masp_tx.clone(),
                    )))
                    .expect("Test failed");
                masp_tx_sender
                    .send(Some((
                        MaspIndexedTx {
                            indexed_tx: IndexedTx {
                                block_height: 2.into(),
                                block_index: TxIndex(2),
                                batch_index: None,
                            },
                            kind: MaspTxKind::Transfer,
                        },
                        masp_tx.clone(),
                    )))
                    .expect("Test failed");
                config.retry_strategy = RetryStrategy::Times(1);
                let dispatcher = config.dispatcher(s, &utils).await;
                // This should complete successfully
                let ctx = dispatcher
                    .run(None, None, &[], &[(vk, None)])
                    .await
                    .expect("Test failed")
                    .expect("Test failed");
                let keys =
                    ctx.note_index.keys().cloned().collect::<BTreeSet<_>>();
                let expected = BTreeSet::from([
                    MaspIndexedTx {
                        indexed_tx: IndexedTx {
                            block_height: 2.into(),
                            block_index: TxIndex(1),
                            batch_index: None,
                        },
                        kind: MaspTxKind::Transfer,
                    },
                    MaspIndexedTx {
                        indexed_tx: IndexedTx {
                            block_height: 2.into(),
                            block_index: TxIndex(2),
                            batch_index: None,
                        },
                        kind: MaspTxKind::Transfer,
                    },
                ]);

                assert_eq!(keys, expected);
                assert_eq!(
                    ctx.vk_sync[&vk.key].height,
                    MaspIndexedTx {
                        indexed_tx: IndexedTx::entire_block(3.into(),),
                        kind: MaspTxKind::Transfer
                    }
                );
                assert_eq!(ctx.note_map.len(), 2);
            })
            .await;
    }

    /// Test that if fetching filters out MASP txs not
    /// list in fmd flags.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_fetch_with_fmd_flags() {
        let temp_dir = tempdir().unwrap();
        let utils = FsShieldedUtils {
            context_dir: temp_dir.path().to_path_buf(),
        };
        let (client, masp_tx_sender) = TestingMaspClient::new(4.into());
        let (_send, shutdown_sig) = shutdown_signal();
        let config = ShieldedSyncConfig::builder()
            .fetched_tracker(DevNullProgressBar)
            .scanned_tracker(DevNullProgressBar)
            .applied_tracker(DevNullProgressBar)
            .shutdown_signal(shutdown_sig)
            .client(client)
            .retry_strategy(RetryStrategy::Times(0))
            .build();
        let vk = dated_arbitrary_vk();

        MaspLocalTaskEnv::new(4)
            .expect("Test failed")
            .run(|s| async {
                let masp_tx = arbitrary_masp_tx();
                masp_tx_sender
                    .send(Some((
                        MaspIndexedTx {
                            indexed_tx: IndexedTx {
                                block_height: 2.into(),
                                block_index: TxIndex(1),
                                batch_index: None,
                            },
                            kind: MaspTxKind::Transfer,
                        },
                        masp_tx.clone(),
                    )))
                    .expect("Test failed");
                masp_tx_sender
                    .send(Some((
                        MaspIndexedTx {
                            indexed_tx: IndexedTx {
                                block_height: 3.into(),
                                block_index: TxIndex(0),
                                batch_index: None,
                            },
                            kind: MaspTxKind::Transfer,
                        },
                        masp_tx.clone(),
                    )))
                    .expect("Test failed");
                masp_tx_sender
                    .send(Some((
                        MaspIndexedTx {
                            indexed_tx: IndexedTx {
                                block_height: 3.into(),
                                block_index: TxIndex(1),
                                batch_index: None,
                            },
                            kind: MaspTxKind::Transfer,
                        },
                        masp_tx.clone(),
                    )))
                    .expect("Test failed");
                masp_tx_sender
                    .send(Some((
                        MaspIndexedTx {
                            indexed_tx: IndexedTx {
                                block_height: 4.into(),
                                block_index: TxIndex(0),
                                batch_index: None,
                            },
                            kind: MaspTxKind::Transfer,
                        },
                        masp_tx.clone(),
                    )))
                    .expect("Test failed");
                let dispatcher = config.clone().dispatcher(s, &utils).await;

                let ctx = dispatcher
                    .run(
                        None,
                        None,
                        &[],
                        &[(
                            vk,
                            Some(
                                [
                                    Index { height: 3, tx: 0 },
                                    Index { height: 3, tx: 1 },
                                    Index { height: 5, tx: 0 },
                                ]
                                .into_iter()
                                .collect(),
                            ),
                        )],
                    )
                    .await
                    .expect("Test failed")
                    .expect("Test failed");

                let keys =
                    ctx.note_index.keys().cloned().collect::<BTreeSet<_>>();
                let expected = BTreeSet::from([
                    MaspIndexedTx {
                        indexed_tx: IndexedTx {
                            block_height: 3.into(),
                            block_index: TxIndex(0),
                            batch_index: None,
                        },
                        kind: MaspTxKind::Transfer,
                    },
                    MaspIndexedTx {
                        indexed_tx: IndexedTx {
                            block_height: 3.into(),
                            block_index: TxIndex(1),
                            batch_index: None,
                        },
                        kind: MaspTxKind::Transfer,
                    },
                ]);

                assert_eq!(keys, expected);
                assert_eq!(
                    ctx.vk_sync[&vk.key].height,
                    MaspIndexedTx {
                        indexed_tx: IndexedTx::entire_block(4.into()),
                        kind: MaspTxKind::Transfer
                    }
                );
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
        let (client, masp_tx_sender) = TestingMaspClient::new(4.into());
        let (_send, shutdown_sig) = shutdown_signal();
        let config = ShieldedSyncConfig::builder()
            .fetched_tracker(DevNullProgressBar)
            .scanned_tracker(DevNullProgressBar)
            .applied_tracker(DevNullProgressBar)
            .shutdown_signal(shutdown_sig)
            .client(client)
            .retry_strategy(RetryStrategy::Times(0))
            .block_batch_size(1)
            .build();

        let vk = dated_arbitrary_vk();
        MaspLocalTaskEnv::new(4)
            .expect("Test failed")
            .run(|s| async {
                let dispatcher = config.clone().dispatcher(s, &utils).await;

                let masp_tx = arbitrary_masp_tx();
                masp_tx_sender
                    .send(Some((
                        MaspIndexedTx {
                            indexed_tx: IndexedTx {
                                block_height: 2.into(),
                                block_index: TxIndex(1),
                                batch_index: None,
                            },
                            kind: MaspTxKind::Transfer,
                        },
                        masp_tx.clone(),
                    )))
                    .expect("Test failed");
                masp_tx_sender
                    .send(Some((
                        MaspIndexedTx {
                            indexed_tx: IndexedTx {
                                block_height: 2.into(),
                                block_index: TxIndex(2),
                                batch_index: None,
                            },
                            kind: MaspTxKind::Transfer,
                        },
                        masp_tx.clone(),
                    )))
                    .expect("Test failed");
                masp_tx_sender.send(None).expect("Test failed");
                let result =
                    dispatcher.run(None, None, &[], &[(vk, None)]).await;
                match result {
                    Err(msg) => assert_eq!(
                        msg.to_string(),
                        "Failed to fetch shielded transfers"
                    ),
                    other => {
                        panic!("{:?} does not match Error::Other(_)", other)
                    }
                }
                let cache = utils.cache_load().await.expect("Test failed");
                let expected = BTreeMap::from([
                    (
                        MaspIndexedTx {
                            indexed_tx: IndexedTx {
                                block_height: 2.into(),
                                block_index: TxIndex(1),
                                batch_index: None,
                            },
                            kind: MaspTxKind::Transfer,
                        },
                        masp_tx.clone(),
                    ),
                    (
                        MaspIndexedTx {
                            indexed_tx: IndexedTx {
                                block_height: 2.into(),
                                block_index: TxIndex(2),
                                batch_index: None,
                            },
                            kind: MaspTxKind::Transfer,
                        },
                        masp_tx.clone(),
                    ),
                ]);
                assert_eq!(cache.fetched.txs, expected);
            })
            .await;
    }

    /// Test that notes in the fetched cache are not trial
    /// decrypted against viewing keys for which they are not
    /// flagged via FMD.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_fmd_with_trial_decryption() {
        let temp_dir = tempdir().unwrap();
        let utils = FsShieldedUtils {
            context_dir: temp_dir.path().to_path_buf(),
        };
        let (client, _masp_tx_sender) = TestingMaspClient::new(2.into());
        let (_send, shutdown_sig) = shutdown_signal();
        let config = ShieldedSyncConfig::builder()
            .fetched_tracker(DevNullProgressBar)
            .scanned_tracker(DevNullProgressBar)
            .applied_tracker(DevNullProgressBar)
            .shutdown_signal(shutdown_sig)
            .client(client)
            .retry_strategy(RetryStrategy::Times(0))
            .block_batch_size(1)
            .build();
        let vk = dated_arbitrary_vk();
        MaspLocalTaskEnv::new(4)
            .expect("Test failed")
            .run(|s| async {
                let mut dispatcher = config.clone().dispatcher(s, &utils).await;
                let masp_tx = arbitrary_masp_tx();
                // insert MASP txs that will not be flagged for the viewing key
                dispatcher.cache.fetched.txs.insert(
                    MaspIndexedTx {
                        indexed_tx: IndexedTx {
                            block_height: 2.into(),
                            block_index: TxIndex(1),
                            batch_index: None,
                        },
                        kind: MaspTxKind::Transfer,
                    },
                    masp_tx.clone(),
                );
                dispatcher.cache.fetched.txs.insert(
                    MaspIndexedTx {
                        indexed_tx: IndexedTx {
                            block_height: 2.into(),
                            block_index: TxIndex(3),
                            batch_index: None,
                        },
                        kind: MaspTxKind::Transfer,
                    },
                    masp_tx.clone(),
                );

                let ctx = dispatcher
                    .run(
                        Some(2.into()),
                        Some(2.into()),
                        &[],
                        &[(
                            vk,
                            Some(
                                [Index { height: 2, tx: 0 }]
                                    .into_iter()
                                    .collect(),
                            ),
                        )],
                    )
                    .await
                    .expect("Test failed")
                    .expect("Test failed");
                // check that no notes have been trial decrypted
                assert!(ctx.pos_map.is_empty());
                assert!(ctx.note_map.is_empty());
                assert!(ctx.vk_map.is_empty());
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
        let (client, masp_tx_sender) = TestingMaspClient::new(3.into());
        let (send, shutdown_sig) = shutdown_signal();
        let config = ShieldedSyncConfig::builder()
            .fetched_tracker(DevNullProgressBar)
            .scanned_tracker(DevNullProgressBar)
            .applied_tracker(DevNullProgressBar)
            .shutdown_signal(shutdown_sig)
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
                        MaspIndexedTx {
                            indexed_tx: IndexedTx {
                                block_height: 2.into(),
                                block_index: TxIndex(1),
                                batch_index: None,
                            },
                            kind: MaspTxKind::Transfer,
                        },
                        masp_tx.clone(),
                    )))
                    .expect("Test failed");

                send.send_replace(true);
                let res = dispatcher
                    .run(None, None, &[], &[(dated_arbitrary_vk(), None)])
                    .await
                    .expect("Test failed");
                assert!(res.is_none());

                let DispatcherCache {
                    commitment_tree,
                    witness_map,
                    note_index,
                    fetched,
                    trial_decrypted,
                } = utils.cache_load().await.expect("Test failed");
                assert!(commitment_tree.is_none());
                assert!(witness_map.is_none());
                assert!(note_index.is_none());
                assert!(fetched.is_empty());
                assert!(trial_decrypted.is_empty());
            })
            .await;
    }
    /// Test the the birthdays of keys are properly reflected in the key
    /// sync heights when starting shielded sync.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_key_birthdays() {
        let temp_dir = tempdir().unwrap();
        let mut shielded_ctx =
            FsShieldedUtils::new(temp_dir.path().to_path_buf());
        let (client, masp_tx_sender) = TestingMaspClient::new(2.into());
        // First test the case where no keys have been seen yet
        let mut vk = DatedKeypair::new(arbitrary_vk(), Some(10.into()));
        let StoredKeypair::Raw(mut sk) = serde_json::from_str::<'_, StoredKeypair::<DatedSpendingKey>>(r#""unencrypted:zsknam1q02rgh4mqqqqpqqm68m2lmd0xe9k5vf4fscmdxuvewqhdhwl0h492fj40tzl5f6gwfk6kgnaxpgct7mx9cw2he4724858jdfhrzdh3e4hu3us463gphqyl6k5hvkjwkv9r7rx3jtcueurgflgj6dx9qn4rg0caf0t9zawfcdwt3ramxlrs4jyan4wyp4nh9hj8s806ru0smk3437ejy56ewtw9ljz8rc3vkyznxdf3l5c70skcw6aatpv5de9zhxuxs5k6l6jz6zktgg0udvl<<30""#).expect("Test failed") else {
            panic!("Test failed")
        };
        let masp_tx = arbitrary_masp_tx();
        masp_tx_sender
            .send(Some((
                MaspIndexedTx {
                    indexed_tx: IndexedTx {
                        block_height: 1.into(),
                        block_index: TxIndex(1),
                        batch_index: None,
                    },
                    kind: MaspTxKind::Transfer,
                },
                masp_tx.clone(),
            )))
            .expect("Test failed");
        let (_shutdown_send, shutdown_sig) = shutdown_signal();
        let config = ShieldedSyncConfig::builder()
            .client(client)
            .fetched_tracker(DevNullProgressBar)
            .scanned_tracker(DevNullProgressBar)
            .applied_tracker(DevNullProgressBar)
            .retry_strategy(RetryStrategy::Times(0))
            .shutdown_signal(shutdown_sig)
            .build();
        shielded_ctx
            .sync(
                MaspLocalTaskEnv::new(4).unwrap(),
                config.clone(),
                None,
                &[(sk, None)],
                &[(vk, None)],
            )
            .await
            .expect("Test failed");
        let birthdays = shielded_ctx
            .vk_sync
            .values()
            .map(|s| s.height)
            .collect::<Vec<_>>();
        assert_eq!(
            birthdays,
            vec![
                MaspIndexedTx {
                    indexed_tx: IndexedTx::entire_block(BlockHeight(30)),
                    kind: MaspTxKind::Transfer
                },
                MaspIndexedTx {
                    indexed_tx: IndexedTx::entire_block(BlockHeight(10)),
                    kind: MaspTxKind::Transfer
                }
            ]
        );

        // Test two cases:
        // * A birthday is less than the synced height of key
        // * A birthday is greater than the synced height of key
        vk.birthday = 5.into();
        sk.birthday = 60.into();
        masp_tx_sender
            .send(Some((
                MaspIndexedTx {
                    indexed_tx: IndexedTx {
                        block_height: 1.into(),
                        block_index: TxIndex(1),
                        batch_index: None,
                    },
                    kind: MaspTxKind::Transfer,
                },
                masp_tx.clone(),
            )))
            .expect("Test failed");
        shielded_ctx
            .sync(
                MaspLocalTaskEnv::new(4).unwrap(),
                config,
                None,
                &[(sk, None)],
                &[(vk, None)],
            )
            .await
            .expect("Test failed");
        let birthdays = shielded_ctx
            .vk_sync
            .values()
            .map(|s| s.height)
            .collect::<Vec<_>>();
        assert_eq!(
            birthdays,
            vec![
                MaspIndexedTx {
                    indexed_tx: IndexedTx::entire_block(BlockHeight(60)),
                    kind: MaspTxKind::Transfer
                },
                MaspIndexedTx {
                    indexed_tx: IndexedTx::entire_block(BlockHeight(10)),
                    kind: MaspTxKind::Transfer
                }
            ]
        )
    }
}
