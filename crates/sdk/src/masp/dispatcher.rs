use std::cmp::Ordering;
use std::collections::BTreeMap;
use std::future::Future;
use std::marker::PhantomData;
use std::pin::Pin;
use std::task::{Context, Poll};

use masp_primitives::merkle_tree::{CommitmentTree, IncrementalWitness};
use masp_primitives::sapling::{Node, ViewingKey};
use namada_core::collections::HashMap;
use namada_core::hash::Hash;
use namada_core::storage::BlockHeight;
use namada_tx::IndexedTx;
use tokio::select;

use crate::control_flow::ShutdownSignal;
use crate::error::Error;
use crate::io::Io;
use crate::masp::utils::{MaspClient, ProgressTracker};
use crate::masp::{
    DecryptedData, IndexedNoteEntry, ScannedData, ShieldedContext,
    ShieldedUtils,
};

struct Task {
    receiver: tokio::sync::oneshot::Receiver<Result<Message, Error>>,
    kind: TaskKind,
}

impl PartialEq for Task {
    fn eq(&self, other: &Self) -> bool {
        self.kind.eq(&other.kind)
    }
}

impl PartialOrd for Task {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        self.kind.partial_cmp(&other.kind)
    }
}

/// Tasks that the dispatcher can schedule
#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub enum TaskKind {
    FetchTxs,
    TrialDecrypt,
    UpdateCommitmentTree,
    UpdateWitness,
    UpdateNotesMap,
}

pub enum Message {
    UpdateCommitmentTree(CommitmentTree<Node>),
    UpdateNotesMap(BTreeMap<IndexedTx, usize>),
    UpdateWitness(IncrementalWitness<Node>),
    FetchTxs(Vec<IndexedNoteEntry>),
    TrialDecrypt(
        (
            ScannedData,
            HashMap<Hash, (IndexedTx, ViewingKey, DecryptedData)>,
        ),
    ),
}

struct DispatcherTasks {
    tasks: std::collections::BinaryHeap<Task>,
    max_msg_size: usize,
}

impl DispatcherTasks {
    pub async fn cache_out(
        mut self,
    ) -> (Vec<Vec<IndexedNoteEntry>>, Vec<ScannedData>) {
        let mut fetched_cache = vec![];
        let mut scanned_cache = vec![];
        for inner in self.tasks.into_iter().map(|t| t.receiver) {
            match inner.await {
                Ok(Ok(Message {
                    payload: Message::FetchTxs(msg),
                })) => fetched_cache.push(msg),
                Ok(Ok(Message {
                    payload: Message::TrialDecrypt(msg),
                })) => scanned_cache.push(msg),
                _ => {}
            }
        }
        (fetched_cache, scanned_cache)
    }
}

impl Future for DispatcherTasks {
    type Output = Vec<Result<Message, Error>>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        if self.tasks.is_empty() {
            return Poll::Ready(vec![]);
        }
        let tasks_to_check = self.tasks.len().min(self.max_msg_size);
        let mut msgs = Vec::with_capacity(tasks_to_check);
        for _ in 0..tasks_to_check {
            let task = self.tasks.pop().unwrap();
            if let Poll::Ready(m) = task.receiver.poll(cx) {
                msgs.push(m.unwrap_or_else(|| {
                    panic!("Dispatched task halted unexpectedly.")
                }));
            } else {
                self.tasks.push(task)
            }
        }
        if msgs.is_empty() {
            Poll::Pending
        } else {
            Poll::Ready(msgs)
        }
    }
}

pub struct Dispatcher<M, U>
where
    M: MaspClient,
    U: ShieldedUtils,
{
    tasks: DispatcherTasks,
    client: M,
    ctx: ShieldedContext<U>,
    can_start_scanning: bool,
}

/// Create a new dispatcher in the initial state
pub fn new<M: MaspClient, U: ShieldedUtils>(
    msg_channel: flume::Receiver<Message>,
    client: M,
    ctx: ShieldedContext<U>,
) -> Dispatcher<M, U> {
    Dispatcher {
        tasks: DispatcherTasks {
            tasks: Default::default(),
            max_msg_size: 8,
        },
        ctx,
        can_start_scanning: !client
            .capabilities()
            .may_fetch_pre_built_notes_map(),
        client,
    }
}

impl<M, U> Dispatcher<M, U>
where
    M: MaspClient,
    U: ShieldedUtils,
{
    pub fn spawn<F, T>(&mut self, kind: TaskKind, fut: F)
    where
        F: Future<Output = Message>,
    {
        if !self.can_start_scanning && kind == TaskKind::TrialDecrypt {
            panic!("Tried to schedule trial decryption prematurely");
        }
        let (sender, receiver) = tokio::sync::oneshot::channel();

        let task = Task { receiver, kind };
        self.tasks.push(task);
        tokio::spawn(async {
            let res = fut.await;
            sender.send(res).unwrap();
        });
    }
}
