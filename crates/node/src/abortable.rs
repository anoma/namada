use std::future::Future;
use std::pin::Pin;

use namada_sdk::control_flow::{
    ShutdownSignal, ShutdownSignalChan, install_shutdown_signal,
};
use tokio::sync::mpsc::{self, UnboundedReceiver, UnboundedSender};
use tokio::task::JoinHandle;

use crate::shell::ShellResult;

/// Serves to identify an aborting async task, which is spawned
/// with an [`AbortableSpawner`].
pub type AbortingTask = &'static str;

/// An [`AbortableSpawner`] will spawn abortable tasks into the asynchronous
/// runtime.
pub struct AbortableSpawner {
    shutdown_recv: ShutdownSignalChan,
    abort_send: UnboundedSender<AbortingTask>,
    abort_recv: UnboundedReceiver<AbortingTask>,
    cleanup_jobs: Vec<Pin<Box<dyn Future<Output = ()>>>>,
    pinned: Option<(AbortingTask, JoinHandle<ShellResult<()>>)>,
    batch: Vec<(AbortingTask, JoinHandle<ShellResult<()>>)>,
}

/// Contains the state of an on-going [`AbortableSpawner`] task spawn.
pub struct AbortableTaskBuilder<'a, A> {
    who: AbortingTask,
    abortable: A,
    spawner: &'a mut AbortableSpawner,
    cleanup: Option<Pin<Box<dyn Future<Output = ()>>>>,
    pin: bool,
}

impl Default for AbortableSpawner {
    #[inline]
    fn default() -> Self {
        Self::new()
    }
}

impl AbortableSpawner {
    /// Creates a new [`AbortableSpawner`].
    pub fn new() -> Self {
        let shutdown_recv = install_shutdown_signal(true);
        let (abort_send, abort_recv) = mpsc::unbounded_channel();
        Self {
            abort_send,
            abort_recv,
            shutdown_recv,
            cleanup_jobs: Vec::new(),
            batch: Vec::new(),
            pinned: None,
        }
    }

    /// Spawns a new task into the asynchronous runtime, with an [`Aborter`]
    /// that shall be dropped when it is no longer running.
    ///
    /// For instance:
    ///
    /// ```ignore
    /// let mut spawner = AbortableSpawner::new();
    /// spawner
    ///     .abortable("ExampleTask", |aborter| async {
    ///         drop(aborter);
    ///         println!("I have signaled a control task that I am no longer running!");
    ///     })
    ///     .spawn();
    /// spawner.run_to_completion().await;
    /// ```
    ///
    /// The return type of this method is [`AbortableTaskBuilder`], such that a
    /// cleanup routine, after the abort is received, can be configured to
    /// execute.
    #[inline]
    pub fn abortable<A>(
        &mut self,
        who: AbortingTask,
        abortable: A,
    ) -> AbortableTaskBuilder<'_, A> {
        AbortableTaskBuilder {
            who,
            abortable,
            spawner: self,
            cleanup: None,
            pin: false,
        }
    }

    /// Wait for any of the spawned tasks to abort.
    ///
    /// ## Resolving this future
    ///
    /// This future runs to completion if:
    ///
    ///   1. A user sends a shutdown signal (e.g. SIGINT), or...
    ///   2. One of the child processes of the ledger terminates, which
    ///      generates a notification upon dropping an [`Aborter`].
    ///
    /// These two scenarios are represented by the [`AborterStatus`] enum.
    async fn wait_for_abort(mut self) -> AborterStatus {
        let status = tokio::select! {
            _ = self.shutdown_recv.wait_for_shutdown() => AborterStatus::UserShutdownLedger,
            msg = self.abort_recv.recv() => {
                // When the msg is `None`, there are no more abort senders, so both
                // Tendermint and the shell must have already exited
                if let Some(who) = msg {
                     tracing::info!("{who} has exited, shutting down...");
                }
                AborterStatus::ChildProcessTerminated
            }
        };

        for job in self.cleanup_jobs {
            job.await;
        }

        status
    }

    /// Run all the spawned tasks to completion.
    pub async fn run_to_completion(mut self) {
        let pinned_task = self.pinned.take();

        let batch = std::mem::take(&mut self.batch);
        let (task_ids, task_handles): (Vec<_>, Vec<_>) =
            batch.into_iter().unzip();

        // Wait for interrupt signal or abort message
        let aborted = self.wait_for_abort().await.child_terminated();

        // Wait for all managed tasks to finish
        match futures::future::try_join_all(task_handles).await {
            Ok(results) => {
                for (i, res) in results.into_iter().enumerate() {
                    match res {
                        Err(err) if aborted => {
                            let who = task_ids[i];
                            tracing::error!("{who} error: {err}");
                        }
                        _ => {}
                    }
                }
            }
            Err(err) => {
                // Ignore cancellation errors
                if !err.is_cancelled() {
                    tracing::error!("Abortable spawner error: {err}");
                }
            }
        }

        if let Some((who, pinned_task)) = pinned_task {
            match pinned_task.await {
                Err(err) if err.is_panic() => {
                    std::panic::resume_unwind(err.into_panic())
                }
                Err(err) => tracing::error!("{who} error: {err}"),
                _ => {}
            }
        }
    }

    fn spawn_abortable_task<A, F>(
        &self,
        who: AbortingTask,
        abortable: A,
    ) -> JoinHandle<ShellResult<()>>
    where
        A: FnOnce(Aborter) -> F,
        F: Future<Output = ShellResult<()>> + Send + 'static,
    {
        let abort = Aborter {
            who,
            sender: self.abort_send.clone(),
        };
        tokio::spawn(abortable(abort))
    }

    fn spawn_abortable_task_blocking<A>(
        &self,
        who: AbortingTask,
        abortable: A,
    ) -> JoinHandle<ShellResult<()>>
    where
        A: FnOnce(Aborter) -> ShellResult<()> + Send + 'static,
    {
        let abort = Aborter {
            who,
            sender: self.abort_send.clone(),
        };
        tokio::task::spawn_blocking(move || abortable(abort))
    }
}

impl<A> AbortableTaskBuilder<'_, A> {
    /// Spawn the built abortable task into the runtime.
    #[inline]
    pub fn spawn<F>(self)
    where
        A: FnOnce(Aborter) -> F,
        F: Future<Output = ShellResult<()>> + Send + 'static,
    {
        if let Some(cleanup) = self.cleanup {
            self.spawner.cleanup_jobs.push(cleanup);
        }
        let task = self.spawner.spawn_abortable_task(self.who, self.abortable);
        if self.pin {
            if let Some(pinned_task) = self.spawner.pinned.take() {
                self.spawner.batch.push(pinned_task);
            }
            self.spawner.pinned = Some((self.who, task));
        } else {
            self.spawner.batch.push((self.who, task));
        }
    }

    /// Spawn the built abortable (blocking) task into the runtime.
    #[inline]
    pub fn spawn_blocking(self)
    where
        A: FnOnce(Aborter) -> ShellResult<()> + Send + 'static,
    {
        if let Some(cleanup) = self.cleanup {
            self.spawner.cleanup_jobs.push(cleanup);
        }
        let task = self
            .spawner
            .spawn_abortable_task_blocking(self.who, self.abortable);
        if self.pin {
            if let Some(pinned_task) = self.spawner.pinned.take() {
                self.spawner.batch.push(pinned_task);
            }
            self.spawner.pinned = Some((self.who, task));
        } else {
            self.spawner.batch.push((self.who, task));
        }
    }

    /// A cleanup routine `cleanup` will be executed for the associated task.
    /// This method replaces the previous cleanup routine, if any.
    #[inline]
    pub fn with_cleanup<C>(mut self, cleanup: C) -> Self
    where
        C: Future<Output = ()> + Send + 'static,
    {
        self.cleanup = Some(Box::pin(cleanup));
        self
    }

    /// Pin the task to spawn. The main purpose behind this operation
    /// is to resume unwinding the stack if the pinned task panics.
    #[inline]
    pub fn pin(mut self) -> Self {
        self.pin = true;
        self
    }
}

/// A panic-proof handle for aborting a future. Will abort during stack
/// unwinding and its drop method sends abort message with `who` inside it.
pub struct Aborter {
    sender: mpsc::UnboundedSender<AbortingTask>,
    who: AbortingTask,
}

impl Drop for Aborter {
    fn drop(&mut self) {
        // Send abort message, ignore result
        let _ = self.sender.send(self.who);
    }
}

/// An [`AborterStatus`] represents one of two possible causes that resulted
/// in shutting down the ledger.
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub enum AborterStatus {
    /// The ledger process received a shutdown signal.
    UserShutdownLedger,
    /// One of the ledger's child processes terminated, signaling the
    /// [`AbortableSpawner`].
    ChildProcessTerminated,
}

impl AborterStatus {
    /// Checks if the reason for aborting was a child process terminating.
    pub fn child_terminated(self) -> bool {
        matches!(self, AborterStatus::ChildProcessTerminated)
    }
}

#[cfg(test)]
mod abortale_spawner_tests {
    use std::sync::{Arc, Mutex};

    use super::*;

    /// Test panicking a non-pinned task shouldn't cause the entire spawner to
    /// come crashing down.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_abortable_spawner_panic_non_pinned_task() {
        let mut spawner = AbortableSpawner::new();

        spawner
            .abortable("TestTask", |_aborter| async {
                panic!();
            })
            .spawn();

        spawner.run_to_completion().await;
    }

    /// Test panicking a pinned task must cause the entire spawner to come
    /// crashing down.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    #[should_panic = "AbortableSpawnerPanic"]
    async fn test_abortable_spawner_panic_pinned_task() {
        let mut spawner = AbortableSpawner::new();

        spawner
            .abortable("TestTask", |_aborter| async {
                panic!("AbortableSpawnerPanic");
            })
            .pin()
            .spawn();

        spawner.run_to_completion().await;
    }

    /// Test that cleanup jobs get triggered.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn test_cleanup_job() {
        let mut spawner = AbortableSpawner::new();

        struct Slot {
            task_data: [String; 3],
        }

        let slot = Arc::new(Mutex::new(Slot {
            task_data: [String::new(), String::new(), String::new()],
        }));

        let task_ids = ["TestTask#1", "TestTask#2", "TestTask#3"];

        for (task_no, &id) in task_ids.iter().enumerate() {
            let slot = Arc::clone(&slot);

            spawner
                .abortable(id, |aborter| async move {
                    drop(aborter);
                    Ok(())
                })
                .with_cleanup(async move {
                    slot.lock().unwrap().task_data[task_no] = id.into();
                })
                .spawn();
        }

        spawner.run_to_completion().await;

        let slot_handle = slot.lock().unwrap();
        assert_eq!(slot_handle.task_data[0].as_str(), task_ids[0]);
        assert_eq!(slot_handle.task_data[1].as_str(), task_ids[1]);
        assert_eq!(slot_handle.task_data[2].as_str(), task_ids[2]);
    }

    /// Test blocking jobs.
    #[tokio::test(flavor = "multi_thread", worker_threads = 1)]
    async fn test_blocking_spawn() {
        let (bing_tx, bing_rx) = tokio::sync::oneshot::channel();
        let (bong_tx, bong_rx) = tokio::sync::oneshot::channel();

        let mut spawner = AbortableSpawner::new();
        spawner
            .abortable("Bing", move |aborter| {
                bing_rx.blocking_recv().unwrap();
                drop(aborter);
                Ok(())
            })
            .spawn_blocking();
        spawner
            .abortable("Bong", move |aborter| {
                bong_rx.blocking_recv().unwrap();
                drop(aborter);
                Ok(())
            })
            .spawn_blocking();

        let spawner_run_fut = Box::pin(spawner.run_to_completion());
        let select_result =
            futures::future::select(spawner_run_fut, std::future::ready(()))
                .await;
        let spawner_run_fut = match select_result {
            futures::future::Either::Left(_) => unreachable!("Test failed"),
            futures::future::Either::Right(((), fut)) => fut,
        };

        bing_tx.send(()).unwrap();
        let select_result =
            futures::future::select(spawner_run_fut, std::future::ready(()))
                .await;
        let spawner_run_fut = match select_result {
            futures::future::Either::Left(_) => unreachable!("Test failed"),
            futures::future::Either::Right(((), fut)) => fut,
        };

        bong_tx.send(()).unwrap();
        spawner_run_fut.await;
    }
}
