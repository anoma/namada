//! Functionality to abstract spawning tasks onto a thread pool.

use std::future::Future;

/// Spawn tasks onto a thread pool.
pub trait TaskSpawner {
    /// Spawn an async task onto a thread pool.
    fn spawn_async<F>(&self, fut: F)
    where
        F: Future<Output = ()> + 'static;

    /// Spawn a sync task onto a thread pool.
    fn spawn_sync<F>(&self, job: F)
    where
        F: FnOnce() + Send + 'static;
}

/// An environment to run async tasks on.
pub trait TaskEnvironment {
    /// Task spawner implementation.
    type Spawner: TaskSpawner;

    /// Run the provided async task to completion.
    ///
    /// An async task spawner is provided, to execute
    /// additional work in the background.
    #[allow(async_fn_in_trait)]
    async fn run<M, F, R>(self, main: M) -> R
    where
        M: FnOnce(Self::Spawner) -> F,
        F: Future<Output = R>;
}

#[cfg(not(target_family = "wasm"))]
mod environment {
    use tokio::task::LocalSet;

    use super::*;

    /// Task spawner that uses a [`LocalSet`].
    pub struct LocalSetSpawner {
        pool: rayon::ThreadPool,
    }

    impl TaskSpawner for LocalSetSpawner {
        #[inline]
        fn spawn_async<F>(&self, fut: F)
        where
            F: Future<Output = ()> + 'static,
        {
            tokio::task::spawn_local(fut);
        }

        #[inline]
        fn spawn_sync<F>(&self, job: F)
        where
            F: FnOnce() + Send + 'static,
        {
            self.pool.spawn(job);
        }
    }

    /// A task environment that uses a [`LocalSet`].
    pub struct LocalSetTaskEnvironment {
        pool: rayon::ThreadPool,
    }

    impl LocalSetTaskEnvironment {
        /// Create a new [`LocalSetTaskEnvironment`] with `num_threads` workers.
        pub fn new(pool: rayon::ThreadPool) -> Self {
            Self { pool }
        }
    }

    impl TaskEnvironment for LocalSetTaskEnvironment {
        type Spawner = LocalSetSpawner;

        async fn run<M, F, R>(self, main: M) -> R
        where
            M: FnOnce(Self::Spawner) -> F,
            F: Future<Output = R>,
        {
            let Self { pool } = self;

            LocalSet::new()
                .run_until(main(LocalSetSpawner { pool }))
                .await
        }
    }
}

#[cfg(not(target_family = "wasm"))]
pub use environment::*;
