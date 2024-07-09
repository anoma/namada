use std::future::Future;
use std::ops::ControlFlow;

use masp_primitives::sapling::note_encryption::{
    try_sapling_note_decryption, PreparedIncomingViewingKey,
};
use masp_primitives::sapling::ViewingKey;
use masp_primitives::transaction::components::OutputDescription;
use masp_primitives::transaction::{Authorization, Authorized, Transaction};
use typed_builder::TypedBuilder;

use super::shielded_sync::utils::{MaspClient, RetryStrategy};
use crate::error::Error;
use crate::masp::shielded_sync::dispatcher::Dispatcher;
use crate::masp::utils::DecryptedData;
use crate::masp::{ShieldedUtils, NETWORK};
use crate::task_env::{
    LocalSetSpawner, LocalSetTaskEnvironment, TaskEnvironment,
};

pub mod dispatcher;
pub mod utils;

const DEFAULT_BUF_SIZE: usize = 32;
const DEFAULT_BATCH_SIZE: usize = 10;

/// A configuration used to tune the concurrency parameters of
/// the shielded sync and the client used to fetch data.
#[derive(Clone, TypedBuilder)]
pub struct ShieldedSyncConfig<M> {
    client: M,
    #[builder(default = RetryStrategy::Forever)]
    retry_strategy: RetryStrategy,
    #[builder(default = DEFAULT_BUF_SIZE)]
    channel_buffer_size: usize,
    #[builder(default = DEFAULT_BATCH_SIZE)]
    block_batch_size: usize,
}

/// A task env whose backing thread-pool uses a no-op
/// panic handler. Custom for MASP dispatchers.
#[cfg(not(target_family = "wasm"))]
pub struct MaspLocalTaskEnv(LocalSetTaskEnvironment);

#[cfg(not(target_family = "wasm"))]
impl MaspLocalTaskEnv {
    /// create a new [`MaspLocalTaskEnv`]
    pub fn new(num_threads: usize) -> Result<Self, Error> {
        let pool = rayon::ThreadPoolBuilder::new()
            .num_threads(num_threads)
            .panic_handler(|_| {})
            .build()
            .map_err(|err| {
                Error::Other(format!("Failed to create thread pool: {err}"))
            })?;
        Ok(Self(LocalSetTaskEnvironment::new(pool)))
    }
}

#[cfg(not(target_family = "wasm"))]
impl TaskEnvironment for MaspLocalTaskEnv {
    type Spawner = LocalSetSpawner;

    async fn run<M, F, R>(self, main: M) -> R
    where
        M: FnOnce(Self::Spawner) -> F,
        F: Future<Output = R>,
    {
        self.0.run(main).await
    }
}

impl<M> ShieldedSyncConfig<M>
where
    M: MaspClient,
{
    /// Retrieve the [`Dispatcher`] used to run shielded sync.
    pub async fn dispatcher<U, S>(
        self,
        spawner: S,
        utils: &U,
    ) -> Dispatcher<M, U, S>
    where
        U: ShieldedUtils,
    {
        dispatcher::new(
            spawner,
            self.client,
            utils,
            dispatcher::Config {
                retry_strategy: self.retry_strategy,
                block_batch_size: self.block_batch_size,
                channel_buffer_size: self.channel_buffer_size,
            },
        )
        .await
    }
}

/// Try to decrypt a MASP transaction with the provided key
pub fn trial_decrypt(
    shielded: Transaction,
    vk: ViewingKey,
    mut interrupted: impl FnMut() -> bool,
) -> ControlFlow<(), Vec<DecryptedData>> {
    type Proof = OutputDescription<
        <
        <Authorized as Authorization>::SaplingAuth
        as masp_primitives::transaction::components::sapling::Authorization
        >::Proof
    >;

    shielded
        .sapling_bundle()
        .map_or(&vec![], |x| &x.shielded_outputs)
        .iter()
        .try_fold(vec![], |mut accum, so| {
            if interrupted() {
                return ControlFlow::Break(());
            }
            // Let's try to see if this viewing key can decrypt latest
            // note
            if let Some(data) = try_sapling_note_decryption::<_, Proof>(
                &NETWORK,
                1.into(),
                &PreparedIncomingViewingKey::new(&vk.ivk()),
                so,
            ) {
                accum.push(data);
            }
            ControlFlow::Continue(accum)
        })
}
