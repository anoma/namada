use std::fmt::Debug;
use std::sync::{Arc, Mutex};

use masp_primitives::sapling::ViewingKey;
use masp_primitives::zip32::ExtendedSpendingKey;
use namada_sdk::error::Error;
use namada_sdk::io::Io;
use namada_sdk::masp::types::IndexedNoteEntry;
use namada_sdk::masp::utils::{
    LedgerMaspClient, PeekableIter, ProgressTracker, ProgressType,
    RetryStrategy,
};
use namada_sdk::masp::{ShieldedContext, ShieldedUtils};
use namada_sdk::queries::Client;
use namada_sdk::storage::BlockHeight;
use namada_sdk::{display, display_line};

#[allow(clippy::too_many_arguments)]
pub async fn syncing<
    U: ShieldedUtils + Send + Sync,
    C: Client + Sync,
    IO: Io + Sync + Send,
>(
    mut shielded: ShieldedContext<U>,
    client: &C,
    io: &IO,
    batch_size: u64,
    start_query_height: Option<BlockHeight>,
    last_query_height: Option<BlockHeight>,
    sks: &[ExtendedSpendingKey],
    fvks: &[ViewingKey],
) -> Result<ShieldedContext<U>, Error> {
    let shutdown_signal = async {
        let (tx, rx) = tokio::sync::oneshot::channel();
        namada_sdk::control_flow::shutdown_send(tx).await;
        rx.await
    };

    display_line!(io, "\n\n");
    let logger = CliProgressTracker::new(io);
    let sync = async move {
        shielded
            .fetch::<_, _, _, LedgerMaspClient<C>>(
                client,
                &logger,
                RetryStrategy::Forever,
                start_query_height,
                last_query_height,
                batch_size,
                sks,
                fvks,
            )
            .await
            .map(|_| shielded)
    };
    tokio::select! {
        sync = sync => {
            let shielded = sync?;
            display!(io, "\nSyncing finished\n");
            Ok(shielded)
        },
        sig = shutdown_signal => {
            sig.map_err(|e| Error::Other(e.to_string()))?;
            display!(io, "\n");
            Ok(ShieldedContext::default())
        },
    }
}

#[derive(Default, Copy, Clone)]
struct IterProgress {
    index: usize,
    length: usize,
}

struct StdoutDrawer<'io, IO: Io> {
    io: &'io IO,
    fetch: IterProgress,
    scan: IterProgress,
}

impl<'io, IO: Io> StdoutDrawer<'io, IO> {
    fn draw(&self) {
        let (fetch_percent, fetch_completed) = (self.fetch.length > 0)
            .then(|| {
                let fetch_percent =
                    (100 * self.fetch.index) / self.fetch.length;
                let fetch_completed: String =
                    vec!['#'; fetch_percent].iter().collect();
                (fetch_percent, fetch_completed)
            })
            .unzip();
        let fetch_incomplete = fetch_percent
            .as_ref()
            .map(|p| vec!['.'; 100 - *p].iter().collect::<String>());

        let (scan_percent, scan_completed) = (self.scan.length > 0)
            .then(|| {
                let scan_percent = (100 * self.scan.index) / self.scan.length;
                let scan_completed: String =
                    vec!['#'; scan_percent].iter().collect();
                (scan_percent, scan_completed)
            })
            .unzip();
        let scan_incomplete = scan_percent
            .as_ref()
            .map(|p| vec!['.'; 100 - *p].iter().collect::<String>());

        match (fetch_percent, scan_percent) {
            (Some(fp), Some(sp)) => {
                display_line!(self.io, "\x1b[4A\x1b[J");
                display_line!(
                    self.io,
                    "Fetched block {:?} of {:?}",
                    self.fetch.index,
                    self.fetch.length
                );
                display_line!(
                    self.io,
                    "[{}{}] ~~ {} %",
                    fetch_completed.unwrap(),
                    fetch_incomplete.unwrap(),
                    fp
                );
                display_line!(
                    self.io,
                    "Scanned {} of {}",
                    self.scan.index,
                    self.scan.length
                );
                display!(
                    self.io,
                    "[{}{}] ~~ {} %",
                    scan_completed.unwrap(),
                    scan_incomplete.unwrap(),
                    sp
                );
                self.io.flush()
            }
            (Some(fp), None) => {
                display_line!(self.io, "\x1b[4A\x1b[J");
                display_line!(self.io, "\x1b[4A\x1b[J");
                display_line!(
                    self.io,
                    "Fetched block {:?} of {:?}",
                    self.fetch.index,
                    self.fetch.length
                );
                display!(
                    self.io,
                    "[{}{}] ~~ {} \n\n%",
                    fetch_completed.unwrap(),
                    fetch_incomplete.unwrap(),
                    fp
                );
                self.io.flush()
            }
            (None, Some(sp)) => {
                display_line!(self.io, "\x1b[4A\x1b[J");
                display_line!(self.io, "\x1b[4A\x1b[J");
                display_line!(
                    self.io,
                    "Scanned {} of {}",
                    self.scan.index,
                    self.scan.length
                );
                display!(
                    self.io,
                    "[{}{}] ~~ {} \n\n%",
                    scan_completed.unwrap(),
                    scan_incomplete.unwrap(),
                    sp
                );
                self.io.flush()
            }
            _ => {}
        }
    }
}

impl<'io, IO: Io> Drop for StdoutDrawer<'io, IO> {
    fn drop(&mut self) {
        display_line!(self.io, "\n\n");
    }
}

pub struct LoggingIterator<'io, T, I, IO>
where
    T: Debug,
    I: Iterator<Item = T>,
    IO: Io,
{
    items: I,
    drawer: Arc<Mutex<StdoutDrawer<'io, IO>>>,
    r#type: ProgressType,
    peeked: Option<T>,
}

/// An iterator that logs to screen the progress it tracks
impl<'io, T, I, IO> LoggingIterator<'io, T, I, IO>
where
    T: Debug,
    I: Iterator<Item = T>,
    IO: Io,
{
    fn new(
        items: I,
        r#type: ProgressType,
        drawer: Arc<Mutex<StdoutDrawer<'io, IO>>>,
    ) -> Self {
        let (size, _) = items.size_hint();
        {
            let mut locked = drawer.lock().unwrap();
            match r#type {
                ProgressType::Fetch => {
                    locked.fetch.length = size;
                }
                ProgressType::Scan => {
                    locked.scan.length = size;
                }
            }
        }
        Self {
            items,
            drawer,
            r#type,
            peeked: None,
        }
    }

    fn advance_index(&self) {
        let mut locked = self.drawer.lock().unwrap();
        match self.r#type {
            ProgressType::Fetch => {
                locked.fetch.index += 1;
            }
            ProgressType::Scan => {
                locked.scan.index += 1;
                locked.scan.length = self.items.size_hint().0;
            }
        }
    }

    fn draw(&self) {
        let locked = self.drawer.lock().unwrap();
        locked.draw();
    }
}

impl<'io, T, I, IO> PeekableIter<T> for LoggingIterator<'io, T, I, IO>
where
    T: Debug,
    I: Iterator<Item = T>,
    IO: Io,
{
    fn peek(&mut self) -> Option<&T> {
        if self.peeked.is_none() {
            self.peeked = self.items.next();
        }
        self.peeked.as_ref()
    }

    fn next(&mut self) -> Option<T> {
        self.peek();
        let next_item = self.peeked.take()?;
        self.advance_index();
        self.draw();
        Some(next_item)
    }
}

impl<'io, T, I, IO> Iterator for LoggingIterator<'io, T, I, IO>
where
    T: Debug,
    I: Iterator<Item = T>,
    IO: Io,
{
    type Item = T;

    fn next(&mut self) -> Option<Self::Item> {
        <Self as PeekableIter<T>>::next(self)
    }
}

/// A progress tracker for the CLI
#[derive(Clone)]
pub struct CliProgressTracker<'io, IO: Io> {
    drawer: Arc<Mutex<StdoutDrawer<'io, IO>>>,
}

impl<'io, IO: Io> CliProgressTracker<'io, IO> {
    pub fn new(io: &'io IO) -> Self {
        Self {
            drawer: Arc::new(Mutex::new(StdoutDrawer {
                io,
                fetch: Default::default(),
                scan: Default::default(),
            })),
        }
    }
}

impl<'io, IO: Io + Send + Sync> ProgressTracker<IO>
    for CliProgressTracker<'io, IO>
{
    fn io(&self) -> &IO {
        let io = {
            let locked = self.drawer.lock().unwrap();
            locked.io
        };
        io
    }

    fn fetch<I>(&self, items: I) -> impl PeekableIter<u64>
    where
        I: Iterator<Item = u64>,
    {
        LoggingIterator::new(items, ProgressType::Fetch, self.drawer.clone())
    }

    fn scan<I>(&self, items: I) -> impl Iterator<Item = IndexedNoteEntry> + Send
    where
        I: Iterator<Item = IndexedNoteEntry> + Send,
    {
        LoggingIterator::new(items, ProgressType::Scan, self.drawer.clone())
    }

    fn left_to_fetch(&self) -> usize {
        let locked = self.drawer.lock().unwrap().fetch;
        locked.length - locked.index
    }
}
