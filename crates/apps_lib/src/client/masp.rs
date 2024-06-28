use std::fmt::Debug;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use color_eyre::owo_colors::OwoColorize;
use masp_primitives::sapling::ViewingKey;
use masp_primitives::zip32::ExtendedSpendingKey;
use namada_sdk::error::Error;
use namada_sdk::io::Io;
use namada_sdk::masp::utils::{
    IndexerMaspClient, LedgerMaspClient, PeekableIter, ProgressTracker,
    ProgressType, RetryStrategy,
};
use namada_sdk::masp::{IndexedNoteEntry, ShieldedContext, ShieldedUtils};
use namada_sdk::queries::Client;
use namada_sdk::storage::BlockHeight;
use namada_sdk::{display, display_line, MaybeSend, MaybeSync};

#[allow(clippy::too_many_arguments)]
pub async fn syncing<
    U: ShieldedUtils + MaybeSend + MaybeSync,
    C: Client + Sync,
    IO: Io + Send + Sync,
>(
    mut shielded: ShieldedContext<U>,
    client: &C,
    indexer_addr: Option<&str>,
    io: &IO,
    start_query_height: Option<BlockHeight>,
    last_query_height: Option<BlockHeight>,
    sks: &[ExtendedSpendingKey],
    fvks: &[ViewingKey],
) -> Result<ShieldedContext<U>, Error> {
    if indexer_addr.is_some() {
        display_line!(
            io,
            "{}",
            "==== Shielded sync started using indexer client ====".bold()
        );
    } else {
        display_line!(
            io,
            "{}",
            "==== Shielded sync started using ledger client ====".bold()
        );
    }
    display_line!(io, "\n\n");
    let tracker = CliProgressTracker::new(io);

    macro_rules! dispatch_client {
        ($client:expr) => {
            shielded
                .fetch(
                    $client,
                    &tracker,
                    start_query_height,
                    last_query_height,
                    RetryStrategy::Forever,
                    sks,
                    fvks,
                )
                .await
                .map(|_| shielded)
        };
    }

    let shielded = if let Some(endpoint) = indexer_addr {
        let client = reqwest::Client::builder()
            .connect_timeout(Duration::from_secs(60))
            .build()
            .map_err(|err| {
                Error::Other(format!("Failed to build http client: {err}"))
            })?;
        let url = endpoint.try_into().map_err(|err| {
            Error::Other(format!(
                "Failed to parse API endpoint {endpoint:?}: {err}"
            ))
        })?;
        dispatch_client!(IndexerMaspClient::new(client, url))?
    } else {
        dispatch_client!(LedgerMaspClient::new(client))?
    };

    display!(io, "Syncing finished\n");
    Ok(shielded)
}

/// The amount of progress a shielded sync sub-process has made
#[derive(Default, Copy, Clone, Debug)]
struct IterProgress {
    index: usize,
    length: usize,
}

pub struct LoggingIterator<'io, T, I, IO>
where
    T: Debug,
    I: Iterator<Item = T>,
    IO: Io,
{
    items: I,
    progress: Arc<Mutex<IterProgress>>,
    io: &'io IO,
    r#type: ProgressType,
    peeked: Option<T>,
}

impl<'io, T, I, IO> LoggingIterator<'io, T, I, IO>
where
    T: Debug,
    I: Iterator<Item = T>,
    IO: Io,
{
    fn new(
        items: I,
        io: &'io IO,
        r#type: ProgressType,
        progress: Arc<Mutex<IterProgress>>,
    ) -> Self {
        let (size, _) = items.size_hint();
        {
            let mut locked = progress.lock().unwrap();
            locked.length = size;
        }
        Self {
            items,
            progress,
            io,
            r#type,
            peeked: None,
        }
    }

    fn advance_index(&mut self) {
        let mut locked = self.progress.lock().unwrap();
        locked.index += 1;
        if let ProgressType::Scan = self.r#type {
            locked.length = self.items.size_hint().0;
        }
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
        let (index, length) = {
            let locked = self.progress.lock().unwrap();
            (locked.length, locked.index)
        };

        let percent = std::cmp::min(100, (100 * index) / length);
        let completed: String = vec!['#'; percent].iter().collect();
        let incomplete: String = vec!['.'; 100 - percent].iter().collect();
        display_line!(self.io, "\x1b[2A\x1b[J");
        match self.r#type {
            ProgressType::Fetch => display_line!(
                self.io,
                "Fetched block {:?} of {:?}",
                index,
                length
            ),
            ProgressType::Scan => {
                display_line!(self.io, "Scanning {} of {}", index, length)
            }
        }
        display!(self.io, "[{}{}] ~~ {} %", completed, incomplete, percent);
        self.io.flush();
        Some(next_item)
    }
}

impl<'io, T, I, IO> Drop for LoggingIterator<'io, T, I, IO>
where
    T: Debug,
    I: Iterator<Item = T>,
    IO: Io,
{
    fn drop(&mut self) {
        display_line!(self.io, "\x1b[2A\x1b[J");
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

/// A progress logger for the CLI
#[derive(Debug, Clone)]
pub struct CliProgressTracker<'io, IO: Io> {
    io: &'io IO,
    fetch: Arc<Mutex<IterProgress>>,
    scan: Arc<Mutex<IterProgress>>,
}

impl<'io, IO: Io> CliProgressTracker<'io, IO> {
    pub fn new(io: &'io IO) -> Self {
        Self {
            io,
            fetch: Arc::new(Mutex::new(IterProgress::default())),
            scan: Arc::new(Mutex::new(IterProgress::default())),
        }
    }
}

impl<'io, IO: Io + Send + Sync> ProgressTracker<IO>
    for CliProgressTracker<'io, IO>
{
    fn io(&self) -> &IO {
        self.io
    }

    fn fetch<I>(&self, items: I) -> impl PeekableIter<u64>
    where
        I: Iterator<Item = u64>,
    {
        LoggingIterator::new(
            items,
            self.io,
            ProgressType::Fetch,
            self.fetch.clone(),
        )
    }

    fn scan<I>(&self, items: I) -> impl Iterator<Item = IndexedNoteEntry> + Send
    where
        I: Iterator<Item = IndexedNoteEntry> + Send,
    {
        {
            let mut locked = self.scan.lock().unwrap();
            *locked = IterProgress::default();
        }
        LoggingIterator::new(
            items,
            self.io,
            ProgressType::Scan,
            self.scan.clone(),
        )
    }

    fn left_to_fetch(&self) -> usize {
        let locked = self.fetch.lock().unwrap();
        if locked.index > locked.length {
            0
        } else {
            locked.length - locked.index
        }
    }
}
