use std::fmt::Debug;

use color_eyre::owo_colors::OwoColorize;
use masp_primitives::sapling::ViewingKey;
use masp_primitives::zip32::ExtendedSpendingKey;
use namada_sdk::error::Error;
use namada_sdk::io::Io;
use namada_sdk::masp::{
    IndexedNoteEntry, ProgressLogger, ProgressType, ShieldedContext,
    ShieldedUtils,
};
use namada_sdk::queries::Client;
use namada_sdk::storage::BlockHeight;
use namada_sdk::{display, display_line, MaybeSend, MaybeSync};

pub async fn syncing<
    U: ShieldedUtils + MaybeSend + MaybeSync,
    C: Client + Sync,
    IO: Io,
>(
    mut shielded: ShieldedContext<U>,
    client: &C,
    io: &IO,
    batch_size: u64,
    last_query_height: Option<BlockHeight>,
    sks: &[ExtendedSpendingKey],
    fvks: &[ViewingKey],
) -> Result<ShieldedContext<U>, Error> {
    let shutdown_signal = async {
        let (tx, rx) = tokio::sync::oneshot::channel();
        namada_sdk::control_flow::shutdown_send(tx).await;
        rx.await
    };

    display_line!(io, "{}", "==== Shielded sync started ====".on_white());
    display_line!(io, "\n\n");
    let logger = CliLogger::new(io);
    let sync = async move {
        shielded
            .fetch(client, &logger, last_query_height, batch_size, sks, fvks)
            .await
            .map(|_| shielded)
    };
    tokio::select! {
        sync = sync => {
            let shielded = sync?;
            display!(io, "Syncing finished\n");
            Ok(shielded)
        },
        sig = shutdown_signal => {
            sig.map_err(|e| Error::Other(e.to_string()))?;
            display!(io, "\n");
            Ok(ShieldedContext::default())
        },
    }
}

pub struct CliLogging<'io, T, IO: Io> {
    items: Vec<T>,
    index: usize,
    length: usize,
    io: &'io IO,
    r#type: ProgressType,
}

impl<'io, T: Debug, IO: Io> CliLogging<'io, T, IO> {
    fn new<I>(items: I, io: &'io IO, r#type: ProgressType) -> Self
    where
        I: IntoIterator<Item = T>,
    {
        let items: Vec<_> = items.into_iter().collect();
        Self {
            length: items.len(),
            items,
            index: 0,
            io,
            r#type,
        }
    }
}

impl<'io, T: Debug, IO: Io> Iterator for CliLogging<'io, T, IO> {
    type Item = T;

    fn next(&mut self) -> Option<Self::Item> {
        if self.index == 0 {
            self.items = {
                let mut new_items = vec![];
                std::mem::swap(&mut new_items, &mut self.items);
                new_items.into_iter().rev().collect()
            };
        }
        if self.items.is_empty() {
            return None;
        }
        self.index += 1;
        let percent = (100 * self.index) / self.length;
        let completed: String = vec!['#'; percent].iter().collect();
        let incomplete: String = vec!['.'; 100 - percent].iter().collect();
        display_line!(self.io, "\x1b[2A\x1b[J");
        match self.r#type {
            ProgressType::Fetch => display_line!(
                self.io,
                "Fetched block {:?} of {:?}",
                self.items.last().unwrap(),
                self.items[0]
            ),
            ProgressType::Scan => display_line!(
                self.io,
                "Scanning {} of {}",
                self.index,
                self.length
            ),
        }
        display!(self.io, "[{}{}] ~~ {} %", completed, incomplete, percent);
        self.io.flush();
        self.items.pop()
    }
}

/// A progress logger for the CLI
#[derive(Debug, Clone)]
pub struct CliLogger<'io, IO: Io> {
    io: &'io IO,
}

impl<'io, IO: Io> CliLogger<'io, IO> {
    pub fn new(io: &'io IO) -> Self {
        Self { io }
    }
}

impl<'io, IO: Io> ProgressLogger<IO> for CliLogger<'io, IO> {
    type Fetch = CliLogging<'io, u64, IO>;
    type Scan = CliLogging<'io, IndexedNoteEntry, IO>;

    fn io(&self) -> &IO {
        self.io
    }

    fn fetch<I>(&self, items: I) -> Self::Fetch
    where
        I: IntoIterator<Item = u64>,
    {
        CliLogging::new(items, self.io, ProgressType::Fetch)
    }

    fn scan<I>(&self, items: I) -> Self::Scan
    where
        I: IntoIterator<Item = IndexedNoteEntry>,
    {
        CliLogging::new(items, self.io, ProgressType::Scan)
    }
}
