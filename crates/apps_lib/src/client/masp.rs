use std::time::Duration;

use color_eyre::owo_colors::OwoColorize;
use masp_primitives::sapling::ViewingKey;
use masp_primitives::zip32::ExtendedSpendingKey;
use namada_sdk::control_flow::install_shutdown_signal;
use namada_sdk::error::Error;
use namada_sdk::io::Io;
use namada_sdk::masp::utils::{IndexerMaspClient, LedgerMaspClient};
use namada_sdk::masp::{
    MaspLocalTaskEnv, ShieldedContext, ShieldedSyncConfig, ShieldedUtils,
};
use namada_sdk::queries::Client;
use namada_sdk::storage::BlockHeight;
use namada_sdk::{display, display_line, MaybeSend, MaybeSync};

#[allow(clippy::too_many_arguments)]
pub async fn syncing<
    U: ShieldedUtils + MaybeSend + MaybeSync,
    C: Client + Send + Sync + 'static,
    IO: Io + Send + Sync,
>(
    mut shielded: ShieldedContext<U>,
    client: C,
    indexer_addr: Option<&str>,
    io: &IO,
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
    let env = MaspLocalTaskEnv::new(500)?;

    let (_multi_progress, fetched, scanned) = {
        let multi = indicatif::MultiProgress::new();
        let fetched = multi.add(indicatif::ProgressBar::new(0));
        let scanned = multi.add(indicatif::ProgressBar::new(0));
        (multi, fetched, scanned)
    };

    macro_rules! dispatch_client {
        ($client:expr) => {{
            let config = ShieldedSyncConfig::builder()
                .client($client)
                .fetched_tracker(fetched)
                .scanned_tracker(scanned)
                .build();
            shielded
                .fetch(
                    install_shutdown_signal(),
                    env,
                    config,
                    last_query_height,
                    sks,
                    fvks,
                )
                .await
                .map(|_| shielded)
        }};
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
