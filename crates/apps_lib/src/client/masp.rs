use std::time::Duration;

use color_eyre::owo_colors::OwoColorize;
use masp_primitives::sapling::ViewingKey;
use masp_primitives::zip32::ExtendedSpendingKey;
use namada_sdk::control_flow::install_shutdown_signal;
use namada_sdk::error::Error;
#[cfg(any(test, feature = "testing"))]
use namada_sdk::io::DevNullProgressBar;
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
    wait_for_last_query_height: bool,
    indexer_addr: Option<&str>,
    io: &IO,
    last_query_height: Option<BlockHeight>,
    sks: &[ExtendedSpendingKey],
    fvks: &[ViewingKey],
) -> Result<ShieldedContext<U>, Error> {
    let (fetched_bar, scanned_bar, applied_bar) = {
        #[cfg(any(test, feature = "testing"))]
        {
            (DevNullProgressBar, DevNullProgressBar, DevNullProgressBar)
        }

        #[cfg(not(any(test, feature = "testing")))]
        {
            let fetched = kdam::tqdm!(
                total = 0,
                desc = "fetched ",
                animation = "fillup",
                position = 0,
                force_refresh = true,
                dynamic_ncols = true,
                miniters = 0,
                mininterval = 0.05
            );

            let scanned = kdam::tqdm!(
                total = 0,
                desc = "scanned ",
                animation = "fillup",
                position = 1,
                force_refresh = true,
                dynamic_ncols = true,
                miniters = 0,
                mininterval = 0.05
            );

            let applied = kdam::tqdm!(
                total = 0,
                desc = "applied ",
                animation = "fillup",
                position = 2,
                force_refresh = true,
                dynamic_ncols = true,
                miniters = 0,
                mininterval = 0.05
            );

            (fetched, scanned, applied)
        }
    };

    macro_rules! dispatch_client {
        ($client:expr) => {{
            let config = ShieldedSyncConfig::builder()
                .client($client)
                .fetched_tracker(fetched_bar)
                .scanned_tracker(scanned_bar)
                .applied_tracker(applied_bar)
                .shutdown_signal(install_shutdown_signal(false))
                .wait_for_last_query_height(wait_for_last_query_height)
                .build();

            let env = MaspLocalTaskEnv::new(500)?;
            let ctx = shielded
                .fetch(env, config, last_query_height, sks, fvks)
                .await
                .map(|_| shielded);

            display!(io, "\nSyncing finished\n");

            ctx
        }};
    }

    let shielded = if let Some(endpoint) = indexer_addr {
        display_line!(
            io,
            "{}\n",
            "==== Shielded sync started using indexer client ====".bold()
        );

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

        dispatch_client!(IndexerMaspClient::new(client, url, true))?
    } else {
        display_line!(
            io,
            "{}\n",
            "==== Shielded sync started using ledger client ====".bold()
        );

        dispatch_client!(LedgerMaspClient::new(client))?
    };

    Ok(shielded)
}
