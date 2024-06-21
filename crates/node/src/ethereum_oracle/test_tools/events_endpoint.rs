use std::net::SocketAddr;

use borsh::BorshDeserialize;
use namada_sdk::ethereum_events::EthereumEvent;
use tokio::sync::mpsc::Sender as BoundedSender;
use tokio::sync::oneshot::{Receiver, Sender};
use warp::reply::WithStatus;
use warp::Filter;

use crate::ethereum_oracle as oracle;

/// The endpoint to which Borsh-serialized Ethereum events should be sent to,
/// via an HTTP POST request.
const EVENTS_POST_ENDPOINT: &str = "eth_events";

/// Starts a [`warp::Server`] that listens for Borsh-serialized Ethereum events
/// and then forwards them to `sender`. It shuts down if a signal is sent on the
/// `abort_recv` channel. Accepts the receive-half of an oracle control channel
/// (`control_recv`) that will be kept alive until shutdown.
pub async fn serve(
    listen_addr: String,
    sender: BoundedSender<EthereumEvent>,
    mut control_recv: oracle::control::Receiver,
    abort_recv: Receiver<Sender<()>>,
) {
    let listen_addr: SocketAddr = listen_addr
        .parse()
        .expect("Failed to parse the events endpoint listen address");
    tracing::info!(?listen_addr, "Ethereum event endpoint is starting");
    let eth_events = warp::post()
        .and(warp::path(EVENTS_POST_ENDPOINT))
        .and(warp::body::bytes())
        .then(move |bytes: bytes::Bytes| send(bytes, sender.clone()));

    let (_, future) = warp::serve(eth_events).bind_with_graceful_shutdown(
        listen_addr,
        async move {
            tracing::info!(
                ?listen_addr,
                "Starting to listen for Borsh-serialized Ethereum events"
            );
            let control_recv_discarder = tokio::spawn(async move {
                while let Some(command) = control_recv.recv().await {
                    tracing::debug!(
                        ?command,
                        "Events endpoint received an oracle command which \
                         will be ignored since we are not running a real \
                         oracle"
                    )
                }
            });
            match abort_recv.await {
                Ok(abort_resp_send) => {
                    if abort_resp_send.send(()).is_err() {
                        tracing::warn!(
                            "Received signal to abort but failed to respond, \
                             will abort now"
                        )
                    }
                }
                Err(_) => tracing::warn!(
                    "Channel for receiving signal to abort was closed \
                     abruptly, will abort now"
                ),
            };
            tracing::info!(
                ?listen_addr,
                "Stopping listening for Borsh-serialized Ethereum events"
            );
            control_recv_discarder.abort();
        },
    );
    future.await
}

/// Callback to send out events from the oracle
async fn send(
    bytes: bytes::Bytes,
    sender: BoundedSender<EthereumEvent>,
) -> WithStatus<&'static str> {
    tracing::info!(len = bytes.len(), "Received request");
    let event = match EthereumEvent::try_from_slice(&bytes) {
        Ok(event) => event,
        Err(error) => {
            tracing::warn!(?error, "Couldn't handle request");
            return warp::reply::with_status(
                "Bad request",
                warp::http::StatusCode::BAD_REQUEST,
            );
        }
    };
    tracing::debug!("Serialized event - {:#?}", event);
    match sender.send(event).await {
        Ok(()) => warp::reply::with_status("OK", warp::http::StatusCode::OK),
        Err(error) => {
            tracing::warn!(?error, "Couldn't send event");
            warp::reply::with_status(
                "Internal server error",
                warp::http::StatusCode::INTERNAL_SERVER_ERROR,
            )
        }
    }
}
