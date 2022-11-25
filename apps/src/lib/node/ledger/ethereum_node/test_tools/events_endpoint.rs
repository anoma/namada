use borsh::BorshDeserialize;
use namada::types::ethereum_events::EthereumEvent;
use tokio::sync::mpsc::Sender as BoundedSender;
use tokio::sync::oneshot::{Receiver, Sender};
use warp::reply::WithStatus;
use warp::Filter;

/// The default IP address and port on which the events endpoint will listen.
const DEFAULT_LISTEN_ADDR: ([u8; 4], u16) = ([0, 0, 0, 0], 3030);

/// The endpoint to which Borsh-serialized Ethereum events should be sent to,
/// via an HTTP POST request.
const EVENTS_POST_ENDPOINT: &str = "eth_events";

/// Starts a [`warp::Server`] that listens for Borsh-serialized Ethereum events
/// and then forwards them to `sender`. It shuts down if a signal is sent on the
/// `abort_recv` channel.
pub async fn serve(
    sender: BoundedSender<EthereumEvent>,
    abort_recv: Receiver<Sender<()>>,
) {
    tracing::info!(?DEFAULT_LISTEN_ADDR, "Ethereum event endpoint is starting");
    let eth_events = warp::post()
        .and(warp::path(EVENTS_POST_ENDPOINT))
        .and(warp::body::bytes())
        .then(move |bytes: bytes::Bytes| send(bytes, sender.clone()));

    let (_, future) = warp::serve(eth_events).bind_with_graceful_shutdown(
        DEFAULT_LISTEN_ADDR,
        async move {
            tracing::info!(
                ?DEFAULT_LISTEN_ADDR,
                "Starting to listen for Borsh-serialized Ethereum events"
            );
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
                ?DEFAULT_LISTEN_ADDR,
                "Stopping listening for Borsh-serialized Ethereum events"
            );
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
