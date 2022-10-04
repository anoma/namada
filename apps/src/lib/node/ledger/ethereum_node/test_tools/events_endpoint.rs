use borsh::BorshDeserialize;
use namada::types::ethereum_events::EthereumEvent;
use tokio::macros::support::poll_fn;
use tokio::sync::mpsc::UnboundedSender;
use warp::Filter;

/// The default IP address and port on which the events endpoint will listen.
const DEFAULT_LISTEN_ADDR: ([u8; 4], u16) = ([0, 0, 0, 0], 3030);

/// The endpoint to which Borsh-serialized Ethereum events should be sent to,
/// via an HTTP POST request.
const EVENTS_POST_ENDPOINT: &str = "eth_events";

/// Starts a [`warp::Server`] that listens for Borsh-serialized Ethereum events
/// and then forwards them to `sender`. It shuts down if `abort_sender` is
/// closed.
pub fn serve(
    sender: UnboundedSender<EthereumEvent>,
    mut abort_sender: tokio::sync::oneshot::Sender<()>,
) -> tokio::task::JoinHandle<()> {
    let eth_events = warp::post()
        .and(warp::path(EVENTS_POST_ENDPOINT))
        .and(warp::body::bytes())
        .map(move |bytes: bytes::Bytes| {
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
            match sender.send(event) {
                Ok(()) => {
                    warp::reply::with_status("OK", warp::http::StatusCode::OK)
                }
                Err(error) => {
                    tracing::warn!(?error, "Couldn't send event");
                    warp::reply::with_status(
                        "Internal server error",
                        warp::http::StatusCode::INTERNAL_SERVER_ERROR,
                    )
                }
            }
        });

    let (_, server) = warp::serve(eth_events).bind_with_graceful_shutdown(
        DEFAULT_LISTEN_ADDR,
        async move {
            tracing::info!(
                ?DEFAULT_LISTEN_ADDR,
                "Starting to listen for Borsh-serialized Ethereum events"
            );
            poll_fn(|cx| abort_sender.poll_closed(cx)).await;
            tracing::info!(
                ?DEFAULT_LISTEN_ADDR,
                "Stopping listening for Borsh-serialized Ethereum events"
            );
        },
    );

    tokio::task::spawn(server)
}
