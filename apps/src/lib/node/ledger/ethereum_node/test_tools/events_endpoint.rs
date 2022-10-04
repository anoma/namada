use borsh::BorshDeserialize;
use namada::types::ethereum_events::EthereumEvent;
use tokio::sync::mpsc::UnboundedSender;

const DEFAULT_ENDPOINT: ([u8; 4], u16) = ([0, 0, 0, 0], 3030);

/// The path to which Borsh-serialized Ethereum events should be submitted
const PATH: &str = "eth_events";

pub fn serve(
    sender: UnboundedSender<EthereumEvent>,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        use warp::Filter;

        tracing::info!(
            ?DEFAULT_ENDPOINT,
            "Ethereum event endpoint is starting"
        );

        let eth_events = warp::post()
            .and(warp::path(PATH))
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
                    Ok(()) => warp::reply::with_status(
                        "OK",
                        warp::http::StatusCode::OK,
                    ),
                    Err(error) => {
                        tracing::warn!(?error, "Couldn't send event");
                        warp::reply::with_status(
                            "Internal server error",
                            warp::http::StatusCode::INTERNAL_SERVER_ERROR,
                        )
                    }
                }
            });

        warp::serve(eth_events).run(DEFAULT_ENDPOINT).await;

        tracing::info!(
            ?DEFAULT_ENDPOINT,
            "Ethereum event endpoint is no longer running"
        );
    })
}
