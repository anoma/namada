use std::collections::HashMap;
use std::convert::TryFrom;
use std::fmt::{Display, Formatter};
use std::net::TcpStream;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use async_trait::async_trait;
use thiserror::Error;
use tokio::time::Instant;
use websocket::result::WebSocketError;
use websocket::{ClientBuilder, Message, OwnedMessage};

use crate::facade::tendermint_config::net::Address;
use crate::facade::tendermint_rpc::{
    Client, Error as RpcError, Request, Response, SimpleRequest,
};

#[derive(Error, Debug)]
pub enum Error {
    #[error("Could not convert into websocket address: {0:?}")]
    Address(Address),
    #[error("Websocket Error: {0:?}")]
    Websocket(WebSocketError),
    #[error("Failed to subscribe to the event: {0}")]
    Subscribe(String),
    #[error("Failed to unsubscribe to the event: {0}")]
    Unsubscribe(String),
    #[error("Unexpected response from query: {0:?}")]
    UnexpectedResponse(OwnedMessage),
    #[error("More then one subscription at a time is not supported")]
    AlreadySubscribed,
    #[error("Cannot wait on a response if not subscribed to an event")]
    NotSubscribed,
    #[error("Received an error response: {0}")]
    Response(String),
    #[error("Encountered JSONRPC request/response without an id")]
    MissingId,
    #[error("Connection timed out")]
    ConnectionTimeout,
}

type Json = serde_json::Value;

/// Module that brings in the basic building blocks from tendermint_rpc
/// and adds the necessary functionality and wrappers to them.
mod rpc_types {
    use std::collections::HashMap;
    use std::fmt;
    use std::str::FromStr;

    use serde::{de, Deserialize, Serialize, Serializer};

    use super::Json;
    use crate::facade::tendermint_rpc::method::Method;
    use crate::facade::tendermint_rpc::query::{EventType, Query};
    use crate::facade::tendermint_rpc::{request, response};

    #[derive(Debug, Deserialize, Serialize)]
    pub struct RpcRequest {
        #[serde(skip_serializing)]
        method: Method,
        params: HashMap<String, String>,
    }

    #[derive(Debug, Deserialize, Serialize)]
    pub enum SubscribeType {
        Subscribe,
        Unsubscribe,
    }

    #[derive(Debug, Deserialize, Serialize)]
    pub struct RpcSubscription(
        #[serde(skip_serializing)] pub SubscribeType,
        #[serde(serialize_with = "serialize_query")]
        #[serde(deserialize_with = "deserialize_query")]
        pub Query,
    );

    pub(super) fn serialize_query<S>(
        query: &Query,
        serialize: S,
    ) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serialize.serialize_str(&query.to_string())
    }

    pub(super) fn deserialize_query<'de, D>(
        deserializer: D,
    ) -> Result<Query, D::Error>
    where
        D: de::Deserializer<'de>,
    {
        struct QueryVisitor;

        impl<'de> de::Visitor<'de> for QueryVisitor {
            type Value = Query;

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str(
                    "a string of params from a valid Tendermint RPC query",
                )
            }

            fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                match EventType::from_str(v) {
                    Ok(event) => Ok(Query::from(event)),
                    Err(error) => {
                        Err(de::Error::custom(format!("{:?}", error)))
                    }
                }
            }
        }
        deserializer.deserialize_any(QueryVisitor)
    }

    /// This type is required by the tendermint_rs traits but we
    /// cannot use it due to a bug in the RPC responses from
    /// tendermint
    #[derive(Debug, Deserialize, Serialize)]
    #[serde(transparent)]
    pub struct RpcResponse(pub Json);

    impl response::Response for RpcResponse {}

    impl request::Request for RpcRequest {
        type Response = RpcResponse;

        fn method(&self) -> Method {
            self.method
        }
    }

    impl request::Request for RpcSubscription {
        type Response = RpcResponse;

        fn method(&self) -> Method {
            match self.0 {
                SubscribeType::Subscribe => Method::Subscribe,
                SubscribeType::Unsubscribe => Method::Unsubscribe,
            }
        }
    }
}

pub struct WebSocketAddress {
    host: String,
    port: u16,
}

impl TryFrom<Address> for WebSocketAddress {
    type Error = Error;

    fn try_from(value: Address) -> Result<Self, Self::Error> {
        match value {
            Address::Tcp { host, port, .. } => Ok(Self { host, port }),
            _ => Err(Error::Address(value)),
        }
    }
}

impl Display for WebSocketAddress {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "ws://{}:{}/websocket", self.host, self.port)
    }
}

/// We need interior mutability since the `perform` method of the `Client`
/// trait from `tendermint_rpc` only takes `&self` as an argument
/// Furthermore, TendermintWebsocketClient must be `Send` since it will be
/// used in async methods
type Websocket = Arc<Mutex<websocket::sync::client::Client<TcpStream>>>;
type ResponseQueue = Arc<Mutex<HashMap<String, String>>>;

pub struct TendermintWebsocketClient {
    websocket: Websocket,
    received_responses: ResponseQueue,
    connection_timeout: Duration,
}

impl TendermintWebsocketClient {
    /// Open up a new websocket given a specified URL.
    /// If no `connection_timeout` is given, defaults to 5 minutes.
    pub fn open(
        url: WebSocketAddress,
        connection_timeout: Option<Duration>,
    ) -> Result<Self, Error> {
        match ClientBuilder::new(&url.to_string())
            .unwrap()
            .connect_insecure()
        {
            Ok(websocket) => Ok(Self {
                websocket: Arc::new(Mutex::new(websocket)),
                received_responses: Arc::new(Mutex::new(HashMap::new())),
                connection_timeout: connection_timeout
                    .unwrap_or_else(|| Duration::new(300, 0)),
            }),
            Err(inner) => Err(Error::Websocket(inner)),
        }
    }

    /// Shutdown the client. Can still be reused afterwards
    pub fn close(&mut self) {
        // Even in the case of errors, this will be shutdown
        let _ = self.websocket.lock().unwrap().shutdown();
        self.received_responses.lock().unwrap().clear();
    }
}

#[async_trait]
impl Client for TendermintWebsocketClient {
    async fn perform<R>(&self, request: R) -> Result<R::Response, RpcError>
    where
        R: SimpleRequest,
    {
        // send the subscription request
        // Return an empty response if the request fails to send
        let req_json = request.into_json();
        let req_id = get_id(&req_json).unwrap();
        if let Err(error) = self
            .websocket
            .lock()
            .unwrap()
            .send_message(&Message::text(&req_json))
        {
            tracing::info! {
                "Unable to send request: {}\nReceived Error: {:?}",
                &req_json,
                error
            };
            return <R as Request>::Response::from_string("");
        }

        // Return the response if text is returned, else return empty response
        let mut websocket = self.websocket.lock().unwrap();
        let start = Instant::now();
        loop {
            let duration = Instant::now().duration_since(start);
            if duration > self.connection_timeout {
                tracing::error!(
                    "Websocket connection timed out while waiting for response"
                );
                return Err(RpcError::web_socket_timeout(duration));
            }
            let response = match websocket
                .recv_message()
                .expect("Failed to receive message from websocket")
            {
                OwnedMessage::Text(resp) => resp,
                OwnedMessage::Ping(data) => {
                    tracing::debug!("Received websocket Ping, sending Pong");
                    websocket.send_message(&OwnedMessage::Pong(data)).unwrap();
                    continue;
                }
                OwnedMessage::Pong(_) => {
                    tracing::debug!("Received websocket Pong, ignoring");
                    continue;
                }
                other => {
                    tracing::info! {
                        "Received unexpected response to query: {}\nReceived {:?}",
                        &req_json,
                        other
                    };
                    String::from("")
                }
            };
            // Check that we did not accidentally get a response for a
            // subscription. If so, store it for later
            if let Ok(resp_id) = get_id(&response) {
                if resp_id != req_id {
                    self.received_responses
                        .lock()
                        .unwrap()
                        .insert(resp_id, response);
                } else {
                    return <R as Request>::Response::from_string(response);
                }
            } else {
                // got an invalid response, just return nothing
                return <R as Request>::Response::from_string(response);
            };
        }
    }
}

fn get_id(req_json: &str) -> Result<String, Error> {
    if let serde_json::Value::Object(req) =
        serde_json::from_str(req_json).unwrap()
    {
        req.get("id").ok_or(Error::MissingId).map(|v| v.to_string())
    } else {
        Err(Error::MissingId)
    }
}
