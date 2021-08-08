use std::convert::TryFrom;
use std::fmt::{Display, Formatter};
use std::net::TcpStream;
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use sha2::{Digest, Sha256};
use tendermint::abci::transaction;
use tendermint::net::Address;
use tendermint_rpc::query::Query;
use tendermint_rpc::{Client, Request, Response, SimpleRequest};
use thiserror::Error;
use websocket::result::WebSocketError;
use websocket::{ClientBuilder, Message, OwnedMessage};

#[derive(Error, Debug)]
pub enum Error {
    #[error("Could not convert into websocket address: {0:?}")]
    Address(tendermint::net::Address),
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
}

/// Module that brings in the basic building blocks from tendermint_rpc
/// and adds the necessary functionality and wrappers to them.
mod rpc_types {
    use std::collections::HashMap;
    use std::fmt;
    use std::str::FromStr;

    use serde::{de, Deserialize, Serialize, Serializer};
    use tendermint_rpc::method::Method;
    use tendermint_rpc::query::{EventType, Query};
    use tendermint_rpc::{request, response};

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

    fn serialize_query<S>(
        query: &Query,
        serialize: S,
    ) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serialize.serialize_str(&query.to_string())
    }

    fn deserialize_query<'de, D>(deserializer: D) -> Result<Query, D::Error>
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
    pub struct RpcResponse(String);

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

impl TryFrom<tendermint::net::Address> for WebSocketAddress {
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

use rpc_types::{RpcSubscription, SubscribeType};

/// We need interior mutability since the `perform` method of the `Client`
/// trait from `tendermint_rpc` only takes `&self` as an argument
/// Furthermore, TendermintRpcClient must be `Send` since it will be
/// used in async methods
type Websocket = Arc<Mutex<websocket::sync::client::Client<TcpStream>>>;

pub struct TendermintRpcClient {
    websocket: Websocket,
    subscribed: Option<Query>,
}

impl TendermintRpcClient {
    /// Open up a new websocket given a specified URL
    pub fn open(url: WebSocketAddress) -> Result<Self, Error> {
        match ClientBuilder::new(&url.to_string())
            .unwrap()
            .connect_insecure()
        {
            Ok(websocket) => Ok(Self {
                websocket: Arc::new(Mutex::new(websocket)),
                subscribed: None,
            }),
            Err(inner) => Err(Error::Websocket(inner)),
        }
    }

    /// Shutdown the client. Can still be reused afterwards
    pub fn close(&mut self) {
        // Even in the case of errors, this will be shutdown
        let _ = self.websocket.lock().unwrap().shutdown();
        self.subscribed = None
    }

    /// Subscribes to an event specified by the query argument.
    pub fn subscribe(&mut self, query: Query) -> Result<(), Error> {
        // We do not support more than one subscription currently
        // This can be fixed by correlating on ids later
        if self.subscribed.is_some() {
            return Err(Error::AlreadySubscribed);
        }
        // send the subscription request
        let message = RpcSubscription(SubscribeType::Subscribe, query.clone())
            .into_json();

        self.websocket
            .lock()
            .unwrap()
            .send_message(&Message::text(&message))
            .map_err(Error::Websocket)?;

        // check that the request was received and a success message returned
        match self.process_response(|_| Error::Subscribe(message)) {
            Ok(_) => {
                self.subscribed = Some(query);
                Ok(())
            }
            Err(err) => Err(err),
        }
    }

    /// Receive a response from the subscribed event
    pub fn receive_response(&self) -> Result<(), Error> {
        if self.subscribed.is_some() {
            let response = self.process_response(Error::Response)?;
            println!("{:?}", response);
            Ok(())
        } else {
            Err(Error::NotSubscribed)
        }
    }

    /// Unsubscribe from the currently subscribed event
    /// Note that even if an error is returned, the client
    /// will return to an unsubscribed state
    pub fn unsubscribe(&mut self) -> Result<(), Error> {
        match self.subscribed.take() {
            Some(query) => {
                // send the subscription request
                let message =
                    RpcSubscription(SubscribeType::Unsubscribe, query)
                        .into_json();

                self.websocket
                    .lock()
                    .unwrap()
                    .send_message(&Message::text(&message))
                    .map_err(Error::Websocket)?;
                // check that the request was received and a success message
                // returned
                match self.process_response(|_| Error::Unsubscribe(message)) {
                    Ok(_) => Ok(()),
                    Err(err) => Err(err),
                }
            }
            _ => Err(Error::NotSubscribed),
        }
    }

    /// Process the next response received and handle any exceptions that
    /// may have occurred. Takes a function to map response to an error
    /// as a parameter
    ///
    /// Ideally the responses from tendermint would be parsed by the
    /// tendermint-rs libraries. Unfortunately, the "result"/"error"
    /// fields in the response are expected to be strings and
    /// tendermint sometimes sends back `{}` instead. So we
    /// process the response ourselves.
    fn process_response<F>(&self, f: F) -> Result<String, Error>
    where
        F: FnOnce(String) -> Error,
    {
        match self
            .websocket
            .lock()
            .unwrap()
            .recv_message()
            .map_err(Error::Websocket)?
        {
            OwnedMessage::Text(resp) => {
                if let serde_json::Value::Object(parsed) =
                    serde_json::from_str(&resp).unwrap()
                {
                    if parsed.contains_key("result") {
                        Ok(resp)
                    } else if parsed.contains_key("error") {
                        Err(f(resp))
                    } else {
                        Err(Error::UnexpectedResponse(OwnedMessage::Text(resp)))
                    }
                } else {
                    Err(Error::UnexpectedResponse(OwnedMessage::Text(resp)))
                }
            }
            other => Err(Error::UnexpectedResponse(other)),
        }
    }
}

#[async_trait]
impl Client for TendermintRpcClient {
    async fn perform<R>(
        &self,
        request: R,
    ) -> Result<R::Response, tendermint_rpc::error::Error>
    where
        R: SimpleRequest,
    {
        // send the subscription request
        // Return an empty response if the request fails to send
        let req_json = request.into_json();
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
        match self
            .websocket
            .lock()
            .unwrap()
            .recv_message()
            .expect("Failed to receive message from websocket")
        {
            OwnedMessage::Text(resp) => {
                <R as Request>::Response::from_string(resp)
            }
            other => {
                tracing::info! {
                    "Received unexpect response to query: {}\nReceived {:?}",
                    &req_json,
                    other
                };
                <R as Request>::Response::from_string("")
            }
        }
    }
}

pub fn hash_tx(tx_bytes: &[u8]) -> transaction::Hash {
    let digest = Sha256::digest(tx_bytes);
    let mut hash_bytes = [0u8; 32];
    hash_bytes.copy_from_slice(&digest);
    transaction::Hash::new(hash_bytes)
}
