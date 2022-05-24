#[cfg(not(feature = "ABCI"))]
mod tm_jsonrpc {
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};
    use std::ops::{Deref, DerefMut};

    use curl::easy::{Easy2, Handler, WriteError};
    use serde::{Deserialize, Serialize};
    use tendermint_rpc::query::Query;
    use thiserror::Error;

    use crate::client::tendermint_rpc_types::{
        parse, Cursor, EventParams, EventReply, TxResponse,
    };

    const JSONRPC_PORT: u16 = 26657;

    #[derive(Error, Debug)]
    pub enum Error {
        #[error("Error in sending JSON RPC request to Tendermint: {0}")]
        SendError(curl::Error),
        #[error("Received an error response from Tendermint: {0:?}")]
        RpcError(tendermint_rpc::response_error::ResponseError),
        #[error("Received malformed JSON response from Tendermint")]
        MalformedJson,
        #[error("Received an empty response from Tendermint")]
        EmptyResponse,
        #[error("Could not deserialize JSON response: {0}")]
        DeserializeError(serde_json::Error),
        #[error("Could not find event for the given hash: {0}")]
        NotFound(String),
    }

    /// The body of a json rpc request
    #[derive(Serialize)]
    pub struct Request {
        /// Method name
        pub method: String,
        /// parameters to give the method
        params: EventParams,
        /// ID of the request
        id: u8,
    }

    impl From<EventParams> for Request {
        fn from(params: EventParams) -> Self {
            Request {
                method: "events".into(),
                params,
                id: 1,
            }
        }
    }

    /// The response we get back from Tendermint
    #[derive(Serialize, Deserialize)]
    pub struct Response {
        /// JSON-RPC version
        jsonrpc: String,
        /// Identifier included in request
        id: u8,
        /// Results of request (if successful)
        result: Option<EventReply>,
        /// Error message if unsuccessful
        error: Option<tendermint_rpc::response_error::ResponseError>,
    }

    impl Response {
        /// Convert the response into a result type
        pub fn into_result(self) -> Result<EventReply, Error> {
            if let Some(e) = self.error {
                Err(Error::RpcError(e))
            } else if let Some(result) = self.result {
                Ok(result)
            } else {
                Err(Error::MalformedJson)
            }
        }
    }

    /// Holds bytes returned in response to curl request
    #[derive(Default)]
    pub struct Collector(Vec<u8>);

    impl Handler for Collector {
        fn write(&mut self, data: &[u8]) -> Result<usize, WriteError> {
            self.0.extend_from_slice(data);
            Ok(data.len())
        }
    }

    /// The RPC client
    pub struct Client<'a> {
        /// The actual curl client
        inner: Easy2<Collector>,
        /// Url to send requests to
        url: &'a str,
        /// The request body
        request: Request,
        /// The latest event returned; used for paging through the event log
        newest: Cursor,
        /// The hash of the tx whose corresponding event is being searched for.
        hash: &'a str,
    }

    impl<'a> Deref for Client<'a> {
        type Target = Easy2<Collector>;

        fn deref(&self) -> &Self::Target {
            &self.inner
        }
    }

    impl<'a> DerefMut for Client<'a> {
        fn deref_mut(&mut self) -> &mut Self::Target {
            &mut self.inner
        }
    }

    impl<'a> Client<'a> {
        /// Create a new client
        pub fn new(url: &'a str, request: Request, hash: &'a str) -> Self {
            let mut client = Self {
                inner: Easy2::new(Collector::default()),
                url,
                request,
                newest: Default::default(),
                hash,
            };
            client.reset();
            client
        }

        /// Send a request to Tendermint
        /// This pages through the event log 20 events at a time
        /// until either
        ///   1. The event is found and thus returned
        ///   2. The end of the log is reached
        pub fn send(&mut self) -> Result<TxResponse, Error> {
            loop {
                // prepare the client to send another request
                // self.reset();
                // send off the request
                self.perform().map_err(Error::SendError)?;
                // deserialize response
                let response: Response = serde_json::from_slice(self.get_ref().0.as_slice())
                        .map_err(Error::DeserializeError)?;
                let response = response.into_result()?;

                // reached the end of the logs, break out.
                if self.newest == response.newest {
                    return Err(Error::NotFound(self.hash.to_string()));
                }

                // update the newest cursor seen
                //self.newest = response.newest.clone();

                // search for the event in the response and return
                // it if found. Else request the next chunk of results
                if let Some(result) = parse(response, self.hash) {
                    return Ok(result);
                }
            }
        }

        /// Reset the client so that it can send it's request again.
        /// Used if the event being searched for is not found yet.
        fn reset(&mut self) {
            self.inner.reset();
            let url = self.url.clone();
            self.url(url).unwrap();
            self.post(true).unwrap();

            // look only at events after the newest seen
            self.request.params.after = self.newest.clone();
            // craft the body of the request
            let request_body = serde_json::to_string(&self.request).unwrap();
            println!("{}", &request_body);
            self.post_field_size(request_body.as_bytes().len() as u64)
                .unwrap();
            // update the request and serialize to bytes
            let data = serde_json::to_string(&self.request).unwrap();
            let data = data.as_bytes();
            self.post_fields_copy(data).unwrap();
        }
    }

    /// Given a query looking for a particular Anoma event,
    /// query the Tendermint's jsonrpc endpoint for the events
    /// log. Returns the appropriate event if found in the log.
    pub async fn fetch_event(
        filter: Query,
        tx_hash: &str,
    ) -> Result<TxResponse, Error> {
        std::thread::sleep(std::time::Duration::from_secs(5));
        let url = SocketAddr::new(
            IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
            JSONRPC_PORT,
        )
        .to_string();
        // craft the body of the request
        let request = Request::from(EventParams::new(
            filter,
            50,
            std::time::Duration::from_secs(60),
        ));
        // construct a curl client
        let mut client = Client::new(&url, request, tx_hash);
        // perform the request
        client.send()
    }

    #[cfg(test)]
    mod test_rpc_types {
        use serde_json::json;

        use super::*;
        use crate::client::tendermint_rpc_types::{EventData, EventItem};

        /// Test that we correctly parse the response from Tendermint
        #[test]
        fn test_parse_response() {
            let resp = r#"
            {
                "jsonrpc":"2.0",
                "id":1,
                "result":{
                    "items": [{
                        "cursor":"16f1b066717b4261-0060",
                        "event":"NewRoundStep",
                        "data":{
                            "type":"tendermint/event/RoundState",
                            "value":{
                                "height":"17416",
                                "round":0,
                                "step":"RoundStepCommit"
                            }
                        }
                    }],
                    "more":true,
                    "oldest":"16f1b065029b23d0-0001",
                    "newest":"16f1b066717b4261-0060"
                }
            }"#;
            let response: Response =
                serde_json::from_str(resp).expect("Test failed");
            let items = response.into_result().expect("Test failed").items;
            assert_eq!(
                items,
                vec![EventItem {
                    cursor: String::from("16f1b066717b4261-0060").into(),
                    event: "NewRoundStep".to_string(),
                    data: EventData {
                        r#type: "tendermint/event/RoundState".to_string(),
                        value: json!({
                            "height":"17416",
                            "round":0,
                            "step":"RoundStepCommit"
                        }),
                    }
                }]
            )
        }
    }
}

#[cfg(not(feature = "ABCI"))]
pub use tm_jsonrpc::*;
