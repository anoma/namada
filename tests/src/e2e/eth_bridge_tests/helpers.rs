//! Helper functionality for use in tests to do with the Ethereum bridge.

use borsh::BorshSerialize;
use eyre::{eyre, Context, Result};
use hyper::client::HttpConnector;
use hyper::{Body, Client, Method, Request, StatusCode};
use namada_core::types::ethereum_events::EthereumEvent;

/// Simple client for submitting fake Ethereum events to a Namada node.
pub struct EventsEndpointClient {
    http: Client<HttpConnector, Body>,
    events_endpoint: String,
}

impl EventsEndpointClient {
    pub fn new(events_endpoint: String) -> Self {
        Self {
            http: Client::new(),
            events_endpoint,
        }
    }

    /// Sends an Ethereum event to the Namada node. Returns `Ok` iff the event
    /// was successfully sent.
    pub async fn send(&mut self, event: &EthereumEvent) -> Result<()> {
        let event = event.try_to_vec()?;

        let req = Request::builder()
            .method(Method::POST)
            .uri(&self.events_endpoint)
            .header("content-type", "application/octet-stream")
            .body(Body::from(event))?;

        let resp = self
            .http
            .request(req)
            .await
            .wrap_err_with(|| "sending event")?;

        if resp.status() != StatusCode::OK {
            return Err(eyre!("unexpected response status: {}", resp.status()));
        }
        Ok(())
    }
}
