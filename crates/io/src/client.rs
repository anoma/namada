use std::fmt::{Debug, Display};

use namada_core::chain::BlockHeight;
use namada_core::tendermint::merkle::proof::ProofOps;
use tendermint_rpc::endpoint::{
    abci_info, block, block_results, blockchain, commit, consensus_params,
    consensus_state, health, net_info, status,
};
use tendermint_rpc::query::Query;
use tendermint_rpc::{Error as RpcError, Order};
use thiserror::Error;

use crate::MaybeSend;
use crate::tendermint::abci::response::Info;
use crate::tendermint::block::Height;

const HEIGHT_CAST_ERR: &str = "Failed to cast block height";

#[allow(missing_docs)]
#[derive(Error, Debug)]
pub enum Error {
    #[error("{0}")]
    Tendermint(#[from] tendermint_rpc::Error),
    #[error("Decoding error: {0}")]
    Decoding(#[from] std::io::Error),
    #[error("Info log: {0}, error code: {1}")]
    Query(String, u32),
    #[error("Invalid block height: {0} (overflown i64)")]
    InvalidHeight(BlockHeight),
}

/// Generic response from a query
#[derive(Clone, Debug, Default)]
pub struct ResponseQuery<T> {
    /// Response data to be borsh encoded
    pub data: T,
    /// Non-deterministic log of the request execution
    pub info: String,
    /// Optional proof - used for storage value reads which request `prove`
    pub proof: Option<ProofOps>,
    /// Block height from which data was derived
    pub height: BlockHeight,
}

/// [`ResponseQuery`] with borsh-encoded `data` field
pub type EncodedResponseQuery = ResponseQuery<Vec<u8>>;

/// A client with async request dispatcher method, which can be used to invoke
/// type-safe methods from a root queries `Router`, generated
/// via `router!` macro.
#[cfg_attr(feature = "async-send", async_trait::async_trait)]
#[cfg_attr(not(feature = "async-send"), async_trait::async_trait(?Send))]
pub trait Client {
    /// `std::io::Error` can happen in decoding with
    /// `BorshDeserialize::try_from_slice`
    type Error: From<std::io::Error> + Display + Debug;

    /// Send a simple query request at the given path. For more options, use the
    /// `request` method.
    async fn simple_request(
        &self,
        path: String,
    ) -> Result<Vec<u8>, Self::Error> {
        self.request(path, None, None, false)
            .await
            .map(|response| response.data)
    }

    /// Send a query request at the given path.
    async fn request(
        &self,
        path: String,
        data: Option<Vec<u8>>,
        height: Option<BlockHeight>,
        prove: bool,
    ) -> Result<EncodedResponseQuery, Self::Error>;

    /// `/abci_info`: get information about the ABCI application.
    async fn abci_info(&self) -> Result<Info, RpcError> {
        Ok(self.perform(abci_info::Request).await?.response)
    }

    /// `/broadcast_tx_sync`: broadcast a transaction, returning the response
    /// from `CheckTx`.
    async fn broadcast_tx_sync(
        &self,
        tx: impl Into<Vec<u8>> + MaybeSend,
    ) -> Result<tendermint_rpc::endpoint::broadcast::tx_sync::Response, RpcError>
    {
        self.perform(
            tendermint_rpc::endpoint::broadcast::tx_sync::Request::new(tx),
        )
        .await
    }

    /// `/block`: get the latest block.
    async fn latest_block(&self) -> Result<block::Response, RpcError> {
        self.perform(block::Request::default()).await
    }

    /// `/block`: get block at a given height.
    async fn block<H>(&self, height: H) -> Result<block::Response, RpcError>
    where
        H: TryInto<Height> + Send,
    {
        self.perform(block::Request::new(
            height
                .try_into()
                .map_err(|_| RpcError::parse(HEIGHT_CAST_ERR.to_string()))?,
        ))
        .await
    }

    /// `/block_search`: search for blocks by BeginBlock and EndBlock events.
    async fn block_search(
        &self,
        query: Query,
        page: u32,
        per_page: u8,
        order: Order,
    ) -> Result<tendermint_rpc::endpoint::block_search::Response, RpcError>
    {
        self.perform(tendermint_rpc::endpoint::block_search::Request::new(
            query, page, per_page, order,
        ))
        .await
    }

    /// `/block_results`: get ABCI results for a block at a particular height.
    async fn block_results<H>(
        &self,
        height: H,
    ) -> Result<tendermint_rpc::endpoint::block_results::Response, RpcError>
    where
        H: TryInto<Height> + Send,
    {
        self.perform(tendermint_rpc::endpoint::block_results::Request::new(
            height
                .try_into()
                .map_err(|_| RpcError::parse(HEIGHT_CAST_ERR.to_string()))?,
        ))
        .await
    }

    /// `/tx_search`: search for transactions with their results.
    async fn tx_search(
        &self,
        query: Query,
        prove: bool,
        page: u32,
        per_page: u8,
        order: Order,
    ) -> Result<tendermint_rpc::endpoint::tx_search::Response, RpcError> {
        self.perform(tendermint_rpc::endpoint::tx_search::Request::new(
            query, prove, page, per_page, order,
        ))
        .await
    }

    /// `/abci_query`: query the ABCI application
    async fn abci_query<V>(
        &self,
        path: Option<String>,
        data: V,
        height: Option<Height>,
        prove: bool,
    ) -> Result<tendermint_rpc::endpoint::abci_query::AbciQuery, RpcError>
    where
        V: Into<Vec<u8>> + Send,
    {
        Ok(self
            .perform(tendermint_rpc::endpoint::abci_query::Request::new(
                path, data, height, prove,
            ))
            .await?
            .response)
    }

    /// `/block_results`: get ABCI results for the latest block.
    async fn latest_block_results(
        &self,
    ) -> Result<block_results::Response, RpcError> {
        self.perform(block_results::Request::default()).await
    }

    /// `/blockchain`: get block headers for `min` <= `height` <= `max`.
    ///
    /// Block headers are returned in descending order (highest first).
    ///
    /// Returns at most 20 items.
    async fn blockchain<H>(
        &self,
        min: H,
        max: H,
    ) -> Result<blockchain::Response, RpcError>
    where
        H: TryInto<Height> + Send,
    {
        self.perform(blockchain::Request::new(
            min.try_into()
                .map_err(|_| RpcError::parse(HEIGHT_CAST_ERR.to_string()))?,
            max.try_into()
                .map_err(|_| RpcError::parse(HEIGHT_CAST_ERR.to_string()))?,
        ))
        .await
    }

    /// `/commit`: get block commit at a given height.
    async fn commit<H>(&self, height: H) -> Result<commit::Response, RpcError>
    where
        H: TryInto<Height> + Send,
    {
        self.perform(commit::Request::new(
            height
                .try_into()
                .map_err(|_| RpcError::parse(HEIGHT_CAST_ERR.to_string()))?,
        ))
        .await
    }

    /// `/consensus_params`: get current consensus parameters at the specified
    /// height.
    async fn consensus_params<H>(
        &self,
        height: H,
    ) -> Result<consensus_params::Response, RpcError>
    where
        H: TryInto<Height> + Send,
    {
        self.perform(consensus_params::Request::new(Some(
            height
                .try_into()
                .map_err(|_| RpcError::parse(HEIGHT_CAST_ERR.to_string()))?,
        )))
        .await
    }

    /// `/consensus_state`: get current consensus state
    async fn consensus_state(
        &self,
    ) -> Result<consensus_state::Response, RpcError> {
        self.perform(consensus_state::Request::new()).await
    }

    /// `/consensus_params`: get the latest consensus parameters.
    async fn latest_consensus_params(
        &self,
    ) -> Result<consensus_params::Response, RpcError> {
        self.perform(consensus_params::Request::new(None)).await
    }

    /// `/commit`: get the latest block commit
    async fn latest_commit(&self) -> Result<commit::Response, RpcError> {
        self.perform(commit::Request::default()).await
    }

    /// `/health`: get node health.
    ///
    /// Returns empty result (200 OK) on success, no response in case of an
    /// error.
    async fn health(&self) -> Result<(), RpcError> {
        self.perform(health::Request).await?;
        Ok(())
    }

    /// `/net_info`: obtain information about P2P and other network connections.
    async fn net_info(&self) -> Result<net_info::Response, RpcError> {
        self.perform(net_info::Request).await
    }

    /// `/status`: get Tendermint status including node info, pubkey, latest
    /// block hash, app hash, block height and time.
    async fn status(&self) -> Result<status::Response, RpcError> {
        self.perform(status::Request).await
    }

    /// Perform a request against the RPC endpoint
    async fn perform<R>(&self, request: R) -> Result<R::Output, RpcError>
    where
        R: tendermint_rpc::SimpleRequest;
}

#[cfg_attr(feature = "async-send", async_trait::async_trait)]
#[cfg_attr(not(feature = "async-send"), async_trait::async_trait(?Send))]
impl<C: tendermint_rpc::client::Client + std::marker::Sync> Client for C {
    type Error = Error;

    async fn request(
        &self,
        path: String,
        data: Option<Vec<u8>>,
        height: Option<BlockHeight>,
        prove: bool,
    ) -> Result<EncodedResponseQuery, Self::Error> {
        use crate::tendermint::abci::Code;

        let data = data.unwrap_or_default();
        let height = height
            .map(|height| {
                crate::tendermint::block::Height::try_from(height.0)
                    .map_err(|_err| Error::InvalidHeight(height))
            })
            .transpose()?;

        let response = self.abci_query(Some(path), data, height, prove).await?;
        match response.code {
            Code::Ok => Ok(EncodedResponseQuery {
                data: response.value,
                info: response.info,
                proof: response.proof,
                height: response.height.value().into(),
            }),
            Code::Err(code) => Err(Error::Query(response.info, code.into())),
        }
    }

    async fn perform<R>(&self, request: R) -> Result<R::Output, RpcError>
    where
        R: tendermint_rpc::SimpleRequest,
    {
        tendermint_rpc::client::Client::perform(self, request).await
    }
}
