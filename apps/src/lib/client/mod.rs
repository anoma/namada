pub mod rpc;
pub mod signing;
pub mod tx;
pub mod utils;

pub mod tm {
    use namada::{
        ledger::queries::{Client, EncodedResponseQuery, MutClient},
        types::storage::BlockHeight,
    };
    use tendermint::block::Height;
    use tendermint_rpc::error::Error as RpcError;
    use tendermint_rpc::{query::Query, Order};
    use thiserror::Error;

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

    pub struct RpcHttpClient<C: tendermint_rpc::Client> {
        inner: C,
    }

    impl<C: tendermint_rpc::Client> RpcHttpClient<C> {
        pub fn new(client: C) -> Self {
            Self { inner: client }
        }
    }

    #[async_trait::async_trait(?Send)]
    impl<C: tendermint_rpc::Client + std::marker::Sync> Client
        for RpcHttpClient<C>
    {
        type Error = Error;

        async fn request(
            &self,
            path: String,
            data: Option<Vec<u8>>,
            height: Option<BlockHeight>,
            prove: bool,
        ) -> Result<EncodedResponseQuery, Self::Error> {
            let data = data.unwrap_or_default();
            let height = height
                .map(|height| {
                    tendermint::block::Height::try_from(height.0)
                        .map_err(|_err| Error::InvalidHeight(height))
                })
                .transpose()?;
            let response = self
                .inner
                .abci_query(
                    // TODO open the private Path constructor in tendermint-rpc
                    Some(std::str::FromStr::from_str(&path).unwrap()),
                    data,
                    height,
                    prove,
                )
                .await?;
            use tendermint::abci::Code;
            match response.code {
                Code::Ok => Ok(EncodedResponseQuery {
                    data: response.value,
                    info: response.info,
                    proof: response.proof,
                }),
                Code::Err(code) => Err(Error::Query(response.info, code)),
            }
        }
    }

    #[async_trait::async_trait(?Send)]
    impl<C: tendermint_rpc::Client + std::marker::Sync> MutClient
        for RpcHttpClient<C>
    {
        async fn broadcast_tx_sync(
            &self,
            tx: tendermint::abci::Transaction,
        ) -> Result<
            tendermint_rpc::endpoint::broadcast::tx_sync::Response,
            RpcError,
        > {
            self.inner.broadcast_tx_sync(tx).await
        }

        async fn latest_block(
            &self,
        ) -> Result<tendermint_rpc::endpoint::block::Response, RpcError>
        {
            self.inner.latest_block().await
        }

        async fn block_search(
            &self,
            query: Query,
            page: u32,
            per_page: u8,
            order: Order,
        ) -> Result<tendermint_rpc::endpoint::block_search::Response, RpcError>
        {
            self.inner.block_search(query, page, per_page, order).await
        }

        async fn block_results<H>(
            &self,
            height: H,
        ) -> Result<tendermint_rpc::endpoint::block_results::Response, RpcError>
        where
            H: Into<Height> + Send,
        {
            self.inner.block_results(height).await
        }

        async fn tx_search(
            &self,
            query: Query,
            prove: bool,
            page: u32,
            per_page: u8,
            order: Order,
        ) -> Result<tendermint_rpc::endpoint::tx_search::Response, RpcError>
        {
            self.inner
                .tx_search(query, prove, page, per_page, order)
                .await
        }
    }
}
