pub mod rpc;
pub mod signing;
pub mod tx;
pub mod utils;

pub mod tm {
    use namada::{
        ledger::queries::{Client, EncodedResponseQuery},
        types::storage::BlockHeight,
    };
    use tendermint_rpc::error::Error as RpcError;
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

        async fn perform<R>(&self, request: R) -> Result<R::Response, RpcError>
        where
            R: tendermint_rpc::SimpleRequest,
        {
            self.inner.perform(request).await
        }
    }
}
