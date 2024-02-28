use namada::io::Io;
use namada::tendermint_rpc::HttpClient;
use namada_sdk::error::Error;
use namada_sdk::queries::Client;
use namada_sdk::rpc::wait_until_node_is_synched;
use tendermint_rpc::Url as TendermintUrl;

/// Trait for clients that can be used with the CLI.
#[async_trait::async_trait(?Send)]
pub trait CliClient: Client + Sync {
    fn from_tendermint_address(address: &TendermintUrl) -> Self;
    async fn wait_until_node_is_synced(
        &self,
        io: &impl Io,
    ) -> Result<(), Error>;
}

#[async_trait::async_trait(?Send)]
impl CliClient for HttpClient {
    fn from_tendermint_address(address: &TendermintUrl) -> Self {
        HttpClient::new(address.clone()).unwrap()
    }

    async fn wait_until_node_is_synced(
        &self,
        io: &impl Io,
    ) -> Result<(), Error> {
        wait_until_node_is_synched(self, io).await
    }
}

pub struct CliIo;

#[async_trait::async_trait(?Send)]
impl Io for CliIo {}

pub struct CliApi;
