use std::marker::PhantomData;

use namada::sdk::queries::Client;
use namada::sdk::rpc::wait_until_node_is_synched;
use namada::tendermint_rpc::HttpClient;
use namada::types::control_flow::Halt;
use namada::types::io::Io;
use tendermint_config::net::Address as TendermintAddress;

use crate::client::utils;

/// Trait for clients that can be used with the CLI.
#[async_trait::async_trait(?Send)]
pub trait CliClient: Client + Sync {
    fn from_tendermint_address(address: &mut TendermintAddress) -> Self;
    async fn wait_until_node_is_synced<IO: Io>(&self) -> Halt<()>;
}

#[async_trait::async_trait(?Send)]
impl CliClient for HttpClient {
    fn from_tendermint_address(address: &mut TendermintAddress) -> Self {
        HttpClient::new(utils::take_config_address(address)).unwrap()
    }

    async fn wait_until_node_is_synced<IO: Io>(&self) -> Halt<()> {
        wait_until_node_is_synched::<_, IO>(self).await
    }
}

pub struct CliIo;

#[async_trait::async_trait(?Send)]
impl Io for CliIo {}

pub struct CliApi<IO: Io = CliIo>(PhantomData<IO>);
