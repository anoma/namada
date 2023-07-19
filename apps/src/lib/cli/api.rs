use std::marker::PhantomData;

use namada::ledger::queries::Client;
use namada::ledger::rpc::wait_until_node_is_synched;
use namada::tendermint_rpc::HttpClient;
use namada::types::control_flow::Halt;
use tendermint_config::net::Address as TendermintAddress;

use crate::client::utils;

/// Trait for clients that can be used with the CLI.
#[async_trait::async_trait(?Send)]
pub trait CliClient: Client + Sync {
    fn from_tendermint_address(address: &mut TendermintAddress) -> Self;
    async fn wait_until_node_is_synced(&self) -> Halt<()>;
}

#[async_trait::async_trait(?Send)]
impl CliClient for HttpClient {
    fn from_tendermint_address(address: &mut TendermintAddress) -> Self {
        HttpClient::new(utils::take_config_address(address)).unwrap()
    }

    async fn wait_until_node_is_synced(&self) -> Halt<()> {
        wait_until_node_is_synched(self).await
    }
}

pub struct CliApi<IO>(PhantomData<IO>);
