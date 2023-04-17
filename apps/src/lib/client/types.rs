use async_trait::async_trait;
use masp_primitives::merkle_tree::MerklePath;
use masp_primitives::primitives::{Diversifier, Note, ViewingKey};
use masp_primitives::sapling::Node;
use masp_primitives::transaction::components::Amount;
use namada::tendermint_rpc::HttpClient;
use namada::types::address::Address;
use namada::types::masp::{
    ExtendedSpendingKey, TransferSource, TransferTarget,
};
use namada::types::storage::Epoch;
use namada::types::transaction::GasLimit;
use namada::types::{key, token};

use super::rpc;
use crate::cli::{args, Context};
use crate::client::tx::Conversions;
use crate::facade::tendermint_config::net::Address as TendermintAddress;

#[derive(Clone, Debug)]
pub struct ParsedTxArgs {
    /// Simulate applying the transaction
    pub dry_run: bool,
    /// Dump the transaction bytes
    pub dump_tx: bool,
    /// Submit the transaction even if it doesn't pass client checks
    pub force: bool,
    /// Do not wait for the transaction to be added to the blockchain
    pub broadcast_only: bool,
    /// The address of the ledger node as host:port
    pub ledger_address: TendermintAddress,
    /// If any new account is initialized by the tx, use the given alias to
    /// save it in the wallet.
    pub initialized_account_alias: Option<String>,
    /// The amount being payed to include the transaction
    pub fee_amount: token::Amount,
    /// The token in which the fee is being paid
    pub fee_token: Address,
    /// The optional spending key to be used for fee unshielding
    pub fee_unshield: Option<ExtendedSpendingKey>,
    /// The max amount of gas used to process tx
    pub gas_limit: GasLimit,
    /// Sign the tx with the key for the given alias from your wallet
    pub signing_key: Option<key::common::SecretKey>,
    /// Sign the tx with the keypair of the public key of the given address
    pub signer: Option<Address>,
}

#[derive(Clone, Debug)]
pub struct ParsedTxTransferArgs {
    /// Common tx arguments
    pub tx: ParsedTxArgs,
    /// Transfer source address
    pub source: TransferSource,
    /// Transfer target address
    pub target: TransferTarget,
    /// Transferred token address
    pub token: Address,
    /// Transferred token amount
    pub amount: token::Amount,
}

#[async_trait(?Send)]
pub trait ShieldedTransferContext {
    async fn collect_unspent_notes(
        &mut self,
        ledger_address: TendermintAddress,
        vk: &ViewingKey,
        target: Amount,
        target_epoch: Epoch,
    ) -> (
        Amount,
        Vec<(Diversifier, Note, MerklePath<Node>)>,
        Conversions,
    );

    async fn query_epoch(&self, ledger_address: TendermintAddress) -> Epoch;
}

#[async_trait(?Send)]
impl ShieldedTransferContext for Context {
    async fn collect_unspent_notes(
        &mut self,
        ledger_address: TendermintAddress,
        vk: &ViewingKey,
        target: Amount,
        target_epoch: Epoch,
    ) -> (
        Amount,
        Vec<(Diversifier, Note, MerklePath<Node>)>,
        Conversions,
    ) {
        // Establish connection with which to do exchange rate queries
        let client = HttpClient::new(ledger_address.clone()).unwrap();
        self.shielded
            .collect_unspent_notes(&client, vk, target, target_epoch)
            .await
    }

    async fn query_epoch(&self, ledger_address: TendermintAddress) -> Epoch {
        rpc::query_and_print_epoch(args::Query { ledger_address }).await
    }
}
