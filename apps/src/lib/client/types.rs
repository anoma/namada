use namada::types::transaction::GasLimit;
use tendermint_config::net::Address as TendermintAddress;
use namada::types::address::Address;
use namada::types::{ key, token };
use namada::types::masp::{TransferSource, TransferTarget};

#[derive(Clone, Debug)]
pub struct ParsedTxArgs {
    /// Simulate applying the transaction
    pub dry_run: bool,
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

pub trait ShieldedTransferContext {
}