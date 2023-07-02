//! Structures encapsulating SDK arguments
use std::path::PathBuf;

use namada_core::types::chain::ChainId;
use namada_core::types::time::DateTimeUtc;
use rust_decimal::Decimal;
use zeroize::Zeroizing;

use crate::ibc::core::ics24_host::identifier::{ChannelId, PortId};
use crate::types::address::Address;
use crate::types::key::{common, SchemeType};
use crate::types::masp::MaspValue;
use crate::types::storage::Epoch;
use crate::types::transaction::GasLimit;
use crate::types::{storage, token};

/// Abstraction of types being used in Namada
pub trait NamadaTypes: Clone + std::fmt::Debug {
    /// Represents an address on the ledger
    type Address: Clone + std::fmt::Debug;
    /// Represents the address of a native token
    type NativeAddress: Clone + std::fmt::Debug;
    /// Represents a key pair
    type Keypair: Clone + std::fmt::Debug;
    /// Represents the address of a Tendermint endpoint
    type TendermintAddress: Clone + std::fmt::Debug;
    /// Represents a viewing key
    type ViewingKey: Clone + std::fmt::Debug;
    /// Represents the owner of a balance
    type BalanceOwner: Clone + std::fmt::Debug;
    /// Represents a public key
    type PublicKey: Clone + std::fmt::Debug;
    /// Represents the source of a Transfer
    type TransferSource: Clone + std::fmt::Debug;
    /// Represents the target of a Transfer
    type TransferTarget: Clone + std::fmt::Debug;
    /// Represents some data that is used in a transaction
    type Data: Clone + std::fmt::Debug;
}

/// The concrete types being used in Namada SDK
#[derive(Clone, Debug)]
pub struct SdkTypes;

impl NamadaTypes for SdkTypes {
    type Address = Address;
    type BalanceOwner = namada_core::types::masp::BalanceOwner;
    type Data = Vec<u8>;
    type Keypair = namada_core::types::key::common::SecretKey;
    type NativeAddress = Address;
    type PublicKey = namada_core::types::key::common::PublicKey;
    type TendermintAddress = ();
    type TransferSource = namada_core::types::masp::TransferSource;
    type TransferTarget = namada_core::types::masp::TransferTarget;
    type ViewingKey = namada_core::types::masp::ExtendedViewingKey;
}

/// Common query arguments
#[derive(Clone, Debug)]
pub struct Query<C: NamadaTypes = SdkTypes> {
    /// The address of the ledger node as host:port
    pub ledger_address: C::TendermintAddress,
}

/// Transaction associated results arguments
#[derive(Clone, Debug)]
pub struct QueryResult<C: NamadaTypes = SdkTypes> {
    /// Common query args
    pub query: Query<C>,
    /// Hash of transaction to lookup
    pub tx_hash: String,
}

/// Custom transaction arguments
#[derive(Clone, Debug)]
pub struct TxCustom<C: NamadaTypes = SdkTypes> {
    /// Common tx arguments
    pub tx: Tx<C>,
    /// Path to the tx WASM code file
    pub code_path: C::Data,
    /// Path to the data file
    pub data_path: Option<C::Data>,
    /// The address that correspond to the signatures/signing-keys
    pub owner: C::Address,
}

/// Transfer transaction arguments
#[derive(Clone, Debug)]
pub struct TxTransfer<C: NamadaTypes = SdkTypes> {
    /// Common tx arguments
    pub tx: Tx<C>,
    /// Transfer source address
    pub source: C::TransferSource,
    /// Transfer target address
    pub target: C::TransferTarget,
    /// Transferred token address
    pub token: C::Address,
    /// Transferred token address
    pub sub_prefix: Option<String>,
    /// Transferred token amount
    pub amount: token::Amount,
    /// Native token address
    pub native_token: C::NativeAddress,
    /// Path to the TX WASM code file
    pub tx_code_path: PathBuf,
}

/// IBC transfer transaction arguments
#[derive(Clone, Debug)]
pub struct TxIbcTransfer<C: NamadaTypes = SdkTypes> {
    /// Common tx arguments
    pub tx: Tx<C>,
    /// Transfer source address
    pub source: C::Address,
    /// Transfer target address
    pub receiver: String,
    /// Transferred token address
    pub token: C::Address,
    /// Transferred token address
    pub sub_prefix: Option<String>,
    /// Transferred token amount
    pub amount: token::Amount,
    /// Port ID
    pub port_id: PortId,
    /// Channel ID
    pub channel_id: ChannelId,
    /// Timeout height of the destination chain
    pub timeout_height: Option<u64>,
    /// Timeout timestamp offset
    pub timeout_sec_offset: Option<u64>,
    /// Path to the TX WASM code file
    pub tx_code_path: PathBuf,
}

/// Transaction to initialize a new account
#[derive(Clone, Debug)]
pub struct TxInitAccount<C: NamadaTypes = SdkTypes> {
    /// Common tx arguments
    pub tx: Tx<C>,
    /// Path to the VP WASM code file for the new account
    pub vp_code_path: PathBuf,
    /// Path to the TX WASM code file
    pub tx_code_path: PathBuf,
    /// Public key for the new account
    pub public_keys: Vec<C::PublicKey>,
    /// The account multisignature threshold
    pub threshold: Option<u8>,
}

/// Transaction to initialize a new account
#[derive(Clone, Debug)]
pub struct TxInitValidator<C: NamadaTypes = SdkTypes> {
    /// Common tx arguments
    pub tx: Tx<C>,
    /// Signature scheme
    pub scheme: SchemeType,
    /// Account keys
    pub account_keys: Vec<C::PublicKey>,
    /// The account multisignature threshold
    pub threshold: Option<u8>,
    /// Consensus key
    pub consensus_key: Option<C::Keypair>,
    /// Protocol key
    pub protocol_key: Option<C::PublicKey>,
    /// Commission rate
    pub commission_rate: Decimal,
    /// Maximum commission rate change
    pub max_commission_rate_change: Decimal,
    /// Path to the VP WASM code file
    pub validator_vp_code_path: PathBuf,
    /// Path to the TX WASM code file
    pub tx_code_path: PathBuf,
    /// Don't encrypt the keypair
    pub unsafe_dont_encrypt: bool,
}

/// Transaction to update a VP arguments
#[derive(Clone, Debug)]
pub struct TxUpdateAccount<C: NamadaTypes = SdkTypes> {
    /// Common tx arguments
    pub tx: Tx<C>,
    /// Path to the VP WASM code file
    pub vp_code_path: Option<PathBuf>,
    /// Path to the TX WASM code file
    pub tx_code_path: PathBuf,
    /// Address of the account whose VP is to be updated
    pub addr: C::Address,
    /// Public keys
    pub public_keys: Vec<C::PublicKey>,
    /// The account threshold
    pub threshold: Option<u8>,
}

/// Bond arguments
#[derive(Clone, Debug)]
pub struct Bond<C: NamadaTypes = SdkTypes> {
    /// Common tx arguments
    pub tx: Tx<C>,
    /// Validator address
    pub validator: C::Address,
    /// Amount of tokens to stake in a bond
    pub amount: token::Amount,
    /// Source address for delegations. For self-bonds, the validator is
    /// also the source.
    pub source: Option<C::Address>,
    /// Native token address
    pub native_token: C::NativeAddress,
    /// Path to the TX WASM code file
    pub tx_code_path: PathBuf,
}

/// Unbond arguments
#[derive(Clone, Debug)]
pub struct Unbond<C: NamadaTypes = SdkTypes> {
    /// Common tx arguments
    pub tx: Tx<C>,
    /// Validator address
    pub validator: C::Address,
    /// Amount of tokens to unbond from a bond
    pub amount: token::Amount,
    /// Source address for unbonding from delegations. For unbonding from
    /// self-bonds, the validator is also the source
    pub source: Option<C::Address>,
    /// Path to the TX WASM code file
    pub tx_code_path: PathBuf,
}

/// Reveal public key
#[derive(Clone, Debug)]
pub struct RevealPk<C: NamadaTypes = SdkTypes> {
    /// Common tx arguments
    pub tx: Tx<C>,
    /// A public key to be revealed on-chain
    pub public_key: C::PublicKey,
}

/// Query proposal
#[derive(Clone, Debug)]
pub struct QueryProposal<C: NamadaTypes = SdkTypes> {
    /// Common query args
    pub query: Query<C>,
    /// Proposal id
    pub proposal_id: Option<u64>,
}

/// Query protocol parameters
#[derive(Clone, Debug)]
pub struct QueryProtocolParameters<C: NamadaTypes = SdkTypes> {
    /// Common query args
    pub query: Query<C>,
}

/// Withdraw arguments
#[derive(Clone, Debug)]
pub struct Withdraw<C: NamadaTypes = SdkTypes> {
    /// Common tx arguments
    pub tx: Tx<C>,
    /// Validator address
    pub validator: C::Address,
    /// Source address for withdrawing from delegations. For withdrawing
    /// from self-bonds, the validator is also the source
    pub source: Option<C::Address>,
    /// Path to the TX WASM code file
    pub tx_code_path: PathBuf,
}

/// Query asset conversions
#[derive(Clone, Debug)]
pub struct QueryConversions<C: NamadaTypes = SdkTypes> {
    /// Common query args
    pub query: Query<C>,
    /// Address of a token
    pub token: Option<C::Address>,
    /// Epoch of the asset
    pub epoch: Option<Epoch>,
}

/// Query token balance(s)
#[derive(Clone, Debug)]
pub struct QueryAccount<C: NamadaTypes = SdkTypes> {
    /// Common query args
    pub query: Query<C>,
    /// Address of an owner
    pub owner: C::Address,
}

/// Query token balance(s)
#[derive(Clone, Debug)]
pub struct QueryBalance<C: NamadaTypes = SdkTypes> {
    /// Common query args
    pub query: Query<C>,
    /// Address of an owner
    pub owner: Option<C::BalanceOwner>,
    /// Address of a token
    pub token: Option<C::Address>,
    /// Whether not to convert balances
    pub no_conversions: bool,
    /// Sub prefix of an account
    pub sub_prefix: Option<String>,
}

/// Query historical transfer(s)
#[derive(Clone, Debug)]
pub struct QueryTransfers<C: NamadaTypes = SdkTypes> {
    /// Common query args
    pub query: Query<C>,
    /// Address of an owner
    pub owner: Option<C::BalanceOwner>,
    /// Address of a token
    pub token: Option<C::Address>,
}

/// Query PoS bond(s)
#[derive(Clone, Debug)]
pub struct QueryBonds<C: NamadaTypes = SdkTypes> {
    /// Common query args
    pub query: Query<C>,
    /// Address of an owner
    pub owner: Option<C::Address>,
    /// Address of a validator
    pub validator: Option<C::Address>,
}

/// Query PoS bonded stake
#[derive(Clone, Debug)]
pub struct QueryBondedStake<C: NamadaTypes = SdkTypes> {
    /// Common query args
    pub query: Query<C>,
    /// Address of a validator
    pub validator: Option<C::Address>,
    /// Epoch in which to find bonded stake
    pub epoch: Option<Epoch>,
}

#[derive(Clone, Debug)]
/// Commission rate change args
pub struct TxCommissionRateChange<C: NamadaTypes = SdkTypes> {
    /// Common tx arguments
    pub tx: Tx<C>,
    /// Validator address (should be self)
    pub validator: C::Address,
    /// Value to which the tx changes the commission rate
    pub rate: Decimal,
    /// Path to the TX WASM code file
    pub tx_code_path: PathBuf,
}

#[derive(Clone, Debug)]
/// Re-activate a jailed validator args
pub struct TxUnjailValidator<C: NamadaTypes = SdkTypes> {
    /// Common tx arguments
    pub tx: Tx<C>,
    /// Validator address (should be self)
    pub validator: C::Address,
    /// Path to the TX WASM code file
    pub tx_code_path: C::Data,
}

/// Query PoS commission rate
#[derive(Clone, Debug)]
pub struct QueryCommissionRate<C: NamadaTypes = SdkTypes> {
    /// Common query args
    pub query: Query<C>,
    /// Address of a validator
    pub validator: C::Address,
    /// Epoch in which to find commission rate
    pub epoch: Option<Epoch>,
}

/// Query PoS slashes
#[derive(Clone, Debug)]
pub struct QuerySlashes<C: NamadaTypes = SdkTypes> {
    /// Common query args
    pub query: Query<C>,
    /// Address of a validator
    pub validator: Option<C::Address>,
}

/// Query PoS delegations
#[derive(Clone, Debug)]
pub struct QueryDelegations<C: NamadaTypes = SdkTypes> {
    /// Common query args
    pub query: Query<C>,
    /// Address of an owner
    pub owner: C::Address,
}

/// Query PoS to find a validator
#[derive(Clone, Debug)]
pub struct QueryFindValidator<C: NamadaTypes = SdkTypes> {
    /// Common query args
    pub query: Query<C>,
    /// Tendermint address
    pub tm_addr: String,
}

/// Query the raw bytes of given storage key
#[derive(Clone, Debug)]
pub struct QueryRawBytes<C: NamadaTypes = SdkTypes> {
    /// The storage key to query
    pub storage_key: storage::Key,
    /// Common query args
    pub query: Query<C>,
}

/// Common transaction arguments
#[derive(Clone, Debug)]
pub struct Tx<C: NamadaTypes = SdkTypes> {
    /// Simulate applying the transaction
    pub dry_run: bool,
    /// Dump the transaction bytes to file
    pub dump_tx: bool,
    /// The output directory path to where serialize the transaction
    pub output_folder: Option<PathBuf>,
    /// Submit the transaction even if it doesn't pass client checks
    pub force: bool,
    /// Do not wait for the transaction to be added to the blockchain
    pub broadcast_only: bool,
    /// The address of the ledger node as host:port
    pub ledger_address: C::TendermintAddress,
    /// If any new account is initialized by the tx, use the given alias to
    /// save it in the wallet.
    pub initialized_account_alias: Option<String>,
    /// Whether to force overwrite the above alias, if it is provided, in the
    /// wallet.
    pub wallet_alias_force: bool,
    /// The fee payer signing key
    pub fee_payer: Option<C::Keypair>,
    /// The amount being payed to include the transaction
    pub fee_amount: token::Amount,
    /// The token in which the fee is being paid
    pub fee_token: C::Address,
    /// The max amount of gas used to process tx
    pub gas_limit: GasLimit,
    /// The optional expiration of the transaction
    pub expiration: Option<DateTimeUtc>,
    /// The chain id for which the transaction is intended
    pub chain_id: Option<ChainId>,
    /// Sign the tx with the key for the given alias from your wallet
    pub signing_keys: Vec<C::Keypair>,
    /// Path to the TX WASM code file to reveal PK
    pub tx_reveal_code_path: PathBuf,
    /// Password to decrypt key
    pub password: Option<Zeroizing<String>>,
}

/// MASP add key or address arguments
#[derive(Clone, Debug)]
pub struct MaspAddrKeyAdd {
    /// Key alias
    pub alias: String,
    /// Whether to force overwrite the alias
    pub alias_force: bool,
    /// Any MASP value
    pub value: MaspValue,
    /// Don't encrypt the keypair
    pub unsafe_dont_encrypt: bool,
}

/// MASP generate spending key arguments
#[derive(Clone, Debug)]
pub struct MaspSpendKeyGen {
    /// Key alias
    pub alias: String,
    /// Whether to force overwrite the alias
    pub alias_force: bool,
    /// Don't encrypt the keypair
    pub unsafe_dont_encrypt: bool,
}

/// MASP generate payment address arguments
#[derive(Clone, Debug)]
pub struct MaspPayAddrGen<C: NamadaTypes = SdkTypes> {
    /// Key alias
    pub alias: String,
    /// Whether to force overwrite the alias
    pub alias_force: bool,
    /// Viewing key
    pub viewing_key: C::ViewingKey,
    /// Pin
    pub pin: bool,
}

/// Wallet generate key and implicit address arguments
#[derive(Clone, Debug)]
pub struct KeyAndAddressGen {
    /// Scheme type
    pub scheme: SchemeType,
    /// Key alias
    pub alias: Option<String>,
    /// Whether to force overwrite the alias, if provided
    pub alias_force: bool,
    /// Don't encrypt the keypair
    pub unsafe_dont_encrypt: bool,
    /// BIP44 derivation path
    pub derivation_path: Option<String>,
}

/// Wallet restore key and implicit address arguments
#[derive(Clone, Debug)]
pub struct KeyAndAddressRestore {
    /// Scheme type
    pub scheme: SchemeType,
    /// Key alias
    pub alias: Option<String>,
    /// Whether to force overwrite the alias, if provided
    pub alias_force: bool,
    /// Don't encrypt the keypair
    pub unsafe_dont_encrypt: bool,
    /// BIP44 derivation path
    pub derivation_path: Option<String>,
}

/// Wallet key lookup arguments
#[derive(Clone, Debug)]
pub struct KeyFind {
    /// Public key to lookup keypair with
    pub public_key: Option<common::PublicKey>,
    /// Key alias to lookup keypair with
    pub alias: Option<String>,
    /// Public key hash to lookup keypair with
    pub value: Option<String>,
    /// Show secret keys to user
    pub unsafe_show_secret: bool,
}

/// Wallet find shielded address or key arguments
#[derive(Clone, Debug)]
pub struct AddrKeyFind {
    /// Address/key alias
    pub alias: String,
    /// Show secret keys to user
    pub unsafe_show_secret: bool,
}

/// Wallet list shielded keys arguments
#[derive(Clone, Debug)]
pub struct MaspKeysList {
    /// Don't decrypt spending keys
    pub decrypt: bool,
    /// Show secret keys to user
    pub unsafe_show_secret: bool,
}

/// Wallet list keys arguments
#[derive(Clone, Debug)]
pub struct KeyList {
    /// Don't decrypt keypairs
    pub decrypt: bool,
    /// Show secret keys to user
    pub unsafe_show_secret: bool,
}

/// Wallet key export arguments
#[derive(Clone, Debug)]
pub struct KeyExport {
    /// Key alias
    pub alias: String,
}

/// Wallet address lookup arguments
#[derive(Clone, Debug)]
pub struct AddressOrAliasFind {
    /// Alias to find
    pub alias: Option<String>,
    /// Address to find
    pub address: Option<Address>,
}

/// Wallet address add arguments
#[derive(Clone, Debug)]
pub struct AddressAdd {
    /// Address alias
    pub alias: String,
    /// Whether to force overwrite the alias
    pub alias_force: bool,
    /// Address to add
    pub address: Address,
}
