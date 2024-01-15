//! Structures encapsulating SDK arguments

use std::collections::HashMap;
use std::path::PathBuf;
use std::time::Duration as StdDuration;

use namada_core::ledger::governance::cli::onchain::{
    DefaultProposal, PgfFundingProposal, PgfStewardProposal,
};
use namada_core::proto::Memo;
use namada_core::types::address::Address;
use namada_core::types::chain::ChainId;
use namada_core::types::dec::Dec;
use namada_core::types::ethereum_events::EthAddress;
use namada_core::types::keccak::KeccakHash;
use namada_core::types::key::{common, SchemeType};
use namada_core::types::masp::PaymentAddress;
use namada_core::types::storage::Epoch;
use namada_core::types::time::DateTimeUtc;
use namada_core::types::transaction::GasLimit;
use namada_core::types::{storage, token};
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::eth_bridge::bridge_pool;
use crate::ibc::core::host::types::identifiers::{ChannelId, PortId};
use crate::signing::SigningTxData;
use crate::{rpc, tx, Namada};

/// [`Duration`](StdDuration) wrapper that provides a
/// method to parse a value from a string.
#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Debug, Hash)]
#[repr(transparent)]
pub struct Duration(pub StdDuration);

impl ::std::str::FromStr for Duration {
    type Err = ::parse_duration::parse::Error;

    #[inline]
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        ::parse_duration::parse(s).map(Duration)
    }
}

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
    /// Represents the address of an Ethereum endpoint
    type EthereumAddress: Clone + std::fmt::Debug;
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
    /// Bridge pool recommendations conversion rates table.
    type BpConversionTable: Clone + std::fmt::Debug;
}

/// The concrete types being used in Namada SDK
#[derive(Clone, Debug)]
pub struct SdkTypes;

/// An entry in the Bridge pool recommendations conversion
/// rates table.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BpConversionTableEntry {
    /// An alias for the token, or the string representation
    /// of its address if none is available.
    pub alias: String,
    /// Conversion rate from the given token to gwei.
    pub conversion_rate: f64,
}

impl NamadaTypes for SdkTypes {
    type Address = Address;
    type BalanceOwner = namada_core::types::masp::BalanceOwner;
    type BpConversionTable = HashMap<Address, BpConversionTableEntry>;
    type Data = Vec<u8>;
    type EthereumAddress = ();
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
    pub code_path: Option<PathBuf>,
    /// Path to the data file
    pub data_path: Option<C::Data>,
    /// Path to the serialized transaction
    pub serialized_tx: Option<C::Data>,
    /// The address that correspond to the signatures/signing-keys
    pub owner: C::Address,
}

impl<C: NamadaTypes> TxBuilder<C> for TxCustom<C> {
    fn tx<F>(self, func: F) -> Self
    where
        F: FnOnce(Tx<C>) -> Tx<C>,
    {
        TxCustom {
            tx: func(self.tx),
            ..self
        }
    }
}

impl<C: NamadaTypes> TxCustom<C> {
    /// Path to the tx WASM code file
    pub fn code_path(self, code_path: PathBuf) -> Self {
        Self {
            code_path: Some(code_path),
            ..self
        }
    }

    /// Path to the data file
    pub fn data_path(self, data_path: C::Data) -> Self {
        Self {
            data_path: Some(data_path),
            ..self
        }
    }

    /// Path to the serialized transaction
    pub fn serialized_tx(self, serialized_tx: C::Data) -> Self {
        Self {
            serialized_tx: Some(serialized_tx),
            ..self
        }
    }

    /// The address that correspond to the signatures/signing-keys
    pub fn owner(self, owner: C::Address) -> Self {
        Self { owner, ..self }
    }
}

impl TxCustom {
    /// Build a transaction from this builder
    pub async fn build(
        &self,
        context: &impl Namada,
    ) -> crate::error::Result<(crate::proto::Tx, SigningTxData)> {
        tx::build_custom(context, self).await
    }
}

/// An amount read in by the cli
#[derive(Copy, Clone, Debug)]
pub enum InputAmount {
    /// An amount whose representation has been validated
    /// against the allowed representation in storage
    Validated(token::DenominatedAmount),
    /// The parsed amount read in from the cli. It has
    /// not yet been validated against the allowed
    /// representation in storage.
    Unvalidated(token::DenominatedAmount),
}

impl std::str::FromStr for InputAmount {
    type Err = <token::DenominatedAmount as std::str::FromStr>::Err;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        token::DenominatedAmount::from_str(s).map(InputAmount::Unvalidated)
    }
}

impl From<token::DenominatedAmount> for InputAmount {
    fn from(amt: token::DenominatedAmount) -> Self {
        InputAmount::Unvalidated(amt)
    }
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
    /// Transferred token amount
    pub amount: InputAmount,
    /// Native token address
    pub native_token: C::NativeAddress,
    /// Path to the TX WASM code file
    pub tx_code_path: PathBuf,
}

impl<C: NamadaTypes> TxBuilder<C> for TxTransfer<C> {
    fn tx<F>(self, func: F) -> Self
    where
        F: FnOnce(Tx<C>) -> Tx<C>,
    {
        TxTransfer {
            tx: func(self.tx),
            ..self
        }
    }
}

impl<C: NamadaTypes> TxTransfer<C> {
    /// Transfer source address
    pub fn source(self, source: C::TransferSource) -> Self {
        Self { source, ..self }
    }

    /// Transfer target address
    pub fn receiver(self, target: C::TransferTarget) -> Self {
        Self { target, ..self }
    }

    /// Transferred token address
    pub fn token(self, token: C::Address) -> Self {
        Self { token, ..self }
    }

    /// Transferred token amount
    pub fn amount(self, amount: InputAmount) -> Self {
        Self { amount, ..self }
    }

    /// Native token address
    pub fn native_token(self, native_token: C::NativeAddress) -> Self {
        Self {
            native_token,
            ..self
        }
    }

    /// Path to the TX WASM code file
    pub fn tx_code_path(self, tx_code_path: PathBuf) -> Self {
        Self {
            tx_code_path,
            ..self
        }
    }
}

impl TxTransfer {
    /// Build a transaction from this builder
    pub async fn build(
        &mut self,
        context: &impl Namada,
    ) -> crate::error::Result<(crate::proto::Tx, SigningTxData, Option<Epoch>)>
    {
        tx::build_transfer(context, self).await
    }
}

/// IBC transfer transaction arguments
#[derive(Clone, Debug)]
pub struct TxIbcTransfer<C: NamadaTypes = SdkTypes> {
    /// Common tx arguments
    pub tx: Tx<C>,
    /// Transfer source address
    pub source: C::TransferSource,
    /// Transfer target address
    pub receiver: String,
    /// Transferred token address
    pub token: C::Address,
    /// Transferred token amount
    pub amount: InputAmount,
    /// Port ID
    pub port_id: PortId,
    /// Channel ID
    pub channel_id: ChannelId,
    /// Timeout height of the destination chain
    pub timeout_height: Option<u64>,
    /// Timeout timestamp offset
    pub timeout_sec_offset: Option<u64>,
    /// Memo
    pub memo: Option<String>,
    /// Path to the TX WASM code file
    pub tx_code_path: PathBuf,
}

impl<C: NamadaTypes> TxBuilder<C> for TxIbcTransfer<C> {
    fn tx<F>(self, func: F) -> Self
    where
        F: FnOnce(Tx<C>) -> Tx<C>,
    {
        TxIbcTransfer {
            tx: func(self.tx),
            ..self
        }
    }
}

impl<C: NamadaTypes> TxIbcTransfer<C> {
    /// Transfer source address
    pub fn source(self, source: C::TransferSource) -> Self {
        Self { source, ..self }
    }

    /// Transfer target address
    pub fn receiver(self, receiver: String) -> Self {
        Self { receiver, ..self }
    }

    /// Transferred token address
    pub fn token(self, token: C::Address) -> Self {
        Self { token, ..self }
    }

    /// Transferred token amount
    pub fn amount(self, amount: InputAmount) -> Self {
        Self { amount, ..self }
    }

    /// Port ID
    pub fn port_id(self, port_id: PortId) -> Self {
        Self { port_id, ..self }
    }

    /// Channel ID
    pub fn channel_id(self, channel_id: ChannelId) -> Self {
        Self { channel_id, ..self }
    }

    /// Timeout height of the destination chain
    pub fn timeout_height(self, timeout_height: u64) -> Self {
        Self {
            timeout_height: Some(timeout_height),
            ..self
        }
    }

    /// Timeout timestamp offset
    pub fn timeout_sec_offset(self, timeout_sec_offset: u64) -> Self {
        Self {
            timeout_sec_offset: Some(timeout_sec_offset),
            ..self
        }
    }

    /// Memo
    pub fn memo(self, memo: String) -> Self {
        Self {
            memo: Some(memo),
            ..self
        }
    }

    /// Path to the TX WASM code file
    pub fn tx_code_path(self, tx_code_path: PathBuf) -> Self {
        Self {
            tx_code_path,
            ..self
        }
    }
}

impl TxIbcTransfer {
    /// Build a transaction from this builder
    pub async fn build(
        &self,
        context: &impl Namada,
    ) -> crate::error::Result<(crate::proto::Tx, SigningTxData, Option<Epoch>)>
    {
        tx::build_ibc_transfer(context, self).await
    }
}

/// Transaction to initialize create a new proposal
#[derive(Clone, Debug)]
pub struct InitProposal<C: NamadaTypes = SdkTypes> {
    /// Common tx arguments
    pub tx: Tx<C>,
    /// The proposal data
    pub proposal_data: C::Data,
    /// Native token address
    pub native_token: C::NativeAddress,
    /// Flag if proposal should be run offline
    pub is_offline: bool,
    /// Flag if proposal is of type Pgf stewards
    pub is_pgf_stewards: bool,
    /// Flag if proposal is of type Pgf funding
    pub is_pgf_funding: bool,
    /// Path to the tx WASM file
    pub tx_code_path: PathBuf,
}

impl<C: NamadaTypes> TxBuilder<C> for InitProposal<C> {
    fn tx<F>(self, func: F) -> Self
    where
        F: FnOnce(Tx<C>) -> Tx<C>,
    {
        InitProposal {
            tx: func(self.tx),
            ..self
        }
    }
}

impl<C: NamadaTypes> InitProposal<C> {
    /// The proposal data
    pub fn proposal_data(self, proposal_data: C::Data) -> Self {
        Self {
            proposal_data,
            ..self
        }
    }

    /// Native token address
    pub fn native_token(self, native_token: C::NativeAddress) -> Self {
        Self {
            native_token,
            ..self
        }
    }

    /// Flag if proposal should be run offline
    pub fn is_offline(self, is_offline: bool) -> Self {
        Self { is_offline, ..self }
    }

    /// Flag if proposal is of type Pgf stewards
    pub fn is_pgf_stewards(self, is_pgf_stewards: bool) -> Self {
        Self {
            is_pgf_stewards,
            ..self
        }
    }

    /// Flag if proposal is of type Pgf funding
    pub fn is_pgf_funding(self, is_pgf_funding: bool) -> Self {
        Self {
            is_pgf_funding,
            ..self
        }
    }

    /// Path to the tx WASM file
    pub fn tx_code_path(self, tx_code_path: PathBuf) -> Self {
        Self {
            tx_code_path,
            ..self
        }
    }
}

impl InitProposal {
    /// Build a transaction from this builder
    pub async fn build(
        &self,
        context: &impl Namada,
    ) -> crate::error::Result<(crate::proto::Tx, SigningTxData)> {
        let current_epoch = rpc::query_epoch(context.client()).await?;
        let governance_parameters =
            rpc::query_governance_parameters(context.client()).await;

        if self.is_pgf_funding {
            let proposal = PgfFundingProposal::try_from(
                self.proposal_data.as_ref(),
            )
            .map_err(|e| {
                crate::error::TxError::FailedGovernaneProposalDeserialize(
                    e.to_string(),
                )
            })?
            .validate(&governance_parameters, current_epoch, self.tx.force)
            .map_err(|e| {
                crate::error::TxError::InvalidProposal(e.to_string())
            })?;

            tx::build_pgf_funding_proposal(context, self, proposal).await
        } else if self.is_pgf_stewards {
            let proposal = PgfStewardProposal::try_from(
                self.proposal_data.as_ref(),
            )
            .map_err(|e| {
                crate::error::TxError::FailedGovernaneProposalDeserialize(
                    e.to_string(),
                )
            })?;
            let nam_address = context.native_token();
            let author_balance = rpc::get_token_balance(
                context.client(),
                &nam_address,
                &proposal.proposal.author,
            )
            .await?;
            let proposal = proposal
                .validate(
                    &governance_parameters,
                    current_epoch,
                    author_balance,
                    self.tx.force,
                )
                .map_err(|e| {
                    crate::error::TxError::InvalidProposal(e.to_string())
                })?;

            tx::build_pgf_stewards_proposal(context, self, proposal).await
        } else {
            let proposal = DefaultProposal::try_from(
                self.proposal_data.as_ref(),
            )
            .map_err(|e| {
                crate::error::TxError::FailedGovernaneProposalDeserialize(
                    e.to_string(),
                )
            })?;
            let nam_address = context.native_token();
            let author_balance = rpc::get_token_balance(
                context.client(),
                &nam_address,
                &proposal.proposal.author,
            )
            .await?;
            let proposal = proposal
                .validate(
                    &governance_parameters,
                    current_epoch,
                    author_balance,
                    self.tx.force,
                )
                .map_err(|e| {
                    crate::error::TxError::InvalidProposal(e.to_string())
                })?;
            tx::build_default_proposal(context, self, proposal).await
        }
    }
}

/// Transaction to vote on a proposal
#[derive(Clone, Debug)]
pub struct VoteProposal<C: NamadaTypes = SdkTypes> {
    /// Common tx arguments
    pub tx: Tx<C>,
    /// Proposal id
    pub proposal_id: Option<u64>,
    /// The vote
    pub vote: String,
    /// The address of the voter
    pub voter: C::Address,
    /// Flag if proposal vote should be run offline
    pub is_offline: bool,
    /// The proposal file path
    pub proposal_data: Option<C::Data>,
    /// Path to the TX WASM code file
    pub tx_code_path: PathBuf,
}

impl<C: NamadaTypes> TxBuilder<C> for VoteProposal<C> {
    fn tx<F>(self, func: F) -> Self
    where
        F: FnOnce(Tx<C>) -> Tx<C>,
    {
        VoteProposal {
            tx: func(self.tx),
            ..self
        }
    }
}

impl<C: NamadaTypes> VoteProposal<C> {
    /// Proposal id
    pub fn proposal_id(self, proposal_id: u64) -> Self {
        Self {
            proposal_id: Some(proposal_id),
            ..self
        }
    }

    /// The vote
    pub fn vote(self, vote: String) -> Self {
        Self { vote, ..self }
    }

    /// The address of the voter
    pub fn voter(self, voter: C::Address) -> Self {
        Self { voter, ..self }
    }

    /// Flag if proposal vote should be run offline
    pub fn is_offline(self, is_offline: bool) -> Self {
        Self { is_offline, ..self }
    }

    /// The proposal file path
    pub fn proposal_data(self, proposal_data: C::Data) -> Self {
        Self {
            proposal_data: Some(proposal_data),
            ..self
        }
    }

    /// Path to the TX WASM code file
    pub fn tx_code_path(self, tx_code_path: PathBuf) -> Self {
        Self {
            tx_code_path,
            ..self
        }
    }
}

impl VoteProposal {
    /// Build a transaction from this builder
    pub async fn build(
        &self,
        context: &impl Namada,
    ) -> crate::error::Result<(crate::proto::Tx, SigningTxData)> {
        let current_epoch = rpc::query_epoch(context.client()).await?;
        tx::build_vote_proposal(context, self, current_epoch).await
    }
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

impl<C: NamadaTypes> TxBuilder<C> for TxInitAccount<C> {
    fn tx<F>(self, func: F) -> Self
    where
        F: FnOnce(Tx<C>) -> Tx<C>,
    {
        TxInitAccount {
            tx: func(self.tx),
            ..self
        }
    }
}

impl<C: NamadaTypes> TxInitAccount<C> {
    /// A vector of public key to associate with the new account
    pub fn public_keys(self, public_keys: Vec<C::PublicKey>) -> Self {
        Self {
            public_keys,
            ..self
        }
    }

    /// A threshold to associate with the new account
    pub fn threshold(self, threshold: u8) -> Self {
        Self {
            threshold: Some(threshold),
            ..self
        }
    }

    /// Path to the VP WASM code file
    pub fn vp_code_path(self, vp_code_path: PathBuf) -> Self {
        Self {
            vp_code_path,
            ..self
        }
    }

    /// Path to the TX WASM code file
    pub fn tx_code_path(self, tx_code_path: PathBuf) -> Self {
        Self {
            tx_code_path,
            ..self
        }
    }
}

impl TxInitAccount {
    /// Build a transaction from this builder
    pub async fn build(
        &self,
        context: &impl Namada,
    ) -> crate::error::Result<(crate::proto::Tx, SigningTxData)> {
        tx::build_init_account(context, self).await
    }
}

/// Transaction to initialize a new account
#[derive(Clone, Debug)]
pub struct TxBecomeValidator<C: NamadaTypes = SdkTypes> {
    /// Common tx arguments
    pub tx: Tx<C>,
    /// Address of an account that will become a validator.
    pub address: C::Address,
    /// Signature scheme
    pub scheme: SchemeType,
    /// Consensus key
    pub consensus_key: Option<C::PublicKey>,
    /// Ethereum cold key
    pub eth_cold_key: Option<C::PublicKey>,
    /// Ethereum hot key
    pub eth_hot_key: Option<C::PublicKey>,
    /// Protocol key
    pub protocol_key: Option<C::PublicKey>,
    /// Commission rate
    pub commission_rate: Dec,
    /// Maximum commission rate change
    pub max_commission_rate_change: Dec,
    /// The validator email
    pub email: String,
    /// The validator description
    pub description: Option<String>,
    /// The validator website
    pub website: Option<String>,
    /// The validator's discord handle
    pub discord_handle: Option<String>,
    /// The validator's avatar
    pub avatar: Option<String>,
    /// Path to the TX WASM code file
    pub tx_code_path: PathBuf,
    /// Don't encrypt the keypair
    pub unsafe_dont_encrypt: bool,
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
    pub consensus_key: Option<C::PublicKey>,
    /// Ethereum cold key
    pub eth_cold_key: Option<C::PublicKey>,
    /// Ethereum hot key
    pub eth_hot_key: Option<C::PublicKey>,
    /// Protocol key
    pub protocol_key: Option<C::PublicKey>,
    /// Commission rate
    pub commission_rate: Dec,
    /// Maximum commission rate change
    pub max_commission_rate_change: Dec,
    /// The validator email
    pub email: String,
    /// The validator description
    pub description: Option<String>,
    /// The validator website
    pub website: Option<String>,
    /// The validator's discord handle
    pub discord_handle: Option<String>,
    /// The validator's avatar
    pub avatar: Option<String>,
    /// Path to the VP WASM code file
    pub validator_vp_code_path: PathBuf,
    /// Path to the TX WASM code file
    pub tx_init_account_code_path: PathBuf,
    /// Path to the TX WASM code file
    pub tx_become_validator_code_path: PathBuf,
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

impl<C: NamadaTypes> TxBuilder<C> for TxUpdateAccount<C> {
    fn tx<F>(self, func: F) -> Self
    where
        F: FnOnce(Tx<C>) -> Tx<C>,
    {
        TxUpdateAccount {
            tx: func(self.tx),
            ..self
        }
    }
}

impl<C: NamadaTypes> TxUpdateAccount<C> {
    /// Path to the VP WASM code file
    pub fn vp_code_path(self, vp_code_path: PathBuf) -> Self {
        Self {
            vp_code_path: Some(vp_code_path),
            ..self
        }
    }

    /// Path to the TX WASM code file
    pub fn tx_code_path(self, tx_code_path: PathBuf) -> Self {
        Self {
            tx_code_path,
            ..self
        }
    }

    /// Address of the account whose VP is to be updated
    pub fn addr(self, addr: C::Address) -> Self {
        Self { addr, ..self }
    }

    /// Public keys
    pub fn public_keys(self, public_keys: Vec<C::PublicKey>) -> Self {
        Self {
            public_keys,
            ..self
        }
    }

    /// The account threshold
    pub fn threshold(self, threshold: u8) -> Self {
        Self {
            threshold: Some(threshold),
            ..self
        }
    }
}

impl TxUpdateAccount {
    /// Build a transaction from this builder
    pub async fn build(
        &self,
        context: &impl Namada,
    ) -> crate::error::Result<(crate::proto::Tx, SigningTxData)> {
        tx::build_update_account(context, self).await
    }
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

impl<C: NamadaTypes> TxBuilder<C> for Bond<C> {
    fn tx<F>(self, func: F) -> Self
    where
        F: FnOnce(Tx<C>) -> Tx<C>,
    {
        Bond {
            tx: func(self.tx),
            ..self
        }
    }
}

impl<C: NamadaTypes> Bond<C> {
    /// Validator address
    pub fn validator(self, validator: C::Address) -> Self {
        Self { validator, ..self }
    }

    /// Amount of tokens to stake in a bond
    pub fn amount(self, amount: token::Amount) -> Self {
        Self { amount, ..self }
    }

    /// Source address for delegations. For self-bonds, the validator is
    /// also the source.
    pub fn source(self, source: C::Address) -> Self {
        Self {
            source: Some(source),
            ..self
        }
    }

    /// Native token address
    pub fn native_token(self, native_token: C::NativeAddress) -> Self {
        Self {
            native_token,
            ..self
        }
    }

    /// Path to the TX WASM code file
    pub fn tx_code_path(self, tx_code_path: PathBuf) -> Self {
        Self {
            tx_code_path,
            ..self
        }
    }
}

impl Bond {
    /// Build a transaction from this builder
    pub async fn build(
        &self,
        context: &impl Namada,
    ) -> crate::error::Result<(crate::proto::Tx, SigningTxData)> {
        tx::build_bond(context, self).await
    }
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

impl Unbond {
    /// Build a transaction from this builder
    pub async fn build(
        &self,
        context: &impl Namada,
    ) -> crate::error::Result<(
        crate::proto::Tx,
        SigningTxData,
        Option<(Epoch, token::Amount)>,
    )> {
        tx::build_unbond(context, self).await
    }
}

impl<C: NamadaTypes> TxBuilder<C> for Unbond<C> {
    fn tx<F>(self, func: F) -> Self
    where
        F: FnOnce(Tx<C>) -> Tx<C>,
    {
        Unbond {
            tx: func(self.tx),
            ..self
        }
    }
}

impl<C: NamadaTypes> Unbond<C> {
    /// Validator address
    pub fn validator(self, validator: C::Address) -> Self {
        Self { validator, ..self }
    }

    /// Amount of tokens to unbond from a bond
    pub fn amount(self, amount: token::Amount) -> Self {
        Self { amount, ..self }
    }

    /// Source address for unbonding from delegations. For unbonding from
    /// self-bonds, the validator is also the source
    pub fn source(self, source: C::Address) -> Self {
        Self {
            source: Some(source),
            ..self
        }
    }

    /// Path to the TX WASM code file
    pub fn tx_code_path(self, tx_code_path: PathBuf) -> Self {
        Self {
            tx_code_path,
            ..self
        }
    }
}

/// Redelegation arguments
#[derive(Clone, Debug)]
pub struct Redelegate<C: NamadaTypes = SdkTypes> {
    /// Common tx arguments
    pub tx: Tx<C>,
    /// Source validator address
    pub src_validator: C::Address,
    /// Destination validator address
    pub dest_validator: C::Address,
    /// Owner of the bonds that are being redelegated
    pub owner: C::Address,
    /// The amount of tokens to redelegate
    pub amount: token::Amount,
    /// Path to the TX WASM code file
    pub tx_code_path: PathBuf,
}

impl Redelegate {
    /// Build a transaction from this builder
    pub async fn build(
        &self,
        context: &impl Namada,
    ) -> crate::error::Result<(crate::proto::Tx, SigningTxData)> {
        tx::build_redelegation(context, self).await
    }
}

impl<C: NamadaTypes> Redelegate<C> {
    /// Src validator address
    pub fn src_validator(self, src_validator: C::Address) -> Self {
        Self {
            src_validator,
            ..self
        }
    }

    /// Dest validator address
    pub fn dest_validator(self, dest_validator: C::Address) -> Self {
        Self {
            dest_validator,
            ..self
        }
    }

    /// Owner (or delegator or source) of the redelegation
    pub fn owner(self, owner: C::Address) -> Self {
        Self { owner, ..self }
    }

    /// Path to the TX WASM code file
    pub fn tx_code_path(self, tx_code_path: PathBuf) -> Self {
        Self {
            tx_code_path,
            ..self
        }
    }
}

impl<C: NamadaTypes> TxBuilder<C> for Redelegate<C> {
    fn tx<F>(self, func: F) -> Self
    where
        F: FnOnce(Tx<C>) -> Tx<C>,
    {
        Redelegate {
            tx: func(self.tx),
            ..self
        }
    }
}

/// Reveal public key
#[derive(Clone, Debug)]
pub struct RevealPk<C: NamadaTypes = SdkTypes> {
    /// Common tx arguments
    pub tx: Tx<C>,
    /// A public key to be revealed on-chain
    pub public_key: C::PublicKey,
}

impl<C: NamadaTypes> TxBuilder<C> for RevealPk<C> {
    fn tx<F>(self, func: F) -> Self
    where
        F: FnOnce(Tx<C>) -> Tx<C>,
    {
        RevealPk {
            tx: func(self.tx),
            ..self
        }
    }
}

impl<C: NamadaTypes> RevealPk<C> {
    /// A public key to be revealed on-chain
    pub fn public_key(self, public_key: C::PublicKey) -> Self {
        Self { public_key, ..self }
    }
}

impl RevealPk {
    /// Build a transaction from this builder
    pub async fn build(
        &self,
        context: &impl Namada,
    ) -> crate::error::Result<(crate::proto::Tx, SigningTxData)> {
        tx::build_reveal_pk(context, &self.tx, &self.public_key).await
    }
}

/// Query proposal votes
#[derive(Clone, Debug)]
pub struct QueryProposalVotes<C: NamadaTypes = SdkTypes> {
    /// Common query args
    pub query: Query<C>,
    /// Proposal id
    pub proposal_id: u64,
    /// Voter address
    pub voter: Option<C::Address>,
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

/// Query pgf data
#[derive(Clone, Debug)]
pub struct QueryPgf<C: NamadaTypes = SdkTypes> {
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

impl<C: NamadaTypes> TxBuilder<C> for Withdraw<C> {
    fn tx<F>(self, func: F) -> Self
    where
        F: FnOnce(Tx<C>) -> Tx<C>,
    {
        Withdraw {
            tx: func(self.tx),
            ..self
        }
    }
}

impl<C: NamadaTypes> Withdraw<C> {
    /// Validator address
    pub fn validator(self, validator: C::Address) -> Self {
        Self { validator, ..self }
    }

    /// Source address for withdrawing from delegations. For withdrawing
    /// from self-bonds, the validator is also the source
    pub fn source(self, source: C::Address) -> Self {
        Self {
            source: Some(source),
            ..self
        }
    }

    /// Path to the TX WASM code file
    pub fn tx_code_path(self, tx_code_path: PathBuf) -> Self {
        Self {
            tx_code_path,
            ..self
        }
    }
}

impl Withdraw {
    /// Build a transaction from this builder
    pub async fn build(
        &self,
        context: &impl Namada,
    ) -> crate::error::Result<(crate::proto::Tx, SigningTxData)> {
        tx::build_withdraw(context, self).await
    }
}

/// Claim arguments
#[derive(Clone, Debug)]
pub struct ClaimRewards<C: NamadaTypes = SdkTypes> {
    /// Common tx arguments
    pub tx: Tx<C>,
    /// Validator address
    pub validator: C::Address,
    /// Source address for claiming rewards due to bonds. For self-bonds, the
    /// validator is also the source
    pub source: Option<C::Address>,
    /// Path to the TX WASM code file
    pub tx_code_path: PathBuf,
}

impl<C: NamadaTypes> TxBuilder<C> for ClaimRewards<C> {
    fn tx<F>(self, func: F) -> Self
    where
        F: FnOnce(Tx<C>) -> Tx<C>,
    {
        ClaimRewards {
            tx: func(self.tx),
            ..self
        }
    }
}

impl ClaimRewards {
    /// Build a transaction from this builder
    pub async fn build(
        &self,
        context: &impl Namada,
    ) -> crate::error::Result<(crate::proto::Tx, SigningTxData)> {
        tx::build_claim_rewards(context, self).await
    }
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

/// Query the state of a validator (its validator set or if it is jailed)
#[derive(Clone, Debug)]
pub struct QueryValidatorState<C: NamadaTypes = SdkTypes> {
    /// Common query args
    pub query: Query<C>,
    /// Address of a validator
    pub validator: C::Address,
    /// Epoch in which to find the validator state
    pub epoch: Option<Epoch>,
}

#[derive(Clone, Debug)]
/// Commission rate change args
pub struct CommissionRateChange<C: NamadaTypes = SdkTypes> {
    /// Common tx arguments
    pub tx: Tx<C>,
    /// Validator address (should be self)
    pub validator: C::Address,
    /// Value to which the tx changes the commission rate
    pub rate: Dec,
    /// Path to the TX WASM code file
    pub tx_code_path: PathBuf,
}

impl<C: NamadaTypes> TxBuilder<C> for CommissionRateChange<C> {
    fn tx<F>(self, func: F) -> Self
    where
        F: FnOnce(Tx<C>) -> Tx<C>,
    {
        CommissionRateChange {
            tx: func(self.tx),
            ..self
        }
    }
}

impl<C: NamadaTypes> CommissionRateChange<C> {
    /// Validator address (should be self)
    pub fn validator(self, validator: C::Address) -> Self {
        Self { validator, ..self }
    }

    /// Value to which the tx changes the commission rate
    pub fn rate(self, rate: Dec) -> Self {
        Self { rate, ..self }
    }

    /// Path to the TX WASM code file
    pub fn tx_code_path(self, tx_code_path: PathBuf) -> Self {
        Self {
            tx_code_path,
            ..self
        }
    }
}

impl CommissionRateChange {
    /// Build a transaction from this builder
    pub async fn build(
        &self,
        context: &impl Namada,
    ) -> crate::error::Result<(crate::proto::Tx, SigningTxData)> {
        tx::build_validator_commission_change(context, self).await
    }
}

#[derive(Clone, Debug)]
/// Consensus key change args
pub struct ConsensusKeyChange<C: NamadaTypes = SdkTypes> {
    /// Common tx arguments
    pub tx: Tx<C>,
    /// Validator address (should be self)
    pub validator: C::Address,
    /// New consensus key
    pub consensus_key: Option<C::PublicKey>,
    /// Don't encrypt the keypair
    pub unsafe_dont_encrypt: bool,
    /// Path to the TX WASM code file
    pub tx_code_path: PathBuf,
}

// impl<C: NamadaTypes> TxBuilder<C> for ConsensusKeyChange<C> {
//     fn tx<F>(self, func: F) -> Self
//     where
//         F: FnOnce(Tx<C>) -> Tx<C>,
//     {
//         ConsensusKeyChange {
//             tx: func(self.tx),
//             ..self
//         }
//     }
// }

// impl<C: NamadaTypes> ConsensusKeyChange<C> {
//     /// Validator address (should be self)
//     pub fn validator(self, validator: C::Address) -> Self {
//         Self { validator, ..self }
//     }

//     /// Value to which the tx changes the commission rate
//     pub fn consensus_key(self, consensus_key: C::Keypair) -> Self {
//         Self {
//             consensus_key: Some(consensus_key),
//             ..self
//         }
//     }

//     /// Path to the TX WASM code file
//     pub fn tx_code_path(self, tx_code_path: PathBuf) -> Self {
//         Self {
//             tx_code_path,
//             ..self
//         }
//     }
// }

// impl ConsensusKeyChange {
//     /// Build a transaction from this builder
//     pub async fn build(
//         &self,
//         context: &impl Namada,
//     ) -> crate::error::Result<(crate::proto::Tx, SigningTxData,
// Option<Epoch>)>     {
//         tx::build_change_consensus_key(context, self).await
//     }
// }

#[derive(Clone, Debug)]
/// Commission rate change args
pub struct MetaDataChange<C: NamadaTypes = SdkTypes> {
    /// Common tx arguments
    pub tx: Tx<C>,
    /// Validator address (should be self)
    pub validator: C::Address,
    /// New validator email
    pub email: Option<String>,
    /// New validator description
    pub description: Option<String>,
    /// New validator website
    pub website: Option<String>,
    /// New validator discord handle
    pub discord_handle: Option<String>,
    /// New validator avatar url
    pub avatar: Option<String>,
    /// New validator commission rate
    pub commission_rate: Option<Dec>,
    /// Path to the TX WASM code file
    pub tx_code_path: PathBuf,
}

impl<C: NamadaTypes> TxBuilder<C> for MetaDataChange<C> {
    fn tx<F>(self, func: F) -> Self
    where
        F: FnOnce(Tx<C>) -> Tx<C>,
    {
        MetaDataChange {
            tx: func(self.tx),
            ..self
        }
    }
}

impl<C: NamadaTypes> MetaDataChange<C> {
    /// Validator address (should be self)
    pub fn validator(self, validator: C::Address) -> Self {
        Self { validator, ..self }
    }

    /// Path to the TX WASM code file
    pub fn tx_code_path(self, tx_code_path: PathBuf) -> Self {
        Self {
            tx_code_path,
            ..self
        }
    }

    /// New validator email
    pub fn email(self, email: String) -> Self {
        Self {
            email: Some(email),
            ..self
        }
    }

    /// New validator description
    pub fn description(self, description: String) -> Self {
        Self {
            description: Some(description),
            ..self
        }
    }

    /// New validator website
    pub fn website(self, website: String) -> Self {
        Self {
            website: Some(website),
            ..self
        }
    }

    /// New validator discord handle
    pub fn discord_handle(self, discord_handle: String) -> Self {
        Self {
            discord_handle: Some(discord_handle),
            ..self
        }
    }

    /// New validator avatar url
    pub fn avatar(self, avatar: String) -> Self {
        Self {
            avatar: Some(avatar),
            ..self
        }
    }

    /// New validator commission rate
    pub fn commission_rate(self, commission_rate: Dec) -> Self {
        Self {
            commission_rate: Some(commission_rate),
            ..self
        }
    }
}

impl MetaDataChange {
    /// Build a transaction from this builder
    pub async fn build(
        &self,
        context: &impl Namada,
    ) -> crate::error::Result<(crate::proto::Tx, SigningTxData)> {
        tx::build_validator_metadata_change(context, self).await
    }
}

#[derive(Clone, Debug)]
/// Commission rate change args
pub struct UpdateStewardCommission<C: NamadaTypes = SdkTypes> {
    /// Common tx arguments
    pub tx: Tx<C>,
    /// Steward address
    pub steward: C::Address,
    /// Value to which the tx changes the commission rate
    pub commission: C::Data,
    /// Path to the TX WASM code file
    pub tx_code_path: PathBuf,
}

impl<C: NamadaTypes> TxBuilder<C> for UpdateStewardCommission<C> {
    fn tx<F>(self, func: F) -> Self
    where
        F: FnOnce(Tx<C>) -> Tx<C>,
    {
        UpdateStewardCommission {
            tx: func(self.tx),
            ..self
        }
    }
}

impl<C: NamadaTypes> UpdateStewardCommission<C> {
    /// Steward address
    pub fn steward(self, steward: C::Address) -> Self {
        Self { steward, ..self }
    }

    /// Value to which the tx changes the commission rate
    pub fn commission(self, commission: C::Data) -> Self {
        Self { commission, ..self }
    }

    /// Path to the TX WASM code file
    pub fn tx_code_path(self, tx_code_path: PathBuf) -> Self {
        Self {
            tx_code_path,
            ..self
        }
    }
}

impl UpdateStewardCommission {
    /// Build a transaction from this builder
    pub async fn build(
        &self,
        context: &impl Namada,
    ) -> crate::error::Result<(crate::proto::Tx, SigningTxData)> {
        tx::build_update_steward_commission(context, self).await
    }
}

#[derive(Clone, Debug)]
/// Commission rate change args
pub struct ResignSteward<C: NamadaTypes = SdkTypes> {
    /// Common tx arguments
    pub tx: Tx<C>,
    /// Validator address
    pub steward: C::Address,
    /// Path to the TX WASM code file
    pub tx_code_path: PathBuf,
}

impl<C: NamadaTypes> TxBuilder<C> for ResignSteward<C> {
    fn tx<F>(self, func: F) -> Self
    where
        F: FnOnce(Tx<C>) -> Tx<C>,
    {
        ResignSteward {
            tx: func(self.tx),
            ..self
        }
    }
}

impl<C: NamadaTypes> ResignSteward<C> {
    /// Validator address
    pub fn steward(self, steward: C::Address) -> Self {
        Self { steward, ..self }
    }

    /// Path to the TX WASM code file
    pub fn tx_code_path(self, tx_code_path: PathBuf) -> Self {
        Self {
            tx_code_path,
            ..self
        }
    }
}

impl ResignSteward {
    /// Build a transaction from this builder
    pub async fn build(
        &self,
        context: &impl Namada,
    ) -> crate::error::Result<(crate::proto::Tx, SigningTxData)> {
        tx::build_resign_steward(context, self).await
    }
}

#[derive(Clone, Debug)]
/// Re-activate a jailed validator args
pub struct TxUnjailValidator<C: NamadaTypes = SdkTypes> {
    /// Common tx arguments
    pub tx: Tx<C>,
    /// Validator address (should be self)
    pub validator: C::Address,
    /// Path to the TX WASM code file
    pub tx_code_path: PathBuf,
}

impl<C: NamadaTypes> TxBuilder<C> for TxUnjailValidator<C> {
    fn tx<F>(self, func: F) -> Self
    where
        F: FnOnce(Tx<C>) -> Tx<C>,
    {
        TxUnjailValidator {
            tx: func(self.tx),
            ..self
        }
    }
}

impl<C: NamadaTypes> TxUnjailValidator<C> {
    /// Validator address (should be self)
    pub fn validator(self, validator: C::Address) -> Self {
        Self { validator, ..self }
    }

    /// Path to the TX WASM code file
    pub fn tx_code_path(self, tx_code_path: PathBuf) -> Self {
        Self {
            tx_code_path,
            ..self
        }
    }
}

impl TxUnjailValidator {
    /// Build a transaction from this builder
    pub async fn build(
        &self,
        context: &impl Namada,
    ) -> crate::error::Result<(crate::proto::Tx, SigningTxData)> {
        tx::build_unjail_validator(context, self).await
    }
}

#[derive(Clone, Debug)]
/// Deactivate validator args
pub struct TxDeactivateValidator<C: NamadaTypes = SdkTypes> {
    /// Common tx arguments
    pub tx: Tx<C>,
    /// Validator address (should be self)
    pub validator: C::Address,
    /// Path to the TX WASM code file
    pub tx_code_path: PathBuf,
}

impl<C: NamadaTypes> TxBuilder<C> for TxDeactivateValidator<C> {
    fn tx<F>(self, func: F) -> Self
    where
        F: FnOnce(Tx<C>) -> Tx<C>,
    {
        TxDeactivateValidator {
            tx: func(self.tx),
            ..self
        }
    }
}

impl<C: NamadaTypes> TxDeactivateValidator<C> {
    /// Validator address (should be self)
    pub fn validator(self, validator: C::Address) -> Self {
        Self { validator, ..self }
    }

    /// Path to the TX WASM code file
    pub fn tx_code_path(self, tx_code_path: PathBuf) -> Self {
        Self {
            tx_code_path,
            ..self
        }
    }
}

impl TxDeactivateValidator {
    /// Build a transaction from this builder
    pub async fn build(
        &self,
        context: &impl Namada,
    ) -> crate::error::Result<(crate::proto::Tx, SigningTxData)> {
        tx::build_deactivate_validator(context, self).await
    }
}

#[derive(Clone, Debug)]
/// Re-activate a deactivated validator args
pub struct TxReactivateValidator<C: NamadaTypes = SdkTypes> {
    /// Common tx arguments
    pub tx: Tx<C>,
    /// Validator address (should be self)
    pub validator: C::Address,
    /// Path to the TX WASM code file
    pub tx_code_path: PathBuf,
}

impl<C: NamadaTypes> TxBuilder<C> for TxReactivateValidator<C> {
    fn tx<F>(self, func: F) -> Self
    where
        F: FnOnce(Tx<C>) -> Tx<C>,
    {
        TxReactivateValidator {
            tx: func(self.tx),
            ..self
        }
    }
}

impl<C: NamadaTypes> TxReactivateValidator<C> {
    /// Validator address (should be self)
    pub fn validator(self, validator: C::Address) -> Self {
        Self { validator, ..self }
    }

    /// Path to the TX WASM code file
    pub fn tx_code_path(self, tx_code_path: PathBuf) -> Self {
        Self {
            tx_code_path,
            ..self
        }
    }
}

impl TxReactivateValidator {
    /// Build a transaction from this builder
    pub async fn build(
        &self,
        context: &impl Namada,
    ) -> crate::error::Result<(crate::proto::Tx, SigningTxData)> {
        tx::build_reactivate_validator(context, self).await
    }
}

#[derive(Clone, Debug)]
/// Sign a transaction offline
pub struct SignTx<C: NamadaTypes = SdkTypes> {
    /// Common tx arguments
    pub tx: Tx<C>,
    /// Transaction data
    pub tx_data: C::Data,
    /// The account address
    pub owner: C::Address,
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

/// Query validator metadata
#[derive(Clone, Debug)]
pub struct QueryMetaData<C: NamadaTypes = SdkTypes> {
    /// Common query args
    pub query: Query<C>,
    /// Address of a validator
    pub validator: C::Address,
}

/// Query PoS slashes
#[derive(Clone, Debug)]
pub struct QuerySlashes<C: NamadaTypes = SdkTypes> {
    /// Common query args
    pub query: Query<C>,
    /// Address of a validator
    pub validator: Option<C::Address>,
}

/// Query PoS rewards
#[derive(Clone, Debug)]
pub struct QueryRewards<C: NamadaTypes = SdkTypes> {
    /// Common query args
    pub query: Query<C>,
    /// Address of the source
    pub source: Option<C::Address>,
    /// Address of the validator
    pub validator: C::Address,
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
    pub tm_addr: Option<String>,
    /// Native validator address
    pub validator_addr: Option<C::Address>,
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
    /// Simulate applying both the wrapper and inner transactions
    pub dry_run_wrapper: bool,
    /// Dump the transaction bytes to file
    pub dump_tx: bool,
    /// The output directory path to where serialize the data
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
    /// The amount being paid (for gas unit) to include the transaction
    pub fee_amount: Option<InputAmount>,
    /// The fee payer signing key
    pub wrapper_fee_payer: Option<C::PublicKey>,
    /// The token in which the fee is being paid
    pub fee_token: C::Address,
    /// The optional spending key for fee unshielding
    pub fee_unshield: Option<C::TransferSource>,
    /// The max amount of gas used to process tx
    pub gas_limit: GasLimit,
    /// The optional expiration of the transaction
    pub expiration: Option<DateTimeUtc>,
    /// Generate an ephimeral signing key to be used only once to sign a
    /// wrapper tx
    pub disposable_signing_key: bool,
    /// The chain id for which the transaction is intended
    pub chain_id: Option<ChainId>,
    /// Sign the tx with the key for the given alias from your wallet
    pub signing_keys: Vec<C::PublicKey>,
    /// List of signatures to attach to the transaction
    pub signatures: Vec<C::Data>,
    /// Path to the TX WASM code file to reveal PK
    pub tx_reveal_code_path: PathBuf,
    /// Password to decrypt key
    pub password: Option<Zeroizing<String>>,
    /// Optional memo to be included in the transaction
    pub memo: Option<Memo>,
    /// Use device to sign the transaction
    pub use_device: bool,
}

/// Builder functions for Tx
pub trait TxBuilder<C: NamadaTypes>: Sized {
    /// Apply the given function to the Tx inside self
    fn tx<F>(self, func: F) -> Self
    where
        F: FnOnce(Tx<C>) -> Tx<C>;
    /// Simulate applying the transaction
    fn dry_run(self, dry_run: bool) -> Self {
        self.tx(|x| Tx { dry_run, ..x })
    }
    /// Simulate applying both the wrapper and inner transactions
    fn dry_run_wrapper(self, dry_run_wrapper: bool) -> Self {
        self.tx(|x| Tx {
            dry_run_wrapper,
            ..x
        })
    }
    /// Dump the transaction bytes to file
    fn dump_tx(self, dump_tx: bool) -> Self {
        self.tx(|x| Tx { dump_tx, ..x })
    }
    /// The output directory path to where serialize the data
    fn output_folder(self, output_folder: PathBuf) -> Self {
        self.tx(|x| Tx {
            output_folder: Some(output_folder),
            ..x
        })
    }
    /// Submit the transaction even if it doesn't pass client checks
    fn force(self, force: bool) -> Self {
        self.tx(|x| Tx { force, ..x })
    }
    /// Do not wait for the transaction to be added to the blockchain
    fn broadcast_only(self, broadcast_only: bool) -> Self {
        self.tx(|x| Tx {
            broadcast_only,
            ..x
        })
    }
    /// The address of the ledger node as host:port
    fn ledger_address(self, ledger_address: C::TendermintAddress) -> Self {
        self.tx(|x| Tx {
            ledger_address,
            ..x
        })
    }
    /// If any new account is initialized by the tx, use the given alias to
    /// save it in the wallet.
    fn initialized_account_alias(
        self,
        initialized_account_alias: String,
    ) -> Self {
        self.tx(|x| Tx {
            initialized_account_alias: Some(initialized_account_alias),
            ..x
        })
    }
    /// Whether to force overwrite the above alias, if it is provided, in the
    /// wallet.
    fn wallet_alias_force(self, wallet_alias_force: bool) -> Self {
        self.tx(|x| Tx {
            wallet_alias_force,
            ..x
        })
    }
    /// The amount being paid (for gas unit) to include the transaction
    fn fee_amount(self, fee_amount: InputAmount) -> Self {
        self.tx(|x| Tx {
            fee_amount: Some(fee_amount),
            ..x
        })
    }
    /// The fee payer signing key
    fn wrapper_fee_payer(self, wrapper_fee_payer: C::PublicKey) -> Self {
        self.tx(|x| Tx {
            wrapper_fee_payer: Some(wrapper_fee_payer),
            ..x
        })
    }
    /// The token in which the fee is being paid
    fn fee_token(self, fee_token: C::Address) -> Self {
        self.tx(|x| Tx { fee_token, ..x })
    }
    /// The optional spending key for fee unshielding
    fn fee_unshield(self, fee_unshield: C::TransferSource) -> Self {
        self.tx(|x| Tx {
            fee_unshield: Some(fee_unshield),
            ..x
        })
    }
    /// The max amount of gas used to process tx
    fn gas_limit(self, gas_limit: GasLimit) -> Self {
        self.tx(|x| Tx { gas_limit, ..x })
    }
    /// The optional expiration of the transaction
    fn expiration(self, expiration: DateTimeUtc) -> Self {
        self.tx(|x| Tx {
            expiration: Some(expiration),
            ..x
        })
    }
    /// Generate an ephimeral signing key to be used only once to sign a
    /// wrapper tx
    fn disposable_signing_key(self, disposable_signing_key: bool) -> Self {
        self.tx(|x| Tx {
            disposable_signing_key,
            ..x
        })
    }
    /// The chain id for which the transaction is intended
    fn chain_id(self, chain_id: ChainId) -> Self {
        self.tx(|x| Tx {
            chain_id: Some(chain_id),
            ..x
        })
    }
    /// Sign the tx with the key for the given alias from your wallet
    fn signing_keys(self, signing_keys: Vec<C::PublicKey>) -> Self {
        self.tx(|x| Tx { signing_keys, ..x })
    }
    /// List of signatures to attach to the transaction
    fn signatures(self, signatures: Vec<C::Data>) -> Self {
        self.tx(|x| Tx { signatures, ..x })
    }
    /// Path to the TX WASM code file to reveal PK
    fn tx_reveal_code_path(self, tx_reveal_code_path: PathBuf) -> Self {
        self.tx(|x| Tx {
            tx_reveal_code_path,
            ..x
        })
    }
    /// Password to decrypt key
    fn password(self, password: Zeroizing<String>) -> Self {
        self.tx(|x| Tx {
            password: Some(password),
            ..x
        })
    }
}

impl<C: NamadaTypes> TxBuilder<C> for Tx<C> {
    fn tx<F>(self, func: F) -> Self
    where
        F: FnOnce(Tx<C>) -> Tx<C>,
    {
        func(self)
    }
}

/// Wallet generate key and implicit address arguments
#[derive(Clone, Debug)]
pub struct KeyGen {
    /// Scheme type
    pub scheme: SchemeType,
    /// Whether to generate a spending key for the shielded pool
    pub shielded: bool,
    /// Whether to generate a raw non-hd key
    pub raw: bool,
    /// Key alias
    pub alias: String,
    /// Whether to force overwrite the alias
    pub alias_force: bool,
    /// Don't encrypt the keypair
    pub unsafe_dont_encrypt: bool,
    /// BIP44 / ZIP32 derivation path
    pub derivation_path: String,
}

/// Wallet restore key and implicit address arguments
#[derive(Clone, Debug)]
pub struct KeyDerive {
    /// Scheme type
    pub scheme: SchemeType,
    /// Whether to generate a MASP spending key
    pub shielded: bool,
    /// Key alias
    pub alias: String,
    /// Whether to force overwrite the alias
    pub alias_force: bool,
    /// Don't encrypt the keypair
    pub unsafe_dont_encrypt: bool,
    /// BIP44 derivation path
    pub derivation_path: String,
    /// Use device to generate key and address
    pub use_device: bool,
}

/// Wallet list arguments
#[derive(Clone, Copy, Debug)]
pub struct KeyAddressList {
    /// Whether to list transparent secret keys only
    pub transparent_only: bool,
    /// Whether to list MASP spending keys only
    pub shielded_only: bool,
    /// List keys only
    pub keys_only: bool,
    /// List addresses only
    pub addresses_only: bool,
    /// Whether to decrypt secret / spending keys
    pub decrypt: bool,
    /// Show secret keys to user
    pub unsafe_show_secret: bool,
}

/// Wallet key / address lookup arguments
#[derive(Clone, Debug)]
pub struct KeyAddressFind {
    /// Alias to find
    pub alias: Option<String>,
    /// Address to find
    pub address: Option<Address>,
    /// Public key to lookup keypair with
    pub public_key: Option<common::PublicKey>,
    /// Public key hash to lookup keypair with
    pub public_key_hash: Option<String>,
    /// Payment address to find
    pub payment_address: Option<PaymentAddress>,
    /// Find keys only
    pub keys_only: bool,
    /// Find addresses only
    pub addresses_only: bool,
    /// Whether to decrypt secret / spending keys
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

/// Wallet key import arguments
#[derive(Clone, Debug)]
pub struct KeyImport {
    /// File name
    pub file_path: String,
    /// Key alias
    pub alias: String,
    /// Whether to force overwrite the alias
    pub alias_force: bool,
    /// Don't encrypt the key
    pub unsafe_dont_encrypt: bool,
}

/// Wallet key / address add arguments
#[derive(Clone, Debug)]
pub struct KeyAddressAdd {
    /// Address alias
    pub alias: String,
    /// Whether to force overwrite the alias
    pub alias_force: bool,
    /// Any supported value
    pub value: String,
    /// Don't encrypt the key
    pub unsafe_dont_encrypt: bool,
}

/// Wallet key / address remove arguments
#[derive(Clone, Debug)]
pub struct KeyAddressRemove {
    /// Address alias
    pub alias: String,
    /// Confirmation to remove the alias
    pub do_it: bool,
}

/// Generate payment address arguments
#[derive(Clone, Debug)]
pub struct PayAddressGen<C: NamadaTypes = SdkTypes> {
    /// Key alias
    pub alias: String,
    /// Whether to force overwrite the alias
    pub alias_force: bool,
    /// Viewing key
    pub viewing_key: C::ViewingKey,
    /// Pin
    pub pin: bool,
}

/// Bridge pool batch recommendation.
#[derive(Clone, Debug)]
pub struct RecommendBatch<C: NamadaTypes = SdkTypes> {
    /// The query parameters.
    pub query: Query<C>,
    /// The maximum amount of gas to spend.
    pub max_gas: Option<u64>,
    /// An optional parameter indicating how much net
    /// gas the relayer is willing to pay.
    pub gas: Option<u64>,
    /// Bridge pool recommendations conversion rates table.
    pub conversion_table: C::BpConversionTable,
}

/// A transfer to be added to the Ethereum bridge pool.
#[derive(Clone, Debug)]
pub struct EthereumBridgePool<C: NamadaTypes = SdkTypes> {
    /// Whether the transfer is for a NUT.
    ///
    /// By default, we add wrapped ERC20s onto the
    /// Bridge pool.
    pub nut: bool,
    /// The args for building a tx to the bridge pool
    pub tx: Tx<C>,
    /// The type of token
    pub asset: EthAddress,
    /// The recipient address
    pub recipient: EthAddress,
    /// The sender of the transfer
    pub sender: C::Address,
    /// The amount to be transferred
    pub amount: InputAmount,
    /// The amount of gas fees
    pub fee_amount: InputAmount,
    /// The account of fee payer.
    ///
    /// If unset, it is the same as the sender.
    pub fee_payer: Option<C::Address>,
    /// The token in which the gas is being paid
    pub fee_token: C::Address,
    /// Path to the tx WASM code file
    pub code_path: PathBuf,
}

impl<C: NamadaTypes> TxBuilder<C> for EthereumBridgePool<C> {
    fn tx<F>(self, func: F) -> Self
    where
        F: FnOnce(Tx<C>) -> Tx<C>,
    {
        EthereumBridgePool {
            tx: func(self.tx),
            ..self
        }
    }
}

impl<C: NamadaTypes> EthereumBridgePool<C> {
    /// Whether the transfer is for a NUT.
    ///
    /// By default, we add wrapped ERC20s onto the
    /// Bridge pool.
    pub fn nut(self, nut: bool) -> Self {
        Self { nut, ..self }
    }

    /// The type of token
    pub fn asset(self, asset: EthAddress) -> Self {
        Self { asset, ..self }
    }

    /// The recipient address
    pub fn recipient(self, recipient: EthAddress) -> Self {
        Self { recipient, ..self }
    }

    /// The sender of the transfer
    pub fn sender(self, sender: C::Address) -> Self {
        Self { sender, ..self }
    }

    /// The amount to be transferred
    pub fn amount(self, amount: InputAmount) -> Self {
        Self { amount, ..self }
    }

    /// The amount of gas fees
    pub fn fee_amount(self, fee_amount: InputAmount) -> Self {
        Self { fee_amount, ..self }
    }

    /// The account of fee payer.
    ///
    /// If unset, it is the same as the sender.
    pub fn fee_payer(self, fee_payer: C::Address) -> Self {
        Self {
            fee_payer: Some(fee_payer),
            ..self
        }
    }

    /// The token in which the gas is being paid
    pub fn fee_token(self, fee_token: C::Address) -> Self {
        Self { fee_token, ..self }
    }

    /// Path to the tx WASM code file
    pub fn code_path(self, code_path: PathBuf) -> Self {
        Self { code_path, ..self }
    }
}

impl EthereumBridgePool {
    /// Build a transaction from this builder
    pub async fn build(
        self,
        context: &impl Namada,
    ) -> crate::error::Result<(crate::proto::Tx, SigningTxData)> {
        bridge_pool::build_bridge_pool_tx(context, self).await
    }
}

/// Bridge pool proof arguments.
#[derive(Debug, Clone)]
pub struct BridgePoolProof<C: NamadaTypes = SdkTypes> {
    /// The query parameters.
    pub query: Query<C>,
    /// The keccak hashes of transfers to
    /// acquire a proof of.
    pub transfers: Vec<KeccakHash>,
    /// The address of the node responsible for relaying
    /// the transfers.
    ///
    /// This node will receive the gas fees escrowed in
    /// the Bridge pool, to compensate the Ethereum relay
    /// procedure.
    pub relayer: Address,
}

/// Arguments to an Ethereum Bridge pool relay operation.
#[derive(Debug, Clone)]
pub struct RelayBridgePoolProof<C: NamadaTypes = SdkTypes> {
    /// The query parameters.
    pub query: Query<C>,
    /// The hashes of the transfers to be relayed
    pub transfers: Vec<KeccakHash>,
    /// The Namada address for receiving fees for relaying
    pub relayer: Address,
    /// The number of confirmations to wait for on Ethereum
    pub confirmations: u64,
    /// The Ethereum RPC endpoint.
    pub eth_rpc_endpoint: C::EthereumAddress,
    /// The Ethereum gas that can be spent during
    /// the relay call.
    pub gas: Option<u64>,
    /// The price of Ethereum gas, during the
    /// relay call.
    pub gas_price: Option<u64>,
    /// The address of the Ethereum wallet to pay the gas fees.
    /// If unset, the default wallet is used.
    pub eth_addr: Option<EthAddress>,
    /// Synchronize with the network, or exit immediately,
    /// if the Ethereum node has fallen behind.
    pub sync: bool,
    /// Safe mode overrides keyboard interrupt signals, to ensure
    /// Ethereum transfers aren't canceled midway through.
    pub safe_mode: bool,
}

/// Bridge validator set arguments.
#[derive(Debug, Clone)]
pub struct BridgeValidatorSet<C: NamadaTypes = SdkTypes> {
    /// The query parameters.
    pub query: Query<C>,
    /// The epoch to query.
    pub epoch: Option<Epoch>,
}

/// Governance validator set arguments.
#[derive(Debug, Clone)]
pub struct GovernanceValidatorSet<C: NamadaTypes = SdkTypes> {
    /// The query parameters.
    pub query: Query<C>,
    /// The epoch to query.
    pub epoch: Option<Epoch>,
}

/// Validator set proof arguments.
#[derive(Debug, Clone)]
pub struct ValidatorSetProof<C: NamadaTypes = SdkTypes> {
    /// The query parameters.
    pub query: Query<C>,
    /// The epoch to query.
    pub epoch: Option<Epoch>,
}

/// Validator set update relayer arguments.
#[derive(Debug, Clone)]
pub struct ValidatorSetUpdateRelay<C: NamadaTypes = SdkTypes> {
    /// Run in daemon mode, which will continuously
    /// perform validator set updates.
    pub daemon: bool,
    /// The query parameters.
    pub query: Query<C>,
    /// The number of block confirmations on Ethereum.
    pub confirmations: u64,
    /// The Ethereum RPC endpoint.
    pub eth_rpc_endpoint: C::EthereumAddress,
    /// The epoch of the validator set to relay.
    pub epoch: Option<Epoch>,
    /// The Ethereum gas that can be spent during
    /// the relay call.
    pub gas: Option<u64>,
    /// The price of Ethereum gas, during the
    /// relay call.
    pub gas_price: Option<u64>,
    /// The address of the Ethereum wallet to pay the gas fees.
    /// If unset, the default wallet is used.
    pub eth_addr: Option<EthAddress>,
    /// Synchronize with the network, or exit immediately,
    /// if the Ethereum node has fallen behind.
    pub sync: bool,
    /// The amount of time to sleep between failed
    /// daemon mode relays.
    pub retry_dur: Option<StdDuration>,
    /// The amount of time to sleep between successful
    /// daemon mode relays.
    pub success_dur: Option<StdDuration>,
    /// Safe mode overrides keyboard interrupt signals, to ensure
    /// Ethereum transfers aren't canceled midway through.
    pub safe_mode: bool,
}

/// IBC shielded transfer generation arguments
#[derive(Clone, Debug)]
pub struct GenIbcShieldedTransafer<C: NamadaTypes = SdkTypes> {
    /// The query parameters.
    pub query: Query<C>,
    /// The output directory path to where serialize the data
    pub output_folder: Option<PathBuf>,
    /// The target address
    pub target: C::TransferTarget,
    /// The token address which could be a non-namada address
    pub token: String,
    /// Transferred token amount
    pub amount: InputAmount,
    /// Port ID via which the token is received
    pub port_id: PortId,
    /// Channel ID via which the token is received
    pub channel_id: ChannelId,
}
