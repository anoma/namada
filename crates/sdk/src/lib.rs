//! Namada SDK

#![doc(html_favicon_url = "https://dev.namada.net/master/favicon.png")]
#![doc(html_logo_url = "https://dev.namada.net/master/rustdoc-logo.png")]
#![deny(rustdoc::broken_intra_doc_links)]
#![deny(rustdoc::private_intra_doc_links)]
#![warn(
    missing_docs,
    rust_2018_idioms,
    clippy::dbg_macro,
    clippy::print_stdout,
    clippy::print_stderr
)]

extern crate alloc;

pub use namada_core::*;
#[cfg(feature = "tendermint-rpc")]
pub use tendermint_rpc;
pub use {
    bip39, masp_primitives, masp_proofs, namada_account as account,
    namada_gas as gas, namada_governance as governance,
    namada_proof_of_stake as proof_of_stake, namada_state as state,
    namada_storage as storage, namada_token as token, zeroize,
};

pub mod eth_bridge;

pub mod rpc;

pub mod args;
pub mod masp;
pub mod signing;
#[allow(clippy::result_large_err)]
pub mod tx;
#[cfg(any(test, feature = "testing", feature = "validation"))]
pub mod validation;

pub mod error;
pub mod events;
pub(crate) mod internal_macros;
pub mod io;
pub mod migrations;
pub mod queries;
pub mod wallet;

#[cfg(feature = "async-send")]
pub use std::marker::Send as MaybeSend;
#[cfg(feature = "async-send")]
pub use std::marker::Sync as MaybeSync;
use std::path::PathBuf;
use std::str::FromStr;

use args::{InputAmount, SdkTypes};
use io::Io;
use masp::{ShieldedContext, ShieldedUtils};
use namada_core::address::Address;
use namada_core::collections::HashSet;
pub use namada_core::control_flow;
use namada_core::dec::Dec;
use namada_core::ethereum_events::EthAddress;
use namada_core::ibc::core::host::types::identifiers::{ChannelId, PortId};
use namada_core::key::*;
use namada_core::masp::{ExtendedSpendingKey, PaymentAddress, TransferSource};
use namada_tx::data::wrapper::GasLimit;
use namada_tx::Tx;
use rpc::{denominate_amount, format_denominated_amount, query_native_token};
use signing::SigningTxData;
use token::{DenominatedAmount, NATIVE_MAX_DECIMAL_PLACES};
use tokio::sync::{RwLock, RwLockReadGuard, RwLockWriteGuard};
use tx::{
    ProcessTxResponse, TX_BECOME_VALIDATOR_WASM, TX_BOND_WASM,
    TX_BRIDGE_POOL_WASM, TX_CHANGE_COMMISSION_WASM,
    TX_CHANGE_CONSENSUS_KEY_WASM, TX_CHANGE_METADATA_WASM,
    TX_CLAIM_REWARDS_WASM, TX_DEACTIVATE_VALIDATOR_WASM, TX_IBC_WASM,
    TX_INIT_ACCOUNT_WASM, TX_INIT_PROPOSAL, TX_REACTIVATE_VALIDATOR_WASM,
    TX_REDELEGATE_WASM, TX_RESIGN_STEWARD, TX_REVEAL_PK, TX_TRANSFER_WASM,
    TX_UNBOND_WASM, TX_UNJAIL_VALIDATOR_WASM, TX_UPDATE_ACCOUNT_WASM,
    TX_UPDATE_STEWARD_COMMISSION, TX_VOTE_PROPOSAL, TX_WITHDRAW_WASM,
    VP_USER_WASM,
};
use wallet::{Wallet, WalletIo, WalletStorage};

/// Default gas-limit
pub const DEFAULT_GAS_LIMIT: u64 = 100_000;

#[allow(missing_docs)]
#[cfg(not(feature = "async-send"))]
pub trait MaybeSync {}
#[cfg(not(feature = "async-send"))]
impl<T> MaybeSync for T where T: ?Sized {}

#[allow(missing_docs)]
#[cfg(not(feature = "async-send"))]
pub trait MaybeSend {}
#[cfg(not(feature = "async-send"))]
impl<T> MaybeSend for T where T: ?Sized {}

#[cfg_attr(feature = "async-send", async_trait::async_trait)]
#[cfg_attr(not(feature = "async-send"), async_trait::async_trait(?Send))]
/// An interface for high-level interaction with the Namada SDK
pub trait Namada: Sized + MaybeSync + MaybeSend {
    /// A client with async request dispatcher method
    type Client: queries::Client + MaybeSend + Sync;
    /// Captures the interactive parts of the wallet's functioning
    type WalletUtils: WalletIo + WalletStorage + MaybeSend + MaybeSync;
    /// Abstracts platform specific details away from the logic of shielded pool
    /// operations.
    type ShieldedUtils: ShieldedUtils + MaybeSend + MaybeSync;
    /// Captures the input/output streams used by this object
    type Io: Io + MaybeSend + MaybeSync;

    /// Obtain the client for communicating with the ledger
    fn client(&self) -> &Self::Client;

    /// Obtain the input/output handle for this context
    fn io(&self) -> &Self::Io;

    /// Obtain read guard on the wallet
    async fn wallet(&self) -> RwLockReadGuard<'_, Wallet<Self::WalletUtils>>;

    /// Obtain write guard on the wallet
    async fn wallet_mut(
        &self,
    ) -> RwLockWriteGuard<'_, Wallet<Self::WalletUtils>>;

    /// Obtain the wallet lock
    fn wallet_lock(&self) -> &RwLock<Wallet<Self::WalletUtils>>;

    /// Obtain read guard on the shielded context
    async fn shielded(
        &self,
    ) -> RwLockReadGuard<'_, ShieldedContext<Self::ShieldedUtils>>;

    /// Obtain write guard on the shielded context
    async fn shielded_mut(
        &self,
    ) -> RwLockWriteGuard<'_, ShieldedContext<Self::ShieldedUtils>>;

    /// Return the native token
    fn native_token(&self) -> Address;

    /// Make a tx builder using no arguments
    fn tx_builder(&self) -> args::Tx {
        args::Tx {
            dry_run: false,
            dry_run_wrapper: false,
            dump_tx: false,
            output_folder: None,
            force: false,
            broadcast_only: false,
            ledger_address: tendermint_rpc::Url::from_str(
                "http://127.0.0.1:26657",
            )
            .unwrap(),
            initialized_account_alias: None,
            wallet_alias_force: false,
            fee_amount: None,
            wrapper_fee_payer: None,
            fee_token: self.native_token(),
            gas_limit: GasLimit::from(DEFAULT_GAS_LIMIT),
            expiration: Default::default(),
            disposable_signing_key: false,
            chain_id: None,
            signing_keys: vec![],
            signatures: vec![],
            tx_reveal_code_path: PathBuf::from(TX_REVEAL_PK),
            password: None,
            memo: None,
            use_device: false,
        }
    }

    /// Make a TxTransparentTransfer builder from the given minimum set of
    /// arguments
    fn new_transparent_transfer(
        &self,
        data: Vec<args::TxTransparentTransferData>,
    ) -> args::TxTransparentTransfer {
        args::TxTransparentTransfer {
            data,
            tx_code_path: PathBuf::from(TX_TRANSFER_WASM),
            tx: self.tx_builder(),
        }
    }

    /// Make a TxShieldedTransfer builder from the given minimum set of
    /// arguments
    fn new_shielded_transfer(
        &self,
        data: Vec<args::TxShieldedTransferData>,
        gas_spending_keys: Vec<ExtendedSpendingKey>,
    ) -> args::TxShieldedTransfer {
        args::TxShieldedTransfer {
            data,
            gas_spending_keys,
            tx_code_path: PathBuf::from(TX_TRANSFER_WASM),
            tx: self.tx_builder(),
        }
    }

    /// Make a TxShieldingTransfer builder from the given minimum set of
    /// arguments
    fn new_shielding_transfer(
        &self,
        target: PaymentAddress,
        data: Vec<args::TxShieldingTransferData>,
    ) -> args::TxShieldingTransfer {
        args::TxShieldingTransfer {
            data,
            target,
            tx_code_path: PathBuf::from(TX_TRANSFER_WASM),
            tx: self.tx_builder(),
        }
    }

    /// Make a TxUnshieldingTransfer builder from the given minimum set of
    /// arguments
    fn new_unshielding_transfer(
        &self,
        source: ExtendedSpendingKey,
        data: Vec<args::TxUnshieldingTransferData>,
        gas_spending_keys: Vec<ExtendedSpendingKey>,
    ) -> args::TxUnshieldingTransfer {
        args::TxUnshieldingTransfer {
            source,
            data,
            gas_spending_keys,
            tx_code_path: PathBuf::from(TX_TRANSFER_WASM),
            tx: self.tx_builder(),
        }
    }

    /// Make a InitAccount builder from the given minimum set of arguments
    fn new_init_account(
        &self,
        public_keys: Vec<common::PublicKey>,
        threshold: Option<u8>,
    ) -> args::TxInitAccount {
        args::TxInitAccount {
            tx: self.tx_builder(),
            vp_code_path: PathBuf::from(VP_USER_WASM),
            tx_code_path: PathBuf::from(TX_INIT_ACCOUNT_WASM),
            public_keys,
            threshold,
        }
    }

    /// Make a RevealPK builder from the given minimum set of arguments
    fn new_reveal_pk(&self, public_key: common::PublicKey) -> args::RevealPk {
        args::RevealPk {
            public_key,
            tx: self.tx_builder(),
        }
    }

    /// Make a Bond builder from the given minimum set of arguments
    fn new_bond(
        &self,
        validator: Address,
        amount: token::Amount,
    ) -> args::Bond {
        args::Bond {
            validator,
            amount,
            source: None,
            tx: self.tx_builder(),
            tx_code_path: PathBuf::from(TX_BOND_WASM),
        }
    }

    /// Make a Unbond builder from the given minimum set of arguments
    fn new_unbond(
        &self,
        validator: Address,
        amount: token::Amount,
    ) -> args::Unbond {
        args::Unbond {
            validator,
            amount,
            source: None,
            tx: self.tx_builder(),
            tx_code_path: PathBuf::from(TX_UNBOND_WASM),
        }
    }

    /// Make a Redelegation builder for the given minimum set of arguments
    fn new_redelegation(
        &self,
        source: Address,
        src_validator: Address,
        dest_validator: Address,
        amount: token::Amount,
    ) -> args::Redelegate {
        args::Redelegate {
            tx: self.tx_builder(),
            // Source validator address
            src_validator,
            // Destination validator address
            dest_validator,
            // Owner of the bonds that are being redelegated
            owner: source,
            // The amount of tokens to redelegate
            amount,
            // Path to the TX WASM code file
            tx_code_path: PathBuf::from(TX_REDELEGATE_WASM),
        }
    }

    /// Make a TxIbcTransfer builder from the given minimum set of arguments
    fn new_ibc_transfer(
        &self,
        source: TransferSource,
        receiver: String,
        token: Address,
        amount: InputAmount,
        channel_id: ChannelId,
    ) -> args::TxIbcTransfer {
        args::TxIbcTransfer {
            source,
            receiver,
            token,
            amount,
            channel_id,
            port_id: PortId::from_str("transfer").unwrap(),
            timeout_height: None,
            timeout_sec_offset: None,
            refund_target: None,
            ibc_shielding_data: None,
            ibc_memo: None,
            gas_spending_keys: Default::default(),
            tx: self.tx_builder(),
            tx_code_path: PathBuf::from(TX_IBC_WASM),
        }
    }

    /// Make a InitProposal builder from the given minimum set of arguments
    fn new_init_proposal(&self, proposal_data: Vec<u8>) -> args::InitProposal {
        args::InitProposal {
            proposal_data,
            is_pgf_stewards: false,
            is_pgf_funding: false,
            tx_code_path: PathBuf::from(TX_INIT_PROPOSAL),
            tx: self.tx_builder(),
        }
    }

    /// Make a TxUpdateAccount builder from the given minimum set of arguments
    fn new_update_account(
        &self,
        addr: Address,
        public_keys: Vec<common::PublicKey>,
        threshold: u8,
    ) -> args::TxUpdateAccount {
        args::TxUpdateAccount {
            addr,
            vp_code_path: None,
            public_keys,
            threshold: Some(threshold),
            tx_code_path: PathBuf::from(TX_UPDATE_ACCOUNT_WASM),
            tx: self.tx_builder(),
        }
    }

    /// Make a VoteProposal builder from the given minimum set of arguments
    fn new_proposal_vote(
        &self,
        proposal_id: u64,
        vote: String,
        voter_address: Address,
    ) -> args::VoteProposal {
        args::VoteProposal {
            vote,
            voter_address,
            proposal_id,
            tx_code_path: PathBuf::from(TX_VOTE_PROPOSAL),
            tx: self.tx_builder(),
        }
    }

    /// Make a CommissionRateChange builder from the given minimum set of
    /// arguments
    fn new_change_commission_rate(
        &self,
        rate: Dec,
        validator: Address,
    ) -> args::CommissionRateChange {
        args::CommissionRateChange {
            rate,
            validator,
            tx_code_path: PathBuf::from(TX_CHANGE_COMMISSION_WASM),
            tx: self.tx_builder(),
        }
    }

    /// Make ConsensusKeyChange builder from the given minimum set of arguments
    fn new_change_consensus_key(
        &self,
        validator: Address,
        consensus_key: common::PublicKey,
    ) -> args::ConsensusKeyChange {
        args::ConsensusKeyChange {
            validator,
            consensus_key: Some(consensus_key),
            tx_code_path: PathBuf::from(TX_CHANGE_CONSENSUS_KEY_WASM),
            unsafe_dont_encrypt: false,
            tx: self.tx_builder(),
        }
    }

    /// Make a CommissionRateChange builder from the given minimum set of
    /// arguments
    fn new_change_metadata(&self, validator: Address) -> args::MetaDataChange {
        args::MetaDataChange {
            validator,
            email: None,
            description: None,
            website: None,
            discord_handle: None,
            avatar: None,
            name: None,
            commission_rate: None,
            tx_code_path: PathBuf::from(TX_CHANGE_METADATA_WASM),
            tx: self.tx_builder(),
        }
    }

    /// Make a TxBecomeValidator builder from the given minimum set of arguments
    #[allow(clippy::too_many_arguments)]
    fn new_become_validator(
        &self,
        address: Address,
        commission_rate: Dec,
        max_commission_rate_change: Dec,
        consesus_key: common::PublicKey,
        eth_cold_key: common::PublicKey,
        eth_hot_key: common::PublicKey,
        protocol_key: common::PublicKey,
        email: String,
    ) -> args::TxBecomeValidator {
        args::TxBecomeValidator {
            address,
            commission_rate,
            max_commission_rate_change,
            scheme: SchemeType::Ed25519,
            consensus_key: Some(consesus_key),
            eth_cold_key: Some(eth_cold_key),
            eth_hot_key: Some(eth_hot_key),
            protocol_key: Some(protocol_key),
            unsafe_dont_encrypt: false,
            tx_code_path: PathBuf::from(TX_BECOME_VALIDATOR_WASM),
            tx: self.tx_builder(),
            email,
            description: None,
            website: None,
            discord_handle: None,
            avatar: None,
            name: None,
        }
    }

    /// Make a TxInitValidator builder from the given minimum set of arguments
    fn new_init_validator(
        &self,
        commission_rate: Dec,
        max_commission_rate_change: Dec,
        email: String,
    ) -> args::TxInitValidator {
        args::TxInitValidator {
            commission_rate,
            max_commission_rate_change,
            scheme: SchemeType::Ed25519,
            account_keys: vec![],
            threshold: None,
            consensus_key: None,
            eth_cold_key: None,
            eth_hot_key: None,
            protocol_key: None,
            validator_vp_code_path: PathBuf::from(VP_USER_WASM),
            unsafe_dont_encrypt: false,
            tx_init_account_code_path: PathBuf::from(TX_INIT_ACCOUNT_WASM),
            tx_become_validator_code_path: PathBuf::from(
                TX_BECOME_VALIDATOR_WASM,
            ),
            tx: self.tx_builder(),
            email,
            description: None,
            website: None,
            discord_handle: None,
            avatar: None,
            name: None,
        }
    }

    /// Make a TxUnjailValidator builder from the given minimum set of arguments
    fn new_unjail_validator(
        &self,
        validator: Address,
    ) -> args::TxUnjailValidator {
        args::TxUnjailValidator {
            validator,
            tx_code_path: PathBuf::from(TX_UNJAIL_VALIDATOR_WASM),
            tx: self.tx_builder(),
        }
    }

    /// Make a TxDeactivateValidator builder from the given minimum set of
    /// arguments
    fn new_deactivate_validator(
        &self,
        validator: Address,
    ) -> args::TxDeactivateValidator {
        args::TxDeactivateValidator {
            validator,
            tx_code_path: PathBuf::from(TX_DEACTIVATE_VALIDATOR_WASM),
            tx: self.tx_builder(),
        }
    }

    /// Make a TxReactivateValidator builder from the given minimum set of
    /// arguments
    fn new_reactivate_validator(
        &self,
        validator: Address,
    ) -> args::TxReactivateValidator {
        args::TxReactivateValidator {
            validator,
            tx_code_path: PathBuf::from(TX_REACTIVATE_VALIDATOR_WASM),
            tx: self.tx_builder(),
        }
    }

    /// Make a Withdraw builder from the given minimum set of arguments
    fn new_withdraw(&self, validator: Address) -> args::Withdraw {
        args::Withdraw {
            validator,
            source: None,
            tx_code_path: PathBuf::from(TX_WITHDRAW_WASM),
            tx: self.tx_builder(),
        }
    }

    /// Make a Claim-rewards builder from the given minimum set of arguments
    fn new_claim_rewards(&self, validator: Address) -> args::ClaimRewards {
        args::ClaimRewards {
            validator,
            source: None,
            tx_code_path: PathBuf::from(TX_CLAIM_REWARDS_WASM),
            tx: self.tx_builder(),
        }
    }

    /// Make a Withdraw builder from the given minimum set of arguments
    fn new_add_erc20_transfer(
        &self,
        sender: Address,
        recipient: EthAddress,
        asset: EthAddress,
        amount: InputAmount,
    ) -> args::EthereumBridgePool {
        args::EthereumBridgePool {
            sender,
            recipient,
            asset,
            amount,
            fee_amount: InputAmount::Unvalidated(
                token::DenominatedAmount::new(
                    token::Amount::default(),
                    NATIVE_MAX_DECIMAL_PLACES.into(),
                ),
            ),
            fee_payer: None,
            fee_token: self.native_token(),
            nut: false,
            code_path: PathBuf::from(TX_BRIDGE_POOL_WASM),
            tx: self.tx_builder(),
        }
    }

    /// Make a ResignSteward builder from the given minimum set of arguments
    fn new_resign_steward(&self, steward: Address) -> args::ResignSteward {
        args::ResignSteward {
            steward,
            tx: self.tx_builder(),
            tx_code_path: PathBuf::from(TX_RESIGN_STEWARD),
        }
    }

    /// Make a UpdateStewardCommission builder from the given minimum set of
    /// arguments
    fn new_update_steward_rewards(
        &self,
        steward: Address,
        commission: Vec<u8>,
    ) -> args::UpdateStewardCommission {
        args::UpdateStewardCommission {
            steward,
            commission,
            tx: self.tx_builder(),
            tx_code_path: PathBuf::from(TX_UPDATE_STEWARD_COMMISSION),
        }
    }

    /// Make a TxCustom builder from the given minimum set of arguments
    fn new_custom(&self, owner: Address) -> args::TxCustom {
        args::TxCustom {
            owner,
            tx: self.tx_builder(),
            code_path: None,
            data_path: None,
            serialized_tx: None,
        }
    }

    /// Sign the given transaction using the given signing data
    async fn sign<D, F>(
        &self,
        tx: &mut Tx,
        args: &args::Tx,
        signing_data: SigningTxData,
        with: impl Fn(Tx, common::PublicKey, HashSet<signing::Signable>, D) -> F
        + MaybeSend
        + MaybeSync,
        user_data: D,
    ) -> crate::error::Result<()>
    where
        D: Clone + MaybeSend + MaybeSync,
        F: MaybeSend
            + MaybeSync
            + std::future::Future<Output = crate::error::Result<Tx>>,
    {
        signing::sign_tx(
            self.wallet_lock(),
            args,
            tx,
            signing_data,
            with,
            user_data,
        )
        .await
    }

    /// Process the given transaction using the given flags
    async fn submit(
        &self,
        tx: Tx,
        args: &args::Tx,
    ) -> crate::error::Result<ProcessTxResponse> {
        tx::process_tx(self, args, tx).await
    }

    /// Look up the denomination of a token in order to make a correctly
    /// denominated amount.
    async fn denominate_amount(
        &self,
        token: &Address,
        amount: token::Amount,
    ) -> DenominatedAmount {
        denominate_amount(self.client(), self.io(), token, amount).await
    }

    /// Look up the denomination of a token in order to format it correctly as a
    /// string.
    async fn format_amount(
        &self,
        token: &Address,
        amount: token::Amount,
    ) -> String {
        format_denominated_amount(self.client(), self.io(), token, amount).await
    }
}

/// Provides convenience methods for common Namada interactions
pub struct NamadaImpl<C, U, V, I>
where
    C: queries::Client,
    U: WalletIo,
    V: ShieldedUtils,
    I: Io,
{
    /// Used to send and receive messages from the ledger
    pub client: C,
    /// Stores the addresses and keys required for ledger interactions
    pub wallet: RwLock<Wallet<U>>,
    /// Stores the current state of the shielded pool
    pub shielded: RwLock<ShieldedContext<V>>,
    /// Captures the input/output streams used by this object
    pub io: I,
    /// The address of the native token
    native_token: Address,
    /// The default builder for a Tx
    prototype: args::Tx,
}

impl<C, U, V, I> NamadaImpl<C, U, V, I>
where
    C: queries::Client + Sync,
    U: WalletIo,
    V: ShieldedUtils,
    I: Io,
{
    /// Construct a new Namada context with the given native token address
    pub fn native_new(
        client: C,
        wallet: Wallet<U>,
        shielded: ShieldedContext<V>,
        io: I,
        native_token: Address,
    ) -> Self {
        NamadaImpl {
            client,
            wallet: RwLock::new(wallet),
            shielded: RwLock::new(shielded),
            io,
            native_token: native_token.clone(),
            prototype: args::Tx {
                dry_run: false,
                dry_run_wrapper: false,
                dump_tx: false,
                output_folder: None,
                force: false,
                broadcast_only: false,
                ledger_address: tendermint_rpc::Url::from_str(
                    "http://127.0.0.1:26657",
                )
                .unwrap(),
                initialized_account_alias: None,
                wallet_alias_force: false,
                fee_amount: None,
                wrapper_fee_payer: None,
                fee_token: native_token,
                gas_limit: GasLimit::from(DEFAULT_GAS_LIMIT),
                expiration: Default::default(),
                disposable_signing_key: false,
                chain_id: None,
                signing_keys: vec![],
                signatures: vec![],
                tx_reveal_code_path: PathBuf::from(TX_REVEAL_PK),
                password: None,
                memo: None,
                use_device: false,
            },
        }
    }

    /// Construct a new Namada context looking up the native token address
    pub async fn new(
        client: C,
        wallet: Wallet<U>,
        shielded: ShieldedContext<V>,
        io: I,
    ) -> crate::error::Result<NamadaImpl<C, U, V, I>> {
        let native_token = query_native_token(&client).await?;
        Ok(NamadaImpl::native_new(
            client,
            wallet,
            shielded,
            io,
            native_token,
        ))
    }
}

#[cfg_attr(feature = "async-send", async_trait::async_trait)]
#[cfg_attr(not(feature = "async-send"), async_trait::async_trait(?Send))]
impl<C, U, V, I> Namada for NamadaImpl<C, U, V, I>
where
    C: queries::Client + MaybeSend + Sync,
    U: WalletIo + WalletStorage + MaybeSync + MaybeSend,
    V: ShieldedUtils + MaybeSend + MaybeSync,
    I: Io + MaybeSend + MaybeSync,
{
    type Client = C;
    type Io = I;
    type ShieldedUtils = V;
    type WalletUtils = U;

    /// Obtain the prototypical Tx builder
    fn tx_builder(&self) -> args::Tx {
        self.prototype.clone()
    }

    fn native_token(&self) -> Address {
        self.native_token.clone()
    }

    fn io(&self) -> &Self::Io {
        &self.io
    }

    fn client(&self) -> &Self::Client {
        &self.client
    }

    async fn wallet(&self) -> RwLockReadGuard<'_, Wallet<Self::WalletUtils>> {
        self.wallet.read().await
    }

    async fn wallet_mut(
        &self,
    ) -> RwLockWriteGuard<'_, Wallet<Self::WalletUtils>> {
        self.wallet.write().await
    }

    async fn shielded(
        &self,
    ) -> RwLockReadGuard<'_, ShieldedContext<Self::ShieldedUtils>> {
        self.shielded.read().await
    }

    async fn shielded_mut(
        &self,
    ) -> RwLockWriteGuard<'_, ShieldedContext<Self::ShieldedUtils>> {
        self.shielded.write().await
    }

    fn wallet_lock(&self) -> &RwLock<Wallet<Self::WalletUtils>> {
        &self.wallet
    }
}

/// Allow the prototypical Tx builder to be modified
impl<C, U, V, I> args::TxBuilder<SdkTypes> for NamadaImpl<C, U, V, I>
where
    C: queries::Client + Sync,
    U: WalletIo,
    V: ShieldedUtils,
    I: Io,
{
    fn tx<F>(self, func: F) -> Self
    where
        F: FnOnce(args::Tx<SdkTypes>) -> args::Tx<SdkTypes>,
    {
        Self {
            prototype: func(self.prototype),
            ..self
        }
    }
}

/// Tests and strategies for transactions
#[cfg(any(test, feature = "testing"))]
pub mod testing {
    use ::borsh::{BorshDeserialize, BorshSchema, BorshSerialize};
    use borsh_ext::BorshSerializeExt;
    use governance::ProposalType;
    use masp_primitives::transaction::components::sapling::builder::StoredBuildParams;
    use namada_account::{InitAccount, UpdateAccount};
    use namada_core::address::testing::{
        arb_established_address, arb_non_internal_address,
    };
    use namada_core::collections::HashMap;
    use namada_core::eth_bridge_pool::PendingTransfer;
    use namada_core::hash::testing::arb_hash;
    use namada_core::key::testing::arb_common_keypair;
    use namada_core::masp::AssetData;
    use namada_governance::storage::proposal::testing::{
        arb_init_proposal, arb_vote_proposal,
    };
    use namada_governance::{InitProposalData, VoteProposalData};
    use namada_ibc::testing::{arb_ibc_msg_nft_transfer, arb_ibc_msg_transfer};
    use namada_ibc::{MsgNftTransfer, MsgTransfer};
    use namada_token::testing::arb_denominated_amount;
    use namada_token::Transfer;
    use namada_tx::data::pgf::UpdateStewardCommission;
    use namada_tx::data::pos::{
        BecomeValidator, Bond, CommissionChange, ConsensusKeyChange,
        MetaDataChange, Redelegation, Unbond, Withdraw,
    };
    use namada_tx::data::{Fee, TxType, WrapperTx};
    use proptest::prelude::{Just, Strategy};
    use proptest::{arbitrary, collection, option, prop_compose, prop_oneof};
    use token::testing::arb_transparent_transfer;

    use super::*;
    use crate::account::tests::{arb_init_account, arb_update_account};
    use crate::chain::ChainId;
    use crate::eth_bridge_pool::testing::arb_pending_transfer;
    use crate::key::testing::arb_common_pk;
    use crate::masp::testing::arb_shielded_transfer;
    use crate::masp::ShieldedTransfer;
    use crate::time::{DateTime, DateTimeUtc, TimeZone, Utc};
    use crate::tx::data::pgf::tests::arb_update_steward_commission;
    use crate::tx::data::pos::tests::{
        arb_become_validator, arb_bond, arb_commission_change,
        arb_consensus_key_change, arb_metadata_change, arb_redelegation,
        arb_withdraw,
    };
    use crate::tx::{
        Authorization, Code, Commitment, Header, MaspBuilder, Section,
        TxCommitments,
    };

    #[derive(Debug, Clone, BorshDeserialize, BorshSchema, BorshSerialize)]
    #[borsh(crate = "::borsh")]
    #[allow(clippy::large_enum_variant)]
    #[allow(missing_docs)]
    /// To facilitate propagating debugging information
    pub enum TxData {
        CommissionChange(CommissionChange),
        ConsensusKeyChange(ConsensusKeyChange),
        MetaDataChange(MetaDataChange),
        ClaimRewards(Withdraw),
        DeactivateValidator(Address),
        InitAccount(InitAccount),
        InitProposal(InitProposalData),
        InitValidator(BecomeValidator),
        ReactivateValidator(Address),
        RevealPk(common::PublicKey),
        Unbond(Unbond),
        UnjailValidator(Address),
        UpdateAccount(UpdateAccount),
        VoteProposal(VoteProposalData),
        Withdraw(Withdraw),
        Transfer(Transfer, Option<(StoredBuildParams, String)>),
        Bond(Bond),
        Redelegation(Redelegation),
        UpdateStewardCommission(UpdateStewardCommission),
        ResignSteward(Address),
        PendingTransfer(PendingTransfer),
        IbcMsgTransfer(MsgTransfer, Option<(StoredBuildParams, String)>),
        IbcMsgNftTransfer(MsgNftTransfer, Option<(StoredBuildParams, String)>),
        Custom,
    }

    prop_compose! {
        /// Generate an arbitrary commitment
        pub fn arb_commitment()(
            commitment in prop_oneof![
                arb_hash().prop_map(Commitment::Hash),
                collection::vec(arbitrary::any::<u8>(), 0..=1024).prop_map(Commitment::Id),
            ],
        ) -> Commitment {
            commitment
        }
    }

    prop_compose! {
        /// Generate an arbitrary code section
        pub fn arb_code()(
            salt: [u8; 8],
            code in arb_commitment(),
            tag in option::of("[a-zA-Z0-9_]*"),
        ) -> Code {
            Code {
                salt,
                code,
                tag,
            }
        }
    }

    prop_compose! {
        /// Generate an arbitrary uttf8 commitment
        pub fn arb_utf8_commitment()(
            commitment in prop_oneof![
                arb_hash().prop_map(Commitment::Hash),
                "[a-zA-Z0-9_]{0,1024}".prop_map(|x| Commitment::Id(x.into_bytes())),
            ],
        ) -> Commitment {
            commitment
        }
    }

    prop_compose! {
        /// Generate an arbitrary code section
        pub fn arb_utf8_code()(
            salt: [u8; 8],
            code in arb_utf8_commitment(),
            tag in option::of("[a-zA-Z0-9_]{0,1024}"),
        ) -> Code {
            Code {
                salt,
                code,
                tag,
            }
        }
    }

    prop_compose! {
        /// Generate a chain ID
        pub fn arb_chain_id()(id in "[a-zA-Z0-9_]*") -> ChainId {
            ChainId(id)
        }
    }

    prop_compose! {
        /// Generate a date and time
        pub fn arb_date_time_utc()(
            secs in Utc.with_ymd_and_hms(0, 1, 1, 0, 0, 0).unwrap().timestamp()..=Utc.with_ymd_and_hms(9999, 12, 31, 23, 59, 59).unwrap().timestamp(),
            nsecs in ..1000000000u32,
        ) -> DateTimeUtc {
            DateTimeUtc(DateTime::<Utc>::from_timestamp(secs, nsecs).unwrap())
        }
    }

    prop_compose! {
        /// Generate an arbitrary fee
        pub fn arb_fee()(
            amount_per_gas_unit in arb_denominated_amount(),
            token in arb_established_address().prop_map(Address::Established),
        ) -> Fee {
            Fee {
                amount_per_gas_unit,
                token,
            }
        }
    }

    prop_compose! {
        /// Generate an arbitrary gas limit
        pub fn arb_gas_limit()(multiplier: u64) -> GasLimit {
            multiplier.into()
        }
    }

    prop_compose! {
        /// Generate an arbitrary wrapper transaction
        pub fn arb_wrapper_tx()(
            fee in arb_fee(),
            pk in arb_common_pk(),
            gas_limit in arb_gas_limit(),
        ) -> WrapperTx {
            WrapperTx {
                fee,
                pk,
                gas_limit,
            }
        }
    }

    prop_compose! {
        /// Generate an arbitrary transaction type
        pub fn arb_tx_type()(tx_type in prop_oneof![
            Just(TxType::Raw),
            arb_wrapper_tx().prop_map(|x| TxType::Wrapper(Box::new(x))),
        ]) -> TxType {
            tx_type
        }
    }

    prop_compose! {
        /// Generate an arbitrary header
        pub fn arb_header()(
            chain_id in arb_chain_id(),
            expiration in option::of(arb_date_time_utc()),
            timestamp in arb_date_time_utc(),
            code_hash in arb_hash(),
            data_hash in arb_hash(),
            memo_hash in arb_hash(),
            atomic in proptest::bool::ANY,
            tx_type in arb_tx_type(),
        ) -> Header {
            Header {
                chain_id,
                expiration,
                timestamp,
                //TODO: arbitrary number of commitments
                batch: [TxCommitments{
                    data_hash,
                    code_hash,
                    memo_hash,
                }].into(),
                atomic,
                tx_type,
            }
        }
    }

    // Maximum number of notes to include in a transaction
    const MAX_ASSETS: usize = 2;

    prop_compose! {
        /// Generate an arbitrary transfer
        pub fn arb_transfer()(
            arb in prop_oneof![
                arb_transparent_transfer(..5).prop_map(|xfer| (xfer, None)),
                arb_shielded_transfer(0..MAX_ASSETS)
                    .prop_map(|(w, x, y, z)| (w, Some((x, y, z))))
            ],
        ) -> (Transfer, Option<(ShieldedTransfer, HashMap<AssetData, u64>, StoredBuildParams)>) {
            arb
        }
    }

    prop_compose! {
        /// Generate an arbitrary masp transfer transaction
        pub fn arb_transfer_tx()(
            mut header in arb_header(),
            wrapper in arb_wrapper_tx(),
            code_hash in arb_hash(),
            (transfer, aux) in arb_transfer(),
        ) -> (Tx, TxData) {
            header.tx_type = TxType::Wrapper(Box::new(wrapper));
            let mut tx = Tx { header, sections: vec![] };
            tx.add_code_from_hash(code_hash, Some(TX_TRANSFER_WASM.to_owned()));
            tx.add_data(transfer.clone());
            if let Some((shielded_transfer, asset_types, build_params)) = aux {
                let shielded_section_hash =
                    tx.add_masp_tx_section(shielded_transfer.masp_tx).1;
                tx.add_masp_builder(MaspBuilder {
                    asset_types: asset_types.into_keys().collect(),
                    // Store how the Info objects map to Descriptors/Outputs
                    metadata: shielded_transfer.metadata,
                    // Store the data that was used to construct the Transaction
                    builder: shielded_transfer.builder,
                    // Link the Builder to the Transaction by hash code
                    target: shielded_section_hash,
                });
                let build_param_bytes =
                    data_encoding::HEXLOWER.encode(&build_params.serialize_to_vec());
                (tx, TxData::Transfer(transfer, Some((build_params, build_param_bytes))))
            } else {
                (tx, TxData::Transfer(transfer, None))
            }
        }
    }

    prop_compose! {
        /// Generate an arbitrary bond transaction
        pub fn arb_bond_tx()(
            mut header in arb_header(),
            wrapper in arb_wrapper_tx(),
            bond in arb_bond(),
            code_hash in arb_hash(),
        ) -> (Tx, TxData) {
            header.tx_type = TxType::Wrapper(Box::new(wrapper));
            let mut tx = Tx { header, sections: vec![] };
            tx.add_data(bond.clone());
            tx.add_code_from_hash(code_hash, Some(TX_BOND_WASM.to_owned()));
            (tx, TxData::Bond(bond))
        }
    }

    prop_compose! {
        /// Generate an arbitrary bond transaction
        pub fn arb_unbond_tx()(
            mut header in arb_header(),
            wrapper in arb_wrapper_tx(),
            unbond in arb_bond(),
            code_hash in arb_hash(),
        ) -> (Tx, TxData) {
            header.tx_type = TxType::Wrapper(Box::new(wrapper));
            let mut tx = Tx { header, sections: vec![] };
            tx.add_data(unbond.clone());
            tx.add_code_from_hash(code_hash, Some(TX_UNBOND_WASM.to_owned()));
            (tx, TxData::Unbond(unbond))
        }
    }

    prop_compose! {
        /// Generate an arbitrary account initialization transaction
        pub fn arb_init_account_tx()(
            mut header in arb_header(),
            wrapper in arb_wrapper_tx(),
            mut init_account in arb_init_account(),
            extra_data in arb_code(),
            code_hash in arb_hash(),
        ) -> (Tx, TxData) {
            header.tx_type = TxType::Wrapper(Box::new(wrapper));
            let mut tx = Tx { header, sections: vec![] };
            let vp_code_hash = tx.add_section(Section::ExtraData(extra_data)).get_hash();
            init_account.vp_code_hash = vp_code_hash;
            tx.add_data(init_account.clone());
            tx.add_code_from_hash(code_hash, Some(TX_INIT_ACCOUNT_WASM.to_owned()));
            (tx, TxData::InitAccount(init_account))
        }
    }

    prop_compose! {
        /// Generate an arbitrary account initialization transaction
        pub fn arb_become_validator_tx()(
            mut header in arb_header(),
            wrapper in arb_wrapper_tx(),
            become_validator in arb_become_validator(),
            code_hash in arb_hash(),
        ) -> (Tx, TxData) {
            header.tx_type = TxType::Wrapper(Box::new(wrapper));
            let mut tx = Tx { header, sections: vec![] };
            tx.add_data(become_validator.clone());
            tx.add_code_from_hash(code_hash, Some(TX_BECOME_VALIDATOR_WASM.to_owned()));
            (tx, TxData::InitValidator(become_validator))
        }
    }

    prop_compose! {
        /// Generate an arbitrary proposal initialization transaction
        pub fn arb_init_proposal_tx()(
            mut header in arb_header(),
            wrapper in arb_wrapper_tx(),
            mut init_proposal in arb_init_proposal(),
            content_extra_data in arb_code(),
            type_extra_data in arb_code(),
            code_hash in arb_hash(),
        ) -> (Tx, TxData) {
            header.tx_type = TxType::Wrapper(Box::new(wrapper));
            let mut tx = Tx { header, sections: vec![] };
            let content_hash = tx.add_section(Section::ExtraData(content_extra_data)).get_hash();
            init_proposal.content = content_hash;
            if let ProposalType::DefaultWithWasm(hash) = &mut init_proposal.r#type {
                let type_hash = tx.add_section(Section::ExtraData(type_extra_data)).get_hash();
                *hash = type_hash;
            }
            tx.add_data(init_proposal.clone());
            tx.add_code_from_hash(code_hash, Some(TX_INIT_PROPOSAL.to_owned()));
            (tx, TxData::InitProposal(init_proposal))
        }
    }

    prop_compose! {
        /// Generate an arbitrary transaction with maybe a memo
        pub fn arb_memoed_tx()(
            (mut tx, tx_data) in arb_tx(),
            memo in option::of(arb_utf8_code()),
        ) -> (Tx, TxData) {
            if let Some(memo) = memo {
                let sechash = tx
                    .add_section(Section::ExtraData(memo))
                    .get_hash();
                tx.set_memo_sechash(sechash);
            } else {
                tx.set_memo_sechash(Default::default());
            }
            (tx, tx_data)
        }
    }

    prop_compose! {
        /// Generate an arbitrary vote proposal transaction
        pub fn arb_vote_proposal_tx()(
            mut header in arb_header(),
            wrapper in arb_wrapper_tx(),
            vote_proposal in arb_vote_proposal(),
            code_hash in arb_hash(),
        ) -> (Tx, TxData) {
            header.tx_type = TxType::Wrapper(Box::new(wrapper));
            let mut tx = Tx { header, sections: vec![] };
            tx.add_data(vote_proposal.clone());
            tx.add_code_from_hash(code_hash, Some(TX_VOTE_PROPOSAL.to_owned()));
            (tx, TxData::VoteProposal(vote_proposal))
        }
    }

    prop_compose! {
        /// Generate an arbitrary reveal public key transaction
        pub fn arb_reveal_pk_tx()(
            mut header in arb_header(),
            wrapper in arb_wrapper_tx(),
            pk in arb_common_pk(),
            code_hash in arb_hash(),
        ) -> (Tx, TxData) {
            header.tx_type = TxType::Wrapper(Box::new(wrapper));
            let mut tx = Tx { header, sections: vec![] };
            tx.add_data(pk.clone());
            tx.add_code_from_hash(code_hash, Some(TX_REVEAL_PK.to_owned()));
            (tx, TxData::RevealPk(pk))
        }
    }

    prop_compose! {
        /// Generate an arbitrary account initialization transaction
        pub fn arb_update_account_tx()(
            mut header in arb_header(),
            wrapper in arb_wrapper_tx(),
            mut update_account in arb_update_account(),
            extra_data in arb_code(),
            code_hash in arb_hash(),
        ) -> (Tx, TxData) {
            header.tx_type = TxType::Wrapper(Box::new(wrapper));
            let mut tx = Tx { header, sections: vec![] };
            if let Some(vp_code_hash) = &mut update_account.vp_code_hash {
                let new_code_hash = tx.add_section(Section::ExtraData(extra_data)).get_hash();
                *vp_code_hash = new_code_hash;
            }
            tx.add_data(update_account.clone());
            tx.add_code_from_hash(code_hash, Some(TX_UPDATE_ACCOUNT_WASM.to_owned()));
            (tx, TxData::UpdateAccount(update_account))
        }
    }

    prop_compose! {
        /// Generate an arbitrary reveal public key transaction
        pub fn arb_withdraw_tx()(
            mut header in arb_header(),
            wrapper in arb_wrapper_tx(),
            withdraw in arb_withdraw(),
            code_hash in arb_hash(),
        ) -> (Tx, TxData) {
            header.tx_type = TxType::Wrapper(Box::new(wrapper));
            let mut tx = Tx { header, sections: vec![] };
            tx.add_data(withdraw.clone());
            tx.add_code_from_hash(code_hash, Some(TX_WITHDRAW_WASM.to_owned()));
            (tx, TxData::Withdraw(withdraw))
        }
    }

    prop_compose! {
        /// Generate an arbitrary claim rewards transaction
        pub fn arb_claim_rewards_tx()(
            mut header in arb_header(),
            wrapper in arb_wrapper_tx(),
            claim_rewards in arb_withdraw(),
            code_hash in arb_hash(),
        ) -> (Tx, TxData) {
            header.tx_type = TxType::Wrapper(Box::new(wrapper));
            let mut tx = Tx { header, sections: vec![] };
            tx.add_data(claim_rewards.clone());
            tx.add_code_from_hash(code_hash, Some(TX_CLAIM_REWARDS_WASM.to_owned()));
            (tx, TxData::ClaimRewards(claim_rewards))
        }
    }

    prop_compose! {
        /// Generate an arbitrary commission change transaction
        pub fn arb_commission_change_tx()(
            mut header in arb_header(),
            wrapper in arb_wrapper_tx(),
            commission_change in arb_commission_change(),
            code_hash in arb_hash(),
        ) -> (Tx, TxData) {
            header.tx_type = TxType::Wrapper(Box::new(wrapper));
            let mut tx = Tx { header, sections: vec![] };
            tx.add_data(commission_change.clone());
            tx.add_code_from_hash(code_hash, Some(TX_CHANGE_COMMISSION_WASM.to_owned()));
            (tx, TxData::CommissionChange(commission_change))
        }
    }

    prop_compose! {
        /// Generate an arbitrary commission change transaction
        pub fn arb_metadata_change_tx()(
            mut header in arb_header(),
            wrapper in arb_wrapper_tx(),
            metadata_change in arb_metadata_change(),
            code_hash in arb_hash(),
        ) -> (Tx, TxData) {
            header.tx_type = TxType::Wrapper(Box::new(wrapper));
            let mut tx = Tx { header, sections: vec![] };
            tx.add_data(metadata_change.clone());
            tx.add_code_from_hash(code_hash, Some(TX_CHANGE_METADATA_WASM.to_owned()));
            (tx, TxData::MetaDataChange(metadata_change))
        }
    }

    prop_compose! {
        /// Generate an arbitrary unjail validator transaction
        pub fn arb_unjail_validator_tx()(
            mut header in arb_header(),
            wrapper in arb_wrapper_tx(),
            address in arb_non_internal_address(),
            code_hash in arb_hash(),
        ) -> (Tx, TxData) {
            header.tx_type = TxType::Wrapper(Box::new(wrapper));
            let mut tx = Tx { header, sections: vec![] };
            tx.add_data(address.clone());
            tx.add_code_from_hash(code_hash, Some(TX_UNJAIL_VALIDATOR_WASM.to_owned()));
            (tx, TxData::UnjailValidator(address))
        }
    }

    prop_compose! {
        /// Generate an arbitrary deactivate validator transaction
        pub fn arb_deactivate_validator_tx()(
            mut header in arb_header(),
            wrapper in arb_wrapper_tx(),
            address in arb_non_internal_address(),
            code_hash in arb_hash(),
        ) -> (Tx, TxData) {
            header.tx_type = TxType::Wrapper(Box::new(wrapper));
            let mut tx = Tx { header, sections: vec![] };
            tx.add_data(address.clone());
            tx.add_code_from_hash(code_hash, Some(TX_DEACTIVATE_VALIDATOR_WASM.to_owned()));
            (tx, TxData::DeactivateValidator(address))
        }
    }

    prop_compose! {
        /// Generate an arbitrary reactivate validator transaction
        pub fn arb_reactivate_validator_tx()(
            mut header in arb_header(),
            wrapper in arb_wrapper_tx(),
            address in arb_non_internal_address(),
            code_hash in arb_hash(),
        ) -> (Tx, TxData) {
            header.tx_type = TxType::Wrapper(Box::new(wrapper));
            let mut tx = Tx { header, sections: vec![] };
            tx.add_data(address.clone());
            tx.add_code_from_hash(code_hash, Some(TX_REACTIVATE_VALIDATOR_WASM.to_owned()));
            (tx, TxData::ReactivateValidator(address))
        }
    }

    prop_compose! {
        /// Generate an arbitrary consensus key change transaction
        pub fn arb_consensus_key_change_tx()(
            mut header in arb_header(),
            wrapper in arb_wrapper_tx(),
            consensus_key_change in arb_consensus_key_change(),
            code_hash in arb_hash(),
        ) -> (Tx, TxData) {
            header.tx_type = TxType::Wrapper(Box::new(wrapper));
            let mut tx = Tx { header, sections: vec![] };
            tx.add_data(consensus_key_change.clone());
            tx.add_code_from_hash(code_hash, Some(TX_CHANGE_CONSENSUS_KEY_WASM.to_owned()));
            (tx, TxData::ConsensusKeyChange(consensus_key_change))
        }
    }

    prop_compose! {
        /// Generate an arbitrary redelegation transaction
        pub fn arb_redelegation_tx()(
            mut header in arb_header(),
            wrapper in arb_wrapper_tx(),
            redelegation in arb_redelegation(),
            code_hash in arb_hash(),
        ) -> (Tx, TxData) {
            header.tx_type = TxType::Wrapper(Box::new(wrapper));
            let mut tx = Tx { header, sections: vec![] };
            tx.add_data(redelegation.clone());
            tx.add_code_from_hash(code_hash, Some(TX_REDELEGATE_WASM.to_owned()));
            (tx, TxData::Redelegation(redelegation))
        }
    }

    prop_compose! {
        /// Generate an arbitrary redelegation transaction
        pub fn arb_update_steward_commission_tx()(
            mut header in arb_header(),
            wrapper in arb_wrapper_tx(),
            update_steward_commission in arb_update_steward_commission(),
            code_hash in arb_hash(),
        ) -> (Tx, TxData) {
            header.tx_type = TxType::Wrapper(Box::new(wrapper));
            let mut tx = Tx { header, sections: vec![] };
            tx.add_data(update_steward_commission.clone());
            tx.add_code_from_hash(code_hash, Some(TX_UPDATE_STEWARD_COMMISSION.to_owned()));
            (tx, TxData::UpdateStewardCommission(update_steward_commission))
        }
    }

    prop_compose! {
        /// Generate an arbitrary redelegation transaction
        pub fn arb_resign_steward_tx()(
            mut header in arb_header(),
            wrapper in arb_wrapper_tx(),
            steward in arb_non_internal_address(),
            code_hash in arb_hash(),
        ) -> (Tx, TxData) {
            header.tx_type = TxType::Wrapper(Box::new(wrapper));
            let mut tx = Tx { header, sections: vec![] };
            tx.add_data(steward.clone());
            tx.add_code_from_hash(code_hash, Some(TX_RESIGN_STEWARD.to_owned()));
            (tx, TxData::ResignSteward(steward))
        }
    }

    prop_compose! {
        /// Generate an arbitrary pending transfer transaction
        pub fn arb_pending_transfer_tx()(
            mut header in arb_header(),
            wrapper in arb_wrapper_tx(),
            pending_transfer in arb_pending_transfer(),
            code_hash in arb_hash(),
        ) -> (Tx, TxData) {
            header.tx_type = TxType::Wrapper(Box::new(wrapper));
            let mut tx = Tx { header, sections: vec![] };
            tx.add_data(pending_transfer.clone());
            tx.add_code_from_hash(code_hash, Some(TX_BRIDGE_POOL_WASM.to_owned()));
            (tx, TxData::PendingTransfer(pending_transfer))
        }
    }

    prop_compose! {
        /// Generate an arbitrary IBC transfer message
        pub fn arb_msg_transfer()(
            message in arb_ibc_msg_transfer(),
            transfer_aux in option::of(arb_transfer()),
        ) -> (MsgTransfer, Option<(ShieldedTransfer, HashMap<AssetData, u64>, StoredBuildParams)>) {
            if let Some((transfer, aux)) = transfer_aux {
                (MsgTransfer { message, transfer: Some(transfer) }, aux)
            } else {
                (MsgTransfer { message, transfer: None }, None)
            }
        }
    }

    prop_compose! {
        /// Generate an arbitrary IBC any transaction
        pub fn arb_ibc_msg_transfer_tx()(
            mut header in arb_header(),
            wrapper in arb_wrapper_tx(),
            (msg_transfer, aux) in arb_msg_transfer(),
            code_hash in arb_hash(),
        ) -> (Tx, TxData) {
            header.tx_type = TxType::Wrapper(Box::new(wrapper));
            let mut tx = Tx { header, sections: vec![] };
            tx.add_serialized_data(msg_transfer.serialize_to_vec());
            tx.add_code_from_hash(code_hash, Some(TX_IBC_WASM.to_owned()));
            if let Some((shielded_transfer, asset_types, build_params)) = aux {
                let shielded_section_hash =
                    tx.add_masp_tx_section(shielded_transfer.masp_tx).1;
                tx.add_masp_builder(MaspBuilder {
                    asset_types: asset_types.into_keys().collect(),
                    // Store how the Info objects map to Descriptors/Outputs
                    metadata: shielded_transfer.metadata,
                    // Store the data that was used to construct the Transaction
                    builder: shielded_transfer.builder,
                    // Link the Builder to the Transaction by hash code
                    target: shielded_section_hash,
                });
                let build_param_bytes =
                    data_encoding::HEXLOWER.encode(&build_params.serialize_to_vec());
                (tx, TxData::IbcMsgTransfer(msg_transfer, Some((build_params, build_param_bytes))))
            } else {
                (tx, TxData::IbcMsgTransfer(msg_transfer, None))
            }
        }
    }

    prop_compose! {
        /// Generate an arbitrary IBC NFT transfer message
        pub fn arb_msg_nft_transfer()(
            message in arb_ibc_msg_nft_transfer(),
            transfer_aux in option::of(arb_transfer()),
        ) -> (MsgNftTransfer, Option<(ShieldedTransfer, HashMap<AssetData, u64>, StoredBuildParams)>) {
            if let Some((transfer, aux)) = transfer_aux {
                (MsgNftTransfer { message, transfer: Some(transfer) }, aux)
            } else {
                (MsgNftTransfer { message, transfer: None }, None)
            }
        }
    }

    prop_compose! {
        /// Generate an arbitrary IBC any transaction
        pub fn arb_ibc_msg_nft_transfer_tx()(
            mut header in arb_header(),
            wrapper in arb_wrapper_tx(),
            (msg_transfer, aux) in arb_msg_nft_transfer(),
            code_hash in arb_hash(),
        ) -> (Tx, TxData) {
            header.tx_type = TxType::Wrapper(Box::new(wrapper));
            let mut tx = Tx { header, sections: vec![] };
            tx.add_serialized_data(msg_transfer.serialize_to_vec());
            tx.add_code_from_hash(code_hash, Some(TX_IBC_WASM.to_owned()));
            if let Some((shielded_transfer, asset_types, build_params)) = aux {
                let shielded_section_hash =
                    tx.add_masp_tx_section(shielded_transfer.masp_tx).1;
                tx.add_masp_builder(MaspBuilder {
                    asset_types: asset_types.into_keys().collect(),
                    // Store how the Info objects map to Descriptors/Outputs
                    metadata: shielded_transfer.metadata,
                    // Store the data that was used to construct the Transaction
                    builder: shielded_transfer.builder,
                    // Link the Builder to the Transaction by hash code
                    target: shielded_section_hash,
                });
                let build_param_bytes =
                    data_encoding::HEXLOWER.encode(&build_params.serialize_to_vec());
                (tx, TxData::IbcMsgNftTransfer(msg_transfer, Some((build_params, build_param_bytes))))
            } else {
                (tx, TxData::IbcMsgNftTransfer(msg_transfer, None))
            }
        }
    }

    /// Generate an arbitrary tx
    pub fn arb_tx() -> impl Strategy<Value = (Tx, TxData)> {
        prop_oneof![
            arb_transfer_tx(),
            arb_bond_tx(),
            arb_unbond_tx(),
            arb_init_account_tx(),
            arb_become_validator_tx(),
            arb_init_proposal_tx(),
            arb_vote_proposal_tx(),
            arb_reveal_pk_tx(),
            arb_update_account_tx(),
            arb_withdraw_tx(),
            arb_claim_rewards_tx(),
            arb_commission_change_tx(),
            arb_metadata_change_tx(),
            arb_unjail_validator_tx(),
            arb_deactivate_validator_tx(),
            arb_reactivate_validator_tx(),
            arb_consensus_key_change_tx(),
            arb_redelegation_tx(),
            arb_update_steward_commission_tx(),
            arb_resign_steward_tx(),
            arb_pending_transfer_tx(),
            arb_ibc_msg_transfer_tx(),
            arb_ibc_msg_nft_transfer_tx(),
        ]
    }

    prop_compose! {
        /// Generate an arbitrary signature section
        pub fn arb_signature(targets: Vec<namada_core::hash::Hash>)(
            targets in Just(targets),
            secret_keys in collection::btree_map(
                arbitrary::any::<u8>(),
                arb_common_keypair(),
                1..3,
            ),
            signer in option::of(arb_non_internal_address()),
        ) -> Authorization {
            if signer.is_some() {
                Authorization::new(targets, secret_keys, signer)
            } else {
                let secret_keys = secret_keys
                    .into_values()
                    .enumerate()
                    .map(|(k, v)| (k as u8, v))
                    .collect();
                Authorization::new(targets, secret_keys, signer)
            }
        }
    }

    prop_compose! {
        /// Generate an arbitrary signed tx
        pub fn arb_signed_tx()(tx in arb_memoed_tx())(
            sigs in collection::vec(arb_signature(tx.0.sechashes()), 0..3),
            mut tx in Just(tx),
        ) -> (Tx, TxData) {
            for sig in sigs {
                // Add all the generated signature sections
                tx.0.add_section(Section::Authorization(sig));
            }
            (tx.0, tx.1)
        }
    }
}
