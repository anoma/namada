extern crate alloc;

pub use namada_core::{ibc, proto, tendermint, tendermint_proto};
#[cfg(feature = "tendermint-rpc")]
pub use tendermint_rpc;
pub use {
    bip39, borsh, masp_primitives, masp_proofs, namada_core as core,
    namada_proof_of_stake as proof_of_stake, zeroize,
};

pub mod eth_bridge;

pub mod rpc;

pub mod args;
pub mod masp;
pub mod signing;
#[allow(clippy::result_large_err)]
pub mod tx;

pub mod control_flow;
pub mod error;
pub mod events;
pub(crate) mod internal_macros;
pub mod io;
pub mod queries;
pub mod wallet;

use std::collections::HashSet;
#[cfg(feature = "async-send")]
pub use std::marker::Send as MaybeSend;
#[cfg(feature = "async-send")]
pub use std::marker::Sync as MaybeSync;
use std::path::PathBuf;
use std::str::FromStr;

use args::{InputAmount, SdkTypes};
use namada_core::ibc::core::host::types::identifiers::{ChannelId, PortId};
use namada_core::types::address::Address;
use namada_core::types::dec::Dec;
use namada_core::types::ethereum_events::EthAddress;
use namada_core::types::key::*;
use namada_core::types::masp::{TransferSource, TransferTarget};
use namada_core::types::token;
use namada_core::types::token::NATIVE_MAX_DECIMAL_PLACES;
use namada_core::types::transaction::GasLimit;
use tokio::sync::{RwLock, RwLockReadGuard, RwLockWriteGuard};

use crate::io::Io;
use crate::masp::{ShieldedContext, ShieldedUtils};
use crate::proto::Tx;
use crate::rpc::{
    denominate_amount, format_denominated_amount, query_native_token,
};
use crate::signing::SigningTxData;
use crate::token::DenominatedAmount;
use crate::tx::{
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
use crate::wallet::{Wallet, WalletIo, WalletStorage};

#[cfg(not(feature = "async-send"))]
pub trait MaybeSync {}
#[cfg(not(feature = "async-send"))]
impl<T> MaybeSync for T where T: ?Sized {}
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
    async fn wallet(&self) -> RwLockReadGuard<Wallet<Self::WalletUtils>>;

    /// Obtain write guard on the wallet
    async fn wallet_mut(&self) -> RwLockWriteGuard<Wallet<Self::WalletUtils>>;

    /// Obtain the wallet lock
    fn wallet_lock(&self) -> &RwLock<Wallet<Self::WalletUtils>>;

    /// Obtain read guard on the shielded context
    async fn shielded(
        &self,
    ) -> RwLockReadGuard<ShieldedContext<Self::ShieldedUtils>>;

    /// Obtain write guard on the shielded context
    async fn shielded_mut(
        &self,
    ) -> RwLockWriteGuard<ShieldedContext<Self::ShieldedUtils>>;

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
            ledger_address: (),
            initialized_account_alias: None,
            wallet_alias_force: false,
            fee_amount: None,
            wrapper_fee_payer: None,
            fee_token: self.native_token(),
            fee_unshield: None,
            gas_limit: GasLimit::from(20_000),
            expiration: None,
            disposable_signing_key: false,
            chain_id: None,
            signing_keys: vec![],
            signatures: vec![],
            tx_reveal_code_path: PathBuf::from(TX_REVEAL_PK),
            password: None,
            use_device: false,
        }
    }

    /// Make a TxTransfer builder from the given minimum set of arguments
    fn new_transfer(
        &self,
        source: TransferSource,
        target: TransferTarget,
        token: Address,
        amount: InputAmount,
    ) -> args::TxTransfer {
        args::TxTransfer {
            source,
            target,
            token,
            amount,
            tx_code_path: PathBuf::from(TX_TRANSFER_WASM),
            tx: self.tx_builder(),
            native_token: self.native_token(),
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
            native_token: self.native_token(),
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

    // Make a Redelegation builder for the given minimum set of arguments
    fn new_redelegation(
        &self,
        source: Address,
        src_validator: Address,
        dest_validator: Address,
        amount: token::Amount,
    ) -> args::Redelegate {
        args::Redelegate {
            tx: self.tx_builder(),
            /// Source validator address
            src_validator,
            /// Destination validator address
            dest_validator,
            /// Owner of the bonds that are being redelegated
            owner: source,
            /// The amount of tokens to redelegate
            amount,
            /// Path to the TX WASM code file
            tx_code_path: PathBuf::from(TX_REDELEGATE_WASM),
        }
    }

    /// Make a TxIbcTransfer builder from the given minimum set of arguments
    fn new_ibc_transfer(
        &self,
        source: Address,
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
            memo: None,
            tx: self.tx_builder(),
            tx_code_path: PathBuf::from(TX_IBC_WASM),
        }
    }

    /// Make a InitProposal builder from the given minimum set of arguments
    fn new_init_proposal(&self, proposal_data: Vec<u8>) -> args::InitProposal {
        args::InitProposal {
            proposal_data,
            native_token: self.native_token(),
            is_offline: false,
            is_pgf_stewards: false,
            is_pgf_funding: false,
            tx_code_path: PathBuf::from(TX_INIT_PROPOSAL),
            tx: self.tx_builder(),
        }
    }

    /// Make a TxUpdateAccount builder from the given minimum set of arguments
    fn new_update_account(&self, addr: Address) -> args::TxUpdateAccount {
        args::TxUpdateAccount {
            addr,
            vp_code_path: None,
            public_keys: vec![],
            threshold: None,
            tx_code_path: PathBuf::from(TX_UPDATE_ACCOUNT_WASM),
            tx: self.tx_builder(),
        }
    }

    /// Make a VoteProposal builder from the given minimum set of arguments
    fn new_vote_prposal(
        &self,
        vote: String,
        voter: Address,
    ) -> args::VoteProposal {
        args::VoteProposal {
            vote,
            voter,
            proposal_id: None,
            is_offline: false,
            proposal_data: None,
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
    ) -> args::ConsensusKeyChange {
        args::ConsensusKeyChange {
            validator,
            consensus_key: None,
            tx_code_path: PathBuf::from(TX_CHANGE_CONSENSUS_KEY_WASM),
            unsafe_dont_encrypt: false,
            tx: self.tx_builder(),
        }
    }

    /// Make a CommissionRateChange builder from the given minimum set of
    /// arguments
    #[allow(clippy::too_many_arguments)]
    fn new_change_metadata(
        &self,
        validator: Address,
        email: Option<String>,
        description: Option<String>,
        website: Option<String>,
        discord_handle: Option<String>,
        commission_rate: Option<Dec>,
    ) -> args::MetaDataChange {
        args::MetaDataChange {
            validator,
            email,
            description,
            website,
            discord_handle,
            commission_rate,
            tx_code_path: PathBuf::from(TX_CHANGE_METADATA_WASM),
            tx: self.tx_builder(),
        }
    }

    /// Make a TxBecomeValidator builder from the given minimum set of arguments
    fn new_become_validator(
        &self,
        address: Address,
        commission_rate: Dec,
        max_commission_rate_change: Dec,
        email: String,
    ) -> args::TxBecomeValidator {
        args::TxBecomeValidator {
            address,
            commission_rate,
            max_commission_rate_change,
            scheme: SchemeType::Ed25519,
            consensus_key: None,
            eth_cold_key: None,
            eth_hot_key: None,
            protocol_key: None,
            unsafe_dont_encrypt: false,
            tx_code_path: PathBuf::from(TX_BECOME_VALIDATOR_WASM),
            tx: self.tx_builder(),
            email,
            description: None,
            website: None,
            discord_handle: None,
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
            fee_amount: InputAmount::Unvalidated(token::DenominatedAmount {
                amount: token::Amount::default(),
                denom: NATIVE_MAX_DECIMAL_PLACES.into(),
            }),
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
        with: impl Fn(Tx, common::PublicKey, HashSet<signing::Signable>, D) -> F,
        user_data: D,
    ) -> crate::error::Result<()>
    where
        D: Clone,
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
                ledger_address: (),
                initialized_account_alias: None,
                wallet_alias_force: false,
                fee_amount: None,
                wrapper_fee_payer: None,
                fee_token: native_token,
                fee_unshield: None,
                gas_limit: GasLimit::from(20_000),
                expiration: None,
                disposable_signing_key: false,
                chain_id: None,
                signing_keys: vec![],
                signatures: vec![],
                tx_reveal_code_path: PathBuf::from(TX_REVEAL_PK),
                password: None,
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

    async fn wallet(&self) -> RwLockReadGuard<Wallet<Self::WalletUtils>> {
        self.wallet.read().await
    }

    async fn wallet_mut(&self) -> RwLockWriteGuard<Wallet<Self::WalletUtils>> {
        self.wallet.write().await
    }

    async fn shielded(
        &self,
    ) -> RwLockReadGuard<ShieldedContext<Self::ShieldedUtils>> {
        self.shielded.read().await
    }

    async fn shielded_mut(
        &self,
    ) -> RwLockWriteGuard<ShieldedContext<Self::ShieldedUtils>> {
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
