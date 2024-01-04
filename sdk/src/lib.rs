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
use namada_core::types::transaction::GasLimit;
use tokio::sync::{RwLock, RwLockReadGuard, RwLockWriteGuard};

use crate::io::Io;
use crate::masp::{ShieldedContext, ShieldedUtils};
use crate::proto::Tx;
use crate::rpc::{
    denominate_amount, format_denominated_amount, query_native_token,
};
use crate::signing::SigningTxData;
use crate::token::{DenominatedAmount, NATIVE_MAX_DECIMAL_PLACES};
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
            memo: None,
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

#[cfg(any(test, feature = "testing"))]
/// Tests and strategies for transactions
pub mod testing {
    use ibc::primitives::proto::Any;
    use namada_core::ledger::governance::storage::proposal::ProposalType;
    use namada_core::ledger::ibc::testing::arb_ibc_any;
    use namada_core::types::address::testing::{
        arb_established_address, arb_non_internal_address,
    };
    use namada_core::types::eth_bridge_pool::PendingTransfer;
    use namada_core::types::hash::testing::arb_hash;
    use namada_core::types::storage::testing::arb_epoch;
    use namada_core::types::token::testing::{
        arb_denominated_amount, arb_transfer,
    };
    use namada_core::types::token::Transfer;
    use namada_core::types::transaction::account::{
        InitAccount, UpdateAccount,
    };
    use namada_core::types::transaction::governance::{
        InitProposalData, VoteProposalData,
    };
    use namada_core::types::transaction::pgf::UpdateStewardCommission;
    use namada_core::types::transaction::pos::{
        BecomeValidator, Bond, CommissionChange, ConsensusKeyChange,
        MetaDataChange, Redelegation, Unbond, Withdraw,
    };
    use proptest::prelude::{Just, Strategy};
    use proptest::{option, prop_compose};
    use prost::Message;

    use super::*;
    use crate::core::types::chain::ChainId;
    use crate::core::types::eth_bridge_pool::testing::arb_pending_transfer;
    use crate::core::types::key::testing::arb_common_pk;
    use crate::core::types::time::{DateTime, DateTimeUtc, Utc};
    use crate::core::types::transaction::account::tests::{
        arb_init_account, arb_update_account,
    };
    use crate::core::types::transaction::governance::tests::{
        arb_init_proposal, arb_vote_proposal,
    };
    use crate::core::types::transaction::pgf::tests::arb_update_steward_commission;
    use crate::core::types::transaction::pos::tests::{
        arb_become_validator, arb_bond, arb_commission_change,
        arb_consensus_key_change, arb_metadata_change, arb_redelegation,
        arb_withdraw,
    };
    use crate::core::types::transaction::{
        DecryptedTx, Fee, TxType, WrapperTx,
    };
    use crate::proto::{Code, Commitment, Header, Section};

    #[derive(Debug)]
    #[allow(clippy::large_enum_variant)]
    // To facilitate propagating debugging information
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
        Transfer(Transfer),
        Bond(Bond),
        Redelegation(Redelegation),
        UpdateStewardCommission(UpdateStewardCommission),
        ResignSteward(Address),
        PendingTransfer(PendingTransfer),
        IbcAny(Any),
        Custom(Box<dyn std::fmt::Debug>),
    }

    prop_compose! {
        // Generate an arbitrary commitment
        pub fn arb_commitment()(
            hash in arb_hash(),
        ) -> Commitment {
            Commitment::Hash(hash)
        }
    }

    prop_compose! {
        // Generate an arbitrary code section
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
        // Generate a chain ID
        pub fn arb_chain_id()(id in "[a-zA-Z0-9_]*") -> ChainId {
            ChainId(id)
        }
    }

    prop_compose! {
        // Generate a date and time
        pub fn arb_date_time_utc()(
            secs in DateTime::<Utc>::MIN_UTC.timestamp()..=DateTime::<Utc>::MAX_UTC.timestamp(),
            nsecs in ..1000000000u32,
        ) -> DateTimeUtc {
            DateTimeUtc(DateTime::<Utc>::from_timestamp(secs, nsecs).unwrap())
        }
    }

    prop_compose! {
        // Generate an arbitrary fee
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
        // Generate an arbitrary gas limit
        pub fn arb_gas_limit()(multiplier: u64) -> GasLimit {
            multiplier.into()
        }
    }

    prop_compose! {
        // Generate an arbitrary wrapper transaction
        pub fn arb_wrapper_tx()(
            fee in arb_fee(),
            epoch in arb_epoch(),
            pk in arb_common_pk(),
            gas_limit in arb_gas_limit(),
            unshield_section_hash in option::of(arb_hash()),
        ) -> WrapperTx {
            WrapperTx {
                fee,
                epoch,
                pk,
                gas_limit,
                unshield_section_hash,
            }
        }
    }

    prop_compose! {
        // Generate an arbitrary decrypted transaction
        pub fn arb_decrypted_tx()(discriminant in 0..2) -> DecryptedTx {
            match discriminant {
                0 => DecryptedTx::Decrypted,
                1 => DecryptedTx::Undecryptable,
                _ => unreachable!(),
            }
        }
    }

    // Generate an arbitrary transaction type
    pub fn arb_tx_type() -> impl Strategy<Value = TxType> {
        let raw_tx = Just(TxType::Raw).boxed();
        let decrypted_tx =
            arb_decrypted_tx().prop_map(TxType::Decrypted).boxed();
        let wrapper_tx = arb_wrapper_tx()
            .prop_map(|x| TxType::Wrapper(Box::new(x)))
            .boxed();
        raw_tx.prop_union(decrypted_tx).or(wrapper_tx)
    }

    prop_compose! {
        // Generate an arbitrary header
        pub fn arb_header()(
            chain_id in arb_chain_id(),
            expiration in option::of(arb_date_time_utc()),
            timestamp in arb_date_time_utc(),
            code_hash in arb_hash(),
            data_hash in arb_hash(),
            memo_hash in arb_hash(),
            tx_type in arb_tx_type(),
        ) -> Header {
            Header {
                chain_id,
                expiration,
                timestamp,
                data_hash,
                code_hash,
                memo_hash,
                tx_type,
            }
        }
    }

    prop_compose! {
        // Generate an arbitrary transfer transaction
        pub fn arb_transfer_tx()(
            mut header in arb_header(),
            wrapper in arb_wrapper_tx(),
            transfer in arb_transfer(),
            code_hash in arb_hash(),
        ) -> (Tx, TxData) {
            header.tx_type = TxType::Wrapper(Box::new(wrapper));
            let mut tx = Tx { header, sections: vec![] };
            tx.add_data(transfer.clone());
            tx.add_code_from_hash(code_hash, Some(TX_TRANSFER_WASM.to_owned()));
            (tx, TxData::Transfer(transfer))
        }
    }

    prop_compose! {
        // Generate an arbitrary bond transaction
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
        // Generate an arbitrary bond transaction
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
        // Generate an arbitrary account initialization transaction
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
        // Generate an arbitrary account initialization transaction
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
        // Generate an arbitrary proposal initialization transaction
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
            if let ProposalType::Default(Some(hash)) = &mut init_proposal.r#type {
                let type_hash = tx.add_section(Section::ExtraData(type_extra_data)).get_hash();
                *hash = type_hash;
            }
            tx.add_data(init_proposal.clone());
            tx.add_code_from_hash(code_hash, Some(TX_INIT_PROPOSAL.to_owned()));
            (tx, TxData::InitProposal(init_proposal))
        }
    }

    prop_compose! {
        // Generate an arbitrary vote proposal transaction
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
        // Generate an arbitrary reveal public key transaction
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
        // Generate an arbitrary account initialization transaction
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
        // Generate an arbitrary reveal public key transaction
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
        // Generate an arbitrary claim rewards transaction
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
        // Generate an arbitrary commission change transaction
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
        // Generate an arbitrary commission change transaction
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
        // Generate an arbitrary unjail validator transaction
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
        // Generate an arbitrary deactivate validator transaction
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
        // Generate an arbitrary reactivate validator transaction
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
        // Generate an arbitrary consensus key change transaction
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
        // Generate an arbitrary redelegation transaction
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
        // Generate an arbitrary redelegation transaction
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
        // Generate an arbitrary redelegation transaction
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
        // Generate an arbitrary pending transfer transaction
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
        // Generate an arbitrary IBC any transaction
        pub fn arb_ibc_any_tx()(
            mut header in arb_header(),
            wrapper in arb_wrapper_tx(),
            ibc_any in arb_ibc_any(),
            code_hash in arb_hash(),
        ) -> (Tx, TxData) {
            header.tx_type = TxType::Wrapper(Box::new(wrapper));
            let mut tx = Tx { header, sections: vec![] };
            let mut tx_data = vec![];
            ibc_any.encode(&mut tx_data).expect("unable to encode IBC data");
            tx.add_serialized_data(tx_data);
            tx.add_code_from_hash(code_hash, Some(TX_IBC_WASM.to_owned()));
            (tx, TxData::IbcAny(ibc_any))
        }
    }

    // Generate an arbitrary tx
    pub fn arb_tx() -> impl Strategy<Value = (Tx, TxData)> {
        arb_transfer_tx()
            .boxed()
            .prop_union(arb_bond_tx().boxed())
            .or(arb_unbond_tx().boxed())
            .or(arb_init_account_tx().boxed())
            .or(arb_become_validator_tx().boxed())
            .or(arb_init_proposal_tx().boxed())
            .or(arb_vote_proposal_tx().boxed())
            .or(arb_reveal_pk_tx().boxed())
            .or(arb_update_account_tx().boxed())
            .or(arb_withdraw_tx().boxed())
            .or(arb_claim_rewards_tx().boxed())
            .or(arb_commission_change_tx().boxed())
            .or(arb_metadata_change_tx().boxed())
            .or(arb_unjail_validator_tx().boxed())
            .or(arb_deactivate_validator_tx().boxed())
            .or(arb_reactivate_validator_tx().boxed())
            .or(arb_consensus_key_change_tx().boxed())
            .or(arb_redelegation_tx().boxed())
            .or(arb_update_steward_commission_tx().boxed())
            .or(arb_resign_steward_tx().boxed())
            .or(arb_pending_transfer_tx().boxed())
            .or(arb_ibc_any_tx().boxed())
    }
}
