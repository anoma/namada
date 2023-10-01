//! The ledger modules

pub mod args;
pub mod eth_bridge;
pub mod events;
pub mod governance;
pub mod ibc;
pub mod inflation;
pub mod masp;
pub mod native_vp;
pub mod pgf;
pub mod pos;
#[cfg(all(feature = "wasm-runtime", feature = "ferveo-tpke"))]
pub mod protocol;
pub mod queries;
pub mod rpc;
pub mod signing;
pub mod storage;
#[allow(clippy::result_large_err)]
pub mod tx;
pub mod vp_host_fns;
pub mod wallet;

use std::path::PathBuf;
use std::str::FromStr;
use std::sync::Arc;

use masp::{ShieldedContext, ShieldedUtils};
pub use namada_core::ledger::{
    gas, parameters, replay_protection, storage_api, tx_env, vp_env,
};
use namada_core::types::dec::Dec;
use namada_core::types::ethereum_events::EthAddress;
use tokio::sync::{RwLock, RwLockReadGuard, RwLockWriteGuard};
use wallet::{Wallet, WalletIo, WalletStorage};

use crate::ibc::core::ics24_host::identifier::{ChannelId, PortId};
use crate::ledger::args::{InputAmount, SdkTypes};
use crate::ledger::signing::SigningTxData;
use crate::ledger::tx::{
    ProcessTxResponse, TX_BOND_WASM, TX_BRIDGE_POOL_WASM,
    TX_CHANGE_COMMISSION_WASM, TX_IBC_WASM, TX_INIT_PROPOSAL,
    TX_INIT_VALIDATOR_WASM, TX_RESIGN_STEWARD, TX_REVEAL_PK, TX_TRANSFER_WASM,
    TX_UNBOND_WASM, TX_UNJAIL_VALIDATOR_WASM, TX_UPDATE_ACCOUNT_WASM,
    TX_UPDATE_STEWARD_COMMISSION, TX_VOTE_PROPOSAL, TX_WITHDRAW_WASM,
    VP_USER_WASM,
};
use crate::proto::Tx;
use crate::types::address::Address;
use crate::types::key::*;
use crate::types::masp::{TransferSource, TransferTarget};
use crate::types::token;
use crate::types::token::NATIVE_MAX_DECIMAL_PLACES;
use crate::types::transaction::GasLimit;

#[async_trait::async_trait(?Send)]
/// An interface for high-level interaction with the Namada SDK
pub trait Namada<'a> {
    /// A client with async request dispatcher method
    type Client: 'a + crate::ledger::queries::Client + Sync;
    /// Captures the interactive parts of the wallet's functioning
    type WalletUtils: 'a + WalletIo + WalletStorage;
    /// Abstracts platform specific details away from the logic of shielded pool
    /// operations.
    type ShieldedUtils: 'a + ShieldedUtils;

    /// Obtain the client for communicating with the ledger
    fn client(&self) -> &'a Self::Client;

    /// Obtain read lock on the wallet
    async fn wallet(
        &self,
    ) -> RwLockReadGuard<&'a mut Wallet<Self::WalletUtils>>;

    /// Obtain write lock on the wallet
    async fn wallet_mut(
        &self,
    ) -> RwLockWriteGuard<&'a mut Wallet<Self::WalletUtils>>;

    /// Obtain read lock on the shielded context
    async fn shielded(
        &self,
    ) -> RwLockReadGuard<&'a mut ShieldedContext<Self::ShieldedUtils>>;

    /// Obtain write lock on the shielded context
    async fn shielded_mut(
        &self,
    ) -> RwLockWriteGuard<&'a mut ShieldedContext<Self::ShieldedUtils>>;

    /// Return the native token
    async fn native_token(&self) -> Address {
        self.wallet()
            .await
            .find_address(args::NAM)
            .expect("NAM not in wallet")
            .clone()
    }

    /// Make a tx builder using no arguments
    async fn tx_builder(&self) -> args::Tx {
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
            fee_token: self.native_token().await,
            fee_unshield: None,
            gas_limit: GasLimit::from(20_000),
            expiration: None,
            disposable_signing_key: false,
            chain_id: None,
            signing_keys: vec![],
            signatures: vec![],
            tx_reveal_code_path: PathBuf::from(TX_REVEAL_PK),
            verification_key: None,
            password: None,
        }
    }

    /// Make a TxTransfer builder from the given minimum set of arguments
    async fn new_transfer(
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
            tx: self.tx_builder().await,
            native_token: self.native_token().await,
        }
    }

    /// Make a RevealPK builder from the given minimum set of arguments
    async fn new_reveal_pk(
        &self,
        public_key: common::PublicKey,
    ) -> args::RevealPk {
        args::RevealPk {
            public_key,
            tx: self.tx_builder().await,
        }
    }

    /// Make a Bond builder from the given minimum set of arguments
    async fn new_bond(
        &self,
        validator: Address,
        amount: token::Amount,
    ) -> args::Bond {
        args::Bond {
            validator,
            amount,
            source: None,
            tx: self.tx_builder().await,
            native_token: self.native_token().await,
            tx_code_path: PathBuf::from(TX_BOND_WASM),
        }
    }

    /// Make a Unbond builder from the given minimum set of arguments
    async fn new_unbond(
        &self,
        validator: Address,
        amount: token::Amount,
    ) -> args::Unbond {
        args::Unbond {
            validator,
            amount,
            source: None,
            tx: self.tx_builder().await,
            tx_code_path: PathBuf::from(TX_UNBOND_WASM),
        }
    }

    /// Make a TxIbcTransfer builder from the given minimum set of arguments
    async fn new_ibc_transfer(
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
            tx: self.tx_builder().await,
            tx_code_path: PathBuf::from(TX_IBC_WASM),
        }
    }

    /// Make a InitProposal builder from the given minimum set of arguments
    async fn new_init_proposal(
        &self,
        proposal_data: Vec<u8>,
    ) -> args::InitProposal {
        args::InitProposal {
            proposal_data,
            native_token: self.native_token().await,
            is_offline: false,
            is_pgf_stewards: false,
            is_pgf_funding: false,
            tx_code_path: PathBuf::from(TX_INIT_PROPOSAL),
            tx: self.tx_builder().await,
        }
    }

    /// Make a TxUpdateAccount builder from the given minimum set of arguments
    async fn new_update_account(&self, addr: Address) -> args::TxUpdateAccount {
        args::TxUpdateAccount {
            addr,
            vp_code_path: None,
            public_keys: vec![],
            threshold: None,
            tx_code_path: PathBuf::from(TX_UPDATE_ACCOUNT_WASM),
            tx: self.tx_builder().await,
        }
    }

    /// Make a VoteProposal builder from the given minimum set of arguments
    async fn new_vote_prposal(
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
            tx: self.tx_builder().await,
        }
    }

    /// Make a CommissionRateChange builder from the given minimum set of
    /// arguments
    async fn new_change_commission_rate(
        &self,
        rate: Dec,
        validator: Address,
    ) -> args::CommissionRateChange {
        args::CommissionRateChange {
            rate,
            validator,
            tx_code_path: PathBuf::from(TX_CHANGE_COMMISSION_WASM),
            tx: self.tx_builder().await,
        }
    }

    /// Make a TxInitValidator builder from the given minimum set of arguments
    async fn new_init_validator(
        &self,
        commission_rate: Dec,
        max_commission_rate_change: Dec,
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
            tx_code_path: PathBuf::from(TX_INIT_VALIDATOR_WASM),
            tx: self.tx_builder().await,
        }
    }

    /// Make a TxUnjailValidator builder from the given minimum set of arguments
    async fn new_unjail_validator(
        &self,
        validator: Address,
    ) -> args::TxUnjailValidator {
        args::TxUnjailValidator {
            validator,
            tx_code_path: PathBuf::from(TX_UNJAIL_VALIDATOR_WASM),
            tx: self.tx_builder().await,
        }
    }

    /// Make a Withdraw builder from the given minimum set of arguments
    async fn new_withdraw(&self, validator: Address) -> args::Withdraw {
        args::Withdraw {
            validator,
            source: None,
            tx_code_path: PathBuf::from(TX_WITHDRAW_WASM),
            tx: self.tx_builder().await,
        }
    }

    /// Make a Withdraw builder from the given minimum set of arguments
    async fn new_add_erc20_transfer(
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
            fee_token: self.native_token().await,
            nut: false,
            code_path: PathBuf::from(TX_BRIDGE_POOL_WASM),
            tx: self.tx_builder().await,
        }
    }

    /// Make a ResignSteward builder from the given minimum set of arguments
    async fn new_resign_steward(
        &self,
        steward: Address,
    ) -> args::ResignSteward {
        args::ResignSteward {
            steward,
            tx: self.tx_builder().await,
            tx_code_path: PathBuf::from(TX_RESIGN_STEWARD),
        }
    }

    /// Make a UpdateStewardCommission builder from the given minimum set of
    /// arguments
    async fn new_update_steward_rewards(
        &self,
        steward: Address,
        commission: Vec<u8>,
    ) -> args::UpdateStewardCommission {
        args::UpdateStewardCommission {
            steward,
            commission,
            tx: self.tx_builder().await,
            tx_code_path: PathBuf::from(TX_UPDATE_STEWARD_COMMISSION),
        }
    }

    /// Make a TxCustom builder from the given minimum set of arguments
    async fn new_custom(&self, owner: Address) -> args::TxCustom {
        args::TxCustom {
            owner,
            tx: self.tx_builder().await,
            code_path: None,
            data_path: None,
            serialized_tx: None,
        }
    }

    /// Sign the given transaction using the given signing data
    async fn sign(
        &self,
        tx: &mut Tx,
        args: &args::Tx,
        signing_data: SigningTxData,
    ) -> crate::types::error::Result<()> {
        signing::sign_tx(*self.wallet_mut().await, args, tx, signing_data)
    }

    /// Process the given transaction using the given flags
    async fn submit(
        &self,
        tx: Tx,
        args: &args::Tx,
    ) -> crate::types::error::Result<ProcessTxResponse> {
        tx::process_tx(self.client(), *self.wallet_mut().await, args, tx).await
    }
}

/// Provides convenience methods for common Namada interactions
pub struct NamadaImpl<'a, C, U, V>
where
    C: crate::ledger::queries::Client + Sync,
    U: WalletIo,
    V: ShieldedUtils,
{
    /// Used to send and receive messages from the ledger
    pub client: &'a C,
    /// Stores the addresses and keys required for ledger interactions
    pub wallet: Arc<RwLock<&'a mut Wallet<U>>>,
    /// Stores the current state of the shielded pool
    pub shielded: Arc<RwLock<&'a mut ShieldedContext<V>>>,
    /// The default builder for a Tx
    prototype: args::Tx,
}

impl<'a, C, U, V> NamadaImpl<'a, C, U, V>
where
    C: crate::ledger::queries::Client + Sync,
    U: WalletIo,
    V: ShieldedUtils,
{
    /// Construct a new Namada context
    pub fn new(
        client: &'a C,
        wallet: &'a mut Wallet<U>,
        shielded: &'a mut ShieldedContext<V>,
    ) -> Self {
        let fee_token = wallet
            .find_address(args::NAM)
            .expect("NAM not in wallet")
            .clone();
        Self {
            client,
            wallet: Arc::new(RwLock::new(wallet)),
            shielded: Arc::new(RwLock::new(shielded)),
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
                fee_token,
                fee_unshield: None,
                gas_limit: GasLimit::from(20_000),
                expiration: None,
                disposable_signing_key: false,
                chain_id: None,
                signing_keys: vec![],
                signatures: vec![],
                tx_reveal_code_path: PathBuf::from(TX_REVEAL_PK),
                verification_key: None,
                password: None,
            },
        }
    }
}

#[async_trait::async_trait(?Send)]
impl<'a, C, U, V> Namada<'a> for NamadaImpl<'a, C, U, V>
where
    C: crate::ledger::queries::Client + Sync,
    U: WalletIo + WalletStorage,
    V: ShieldedUtils,
{
    type Client = C;
    type ShieldedUtils = V;
    type WalletUtils = U;

    /// Obtain the prototypical Tx builder
    async fn tx_builder(&self) -> args::Tx {
        self.prototype.clone()
    }

    fn client(&self) -> &'a Self::Client {
        self.client
    }

    async fn wallet(
        &self,
    ) -> RwLockReadGuard<&'a mut Wallet<Self::WalletUtils>> {
        self.wallet.read().await
    }

    async fn wallet_mut(
        &self,
    ) -> RwLockWriteGuard<&'a mut Wallet<Self::WalletUtils>> {
        self.wallet.write().await
    }

    async fn shielded(
        &self,
    ) -> RwLockReadGuard<&'a mut ShieldedContext<Self::ShieldedUtils>> {
        self.shielded.read().await
    }

    async fn shielded_mut(
        &self,
    ) -> RwLockWriteGuard<&'a mut ShieldedContext<Self::ShieldedUtils>> {
        self.shielded.write().await
    }
}

/// Allow the prototypical Tx builder to be modified
impl<'a, C, U, V> args::TxBuilder<SdkTypes> for NamadaImpl<'a, C, U, V>
where
    C: crate::ledger::queries::Client + Sync,
    U: WalletIo,
    V: ShieldedUtils,
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
