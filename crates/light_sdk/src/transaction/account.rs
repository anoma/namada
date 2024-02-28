use namada_sdk::address::Address;
use namada_sdk::hash::Hash;
use namada_sdk::key::common;
use namada_sdk::storage::Epoch;
use namada_sdk::token::DenominatedAmount;
use namada_sdk::tx::data::GasLimit;
use namada_sdk::tx::{Signature, Tx, TxError};

use super::{attach_fee, attach_fee_signature, GlobalArgs};
use crate::transaction;

const TX_INIT_ACCOUNT_WASM: &str = "tx_init_account.wasm";
const TX_REVEAL_PK_WASM: &str = "tx_reveal_pk.wasm";
const TX_UPDATE_ACCOUNT_WASM: &str = "tx_update_account.wasm";

/// Transaction to initialize an established account
pub struct InitAccount(Tx);

impl InitAccount {
    /// Build a raw InitAccount transaction from the given parameters
    pub fn new(
        public_keys: Vec<common::PublicKey>,
        vp_code_hash: Hash,
        threshold: u8,
        args: GlobalArgs,
    ) -> Self {
        let init_account = namada_sdk::account::InitAccount {
            public_keys,
            vp_code_hash,
            threshold,
        };

        Self(transaction::build_tx(
            args,
            init_account,
            TX_INIT_ACCOUNT_WASM.to_string(),
        ))
    }

    /// Get the bytes to sign for the given transaction
    pub fn get_sign_bytes(&self) -> Vec<Hash> {
        transaction::get_sign_bytes(&self.0)
    }

    /// Attach the provided signatures to the tx
    pub fn attach_signatures(
        self,
        signer: common::PublicKey,
        signature: common::Signature,
    ) -> Self {
        Self(transaction::attach_raw_signatures(
            self.0, signer, signature,
        ))
    }

    /// Attach the fee data to the tx
    pub fn attach_fee(
        self,
        fee: DenominatedAmount,
        token: Address,
        fee_payer: common::PublicKey,
        epoch: Epoch,
        gas_limit: GasLimit,
    ) -> Self {
        Self(attach_fee(self.0, fee, token, fee_payer, epoch, gas_limit))
    }

    /// Get the bytes of the fee data to sign
    pub fn get_fee_sig_bytes(&self) -> Hash {
        transaction::get_wrapper_sign_bytes(&self.0)
    }

    /// Attach a signature of the fee to the tx
    pub fn attach_fee_signature(
        self,
        signer: common::PublicKey,
        signature: common::Signature,
    ) -> Self {
        Self(attach_fee_signature(self.0, signer, signature))
    }

    /// Generates the protobuf encoding of this transaction
    pub fn to_bytes(&self) -> Vec<u8> {
        self.0.to_bytes()
    }

    /// Gets the inner transaction without the domain wrapper
    pub fn payload(self) -> Tx {
        self.0
    }

    /// Validate this wrapper transaction
    pub fn validate_tx(&self) -> Result<Option<&Signature>, TxError> {
        self.0.validate_tx()
    }
}

/// Transaction to reveal a public key to the ledger to validate signatures of
/// an implicit account
pub struct RevealPk(Tx);

impl RevealPk {
    /// Build a raw Reveal Public Key transaction from the given parameters
    pub fn new(public_key: common::PublicKey, args: GlobalArgs) -> Self {
        Self(transaction::build_tx(
            args,
            public_key,
            TX_REVEAL_PK_WASM.to_string(),
        ))
    }

    /// Get the bytes to sign for the given transaction
    pub fn get_sign_bytes(&self) -> Vec<Hash> {
        transaction::get_sign_bytes(&self.0)
    }

    /// Attach the provided signatures to the tx
    pub fn attach_signatures(
        self,
        signer: common::PublicKey,
        signature: common::Signature,
    ) -> Self {
        Self(transaction::attach_raw_signatures(
            self.0, signer, signature,
        ))
    }

    /// Attach the fee data to the tx
    pub fn attach_fee(
        self,
        fee: DenominatedAmount,
        token: Address,
        fee_payer: common::PublicKey,
        epoch: Epoch,
        gas_limit: GasLimit,
    ) -> Self {
        Self(attach_fee(self.0, fee, token, fee_payer, epoch, gas_limit))
    }

    /// Get the bytes of the fee data to sign
    pub fn get_fee_sig_bytes(&self) -> Hash {
        transaction::get_wrapper_sign_bytes(&self.0)
    }

    /// Attach a signature of the fee to the tx
    pub fn attach_fee_signature(
        self,
        signer: common::PublicKey,
        signature: common::Signature,
    ) -> Self {
        Self(attach_fee_signature(self.0, signer, signature))
    }

    /// Generates the protobuf encoding of this transaction
    pub fn to_bytes(&self) -> Vec<u8> {
        self.0.to_bytes()
    }

    /// Gets the inner transaction without the domain wrapper
    pub fn payload(self) -> Tx {
        self.0
    }

    /// Validate this wrapper transaction
    pub fn validate_tx(&self) -> Result<Option<&Signature>, TxError> {
        self.0.validate_tx()
    }
}

/// Transaction to update the parameters of an established account
pub struct UpdateAccount(Tx);

impl UpdateAccount {
    /// Build a raw UpdateAccount transaction from the given parameters
    pub fn new(
        addr: Address,
        vp_code_hash: Option<Hash>,
        public_keys: Vec<common::PublicKey>,
        threshold: Option<u8>,
        args: GlobalArgs,
    ) -> Self {
        let update_account = namada_sdk::account::UpdateAccount {
            addr,
            vp_code_hash,
            public_keys,
            threshold,
        };

        Self(transaction::build_tx(
            args,
            update_account,
            TX_UPDATE_ACCOUNT_WASM.to_string(),
        ))
    }

    /// Get the bytes to sign for the given transaction
    pub fn get_sign_bytes(&self) -> Vec<Hash> {
        transaction::get_sign_bytes(&self.0)
    }

    /// Attach the provided signatures to the tx
    pub fn attach_signatures(
        self,
        signer: common::PublicKey,
        signature: common::Signature,
    ) -> Self {
        Self(transaction::attach_raw_signatures(
            self.0, signer, signature,
        ))
    }

    /// Attach the fee data to the tx
    pub fn attach_fee(
        self,
        fee: DenominatedAmount,
        token: Address,
        fee_payer: common::PublicKey,
        epoch: Epoch,
        gas_limit: GasLimit,
    ) -> Self {
        Self(attach_fee(self.0, fee, token, fee_payer, epoch, gas_limit))
    }

    /// Get the bytes of the fee data to sign
    pub fn get_fee_sig_bytes(&self) -> Hash {
        transaction::get_wrapper_sign_bytes(&self.0)
    }

    /// Attach a signature of the fee to the tx
    pub fn attach_fee_signature(
        self,
        signer: common::PublicKey,
        signature: common::Signature,
    ) -> Self {
        Self(attach_fee_signature(self.0, signer, signature))
    }

    /// Generates the protobuf encoding of this transaction
    pub fn to_bytes(&self) -> Vec<u8> {
        self.0.to_bytes()
    }

    /// Gets the inner transaction without the domain wrapper
    pub fn payload(self) -> Tx {
        self.0
    }

    /// Validate this wrapper transaction
    pub fn validate_tx(&self) -> Result<Option<&Signature>, TxError> {
        self.0.validate_tx()
    }
}
