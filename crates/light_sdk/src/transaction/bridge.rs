use namada_sdk::address::Address;
pub use namada_sdk::eth_bridge_pool::{GasFee, TransferToEthereum};
use namada_sdk::hash::Hash;
use namada_sdk::key::common;
use namada_sdk::storage::Epoch;
use namada_sdk::token::DenominatedAmount;
use namada_sdk::tx::data::GasLimit;
use namada_sdk::tx::{Signature, Tx, TxError};

use super::{attach_fee, attach_fee_signature, GlobalArgs};
use crate::transaction;

const TX_BRIDGE_POOL_WASM: &str = "tx_bridge_pool.wasm";

/// A transfer over the Ethereum bridge
pub struct BridgeTransfer(Tx);

impl BridgeTransfer {
    /// Build a raw BridgeTransfer transaction from the given parameters
    pub fn new(
        transfer: TransferToEthereum,
        gas_fee: GasFee,
        args: GlobalArgs,
    ) -> Self {
        let pending_transfer =
            namada_sdk::eth_bridge_pool::PendingTransfer { transfer, gas_fee };

        Self(transaction::build_tx(
            args,
            pending_transfer,
            TX_BRIDGE_POOL_WASM.to_string(),
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
