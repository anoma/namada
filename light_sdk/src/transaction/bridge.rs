use namada_core::proto::Tx;
pub use namada_core::types::eth_bridge_pool::{GasFee, TransferToEthereum};
use namada_core::types::hash::Hash;
use namada_core::types::key::common;

use super::GlobalArgs;
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
            namada_core::types::eth_bridge_pool::PendingTransfer {
                transfer,
                gas_fee,
            };

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
}
