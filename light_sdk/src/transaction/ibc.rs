use ibc::core::Msg;
pub use namada_core::ibc::applications::transfer::msgs::transfer::MsgTransfer;
use namada_core::proto::Tx;
use namada_core::types::hash::Hash;
use namada_core::types::key::common;
use namada_core::types::time::MIN_UTC;

use super::GlobalArgs;
use crate::transaction;

const TX_IBC_WASM: &str = "tx_ibc.wasm";

pub struct IbcTransfer(Tx);

impl IbcTransfer {
    /// Build a raw IbcTransfer transaction from the given parameters
    pub fn new(
        packet_data: MsgTransfer,
        GlobalArgs {
            expiration,
            code_hash,
            chain_id,
        }: GlobalArgs,
    ) -> Self {
        let mut tx = Tx::new(chain_id, expiration);
        tx.header.timestamp = MIN_UTC;
        tx.add_code_from_hash(code_hash, Some(TX_IBC_WASM.to_string()));

        let mut data = vec![];
        prost::Message::encode(&packet_data.to_any(), &mut data).unwrap();
        tx.set_data(namada_core::proto::Data::new(data));

        Self(tx)
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
