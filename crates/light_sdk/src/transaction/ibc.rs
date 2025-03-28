use std::str::FromStr;

use namada_sdk::address::Address;
use namada_sdk::hash::Hash;
pub use namada_sdk::ibc::apps::transfer::types::msgs::transfer::MsgTransfer;
use namada_sdk::ibc::primitives::ToProto;
use namada_sdk::key::common;
use namada_sdk::time::DateTimeUtc;
use namada_sdk::token::DenominatedAmount;
use namada_sdk::tx::data::GasLimit;
use namada_sdk::tx::{Authorization, Tx, TxError};

use super::{GlobalArgs, attach_fee, attach_fee_signature};
use crate::transaction;

const TX_IBC_WASM: &str = "tx_ibc.wasm";

/// An IBC transfer
#[derive(Debug, Clone)]
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
        tx.header.timestamp =
            DateTimeUtc::from_str("2000-01-01T00:00:00Z").unwrap();
        tx.add_code_from_hash(code_hash, Some(TX_IBC_WASM.to_string()));

        let mut data = vec![];
        prost::Message::encode(&packet_data.to_any(), &mut data).unwrap();
        tx.set_data(namada_sdk::tx::Data::new(data));

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

    /// Attach the fee data to the tx
    pub fn attach_fee(
        self,
        fee: DenominatedAmount,
        token: Address,
        fee_payer: common::PublicKey,
        gas_limit: GasLimit,
    ) -> Self {
        Self(attach_fee(self.0, fee, token, fee_payer, gas_limit))
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
    pub fn validate_tx(&self) -> Result<Option<&Authorization>, TxError> {
        self.0.validate_tx()
    }
}
