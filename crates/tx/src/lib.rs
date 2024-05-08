#![allow(missing_docs)]

pub mod action;
pub mod data;
pub mod event;
pub mod proto;
mod types;

use data::TxType;
pub use event::new_tx_event;
pub use namada_core::key::SignableEthMessage;
pub use namada_core::sign::SignatureIndex;
pub use types::{
    standalone_signature, verify_standalone_sig, Authorization, BatchedTx,
    BatchedTxRef, Code, Commitment, CompressedAuthorization, Data, DecodeError,
    Header, IndexedInnerTx, IndexedTx, MaspBuilder, Memo, Section, Signed,
    Signer, Tx, TxCommitments, TxError, VerifySigError,
};

#[cfg(test)]
mod tests {
    use data_encoding::HEXLOWER;
    use prost::Message;

    use super::*;

    #[test]
    fn encoding_round_trip() {
        use proto::Tx;

        let tx = Tx {
            data: "arbitrary data".as_bytes().to_owned(),
        };
        let mut tx_bytes = vec![];
        tx.encode(&mut tx_bytes).unwrap();
        let tx_hex = HEXLOWER.encode(&tx_bytes);
        let tx_from_hex = HEXLOWER.decode(tx_hex.as_ref()).unwrap();
        let tx_from_bytes = Tx::decode(&tx_from_hex[..]).unwrap();
        assert_eq!(tx, tx_from_bytes);
    }
}
