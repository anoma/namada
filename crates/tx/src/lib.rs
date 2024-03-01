#![allow(missing_docs)]

pub mod data;
pub mod proto;
mod types;

use data::TxType;
use namada_core::event::extend::*;
use namada_core::event::Event;
pub use namada_core::key::SignableEthMessage;
pub use namada_core::sign::SignatureIndex;
pub use types::{
    standalone_signature, verify_standalone_sig, Code, Commitment,
    CompressedSignature, Data, DecodeError, Header, MaspBuilder, Memo, Section,
    Signature, Signed, Signer, Tx, TxError, VerifySigError,
};

/// Creates a new event with the hash and height of the transaction
/// already filled in
pub fn new_tx_event(tx: &Tx, height: u64) -> Event {
    let base_event = match tx.header().tx_type {
        TxType::Wrapper(_) => {
            Event::accepted_tx().compose(WithTxHash(tx.header_hash()))
        }
        TxType::Decrypted(_) => Event::applied_tx().compose(WithTxHash(
            tx.clone().update_header(TxType::Raw).header_hash(),
        )),
        TxType::Protocol(_) => {
            Event::applied_tx().compose(WithTxHash(tx.header_hash()))
        }
        _ => unreachable!(),
    };
    base_event
        .compose(WithBlockHeight(height.into()))
        .compose(WithLog(String::new()))
        .into()
}

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
