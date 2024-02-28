#![allow(missing_docs)]

pub mod data;
pub mod proto;
mod types;

use std::collections::HashMap;

use data::TxType;
use namada_core::event::{Event, EventLevel, EventType};
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
    let mut event = match tx.header().tx_type {
        TxType::Wrapper(_) => {
            let mut event = Event {
                event_type: EventType::Accepted,
                level: EventLevel::Tx,
                attributes: HashMap::new(),
            };
            event["hash"] = tx.header_hash().to_string();
            event
        }
        TxType::Decrypted(_) => {
            let mut event = Event {
                event_type: EventType::Applied,
                level: EventLevel::Tx,
                attributes: HashMap::new(),
            };
            event["hash"] = tx
                .clone()
                .update_header(TxType::Raw)
                .header_hash()
                .to_string();
            event
        }
        TxType::Protocol(_) => {
            let mut event = Event {
                event_type: EventType::Applied,
                level: EventLevel::Tx,
                attributes: HashMap::new(),
            };
            event["hash"] = tx.header_hash().to_string();
            event
        }
        _ => unreachable!(),
    };
    event["height"] = height.to_string();
    event["log"] = "".to_string();
    event
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
