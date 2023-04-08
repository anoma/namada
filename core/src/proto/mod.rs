#![allow(missing_docs)]

pub mod generated;
mod types;

pub use types::{Dkg, Error, Signed, Tx, Data, Code, Signature, Section};

#[cfg(test)]
mod tests {
    use data_encoding::HEXLOWER;
    use generated::types::Tx;
    use prost::Message;

    use super::*;

    /*#[test]
    fn encoding_round_trip() {
        let code = "wasm code".as_bytes().to_owned();
        let inner_tx = "arbitrary data".as_bytes().to_owned();
        let tx = Tx {
            outer_code: code,
            outer_data: Some("arbitrary data".as_bytes().to_owned()),
            outer_timestamp: Some(std::time::SystemTime::now().into()),
            data: None,
            code: vec![],
            extra: vec![],
            timestamp: Some(std::time::SystemTime::now().into()),
            outer_extra: vec![],
        };
        let mut tx_bytes = vec![];
        tx.encode(&mut tx_bytes).unwrap();
        let tx_hex = HEXLOWER.encode(&tx_bytes);
        let tx_from_hex = HEXLOWER.decode(tx_hex.as_ref()).unwrap();
        let tx_from_bytes = Tx::decode(&tx_from_hex[..]).unwrap();
        assert_eq!(tx, tx_from_bytes);
    }*/
}
