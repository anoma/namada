use prost;
pub use prost::Message;

#[derive(Clone, Eq, PartialEq, Message)]
pub struct Tx {
    #[prost(bytes = "vec")]
    pub code: Vec<u8>,
    #[prost(bytes = "vec", optional)]
    pub data: Option<Vec<u8>>,
}

#[test]
fn encoding_round_trip() {
    let tx = Tx {
        code: "wasm code".as_bytes().to_owned(),
        data: Some("arbitrary data".as_bytes().to_owned()),
    };
    let mut tx_bytes = vec![];
    tx.encode(&mut tx_bytes).unwrap();
    let tx_hex = hex::encode(tx_bytes);
    let tx_from_hex = hex::decode(tx_hex).unwrap();
    let tx_from_bytes = Tx::decode(&tx_from_hex[..]).unwrap();
    assert_eq!(tx, tx_from_bytes);
}
