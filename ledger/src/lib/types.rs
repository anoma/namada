use prost;
pub use prost::Message;

#[derive(Clone, Eq, PartialEq, Message)]
pub struct Transaction {
    #[prost(uint64)]
    pub count: u64,
}

#[test]
fn encoding_round_trip() {
    let tx = Transaction { count: 10 };
    let mut tx_bytes = vec![];
    tx.encode(&mut tx_bytes).unwrap();
    let tx_hex = hex::encode(tx_bytes);
    let tx_from_hex = hex::decode(tx_hex).unwrap();
    let tx_from_bytes = Transaction::decode(&tx_from_hex[..]).unwrap();
    assert_eq!(tx, tx_from_bytes);
}
