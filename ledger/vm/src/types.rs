use borsh::{BorshDeserialize, BorshSerialize};

// TODO remove this file

// TODO Temporary
#[derive(Clone, Debug, BorshSerialize, BorshDeserialize)]
pub struct TxMsg {
    pub src: String,
    pub dest: String,
    pub amount: u64,
}
