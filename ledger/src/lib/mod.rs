//! Shared code for the node, client etc.

use prost;
pub use prost::Message;

// TODO all the data here will use concrete types that will be convertable
// to/from bytes to be used by tendermint module
#[derive(Clone, Eq, PartialEq, Message)]
pub struct Transaction {
    #[prost(uint64)]
    pub count: u64
}