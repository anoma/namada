//! Shared code for the node, client etc.
// TODO all the data here will use concrete types that will be convertable
// to/from bytes to be used by tendermint module
pub struct Transaction<'a> {
    pub data: &'a [u8],
}