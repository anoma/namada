use std::collections::HashSet;

use crate::proto::types;

#[derive(Debug)]
pub enum MatchmakerMessage {
    InjectTx(types::Tx),
    RemoveIntents(HashSet<Vec<u8>>),
    UpdateData(Vec<u8>),
}
