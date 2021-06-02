use std::collections::HashSet;

use crate::proto::Tx;

#[derive(Debug)]
pub enum MatchmakerMessage {
    InjectTx(Tx),
    RemoveIntents(HashSet<Vec<u8>>),
    UpdateData(Vec<u8>),
}
