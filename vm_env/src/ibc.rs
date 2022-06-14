//! IBC functions for transactions.

pub use namada::ledger::ibc::handler::IbcActions;
use namada::types::ibc::IbcEvent;
use namada::types::storage::{BlockHeight, Key};
use namada::types::time::Rfc3339String;
use namada::types::token::Amount;

use crate::imports::tx;
use crate::token::tx::multitoken_transfer;

/// This struct integrates and gives access to lower-level IBC functions.
pub struct Ibc;

impl IbcActions for Ibc {
    fn read_ibc_data(&self, key: &Key) -> Option<Vec<u8>> {
        tx::read_bytes(key.to_string())
    }

    fn write_ibc_data(&self, key: &Key, data: impl AsRef<[u8]>) {
        tx::write_bytes(key.to_string(), data)
    }

    fn delete_ibc_data(&self, key: &Key) {
        tx::delete(key.to_string())
    }

    fn emit_ibc_event(&self, event: IbcEvent) {
        tx::emit_ibc_event(&event)
    }

    fn transfer_token(&self, src: &Key, dest: &Key, amount: Amount) {
        multitoken_transfer(src, dest, amount)
    }

    fn get_height(&self) -> BlockHeight {
        tx::get_block_height()
    }

    fn get_header_time(&self) -> Rfc3339String {
        tx::get_block_time()
    }
}
