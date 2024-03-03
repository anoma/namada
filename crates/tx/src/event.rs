//! Transaction events.

use namada_core::event::extend::{
    ComposeEvent, ExtendEvent, WithBlockHeight, WithLog, WithTxHash,
};
use namada_core::event::Event;

use super::Tx;
use crate::data::{ResultCode, TxResult};
use crate::TxType;

/// Creates a new event with the hash and height of the transaction
/// already filled in
pub fn new_tx_event(tx: &Tx, height: u64) -> Event {
    let base_event = match tx.header().tx_type {
        TxType::Wrapper(_) => {
            Event::accepted_tx().compose(WithTxHash(tx.header_hash()))
        }
        TxType::Decrypted(_) => Event::applied_tx().compose(WithTxHash(
            tx.clone().update_header(TxType::Raw).header_hash(),
        )),
        TxType::Protocol(_) => {
            Event::applied_tx().compose(WithTxHash(tx.header_hash()))
        }
        _ => unreachable!(),
    };
    base_event
        .compose(WithBlockHeight(height.into()))
        .compose(WithLog(String::new()))
        .into()
}

/// Extend an [`Event`] with result code data.
pub struct WithResultCode(pub ResultCode);

impl ExtendEvent for WithResultCode {
    #[inline]
    fn extend_event(self, event: &mut Event) {
        let Self(code) = self;
        event["code"] = code.into();
    }
}

/// Extend an [`Event`] with inner tx data.
pub struct WithInnerTx<'result>(pub &'result TxResult);

impl ExtendEvent for WithInnerTx<'_> {
    #[inline]
    fn extend_event(self, event: &mut Event) {
        let Self(tx_result) = self;
        event["inner_tx"] = tx_result.to_string();
    }
}
