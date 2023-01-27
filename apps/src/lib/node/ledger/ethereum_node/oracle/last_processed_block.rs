//! Functionality to do with publishing which blocks we have processed.

use namada::core::types::ethereum;
use tokio::sync::watch;

pub type Sender = watch::Sender<Option<ethereum::BlockHeight>>;
pub type Receiver = watch::Receiver<Option<ethereum::BlockHeight>>;

/// Construct a [`tokio::sync::watch`] channel to publish the most recently
/// processed block. Until the live oracle processes its first block, this will
/// be `None`.
pub fn channel() -> (Sender, Receiver) {
    watch::channel(None)
}
