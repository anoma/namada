//! The oracle is controlled by sending commands over a channel.

use tokio::sync::mpsc;

use super::config::Config;

/// Returns two sides of a [`mpsc`] channel that can be used for controlling an
/// oracle.
pub fn channel() -> (mpsc::Sender<Command>, mpsc::Receiver<Command>) {
    mpsc::channel(1)
}

/// Commands used to configure and control an `Oracle`.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash, Ord, PartialOrd)]
pub enum Command {
    /// Initializes the oracle with the given configuration and immediately
    /// starts it.
    Initialize { config: Config },
}
