//! The oracle is controlled by sending commands over a channel.

use namada::eth_bridge::oracle::config::Config;
use tokio::sync::mpsc;

/// Used to send commands to an oracle.
pub type Sender = mpsc::Sender<Command>;
/// Used by an oracle to receive commands.
pub type Receiver = mpsc::Receiver<Command>;

/// Returns two sides of a [`mpsc`] channel that can be used for controlling an
/// oracle.
pub fn channel() -> (Sender, Receiver) {
    mpsc::channel(5)
}

/// Commands used to configure and control an `Oracle`.
#[derive(Clone, Debug, Eq, PartialEq, Hash, Ord, PartialOrd)]
pub enum Command {
    /// Update the config if it changes in storage.
    /// Also used to send an initial configuration to the oracle for it to use.
    /// The oracle will not do anything until this command has been sent.
    UpdateConfig(Config),
}
