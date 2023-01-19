//! The oracle is controlled by sending commands over a channel.

use tokio::sync::mpsc;

use super::config::Config;

/// Used to send commands to an oracle.
pub type Sender = mpsc::Sender<Command>;
/// Used by an oracle to receive commands.
pub type Receiver = mpsc::Receiver<Command>;

/// Returns two sides of a [`mpsc`] channel that can be used for controlling an
/// oracle.
pub fn channel() -> (Sender, Receiver) {
    mpsc::channel(1)
}

/// Commands used to configure and control an `Oracle`.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash, Ord, PartialOrd)]
pub enum Command {
    /// Sends an initial configuration to the oracle for it to use. The oracle
    /// will not do anything until this command has been sent.
    /// [`Command::Start`] should be the first command sent, and at most
    /// once.
    Start { initial: Config },
}
